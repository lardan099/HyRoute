// Package events turns what the controller sees — monitoring rounds, jobs
// that end, SSH logins, geo updates — into events (P4-05). The bus lives
// in the controller's process, no broker: it keeps open and closed events
// in the database (store.Events), glues repeats of an open event into it
// by a dedupe key, and tells its subscribers (the notification channels)
// when an event opens or closes. Texts name servers and cascades, never
// their addresses, and pass through redact (clean.go).
//
// Watcher (watch.go) is where the signals come in; Attention
// (attention.go) is the summary of what wants a look now.
package events

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Keep is how long closed events stay.
const Keep = 30 * 24 * time.Hour

// Store is what the bus reads and writes.
type Store interface {
	store.Events
	ListServers(ctx context.Context) ([]model.Server, error)
	ServerByID(ctx context.Context, id int64) (model.Server, error)
	ChainByID(ctx context.Context, id int64) (model.Chain, error)
	JobByID(ctx context.Context, id int64) (model.Job, error)
}

// Notice is an event that has just opened or closed.
type Notice struct {
	Event model.Event
	// Closed: it ended (Event.CloseText says how).
	Closed bool
}

// Bus stores events and hands them to subscribers.
type Bus struct {
	Store Store
	// Redact holds the secrets the controller knows at run time (SSH
	// passwords, job secrets): texts pass through it.
	Redact *redact.Redactor
	Now    func() time.Time
	Log    *slog.Logger

	// wmu makes a write and the open-key cache one step.
	wmu  sync.Mutex
	open map[string]bool // keys of open events; nil: not read yet
	smu  sync.RWMutex
	subs []func(Notice)
}

func (b *Bus) now() time.Time {
	if b.Now == nil {
		return time.Now()
	}
	return b.Now()
}

func (b *Bus) log() *slog.Logger {
	if b.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return b.Log
}

// Subscribe calls fn with every event that opens or closes. fn runs on
// the raiser's goroutine (the monitor, a job): it must not block.
func (b *Bus) Subscribe(fn func(Notice)) {
	b.smu.Lock()
	b.subs = append(b.subs, fn)
	b.smu.Unlock()
}

func (b *Bus) publish(n Notice) {
	b.smu.RLock()
	subs := b.subs
	b.smu.RUnlock()
	for _, fn := range subs {
		fn(n)
	}
}

// loadOpen reads the keys of the open events once. The caller holds wmu.
func (b *Bus) loadOpen(ctx context.Context) {
	if b.open != nil {
		return
	}
	evs, err := b.Store.ListEvents(ctx, model.EventFilter{OpenOnly: true})
	if err != nil {
		return // the next write tries again; until then, the database decides
	}
	b.open = map[string]bool{}
	for _, e := range evs {
		b.open[e.Key] = true
	}
}

// Raise opens e or, while an event of its key is open, glues it into
// that one. The text is cleaned of secrets and addresses first.
// Subscribers hear of a new event only.
func (b *Bus) Raise(ctx context.Context, e model.Event) error {
	if e.Key == "" || !e.Kind.Valid() {
		return errors.New("events: an event needs a known kind and a key")
	}
	if e.Severity == "" {
		e.Severity = model.SeverityWarning
	}
	e.Text = b.clean(ctx, e.Text)
	e.OpenedAt = b.now()
	b.wmu.Lock()
	b.loadOpen(ctx)
	out, opened, err := b.Store.RaiseEvent(ctx, e)
	if err == nil && b.open != nil {
		b.open[e.Key] = true
	}
	b.wmu.Unlock()
	if err != nil {
		b.log().Warn("events: store", "kind", e.Kind, "err", err)
		return err
	}
	if opened {
		b.log().Info("event", "kind", out.Kind, "text", out.Text)
		b.publish(Notice{Event: out})
	}
	return nil
}

// Resolve closes the open event of key with text (how it ended); nothing
// when none is open. Subscribers hear of it.
func (b *Bus) Resolve(ctx context.Context, key, text string) error {
	b.wmu.Lock()
	b.loadOpen(ctx)
	if b.open != nil && !b.open[key] {
		b.wmu.Unlock()
		return nil
	}
	out, closed, err := b.Store.CloseEvent(ctx, key, b.now(), b.clean(ctx, text))
	if err == nil && b.open != nil {
		delete(b.open, key)
	}
	b.wmu.Unlock()
	if err != nil {
		b.log().Warn("events: store", "key", key, "err", err)
		return err
	}
	if closed {
		b.log().Info("event closed", "kind", out.Kind, "text", out.CloseText)
		b.publish(Notice{Event: out, Closed: true})
	}
	return nil
}

// IsOpen reports whether an event of key is open.
func (b *Bus) IsOpen(ctx context.Context, key string) bool {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	b.loadOpen(ctx)
	return b.open[key]
}

// Run sweeps at once and then every hour until ctx ends.
func (b *Bus) Run(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if err := b.Sweep(ctx); err != nil && ctx.Err() == nil {
			b.log().Warn("events: sweep", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Sweep drops events closed more than Keep ago and closes, without a
// notice, the open events of servers, cascades and jobs that are gone.
func (b *Bus) Sweep(ctx context.Context) error {
	if err := b.Store.PruneEvents(ctx, b.now().Add(-Keep)); err != nil {
		return err
	}
	open, err := b.Store.ListEvents(ctx, model.EventFilter{OpenOnly: true})
	if err != nil {
		return err
	}
	for _, e := range open {
		var err error
		switch e.Subject {
		case model.SubjectServer:
			_, err = b.Store.ServerByID(ctx, e.SubjectID)
		case model.SubjectChain:
			_, err = b.Store.ChainByID(ctx, e.SubjectID)
		case model.SubjectJob:
			_, err = b.Store.JobByID(ctx, e.SubjectID)
		}
		if !errors.Is(err, store.ErrNotFound) {
			continue
		}
		b.wmu.Lock()
		_, _, err = b.Store.CloseEvent(ctx, e.Key, b.now(), "Удалено из панели.")
		if err == nil && b.open != nil {
			delete(b.open, e.Key)
		}
		b.wmu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}
