// Package reconcile compares what is on the servers with what HyRoute
// recorded (P4-06): the Hysteria config with the current revision, the
// unit and the binary with the installation, the geo databases with
// server_geo, the client config and the unit of a cascade link with the
// link. A round reads only (remote.ReadOnly) and runs outside the job
// engine, as the monitor does. A difference makes the server need
// attention («изменено вне HyRoute»); nothing on a server changes until
// the admin accepts what is there (Accept: a revision with source
// external, or the hashes recorded) or puts HyRoute's version back
// (Revert: the job that writes it, with its checks, backup and rollback).
package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Store is what the reconciliation reads and records.
type Store interface {
	ListServers(ctx context.Context) ([]model.Server, error)
	ServerByID(ctx context.Context, id int64) (model.Server, error)
	HostKey(ctx context.Context, serverID int64) (model.HostKey, error)
	SwapServerState(ctx context.Context, id int64, from []model.ServerState, state model.ServerState, at time.Time) (bool, error)
	UnfinishedJobs(ctx context.Context) ([]model.Job, error)
	ListJobs(ctx context.Context, f model.JobFilter) ([]model.Job, error)
	JobByID(ctx context.Context, id int64) (model.Job, error)
	ListChains(ctx context.Context) ([]model.Chain, error)
	ChainByID(ctx context.Context, id int64) (model.Chain, error)
	UpdateLink(ctx context.Context, l model.ChainLink) error
	AddAudit(ctx context.Context, e model.AuditEntry) error
	store.Configs
	store.Installations
	store.ServerGeos
	store.Drifts
}

// Connector opens an SSH connection to a server (connect.Connector).
type Connector interface {
	Connect(ctx context.Context, serverID int64) (remote.Executor, error)
}

// Events hears of a server's differences, one event a server (the
// watcher of the events of P4-05 is wired here).
type Events interface {
	// Drift: the server's differences are new or changed; what names
	// them briefly (Brief: names and paths, no values). The masked diff
	// stays in the result.
	Drift(ctx context.Context, srv model.Server, what string)
	// DriftGone: nothing differs any more (accepted, reverted, or as
	// HyRoute recorded again).
	DriftGone(ctx context.Context, srv model.Server)
}

// Reconciler checks every server with a trusted host key and a known
// installation each Interval.
type Reconciler struct {
	Store Store
	Conn  Connector
	// Keys seal the config found on a server and open revisions.
	Keys *secrets.Keyring
	// Jobs queues the reverts (nil: Revert is not offered).
	Jobs Reverter
	// Events hears of the differences (nil: nobody).
	Events Events
	Log    *slog.Logger
	Now    func() time.Time
	// Interval between rounds (0: no rounds, a server is checked when
	// asked); First is the wait for the first round after Run starts
	// (default 2 min: jobs the start recovers go first).
	Interval time.Duration
	First    time.Duration
	// Timeout per server (default 60 s); Parallel connections at most
	// (default 4); Poll is how often a revert job is looked at until it
	// ends (default 5 s).
	Timeout  time.Duration
	Parallel int
	Poll     time.Duration

	mu    sync.Mutex
	locks map[int64]*sync.Mutex
	// ctx is Run's: the watches of revert jobs end with it, and Run
	// waits for them.
	ctx     context.Context
	watches sync.WaitGroup
}

var (
	// ErrGone: the difference is not (or no longer) there.
	ErrGone = errors.New("reconcile: no such difference")
	// ErrChanged: the server is not as the reconciliation found it any
	// more; it has to be checked again.
	ErrChanged = errors.New("reconcile: the server changed since it was checked")
	// ErrNoRoot: the SSH user can read neither the config nor the
	// files of a link (no root, no passwordless sudo).
	ErrNoRoot = errors.New("reconcile: the SSH user is neither root nor a passwordless sudoer")
)

func (r *Reconciler) defaults() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Log == nil {
		r.Log = slog.New(slog.DiscardHandler)
	}
	if r.First == 0 {
		r.First = 2 * time.Minute
	}
	if r.Timeout == 0 {
		r.Timeout = time.Minute
	}
	if r.Parallel == 0 {
		r.Parallel = 4
	}
	if r.Poll == 0 {
		r.Poll = 5 * time.Second
	}
	if r.locks == nil {
		r.locks = map[int64]*sync.Mutex{}
	}
}

// lock serializes what touches a server's result: a check, an accept, a
// revert.
func (r *Reconciler) lock(serverID int64) func() {
	r.mu.Lock()
	l := r.locks[serverID]
	if l == nil {
		l = &sync.Mutex{}
		r.locks[serverID] = l
	}
	r.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// background is the context of watches: Run's, or none before Run.
func (r *Reconciler) background() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx == nil {
		return context.Background()
	}
	return r.ctx
}

// Run checks the servers each Interval until ctx ends (with Interval 0
// it only keeps the watches of revert jobs going). It returns once the
// watches have ended too.
func (r *Reconciler) Run(ctx context.Context) {
	r.defaults()
	r.mu.Lock()
	r.ctx = ctx
	r.mu.Unlock()
	defer r.watches.Wait()
	if r.Interval <= 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTimer(r.First)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r.Round(ctx)
		t.Reset(r.Interval)
	}
}

// Round checks every server once: those with a trusted host key and an
// installation HyRoute knows, but not offline ones (the monitor watches
// them) and not those with an unfinished job (the job changes them; they
// go in the next round).
func (r *Reconciler) Round(ctx context.Context) {
	r.defaults()
	list, err := r.Store.ListServers(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.Log.Warn("reconcile: list servers", "err", err)
		}
		return
	}
	busy, err := r.busy(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.Log.Warn("reconcile: jobs", "err", err)
		}
		return
	}
	sem := make(chan struct{}, r.Parallel)
	var wg sync.WaitGroup
	for _, srv := range list {
		if srv.State == model.StateOffline || busy[srv.ID] {
			continue
		}
		if _, err := r.Store.HostKey(ctx, srv.ID); err != nil {
			continue // not trusted yet: no connection
		}
		if _, err := r.Store.Installation(ctx, srv.ID); err != nil {
			continue // nothing HyRoute put there or found
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			if _, err := r.check(ctx, srv); err != nil && !errors.Is(err, store.ErrBusy) && ctx.Err() == nil {
				r.Log.Warn("reconcile: check", "server", srv.Name, "err", err)
			}
		}()
	}
	wg.Wait()
}

// busy are the servers of unfinished jobs.
func (r *Reconciler) busy(ctx context.Context) (map[int64]bool, error) {
	js, err := r.Store.UnfinishedJobs(ctx)
	if err != nil {
		return nil, err
	}
	out := map[int64]bool{}
	for _, j := range js {
		for _, s := range j.AllServers() {
			out[s] = true
		}
	}
	return out, nil
}

// newestJob is the ID of the newest job of the server (0: none) and
// whether the server has an unfinished one.
func (r *Reconciler) newestJob(ctx context.Context, serverID int64) (int64, bool, error) {
	busy, err := r.busy(ctx)
	if err != nil {
		return 0, false, err
	}
	js, err := r.Store.ListJobs(ctx, model.JobFilter{ServerID: serverID, Limit: 1})
	if err != nil || len(js) == 0 {
		return 0, busy[serverID], err
	}
	return js[0].ID, busy[serverID], nil
}

// Check checks one server now (the admin asked): also an offline one,
// never one with an unfinished job (store.ErrBusy). The result is stored
// and returned; a server that could not be read keeps what was found
// before, with the error.
func (r *Reconciler) Check(ctx context.Context, serverID int64) (model.Drift, error) {
	r.defaults()
	srv, err := r.Store.ServerByID(ctx, serverID)
	if err != nil {
		return model.Drift{}, err
	}
	return r.check(ctx, srv)
}

// check compares one server and stores the result.
func (r *Reconciler) check(ctx context.Context, srv model.Server) (model.Drift, error) {
	unlock := r.lock(srv.ID)
	defer unlock()
	newest, busy, err := r.newestJob(ctx, srv.ID)
	if err != nil {
		return model.Drift{}, err
	}
	if busy {
		return model.Drift{}, store.ErrBusy
	}
	prev, err := r.Store.Drift(ctx, srv.ID)
	if errors.Is(err, store.ErrNotFound) {
		prev = model.Drift{ServerID: srv.ID}
	} else if err != nil {
		return prev, err
	}
	cctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	f, err := r.inspect(cctx, srv)
	if err != nil {
		if ctx.Err() != nil {
			return prev, ctx.Err()
		}
		// What was found before still holds as far as anyone knows.
		prev.At, prev.Error = r.Now(), failure(err)
		if serr := r.Store.SetDrift(ctx, prev); serr != nil {
			return prev, serr
		}
		return prev, err
	}
	// A job that started meanwhile may have changed what was read (and
	// what HyRoute recorded): the server waits for the next round.
	if n, busy, err := r.newestJob(ctx, srv.ID); err != nil {
		return prev, err
	} else if busy || n != newest {
		return prev, store.ErrBusy
	}
	d, news, gone, err := r.merge(ctx, prev, f)
	if err != nil {
		return prev, err
	}
	if err := r.Store.SetDrift(ctx, d); err != nil {
		return prev, err
	}
	for _, it := range news {
		r.Log.Warn("reconcile: changed outside HyRoute", "server", srv.Name, "what", it.Key)
	}
	if len(news) > 0 || len(gone) > 0 {
		r.report(ctx, srv, d)
	}
	return d, nil
}

// report tells Events what differs on the server now.
func (r *Reconciler) report(ctx context.Context, srv model.Server, d model.Drift) {
	switch {
	case r.Events == nil:
	case len(d.Items) == 0:
		r.Events.DriftGone(ctx, srv)
	default:
		r.Events.Drift(ctx, srv, Brief(d.Items))
	}
}

// failure is the error of a check for people, without secrets.
func failure(err error) string {
	if errors.Is(err, ErrNoRoot) {
		return "Сервер не проверен: пользователь SSH не root и не может выполнять sudo без пароля, конфиг Hysteria ему не прочитать."
	}
	return "Сервер не проверен: " + redact.String(err.Error())
}

// merge makes the new result from the previous one and what a check
// found: a difference that stays as it was keeps its time and its revert
// job; the server needs attention while there are differences (when it
// was healthy or degraded) and gets back to healthy once they are gone
// (release). news are the differences that are new or changed, gone the
// keys of those no longer there.
func (r *Reconciler) merge(ctx context.Context, prev model.Drift, f found) (d model.Drift, news []model.DriftItem, gone []string, err error) {
	now := r.Now()
	d = model.Drift{ServerID: prev.ServerID, At: now, Checked: f.checked, Skipped: f.skipped, Items: []model.DriftItem{}, AttentionAt: prev.AttentionAt, Reverts: prev.Reverts}
	for _, it := range f.items {
		if old, ok := prev.Item(it.Key); ok && slices.Equal(old.Files, it.Files) {
			it.Since, it.Job = old.Since, old.Job
			// A revert that completed and left the thing as it was
			// (a drop-in reinstall does not remove) is done with.
			if j, err := r.Store.JobByID(ctx, it.Job); it.Job != 0 && err == nil && j.State == model.JobCompleted {
				it.Job = 0
			}
		} else {
			it.Since = now
			news = append(news, it)
		}
		d.Items = append(d.Items, it)
	}
	for _, old := range prev.Items {
		if _, ok := d.Item(old.Key); !ok {
			gone = append(gone, old.Key)
		}
	}
	if f.config != nil {
		if d.Config, err = r.Keys.Seal(f.config, model.DriftContext(d.ServerID)); err != nil {
			return d, nil, nil, err
		}
	}
	if len(d.Items) == 0 {
		r.release(ctx, &d)
		return d, news, gone, nil
	}
	// A job set the state since (it ended healthy, say): the
	// differences make it needs attention again.
	ok, err := r.Store.SwapServerState(ctx, d.ServerID, []model.ServerState{model.StateHealthy, model.StateDegraded}, model.StateNeedsAttention, now)
	if err != nil {
		return d, nil, nil, err
	}
	if ok {
		d.AttentionAt, d.Reverts = now, nil
	}
	return d, news, gone, nil
}

// release gives the server back to healthy once its differences are
// gone, if the needs_attention is the reconciliation's: it set it, and
// no job but the reverts queued from it ran on the server since (another
// job set the state its own way: a failed rollback, an import with
// warnings). The monitor's next round corrects healthy to what the
// server is.
func (r *Reconciler) release(ctx context.Context, d *model.Drift) {
	at, reverts := d.AttentionAt, d.Reverts
	d.AttentionAt, d.Reverts = time.Time{}, nil
	if at.IsZero() {
		return
	}
	js, err := r.Store.ListJobs(ctx, model.JobFilter{ServerID: d.ServerID, Limit: 100})
	if err != nil {
		r.Log.Warn("reconcile: jobs", "err", err)
		return
	}
	for _, j := range js {
		if j.CreatedAt.Before(at) {
			break // newest first
		}
		if !slices.Contains(reverts, j.ID) {
			return
		}
	}
	if _, err := r.Store.SwapServerState(ctx, d.ServerID, []model.ServerState{model.StateNeedsAttention}, model.StateHealthy, r.Now()); err != nil {
		r.Log.Warn("reconcile: state", "err", err)
	}
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
