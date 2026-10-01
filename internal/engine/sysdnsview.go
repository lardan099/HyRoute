package engine

import (
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/sysdns"
)

// SysDNSView holds the last snapshot of the adapters' DNS setup (dns):
// which addresses are DNS servers, of adapters with or without a default
// gateway, and the local namespaces. Get and Local never block; Kick
// schedules a refresh in the background, so nothing on the packet loop
// waits for the OS.
type SysDNSView struct {
	snap    func() (sysdns.Info, error) // sysdns.Snapshot on Windows; tests inject a fake
	cur     atomic.Pointer[sysdns.Info]
	running atomic.Bool
	last    atomic.Int64 // unix nanos of the last refresh start
	now     func() time.Time
	log     *slog.Logger
	// done is called after each background refresh (tests).
	done func()
}

// kickGap is the least time between two background refreshes.
const kickGap = 5 * time.Second

// NewSysDNSView returns a view that refreshes through snap.
func NewSysDNSView(snap func() (sysdns.Info, error), log *slog.Logger) *SysDNSView {
	if log == nil {
		log = slog.Default()
	}
	return &SysDNSView{snap: snap, now: time.Now, log: log}
}

// Get is the last snapshot, nil before the first refresh (or on a nil
// view).
func (v *SysDNSView) Get() *sysdns.Info {
	if v == nil {
		return nil
	}
	return v.cur.Load()
}

// Local reports a name under a local namespace of the last snapshot.
func (v *SysDNSView) Local(name string) bool { return v.Get().Local(name) }

// Kick starts a background refresh unless one runs or the last one
// started less than kickGap ago. It never blocks.
func (v *SysDNSView) Kick() {
	if v == nil || v.snap == nil {
		return
	}
	if last := v.last.Load(); last != 0 && v.now().Sub(time.Unix(0, last)) < kickGap {
		return
	}
	if !v.running.CompareAndSwap(false, true) {
		return
	}
	v.last.Store(v.now().UnixNano())
	go func() {
		v.refresh()
		// Before done: a Kick right after it may start the next refresh.
		v.running.Store(false)
		if v.done != nil {
			v.done()
		}
	}()
}

// Refresh reads the snapshot now (a caller off the packet loop: the
// session before it starts capturing).
func (v *SysDNSView) Refresh() {
	if v == nil || v.snap == nil {
		return
	}
	v.last.Store(v.now().UnixNano())
	v.refresh()
}

// refresh stores a new snapshot; a failure keeps the old one.
func (v *SysDNSView) refresh() {
	info, err := v.snap()
	if err != nil && info.All == nil {
		v.log.Debug("DNS servers of the adapters not read; the last list stays", "err", err)
		return
	}
	if err != nil {
		v.log.Debug("local DNS namespaces not read completely", "err", err)
	}
	v.cur.Store(&info)
}
