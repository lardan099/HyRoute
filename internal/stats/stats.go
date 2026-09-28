// Package stats keeps the traffic statistics of «Статистика»: per day, by
// program, site, server and group. It turns flow records (flows.Registry)
// into per-day deltas: every record is observed when it closes (the
// registry's OnClose) and every few seconds by a sampler (Registry.Ticks),
// which adds only the bytes moved since the last observation. Nothing is
// counted on the packet path, and nothing here can block or fail traffic.
//
// Deltas are written to day files (%APPDATA%\HyRoute\stats\day-*.json, 90
// days), folded into month files (month-*.json, 24 months) by Compact. The
// package does no file I/O itself: Files (internal/store) does.
package stats

import (
	"errors"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
)

// Mode is the collection mode (stats\mode.json).
type Mode string

const (
	ModeAll     Mode = ""
	ModeNoSites Mode = "no-sites"
	ModeOff     Mode = "off"
)

// ParseMode checks a mode from the UI or a file.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case ModeAll, ModeNoSites, ModeOff:
		return m, nil
	}
	return ModeOff, errors.New("неизвестный режим статистики")
}

// Stricter is the stricter of two modes: off > no-sites > all (a restore
// never turns collection or site history back on).
func Stricter(a, b Mode) Mode {
	rank := func(m Mode) int {
		switch m {
		case ModeOff:
			return 2
		case ModeNoSites:
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Label is the mode as the UI names it.
func (m Mode) Label() string {
	switch m {
	case ModeNoSites:
		return "без сайтов"
	case ModeOff:
		return "выключен"
	}
	return "всё"
}

const (
	// maxDeltaDays: unflushed days kept while the disk is unusable; an
	// eighth day drops the oldest.
	maxDeltaDays = 7
	// chunk: observations applied per hold of Collector.mu.
	chunk = 256
	// tombEvery: how often the tombstone generations turn (a tombstone
	// lives one to two of them).
	tombEvery = time.Minute
)

// Collector aggregates the flows of every Source. Lock order: ioMu, then
// mu; mu is innermost (no I/O, no callbacks, bounded work under it). ioMu
// is never taken with a lock of the caller held that a lifecycle path
// waits for (see internal/app).
type Collector struct {
	Log *slog.Logger
	Now func() time.Time // tests; default time.Now (local time decides the day)
	// Names returns the current name of a server or group ID ("" =
	// unknown), stored with its row when a flow is first counted. It is
	// called outside the collector's locks and must not block.
	Names func(id string) string
	// LegacyProxy maps a program of HyRoute 1.2.0's statistics that is a
	// local proxy («Локальный прокси «имя»», «Локальный прокси :порт») to
	// the key ("proxy:<id>") and name of that proxy's rows; ok=false when
	// no current proxy matches unambiguously. Called under ioMu only.
	LegacyProxy func(name string) (key, label string, ok bool)

	ioMu  sync.Mutex // serializes file work
	files Files      // nil: memory only
	// legacy: v1.2.0's traffic.json, imported once (all under ioMu):
	// imported is the mark in mode.json that the import is done;
	// legacyDone ends the attempts of this run; after a transient
	// failure the next one waits until legacyRetry.
	legacy      Legacy
	legacyDone  bool
	imported    bool
	legacyRetry time.Time
	legacyWait  time.Duration

	mode atomic.Value // Mode; read lock-free by the sampler and the close hook

	mu        sync.Mutex
	delta     map[string]*mem // day -> unflushed delta; at most maxDeltaDays keys
	cache     fileCache       // parsed files by name
	bad       map[string]string
	srvs      map[string]srvState
	modeErr   string // mode.json could not be read (collection off)
	writeErr  string // the last flush failed
	readErr   string // the last report could not read a file or the folder
	lost      string // a day's delta was dropped (maxDeltaDays)
	compactAt string // day of the last compaction ("" = due)

	panics atomic.Int64

	// Test hooks (nil in HyRoute): hold runs at every hold of mu by
	// Sample, view at every View it builds.
	testHold, testView func()
}

type srvState struct {
	started   time.Time
	connected bool
	restarts  int
}

// New returns a memory-only collector in mode «Всё» (Configure attaches
// the files and reads the mode).
func New(log *slog.Logger) *Collector {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	c := &Collector{Log: log, delta: map[string]*mem{}, bad: map[string]string{}, srvs: map[string]srvState{}}
	c.mode.Store(ModeAll)
	c.cache.init()
	return c
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Mode is the collection mode in use.
func (c *Collector) Mode() Mode { return c.mode.Load().(Mode) }

// StoreError says why the statistics are not saved completely ("" = they
// are). Texts carry file names and dates only.
func (c *Collector) StoreError() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.storeErrLocked()
}

func (c *Collector) storeErrLocked() string {
	if c.modeErr != "" {
		return c.modeErr
	}
	if c.writeErr != "" {
		return c.writeErr
	}
	if c.readErr != "" {
		return c.readErr
	}
	var newer, broken []string
	for n, why := range c.bad {
		if why == badNewer {
			newer = append(newer, n)
		} else {
			broken = append(broken, n)
		}
	}
	sort.Strings(newer)
	sort.Strings(broken)
	switch {
	case len(newer) > 0:
		return newer[0] + ".json записан более новой версией HyRoute"
	case len(broken) > 0:
		return "файл " + broken[0] + ".json повреждён, пропущен"
	}
	return c.lost
}

func dayOf(t time.Time) string { return t.In(time.Local).Format(dayFmt) }

const (
	dayFmt   = "2006-01-02"
	monthFmt = "2006-01"
)

// deltaLocked returns the delta of day, created on demand (an eighth day
// drops the oldest one). c.mu held.
func (c *Collector) deltaLocked(day string) *mem {
	if m := c.delta[day]; m != nil {
		return m
	}
	if len(c.delta) >= maxDeltaDays {
		oldest := ""
		for d := range c.delta {
			if oldest == "" || d < oldest {
				oldest = d
			}
		}
		delete(c.delta, oldest)
		c.lost = "часть статистики за " + oldest + " потеряна: диск недоступен"
		c.Log.Warn("stats: statistics of a day dropped: storage unavailable", "day", oldest)
	}
	m := newMem()
	c.delta[day] = m
	return m
}

// readdLocked puts a delta that could not be written back (c.mu held).
func (c *Collector) readdLocked(day string, m *mem) {
	c.deltaLocked(day).merge(m)
}

// ---- observations ----

// Source is one flows.Registry (one session, or the local proxies).
type Source struct {
	c      *Collector
	seen   map[uint64]*flowState  // guarded by c.mu
	tomb   [2]map[uint64]struct{} // closed IDs: current and previous generation (c.mu)
	tombAt time.Time              // when tomb[0] became current (c.mu)
	sampMu sync.Mutex             // serializes Sample; guards last, buf, obs
	last   map[uint64]tickState
	buf    []flows.Tick
	obs    []obs
}

type flowState struct {
	f          Flow
	site       string
	ignored    bool  // first seen while collection was off: never counted
	sent, recv int64 // offsets already accounted
}

type tickState struct {
	sent, recv int64
	rev        uint32
	settled    bool // as of the last full View
	refused    bool // flowOf said ok=false (service traffic)
}

// obs is one observation: full (a View's Flow) or counters-only.
type obs struct {
	id              uint64
	full            bool
	f               Flow
	site            string
	siteSet         bool
	settled, closed bool
	sent, recv      int64
}

// NewSource returns a source for one registry.
func (c *Collector) NewSource() *Source {
	return &Source{c: c, seen: map[uint64]*flowState{}, tomb: [2]map[uint64]struct{}{{}, {}}, last: map[uint64]tickState{}}
}

// recovered logs a panic of the observation code once per 1000: it runs
// on engine goroutines, and a statistics bug must not take routing down.
func (c *Collector) recovered(where string) {
	if r := recover(); r != nil {
		if n := c.panics.Add(1); n%1000 == 1 {
			c.Log.Error("stats: observation failed", "where", where, "panic", r, "count", n)
		}
	}
}

// Sample applies one sample of reg (the sampler every 5 s, the final
// sample at Disconnect/EndSession/Shutdown). A flow whose counters and
// field revision did not change is skipped; a known flow whose revision
// did not change gives a counters-only observation (no View); a new ID or
// a changed revision gives a full one (View + flowOf, the site key
// computed here, outside c.mu). In mode off no View is built. Observations
// are applied under c.mu in chunks of at most 256 per hold.
func (s *Source) Sample(now time.Time, reg *flows.Registry) {
	if reg == nil {
		return
	}
	defer s.c.recovered("sample")
	s.sampMu.Lock()
	defer s.sampMu.Unlock()
	s.buf = reg.Ticks(s.buf)
	off := s.c.Mode() == ModeOff
	next := make(map[uint64]tickState, len(s.buf))
	s.obs = s.obs[:0]
	for _, t := range s.buf {
		l, known := s.last[t.ID]
		switch {
		case known && t.Sent == l.sent && t.Recv == l.recv && t.Rev == l.rev,
			known && t.Rev == l.rev && (!l.settled || l.refused):
			// Nothing can have changed, or not counted yet (unsettled or
			// service traffic).
			next[t.ID] = l
			continue
		case known && t.Rev == l.rev:
			s.obs = append(s.obs, obs{id: t.ID, sent: t.Sent, recv: t.Recv})
			l.sent, l.recv = t.Sent, t.Recv
			next[t.ID] = l
			continue
		case off:
			// No View: a new flow is entered as ignored, a counted one
			// only moves its offsets.
			s.obs = append(s.obs, obs{id: t.ID, sent: t.Sent, recv: t.Recv})
			next[t.ID] = tickState{sent: t.Sent, recv: t.Recv, rev: t.Rev, settled: known && l.settled}
			continue
		}
		if s.c.testView != nil {
			s.c.testView()
		}
		v := t.Rec.View(now)
		f, settled, ok := flowOf(v)
		st := tickState{sent: v.Sent, recv: v.Recv, rev: t.Rev, settled: settled && ok, refused: !ok}
		next[t.ID] = st
		if !ok || !settled {
			continue
		}
		o := obs{id: t.ID, full: true, f: f, settled: true, sent: v.Sent, recv: v.Recv}
		if !known || !l.settled {
			// Not counted yet: the site key and the names are needed
			// (computed once).
			s.c.prepare(&o)
		}
		s.obs = append(s.obs, o)
	}
	s.last = next
	for i := 0; i < len(s.obs); i += chunk {
		end := min(i+chunk, len(s.obs))
		s.c.mu.Lock()
		if s.c.testHold != nil {
			s.c.testHold()
		}
		for j := i; j < end; j++ {
			s.applyLocked(now, &s.obs[j])
		}
		s.c.mu.Unlock()
	}
}

// Closed is the registry's OnClose hook: it applies the final View of one
// record. The site key is computed outside c.mu and only for an ID not
// seen yet. Mode off: only forgets the flow.
func (s *Source) Closed(v flows.View) {
	defer s.c.recovered("close")
	now := s.c.now()
	o := obs{id: v.ID, full: true, closed: true, sent: v.Sent, recv: v.Recv}
	var ok bool
	o.f, o.settled, ok = flowOf(v)
	if !ok {
		o.full, o.settled = false, false
	}
	s.c.mu.Lock()
	_, known := s.seen[v.ID]
	s.c.mu.Unlock()
	if ok && o.settled && !known && s.c.Mode() != ModeOff {
		s.c.prepare(&o)
	}
	s.c.mu.Lock()
	s.applyLocked(now, &o)
	s.c.mu.Unlock()
}

// prepare computes what a first observation needs, outside c.mu: the site
// key and the names of the server and group.
func (c *Collector) prepare(o *obs) {
	o.site, o.siteSet = siteKey(o.f.Domain), true
	if c.Names != nil && o.f.Route == Tunnel {
		if o.f.Server != "" {
			o.f.ServerName = c.Names(o.f.Server)
		}
		if o.f.Group != "" {
			o.f.GroupName = c.Names(o.f.Group)
		}
	}
}

// applyLocked applies one observation (c.mu held).
func (s *Source) applyLocked(now time.Time, o *obs) {
	c := s.c
	if now.Sub(s.tombAt) >= tombEvery || now.Before(s.tombAt) {
		s.tomb[1], s.tomb[0], s.tombAt = s.tomb[0], map[uint64]struct{}{}, now
	}
	if _, ok := s.tomb[0][o.id]; ok {
		return
	}
	if _, ok := s.tomb[1][o.id]; ok {
		return
	}
	mode := c.Mode()
	st := s.seen[o.id]
	if st == nil {
		switch {
		case mode == ModeOff:
			if !o.closed {
				s.seen[o.id] = &flowState{ignored: true, sent: o.sent, recv: max(o.recv, 0)}
			}
		case !o.full || !o.settled:
			// Not counted: unsettled, service traffic, or a flow this
			// source forgot.
		default:
			site := o.site
			if !o.siteSet {
				site = siteKey(o.f.Domain)
			}
			st = &flowState{f: o.f, site: site}
			s.seen[o.id] = st
			c.countConnLocked(now, st, mode)
		}
		if st == nil {
			if o.closed {
				s.tomb[0][o.id] = struct{}{}
			}
			return
		}
	} else if o.full && !st.ignored {
		// The NL6 case: a flow refused while the tunnel was down that
		// carries datagrams once it is up. Its connection stays counted
		// as it was.
		st.f.Failed = o.f.Failed
	}
	recv := max(o.recv, 0)
	ds, dr := max(o.sent-st.sent, 0), max(recv-st.recv, 0)
	st.sent, st.recv = max(st.sent, o.sent), max(st.recv, recv)
	if !st.ignored && !st.f.Failed && mode != ModeOff && ds+dr > 0 {
		c.countBytesLocked(now, st, mode, ds, dr)
	}
	if o.closed {
		delete(s.seen, o.id)
		s.tomb[0][o.id] = struct{}{}
	}
}

// rows returns the rows of a flow in day d (site unless mode no-sites;
// server and group for tunnel flows only).
func (c *Collector) rowsLocked(d *mem, st *flowState, mode Mode) []*Row {
	rows := make([]*Row, 0, 4)
	rows = append(rows, d.row(listApps, st.f.App, st.f.AppName))
	if mode != ModeNoSites {
		rows = append(rows, d.row(listSites, st.site, ""))
	}
	if st.f.Route == Tunnel {
		rows = append(rows, d.row(listServers, st.f.Server, st.f.ServerName))
		if st.f.Group != "" {
			rows = append(rows, d.row(listGroups, st.f.Group, st.f.GroupName))
		}
	}
	return rows
}

func (c *Collector) countConnLocked(now time.Time, st *flowState, mode Mode) {
	var n Counters
	switch st.f.Route {
	case Tunnel:
		if st.f.Failed {
			n.F = 1
		} else {
			n.TC = 1
		}
		if st.f.Failover {
			n.FO = 1
		}
	case Direct:
		if st.f.Failed {
			n.F = 1
		} else {
			n.DC = 1
		}
	case Block:
		n.BC = 1
	}
	d := c.deltaLocked(dayOf(now))
	d.total.add(n)
	for _, r := range c.rowsLocked(d, st, mode) {
		r.Counters.add(n)
	}
}

func (c *Collector) countBytesLocked(now time.Time, st *flowState, mode Mode, ds, dr int64) {
	var n Counters
	switch st.f.Route {
	case Tunnel:
		n.TU, n.TD = clamp(ds), clamp(dr)
	case Direct:
		n.DU = clamp(ds) // direct ↓ is not measured
	default:
		return
	}
	d := c.deltaLocked(dayOf(now))
	d.total.add(n)
	for _, r := range c.rowsLocked(d, st, mode) {
		r.Counters.add(n)
	}
}

// ---- events ----

// ServerState is a running server as the drop detection sees it.
type ServerState struct {
	ID, Name  string
	Started   time.Time
	Connected bool
	Restarts  int
}

// ServerStates feeds the servers' statuses (every sample): a drop is
// counted when the same endpoint (Started unchanged) was connected at the
// previous call and now is not, or restarted meanwhile. A new endpoint or
// a server that is gone resets its state without counting. In mode off
// the states are kept up to date but nothing is counted (a drop while
// collection was off is not counted when it is back on); no session is
// an empty list.
func (c *Collector) ServerStates(now time.Time, list []ServerState) {
	off := c.Mode() == ModeOff
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[string]srvState, len(list))
	for _, s := range list {
		prev, ok := c.srvs[s.ID]
		next[s.ID] = srvState{started: s.Started, connected: s.Connected, restarts: s.Restarts}
		if off || !ok || !prev.started.Equal(s.Started) || !prev.connected {
			continue
		}
		if !s.Connected || s.Restarts > prev.restarts {
			d := c.deltaLocked(dayOf(now))
			d.events.Drops = add(d.events.Drops, 1)
			r := d.row(listServers, s.ID, s.Name)
			r.Drops = add(r.Drops, 1)
		}
	}
	c.srvs = next
}

// EngineFailed counts a failure of the interception engine.
func (c *Collector) EngineFailed(now time.Time) {
	if c.Mode() == ModeOff {
		return
	}
	c.mu.Lock()
	d := c.deltaLocked(dayOf(now))
	d.events.EngineFails = add(d.events.EngineFails, 1)
	c.mu.Unlock()
}
