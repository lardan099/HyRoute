// Package flows is the registry behind the "Connections" tab: every decided
// flow, where it went and why.
package flows

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/logx"
)

// Record is one flow. Identity fields are set before Open; the rest is
// updated through Set while the flow lives.
type Record struct {
	ID      uint64
	PID     uint32
	Process string // exe name
	Path    string
	Proto   uint8
	Src     netip.AddrPort
	Dst     netip.AddrPort
	Start   time.Time

	// Sent/Recv are exact for relayed and tunneled UDP flows. For Direct
	// TCP only Sent is known (inbound is not intercepted): Recv stays -1.
	Sent atomic.Int64
	Recv atomic.Int64

	mu     sync.Mutex
	f      Fields
	end    time.Time
	closed bool
	// counted: Sent and Recv already passed to Registry.OnTraffic.
	counted [2]int64
}

// take returns the tunneled bytes not counted yet (r.mu held).
func (r *Record) take() (profile string, sent, recv int64) {
	if r.f.Route != "tunnel" || r.f.Profile == "" {
		return "", 0, 0
	}
	s, v := r.Sent.Load(), max(r.Recv.Load(), 0)
	sent, recv = s-r.counted[0], v-r.counted[1]
	r.counted = [2]int64{s, v}
	return r.f.Profile, max(sent, 0), max(recv, 0)
}

// Fields are the mutable descriptive fields.
type Fields struct {
	Domain    string `json:"domain"`
	DomainSrc string `json:"domainSrc"` // sni | host | dns | unknown
	Rule      string `json:"rule"`
	Route     string `json:"route"`   // tunnel | direct | block | pending
	Profile   string `json:"profile"` // profile ID for tunnel
	Outcome   string `json:"outcome"` // reflected | passed | rst: ... | dropped: ...
	// Attrib says how the owner process was found:
	// packet | pending | iphelper | pending-timeout | pending-full.
	Attrib string `json:"attrib"`
	// Stage says where the route was decided: packet | sniff | sniff-timeout.
	Stage string `json:"stage"`
	// foundation
	// Excluded is the mandatory exclusion the flow fell under (rules do not
	// apply to it): hysteria | system-dns (self exists in the engine but
	// its flows are never recorded); "" = none. The Rule text of such a
	// flow is for display only.
	Excluded string `json:"excluded,omitempty"`
	// groups
	// Group is the server group Profile (a member) was chosen through
	// (tunnel only).
	Group string `json:"group,omitempty"`
	// Failover: the flow could not use its preferred server
	// (rules.Result.Failover).
	Failover bool `json:"failover,omitempty"`
}

// Set updates fields under the record lock.
func (r *Record) Set(f func(*Fields)) {
	r.mu.Lock()
	f(&r.f)
	r.mu.Unlock()
}

// View is a plain snapshot for the UI and logs.
type View struct {
	ID      uint64 `json:"id"`
	PID     uint32 `json:"pid"`
	Process string `json:"process"`
	Path    string `json:"path"`
	Proto   string `json:"proto"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Fields
	Sent     int64         `json:"sent"`
	Recv     int64         `json:"recv"` // -1 = unknown
	Start    time.Time     `json:"start"`
	Duration time.Duration `json:"duration"`
	Closed   bool          `json:"closed"`
}

func (r *Record) View(now time.Time) View {
	r.mu.Lock()
	defer r.mu.Unlock()
	end := now
	if r.closed {
		end = r.end
	}
	p := "tcp"
	if r.Proto == 17 {
		p = "udp"
	}
	return View{
		ID: r.ID, PID: r.PID, Process: r.Process, Path: r.Path, Proto: p,
		Src: r.Src.String(), Dst: r.Dst.String(), Fields: r.f,
		Sent: r.Sent.Load(), Recv: r.Recv.Load(), Start: r.Start,
		Duration: end.Sub(r.Start), Closed: r.closed,
	}
}

// Registry is safe for concurrent use.
type Registry struct {
	// OnClose is called once per closed record.
	OnClose func(View)
	// OnTraffic receives the bytes tunneled flows moved since the last
	// call for them: from Sample for live flows, and once more on Close.
	// Only the server and the program are passed, never the destination.
	OnTraffic func(profile, process string, sent, recv int64)

	seq    atomic.Uint64
	mu     sync.Mutex
	active map[uint64]*Record
	closed *logx.Ring[View]
}

// NewRegistry keeps the last keepClosed closed flows.
func NewRegistry(keepClosed int) *Registry {
	return &Registry{active: make(map[uint64]*Record), closed: logx.NewRing[View](keepClosed)}
}

// Open registers r and assigns its ID.
func (g *Registry) Open(r *Record) *Record {
	r.ID = g.seq.Add(1)
	if r.Start.IsZero() {
		r.Start = time.Now()
	}
	g.mu.Lock()
	g.active[r.ID] = r
	g.mu.Unlock()
	return r
}

// Close finishes r; repeated calls and records never opened are ignored.
func (g *Registry) Close(r *Record, now time.Time) {
	if r == nil || r.ID == 0 {
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed, r.end = true, now
	profile, sent, recv := r.take()
	r.mu.Unlock()
	g.mu.Lock()
	delete(g.active, r.ID)
	g.mu.Unlock()
	if fn := g.OnTraffic; fn != nil && sent+recv > 0 {
		fn(profile, r.Process, sent, recv)
	}
	v := r.View(now)
	g.closed.Add(v)
	if g.OnClose != nil {
		g.OnClose(v)
	}
}

// Active returns snapshots of live flows.
func (g *Registry) Active(now time.Time) []View {
	g.mu.Lock()
	recs := make([]*Record, 0, len(g.active))
	for _, r := range g.active {
		recs = append(recs, r)
	}
	g.mu.Unlock()
	out := make([]View, len(recs))
	for i, r := range recs {
		out[i] = r.View(now)
	}
	return out
}

// Sample passes the traffic of live tunneled flows since the last call to
// OnTraffic, so that a long download counts in the hour it happens.
func (g *Registry) Sample() {
	fn := g.OnTraffic
	if fn == nil {
		return
	}
	g.mu.Lock()
	recs := make([]*Record, 0, len(g.active))
	for _, r := range g.active {
		recs = append(recs, r)
	}
	g.mu.Unlock()
	for _, r := range recs {
		r.mu.Lock()
		var profile string
		var sent, recv int64
		if !r.closed { // Close counts the rest
			profile, sent, recv = r.take()
		}
		r.mu.Unlock()
		if sent+recv > 0 {
			fn(profile, r.Process, sent, recv)
		}
	}
}

// Closed returns the retained closed flows, oldest first.
func (g *Registry) Closed() []View { return g.closed.Snapshot() }
