// Package flows is the registry behind the "Connections" tab: every decided
// flow, where it went and why.
package flows

import (
	"net/netip"
	"strings"
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
	// bigudp
	// TooBig: UDP datagrams dropped as larger than Hysteria carries.
	TooBig atomic.Int64
	// conn-rules
	// Parents are the owner's ancestors, nearest first, as the rules saw
	// them: the full path, or the lower-case name when the path is
	// unknown. At most procinfo.MaxDepth. Never mutated after Open.
	Parents []string
	// Sites are the DNS cache names of Dst grouped by site
	// (dnscache.Cache.Sites: the queried name first, then the CNAMEs that
	// led to Dst), as the engine saw them when it decided. At most
	// MaxSites sites of at most MaxSiteNames names; SitesPartial when cut.
	// Nil for flows not decided from a packet. Never mutated after Open.
	Sites        [][]string
	SitesPartial bool

	mu     sync.Mutex
	f      Fields
	end    time.Time
	closed bool
	// stats: rev changes with every Set (the fields may have changed), so
	// the statistics sampler tells "only the counters moved" without a
	// View.
	rev atomic.Uint32
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
	// dns
	// Count: the queries aggregated into a DNS row (Stage StageDNS).
	Count int `json:"count,omitempty"`
	// conn-rules
	// ECH: the ClientHello carried the encrypted_client_hello extension
	// (rules.SrcECH reached the decider), whatever the decider made of the
	// outer name. Domain/DomainSrc still say what decided ("sni" when the
	// outer name was taken for the site).
	ECH bool `json:"ech,omitempty"`
}

// StageDNS marks a DNS row: queries HyRoute answered itself, aggregated
// per requester, name and outcome (dns). Such rows are kept in their own
// ring and are not traffic.
const StageDNS = "dns"

// Set updates fields under the record lock.
func (r *Record) Set(f func(*Fields)) {
	r.mu.Lock()
	f(&r.f)
	r.rev.Add(1)
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
	// bigudp
	TooBig int64 `json:"tooBig,omitempty"` // UDP datagrams dropped as larger than Hysteria carries
	// conn-rules: kept in the closed ring for Lookup, not sent to the UI
	// (up to 8 paths and 16 sites per row; the page polls every second).
	Parents      []string   `json:"-"`
	Sites        [][]string `json:"-"`
	SitesPartial bool       `json:"-"`
}

// OutcomeTooBig is the outcome a view shows for a tunneled UDP flow of
// which nothing was sent because every datagram was larger than Hysteria
// carries (bigudp). It is derived in View, never stored: the first datagram
// that goes through shows "tunneled" again.
const OutcomeTooBig = "dropped: larger than Hysteria carries"

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
	v := View{
		ID: r.ID, PID: r.PID, Process: r.Process, Path: r.Path, Proto: p,
		Src: r.Src.String(), Dst: r.Dst.String(), Fields: r.f,
		Sent: r.Sent.Load(), Recv: r.Recv.Load(), Start: r.Start,
		Duration: end.Sub(r.Start), Closed: r.closed,
	}
	v.TooBig = r.TooBig.Load()
	v.Parents, v.Sites, v.SitesPartial = r.Parents, r.Sites, r.SitesPartial
	if v.TooBig > 0 && v.Sent == 0 && v.Outcome == "tunneled" {
		v.Outcome = OutcomeTooBig
	}
	return v
}

// Registry is safe for concurrent use.
type Registry struct {
	// OnClose is called once per closed record.
	OnClose func(View)

	seq    atomic.Uint64
	mu     sync.Mutex
	active map[uint64]*Record
	closed *logx.Ring[View]
	// dns: closed DNS rows, so they never push connections out of closed.
	dnsClosed atomic.Pointer[logx.Ring[View]]
}

// KeepDNS is how many closed DNS rows a registry keeps by default.
const KeepDNS = 1000

// NewRegistry keeps the last keepClosed closed flows (and the last
// KeepDNS closed DNS rows, see SetKeepDNS).
func NewRegistry(keepClosed int) *Registry {
	g := &Registry{active: make(map[uint64]*Record), closed: logx.NewRing[View](keepClosed)}
	g.dnsClosed.Store(logx.NewRing[View](KeepDNS))
	return g
}

// SetKeepDNS keeps the last n closed DNS rows (dns); the rows kept so far
// are dropped.
func (g *Registry) SetKeepDNS(n int) { g.dnsClosed.Store(logx.NewRing[View](max(n, 1))) }

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
	r.mu.Unlock()
	g.mu.Lock()
	delete(g.active, r.ID)
	g.mu.Unlock()
	v := r.View(now)
	if v.Stage == StageDNS {
		g.dnsClosed.Load().Add(v)
	} else {
		g.closed.Add(v)
	}
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

// Closed returns the retained closed flows, oldest first.
// DNS rows (dns) come from their own ring, merged in by close time.
func (g *Registry) Closed() []View {
	conns, dns := g.closed.Snapshot(), g.dnsClosed.Load().Snapshot()
	if len(dns) == 0 {
		return conns
	}
	out := make([]View, 0, len(conns)+len(dns))
	i, j := 0, 0
	for i < len(conns) || j < len(dns) {
		if j == len(dns) || (i < len(conns) && !conns[i].end().After(dns[j].end())) {
			out = append(out, conns[i])
			i++
		} else {
			out = append(out, dns[j])
			j++
		}
	}
	return out
}

// end is when a closed view was closed.
func (v *View) end() time.Time { return v.Start.Add(v.Duration) }

// ---- stats ----

// Tick is the part of a live record the statistics sampler reads every
// few seconds.
type Tick struct {
	ID         uint64
	Sent, Recv int64
	Rev        uint32
	Rec        *Record // for a full View when the sampler needs one
}

// Ticks appends a Tick of every live record to dst[:0] (reuse dst between
// calls). Only the registry lock is held, for the map walk and atomic
// loads: no field lock, no strings. Live DNS rows are included; the
// sampler skips them by their stage (dns).
func (g *Registry) Ticks(dst []Tick) []Tick {
	dst = dst[:0]
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range g.active {
		dst = append(dst, Tick{ID: r.ID, Sent: r.Sent.Load(), Recv: r.Recv.Load(), Rev: r.rev.Load(), Rec: r})
	}
	return dst
}

// Settled reports that the flow's route and success are final: decided
// and past the relay's dial. "reflected…" (the relay has not finished its
// dial) and "aborted…" (the dial was cancelled because HyRoute stops) are
// never settled, even when the record is closed: such flows are not
// counted at all. Settled and Failed are the only interpreters of outcome
// strings (the engine's finish and the relay's setOutcome point here): a
// new outcome goes into their test table.
func (v View) Settled() bool {
	if v.Route == "" || v.Route == "pending" {
		return false
	}
	return !strings.HasPrefix(v.Outcome, "reflected") && !strings.HasPrefix(v.Outcome, "aborted")
}

// Failed: a tunnel or direct flow that did not open (outcomes "rst: …"
// and "dropped: …" of those routes; for block they are the block itself).
func (v View) Failed() bool {
	return (v.Route == "tunnel" || v.Route == "direct") &&
		(strings.HasPrefix(v.Outcome, "rst: ") || strings.HasPrefix(v.Outcome, "dropped: "))
}

// conn-rules

// MaxSites and MaxSiteNames bound Record.Sites (CapSites).
const (
	MaxSites     = 16
	MaxSiteNames = 8
)

// CapSites cuts sites to MaxSites sites of at most MaxSiteNames names;
// partial reports a cut. The slices are resliced, not copied: callers pass
// fresh slices nobody mutates (dnscache.Cache.Sites).
func CapSites(sites [][]string) (out [][]string, partial bool) {
	if len(sites) > MaxSites {
		sites, partial = sites[:MaxSites], true
	}
	copied := false
	for i, s := range sites {
		if len(s) > MaxSiteNames {
			if !copied { // the caller's outer slice stays intact
				sites, copied = append([][]string(nil), sites...), true
			}
			sites[i], partial = s[:MaxSiteNames], true
		}
	}
	return sites, partial
}

// Lookup returns the flow with this ID: a live one, else the newest
// retained closed one. IDs restart with every session (a new Registry), so
// callers check the identity fields.
func (g *Registry) Lookup(id uint64, now time.Time) (View, bool) {
	if id == 0 {
		return View{}, false
	}
	g.mu.Lock()
	r := g.active[id]
	g.mu.Unlock()
	if r != nil {
		return r.View(now), true
	}
	// Both closed rings: connections, then DNS rows (dns), so DNS-query
	// rows can be right-clicked as well.
	for _, ring := range []*logx.Ring[View]{g.closed, g.dnsClosed.Load()} {
		closed := ring.Snapshot()
		for i := len(closed) - 1; i >= 0; i-- {
			if closed[i].ID == id {
				return closed[i], true
			}
		}
	}
	return View{}, false
}
