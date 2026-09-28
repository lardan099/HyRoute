package engine

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/dnscache"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/relay"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

// Tunnel is what the core needs from one profile's Hysteria (TCP goes
// through the relay).
type Tunnel interface {
	Available() bool
	UDPAvailable() bool
	UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error)
}

// Tunnels returns the tunnel of a profile, or nil when that profile is not
// running. Implementations must return an untyped nil.
type Tunnels func(profile string) Tunnel

// counting mirrors relay.Counting: per-profile counters.
type counting interface {
	NoteRejected()
	NoteTraffic(sent, recv int64)
}

func noteRejected(t Tunnel) {
	if c, ok := t.(counting); ok {
		c.NoteRejected()
	}
}

type Options struct {
	RelayPort uint16
	// BlockQUIC drops UDP/443 whose route depends on a still-unknown domain,
	// so browsers fall back to TCP where SNI is visible.
	BlockQUIC bool
	// BlockIPv6Tunnel resets/drops IPv6 flows routed to the tunnel so apps
	// fall back to IPv4.
	BlockIPv6Tunnel bool
	TCPOnly         bool
	// NoDefaultExclusions disables the user-space exclusion check (tests
	// use loopback destinations).
	NoDefaultExclusions bool
	// ResetUnknownDomain resets a connection opened before start (see
	// untrackedOut) whose route depends on a domain the engine does not know,
	// instead of deciding it without one. Set when the connection may have
	// gone through the tunnel and was not reset: after an engine failure,
	// and over a kill switch block (a crash, an update, a reconnect). Decided
	// without its domain, such a connection could go on direct.
	ResetUnknownDomain bool
	UDPIdle            time.Duration // default 60s
	DNSIdle            time.Duration // default 10s (UDP to port 53)
	PendingTimeout     time.Duration // default 100ms
	IPHelperAfter      time.Duration // default 20ms
}

// Stats are exposed to the UI.
type Stats struct {
	Reflected  atomic.Int64
	Passed     atomic.Int64
	Rejected   atomic.Int64 // Tunnel flows refused because the tunnel was down
	Blocked    atomic.Int64
	Unknown    atomic.Int64 // flows with unknown owner process
	StrayRelay atomic.Int64 // external inbound to the relay port, dropped
	// Panics counts packets whose processing panicked. Such a packet is
	// dropped and routing goes on: a malformed packet from the network must
	// not remove the filters (which would send everything direct).
	Panics atomic.Int64
	// Malformed: outbound packets that matched the filter but do not
	// parse; dropped, never passed unrouted.
	Malformed atomic.Int64
	// FragDropped: fragments dropped (route not direct, or no first
	// fragment); FragOrphan counts the latter, FragDatagrams datagrams.
	FragDropped, FragOrphan, FragDatagrams atomic.Int64
	PendingFull                            atomic.Int64
	UDPTunneled                            atomic.Int64 // datagrams sent into the tunnel
	UDPDropped                             atomic.Int64 // tunnel datagrams dropped (tunnel down, no session)
	SYNRetries                             atomic.Int64 // OS retries of a refused SYN, reset again
	// UntrackedReset: connections the engine held no state for (opened
	// before start) that the rules send through the tunnel or block, reset.
	UntrackedReset atomic.Int64
}

// Core decides routes and moves packets. It is driven by the platform layer
// through HandlePacket / HandleSocketEvent / HandleFlowEvent / HandleDNS and
// Maintain, and injects through Inject.
type Core struct {
	Opt     Options
	Rules   *rules.Store
	DNS     *dnscache.Cache
	NAT     *nat.Table
	Conns   *attrib.Table
	Procs   *procinfo.Cache
	Flows   *flows.Registry
	Tunnels Tunnels
	// Inject sends a packet (the platform picks the handle).
	Inject func(pkt []byte, addr *divert.Address)
	// OwnerFallback asks the OS connection tables (IP Helper).
	OwnerFallback func(proto uint8, local, remote netip.AddrPort) (uint32, bool)
	// TCPTable reads the OS table of TCP connections (IP Helper), listening
	// sockets included: one read serves many untracked connections (see
	// untrackedOut).
	TCPTable    func() ([]attrib.TCPRow, error)
	SelfPID     uint32
	DnscachePID atomic.Uint32
	// SystemDNS reports whether an address is a DNS server of the system
	// (its network adapters'): Dnscache's encrypted DNS goes there.
	SystemDNS func(netip.Addr) bool
	// IPv4Route reports whether the machine has an IPv4 route to the
	// internet (nil: assume it does). Without one an IPv6 connection
	// refused at its SYN has no IPv4 to fall back to (an IPv6-only
	// network, NAT64 without CLAT).
	IPv4Route func() bool
	Log       *slog.Logger
	// OnDecision is called once per new flow after the decision.
	OnDecision func(flows.View)
	Stats

	mu       sync.Mutex
	tcp      map[nat.FlowKey]*tcpFlow
	udp      map[nat.FlowKey]*udpFlow
	sessions map[sessKey]*udpSession
	pending  map[pendKey]*pendingFlow
	rejected map[nat.FlowKey]time.Time    // refused SYNs, until
	gone     map[nat.FlowKey]time.Time    // reset flows the app may still use (expired reflected, untracked), until
	frags    map[packet.FragKey]fragEntry // decided fragmented datagrams
	sem      chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
	bigWarn  atomic.Bool

	// untracked: connections without state (see untrackedOut) that the
	// rules let go direct, until.
	untracked map[nat.FlowKey]time.Time

	snapMu sync.Mutex // guards snap and snapAt; held through TCPTable
	snap   *attrib.TCPSnapshot
	snapAt time.Time
}

type tcpFlow struct {
	rec    *flows.Record
	last   time.Time
	finAt  time.Time
	hasFIN bool
}

type udpFlow struct {
	rec     *flows.Record
	route   rules.Action
	profile string
	last    time.Time
	sub     rules.Subject // for a new decision when the profile cannot carry it (udpRetarget)
	checked time.Time     // last udpRetarget
	// refused: a Tunnel flow recorded as refused, its tunnel down; set
	// back to "tunneled" once the tunnel carries it.
	refused atomic.Bool
}

// sessKey: one SOCKS5 UDP association per application socket and profile.
type sessKey struct {
	local   netip.AddrPort
	profile string
}

type pendKey struct {
	proto uint8
	key   nat.FlowKey
}

type pendingPkt struct {
	raw  []byte
	addr divert.Address
}

type pendingFlow struct {
	pkts []pendingPkt
}

const (
	pendingMaxFlows   = 128
	pendingMaxPackets = 8
	sessionQueueMax   = 32
	// maxSOCKSPayload: Hysteria's SOCKS5 UDP buffer is 4096 bytes including
	// the SOCKS header, and it does not support fragmentation.
	maxSOCKSPayload = 4096 - 22
	// goneTTL: how long after its last segment a reflected flow whose NAT
	// entry expired is still remembered (see Core.gone); goneMax bounds
	// the set.
	goneTTL = 2 * time.Hour
	goneMax = 16384
	// untrackedTTL: how long after its last segment an untracked connection
	// the rules let go direct is remembered; untrackedMax bounds the set (a
	// connection forgotten early is decided again).
	untrackedTTL = 2 * time.Hour
	untrackedMax = 16384
	// snapshotAge: how long one read of the OS TCP table serves untracked
	// connections.
	snapshotAge = time.Second
	// snapshotFresh: an owner the snapshot lacks is looked up in a new read
	// once the snapshot is this old.
	snapshotFresh = 100 * time.Millisecond
	// retargetEvery throttles udpRetarget for a flow whose tunnel is down.
	retargetEvery = time.Second
)

// NewCore creates a core with fresh tables.
func NewCore(opt Options, tun Tunnels, procs *procinfo.Cache, inject func([]byte, *divert.Address)) *Core {
	if opt.UDPIdle == 0 {
		opt.UDPIdle = 60 * time.Second
	}
	if opt.DNSIdle == 0 {
		opt.DNSIdle = 10 * time.Second
	}
	if opt.PendingTimeout == 0 {
		opt.PendingTimeout = 100 * time.Millisecond
	}
	if opt.IPHelperAfter == 0 {
		opt.IPHelperAfter = 20 * time.Millisecond
	}
	return &Core{
		Opt: opt, Rules: &rules.Store{}, DNS: dnscache.New(), NAT: nat.NewTable(),
		Conns: attrib.NewTable(), Procs: procs, Flows: flows.NewRegistry(5000),
		Tunnels: tun, Inject: inject, Log: slog.Default(),
		tcp: map[nat.FlowKey]*tcpFlow{}, udp: map[nat.FlowKey]*udpFlow{},
		sessions: map[sessKey]*udpSession{}, pending: map[pendKey]*pendingFlow{},
		rejected: map[nat.FlowKey]time.Time{},
		gone:     map[nat.FlowKey]time.Time{},
		frags:    map[packet.FragKey]fragEntry{},
		sem:      make(chan struct{}, pendingMaxFlows), stop: make(chan struct{}),
		untracked: map[nat.FlowKey]time.Time{},
	}
}

// Close stops UDP sessions and pending waits.
func (c *Core) Close() {
	c.stopOnce.Do(func() { close(c.stop) })
	c.mu.Lock()
	sess := c.sessions
	c.sessions = map[sessKey]*udpSession{}
	c.mu.Unlock()
	for _, s := range sess {
		s.close()
	}
}

// tunnel returns the profile's tunnel or nil.
func (c *Core) tunnel(profile string) Tunnel {
	if c.Tunnels == nil {
		return nil
	}
	return c.Tunnels(profile)
}

// pick moves a Tunnel decision to the first fallback profile that can
// carry the flow when its own profile cannot. With every profile down it
// stays on the primary one, which refuses the flow as before.
func (c *Core) pick(res rules.Result, udp bool) rules.Result {
	if res.NeedsDomain || res.Action != rules.Tunnel || len(res.Fallback) == 0 || c.usable(res.Profile, udp) {
		return res
	}
	for _, id := range res.Fallback {
		if c.usable(id, udp) {
			res.Profile = id
			res.Rule += " (fallback)"
			return res
		}
	}
	return res
}

func (c *Core) usable(profile string, udp bool) bool {
	t := c.tunnel(profile)
	if t == nil {
		return false
	}
	if udp {
		return t.UDPAvailable()
	}
	return t.Available()
}

func (c *Core) excluded(a netip.Addr) bool {
	return !c.Opt.NoDefaultExclusions && DefaultExclusions(a)
}

// guard turns a panic while handling one packet into a dropped packet.
func (c *Core) guard(what string) {
	if r := recover(); r != nil {
		n := c.Panics.Add(1)
		if n <= 5 || n%1000 == 0 {
			c.Log.Error(what+": panic, packet dropped", "panic", r, "count", n, "stack", string(debug.Stack()))
		}
	}
}

// HandlePacket processes one packet from the main handle.
func (c *Core) HandlePacket(raw []byte, addr *divert.Address) {
	defer c.guard("packet")
	p, err := packet.Parse(raw)
	if err != nil {
		switch {
		case !addr.Outbound():
			c.Inject(raw, addr) // inbound is not routed
		case errors.Is(err, packet.ErrFragment):
			c.fragOut(raw, addr)
		case errors.Is(err, packet.ErrIPsec):
			// IPv6 TCP/UDP under IPsec AH: rewriting it would break the ICV,
			// so it goes on unchanged, like IPv4 AH, which the filter does
			// not capture at all.
			c.Inject(raw, addr)
		default:
			// Outbound TCP/UDP we cannot parse is dropped: passing it
			// unrouted would bypass Tunnel and Block.
			c.Malformed.Add(1)
		}
		return
	}
	if !addr.Outbound() {
		if p.Proto == packet.ProtoTCP && p.DstPort() == c.Opt.RelayPort {
			// Our own reflected packets never come back to the injecting
			// handle; anything else is an outside attempt to reach the relay.
			c.StrayRelay.Add(1)
			return
		}
		c.Inject(raw, addr)
		return
	}
	switch p.Proto {
	case packet.ProtoTCP:
		c.tcpOut(&p, addr)
	case packet.ProtoUDP:
		if c.Opt.TCPOnly {
			c.Inject(raw, addr)
			return
		}
		c.udpOut(&p, addr)
	default:
		c.Inject(raw, addr)
	}
}

func (c *Core) tcpOut(p *packet.Packet, addr *divert.Address) {
	now := time.Now()
	flags := p.TCPFlags()
	if p.SrcPort() == c.Opt.RelayPort {
		ent := c.NAT.LookupReflect(p.DstIP(), p.DstPort())
		if ent == nil {
			return // entry gone; the relay socket is closing anyway
		}
		c.NAT.TouchPacket(ent, p, false, nil, now)
		nat.ReflectFromRelay(p, ent)
		c.injectInbound(p, addr)
		return
	}
	key := nat.FlowKey{Src: p.Src(), Dst: p.Dst()}
	if ent := c.NAT.LookupFlow(key); ent != nil {
		if !p.IsSYN() || !c.NAT.RemoveClosed(ent) {
			c.NAT.TouchPacket(ent, p, true, addr, now)
			nat.ReflectToRelay(p, c.Opt.RelayPort)
			c.injectInbound(p, addr)
			return
		}
		// A new connection on the 4-tuple of one that ended (port reuse):
		// it gets its own decision instead of following the old entry,
		// whose grace timer would cut it off and send the rest direct.
		c.Flows.Close(ent.Rec, now)
	}
	c.mu.Lock()
	tf := c.tcp[key]
	if tf != nil && p.IsSYN() && tf.hasFIN {
		// Port reuse after the old flow finished.
		delete(c.tcp, key)
		c.mu.Unlock()
		c.Flows.Close(tf.rec, now)
		tf = nil
		c.mu.Lock()
	}
	if tf != nil {
		tf.last = now
		if flags&(packet.FlagFIN|packet.FlagRST) != 0 && !tf.hasFIN {
			tf.hasFIN, tf.finAt = true, now
		}
		c.mu.Unlock()
		tf.rec.Sent.Add(int64(len(p.Payload())))
		c.Inject(p.Buf, addr)
		return
	}
	if until, ok := c.rejected[key]; ok && p.IsSYN() {
		if now.Before(until) {
			c.rejected[key] = now.Add(rejectMemory)
			c.mu.Unlock()
			c.SYNRetries.Add(1)
			c.resetApp(p, addr)
			return
		}
		delete(c.rejected, key)
	}
	if _, ok := c.gone[key]; ok {
		if p.IsSYN() {
			delete(c.gone, key) // port reuse: a new connection
		} else {
			// The application still uses a connection that went through
			// the relay, or that the rules send there or block: sending
			// this segment direct would leak it.
			c.gone[key] = now.Add(goneTTL)
			c.mu.Unlock()
			if flags&packet.FlagRST == 0 {
				c.resetApp(p, addr)
			}
			return
		}
	}
	if _, ok := c.untracked[key]; ok {
		if p.IsSYN() {
			delete(c.untracked, key) // port reuse: a new connection
		} else {
			c.untracked[key] = now.Add(untrackedTTL)
			c.mu.Unlock()
			c.Inject(p.Buf, addr)
			return
		}
	}
	c.mu.Unlock()
	if c.excluded(p.DstIP()) {
		c.Inject(p.Buf, addr)
		return
	}
	if !p.IsSYN() {
		c.untrackedOut(p, addr, key, now)
		return
	}
	c.newFlow(p, addr, packet.ProtoTCP, key)
}

// untrackedOut handles a segment (not a SYN) of a connection the engine
// holds no state for: one opened before start (after a crash or a failure
// of the previous engine it may be one that went through the tunnel), a
// Direct connection whose record expired, or a local server's side of a
// connection from outside. The rules decide it as they would a new
// connection, with the owner from the OS tables and a domain only from the
// DNS cache (there is no handshake left to sniff). Direct passes. Tunnel or
// Block resets the application's connection, which then reopens through
// the engine: this segment must not leave direct, and it cannot join the
// relay midway. The decision is remembered (c.untracked, c.gone), so a
// connection costs one decision.
func (c *Core) untrackedOut(p *packet.Packet, addr *divert.Address, key nat.FlowKey, now time.Time) {
	res, proc := c.untrackedRoute(p, key, now)
	pass := res.Action == rules.Direct
	// The application's RST ends the connection: nothing to remember. It
	// is dropped unless Direct, not answered.
	rst := p.TCPFlags()&packet.FlagRST != 0
	c.mu.Lock()
	switch {
	case rst:
	case pass:
		if len(c.untracked) >= untrackedMax {
			for k := range c.untracked {
				delete(c.untracked, k) // forget one; it is decided again
				break
			}
		}
		c.untracked[key] = now.Add(untrackedTTL)
	case len(c.gone) < goneMax:
		c.gone[key] = now.Add(goneTTL)
	}
	c.mu.Unlock()
	if pass {
		c.Inject(p.Buf, addr)
		return
	}
	if rst {
		return
	}
	if n := c.UntrackedReset.Add(1); n <= 20 || n%100 == 0 {
		var name string
		if proc != nil {
			name = proc.Name
		}
		c.Log.Info("untracked connection (opened before start?) reset: the rules send it through the tunnel or block it",
			"process", name, "dst", key.Dst, "route", res.Action.String(), "rule", res.Rule, "count", n)
	}
	c.resetApp(p, addr)
}

// untrackedRoute decides an untracked connection. A local server's side of
// a connection from outside (its SYN-ACK, or a connection of the process
// listening on its port) is not routed: its inbound half is never
// captured.
func (c *Core) untrackedRoute(p *packet.Packet, key nat.FlowKey, now time.Time) (rules.Result, *procinfo.Info) {
	server := rules.Result{Action: rules.Direct, Rule: "local server"}
	if p.TCPFlags()&packet.FlagSYN != 0 {
		return server, nil
	}
	snap := c.tcpSnapshot(now, snapshotAge)
	// Not the bind of the local port: the events never saw a connection
	// opened before start, so a bind of its port is another socket's.
	pid, known := c.Conns.LookupConn(attrib.Key5{Proto: packet.ProtoTCP, Local: key.Src, Remote: key.Dst})
	if !known && snap != nil {
		pid, known = snap.Owner(key.Src, key.Dst)
		if !known {
			// The connection may have come up after the read (its SYN
			// left before start): a newer one finds it.
			if fresh := c.tcpSnapshot(now, snapshotFresh); fresh != snap {
				snap = fresh
				pid, known = snap.Owner(key.Src, key.Dst)
			}
		}
	}
	if known && snap != nil && snap.Listening(key.Src, pid) {
		return server, nil
	}
	var proc *procinfo.Info
	if known {
		proc = c.Procs.Get(pid)
	}
	if res, ok := c.exclusion(pid, known, proc, packet.ProtoTCP, key.Dst); ok {
		return res, proc
	}
	set := c.Rules.Load()
	sub := rules.Subject{Proc: proc, Proto: packet.ProtoTCP, Dst: key.Dst}
	res := set.EvaluateSites(sub, c.packetSites(set, packet.ProtoTCP, key.Dst))
	if res.NeedsDomain {
		res = set.EvaluateNoDomain(sub)
		if c.Opt.ResetUnknownDomain && res.Action == rules.Direct {
			// It may be one the tunnel carried: reset, the application
			// reopens it and the relay sees its domain.
			return rules.Result{Action: rules.Block, Rule: res.Rule + " (domain unknown, reset)"}, proc
		}
		res.Rule += " (domain unknown)"
	}
	return res, proc
}

// tcpSnapshot is the OS table of TCP connections, read again only once the
// last read is maxAge old: the segments of hundreds of connections opened
// before start cost one read, not one each. Nil without TCPTable.
func (c *Core) tcpSnapshot(now time.Time, maxAge time.Duration) *attrib.TCPSnapshot {
	if c.TCPTable == nil {
		return nil
	}
	c.snapMu.Lock()
	defer c.snapMu.Unlock()
	if c.snap == nil || now.Sub(c.snapAt) >= maxAge {
		rows, err := c.TCPTable()
		if err != nil {
			c.Log.Warn("TCP connection table not read completely; owners may be unknown", "err", err, "rows", len(rows))
		}
		c.snap, c.snapAt = attrib.NewTCPSnapshot(rows), now
	}
	return c.snap
}

func (c *Core) udpOut(p *packet.Packet, addr *divert.Address) {
	if c.excluded(p.DstIP()) {
		c.Inject(p.Buf, addr)
		return
	}
	key := nat.FlowKey{Src: p.Src(), Dst: p.Dst()}
	now := time.Now()
	c.mu.Lock()
	uf := c.udp[key]
	if uf != nil {
		uf.last = now
	}
	c.mu.Unlock()
	if uf == nil {
		c.newFlow(p, addr, packet.ProtoUDP, key)
		return
	}
	if uf.route == rules.Tunnel && !c.usable(uf.profile, true) && c.retargetDue(uf, now) && c.udpRetarget(uf, key) {
		// The flow's profile stopped (the rules moved on) or is down while
		// another server of its rule is up: the flow is decided again, as
		// a new one would be, instead of dropping its datagrams for as
		// long as the socket keeps sending.
		c.mu.Lock()
		if c.udp[key] == uf {
			delete(c.udp, key)
		}
		c.mu.Unlock()
		c.Flows.Close(uf.rec, now)
		c.newFlow(p, addr, packet.ProtoUDP, key)
		return
	}
	c.udpApply(uf, p, addr, key)
}

// retargetDue limits udpRetarget to once per retargetEvery for a flow:
// while its tunnel is down, every datagram would evaluate the rules.
func (c *Core) retargetDue(uf *udpFlow, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(uf.checked) < retargetEvery {
		return false
	}
	uf.checked = now
	return true
}

// udpRetarget reports whether a new decision would move the Tunnel flow
// uf, whose profile cannot carry UDP now, elsewhere: to another route, or
// to a fallback profile that is up.
func (c *Core) udpRetarget(uf *udpFlow, key nat.FlowKey) bool {
	set := c.Rules.Load()
	res := set.EvaluateSites(uf.sub, c.packetSites(set, packet.ProtoUDP, key.Dst))
	if res.NeedsDomain {
		// As in applyUDP: the domain of a UDP flow never shows up later.
		if c.Opt.BlockQUIC && key.Dst.Port() == 443 {
			return true
		}
		res = set.EvaluateNoDomain(uf.sub)
	}
	res = c.pick(res, true)
	return res.Action != rules.Tunnel || res.Profile != uf.profile
}

func (c *Core) udpApply(uf *udpFlow, p *packet.Packet, addr *divert.Address, key nat.FlowKey) {
	switch uf.route {
	case rules.Direct:
		uf.rec.Sent.Add(int64(len(p.Payload())))
		c.Inject(p.Buf, addr)
	case rules.Block:
	case rules.Tunnel:
		if uf.refused.Load() {
			if t := c.tunnel(uf.profile); t != nil && t.Available() && t.UDPAvailable() && uf.refused.CompareAndSwap(true, false) {
				c.finish(uf.rec, rules.Tunnel, "tunneled")
			}
		}
		c.udpSend(uf, p.Payload(), addr, key)
	}
}

// newFlow attributes the flow and decides, parking the first packets while
// the owner is unknown.
func (c *Core) newFlow(p *packet.Packet, addr *divert.Address, proto uint8, key nat.FlowKey) {
	pk := pendKey{proto, key}
	c.mu.Lock()
	if pf := c.pending[pk]; pf != nil {
		// The flow is parked: this packet waits for its first one's
		// decision even if the owner is known by now (deciding it here
		// would open a second record and overwrite the flow's state).
		if len(pf.pkts) < pendingMaxPackets {
			pf.pkts = append(pf.pkts, pendingPkt{append([]byte(nil), p.Buf...), *addr})
		}
		c.mu.Unlock()
		return
	}
	pid, ok := c.Conns.Lookup(attrib.Key5{Proto: proto, Local: key.Src, Remote: key.Dst})
	if ok {
		c.mu.Unlock()
		c.decide(p, addr, proto, key, pid, true, "packet")
		return
	}
	select {
	case c.sem <- struct{}{}:
	default:
		c.mu.Unlock()
		c.PendingFull.Add(1)
		// No room to wait for the SOCKET event: ask the OS tables at once,
		// so an owner already listed there (above all HyRoute's own dials,
		// which must stay excluded) is not decided as unknown.
		stage := "pending-full"
		if c.OwnerFallback != nil {
			if pid, ok = c.OwnerFallback(proto, key.Src, key.Dst); ok {
				stage = "iphelper"
			}
		}
		c.decide(p, addr, proto, key, pid, ok, stage)
		return
	}
	pf := &pendingFlow{pkts: []pendingPkt{{append([]byte(nil), p.Buf...), *addr}}}
	c.pending[pk] = pf
	c.mu.Unlock()
	go func() {
		defer func() { <-c.sem }()
		defer func() {
			// Also after a panic: a flow left parked would swallow its
			// packets for good.
			c.mu.Lock()
			if c.pending[pk] == pf {
				delete(c.pending, pk)
			}
			c.mu.Unlock()
		}()
		// A panic while deciding costs the parked packets, not the process
		// (the packet loop is guarded the same way).
		defer c.guard("pending")
		pid, ok, stage := c.waitOwner(proto, key)
		c.mu.Lock()
		first := pf.pkts[0]
		c.mu.Unlock()
		if fp, err := packet.Parse(first.raw); err == nil {
			c.decide(&fp, &first.addr, proto, key, pid, ok, stage)
		}
		// Tables are populated now: replay the rest through the normal path.
		c.mu.Lock()
		rest := pf.pkts[1:]
		delete(c.pending, pk)
		c.mu.Unlock()
		for i := range rest {
			c.HandlePacket(rest[i].raw, &rest[i].addr)
		}
	}()
}

func (c *Core) waitOwner(proto uint8, key nat.FlowKey) (uint32, bool, string) {
	k := attrib.Key5{Proto: proto, Local: key.Src, Remote: key.Dst}
	deadline := time.NewTimer(c.Opt.PendingTimeout)
	defer deadline.Stop()
	helper := time.NewTimer(c.Opt.IPHelperAfter)
	defer helper.Stop()
	for {
		changed := c.Conns.Changed()
		if pid, ok := c.Conns.Lookup(k); ok {
			return pid, true, "pending"
		}
		select {
		case <-changed:
		case <-helper.C:
			if c.OwnerFallback != nil {
				if pid, ok := c.OwnerFallback(proto, key.Src, key.Dst); ok {
					return pid, true, "iphelper"
				}
			}
		case <-deadline.C:
			return 0, false, "pending-timeout"
		case <-c.stop:
			return 0, false, "stopped"
		}
	}
}

func (c *Core) decide(p *packet.Packet, addr *divert.Address, proto uint8, key nat.FlowKey, pid uint32, known bool, stage string) {
	var proc *procinfo.Info
	if known {
		proc = c.Procs.Get(pid)
	} else {
		c.Unknown.Add(1)
	}
	rec := &flows.Record{PID: pid, Proto: proto, Src: key.Src, Dst: key.Dst}
	if proc != nil {
		rec.Process, rec.Path = proc.Name, proc.Path
	}
	sub := rules.Subject{Proc: proc, Proto: proto, Dst: key.Dst}
	set := c.Rules.Load()
	res, excl := c.exclusion(pid, known, proc, proto, key.Dst)
	if !excl {
		res = c.pick(set.EvaluateSites(sub, c.packetSites(set, proto, key.Dst)), proto == packet.ProtoUDP)
	}
	// Our own sockets (the relay's Direct dials, Hysteria's control
	// traffic) are not shown: the relayed flow already describes them.
	self := known && pid == c.SelfPID
	if !self {
		c.Flows.Open(rec)
	}
	rec.Set(func(f *flows.Fields) {
		f.Attrib, f.Stage, f.Rule, f.Domain, f.DomainSrc = stage, "packet", res.Rule, res.Domain, res.DomainSrc.String()
		f.Profile = res.Profile
		if res.Domain == "" {
			f.DomainSrc = rules.SrcNone.String()
		}
	})
	if res.Domain == "" && !res.NeedsDomain {
		// The route did not depend on the domain; show the cached name
		// anyway so the connection is recognizable.
		if names := c.DNS.Names(key.Dst.Addr()); len(names) > 0 {
			rec.Set(func(f *flows.Fields) { f.Domain, f.DomainSrc = strings.Join(names, ","), rules.SrcDNS.String() })
		}
	}
	closed := false
	if proto == packet.ProtoTCP {
		closed = c.applyTCP(p, addr, key, pid, proc, sub, set, res, rec)
	} else {
		c.applyUDP(p, addr, key, sub, set, res, rec)
	}
	now := time.Now()
	if c.OnDecision != nil && !self {
		c.OnDecision(rec.View(now))
	}
	if closed {
		c.Flows.Close(rec, now)
	}
}

// exclusion is the mandatory exclusion (ARCHITECTURE §3) that a flow of a
// known owner falls under, if any: HyRoute itself, the Hysteria processes
// it started, and the Windows DNS client (Dnscache), which resolves the
// Hysteria servers: plain DNS on port 53, and DNS over HTTPS (TCP 443) or
// TLS (TCP 853) to the system's DNS servers when Windows encrypts DNS.
// Dnscache may share its svchost with other services, whose HTTPS to
// anywhere else follows the rules.
func (c *Core) exclusion(pid uint32, known bool, proc *procinfo.Info, proto uint8, dst netip.AddrPort) (rules.Result, bool) {
	if !known {
		return rules.Result{}, false
	}
	switch port := dst.Port(); {
	case pid == c.SelfPID:
		return rules.Result{Action: rules.Direct, Rule: "exclusion: self"}, true
	case c.SelfPID != 0 && proc != nil && proc.Name == "hysteria.exe" && proc.Parent != nil && proc.Parent.PID == c.SelfPID:
		// Normally Hysteria only talks to its server, which the kernel
		// filter already excludes; this covers an address it resolved on
		// its own. Its traffic must never loop back into a tunnel.
		return rules.Result{Action: rules.Direct, Rule: "exclusion: hysteria"}, true
	case pid != 0 && pid == c.DnscachePID.Load() && (port == 53 || c.encryptedDNS(proto, dst)):
		return rules.Result{Action: rules.Direct, Rule: "exclusion: system DNS"}, true
	}
	return rules.Result{}, false
}

// encryptedDNS: TCP 443 or 853 to a DNS server of the system.
func (c *Core) encryptedDNS(proto uint8, dst netip.AddrPort) bool {
	port := dst.Port()
	return proto == packet.ProtoTCP && (port == 443 || port == 853) && c.SystemDNS != nil && c.SystemDNS(dst.Addr().Unmap())
}

func (c *Core) finish(rec *flows.Record, route rules.Action, outcome string) {
	rec.Set(func(f *flows.Fields) { f.Route, f.Outcome = route.String(), outcome })
}

func (c *Core) applyTCP(p *packet.Packet, addr *divert.Address, key nat.FlowKey, pid uint32, proc *procinfo.Info,
	sub rules.Subject, set *rules.Set, res rules.Result, rec *flows.Record) (closed bool) {
	now := time.Now()
	if res.NeedsDomain && p.IPv6 && c.Opt.BlockIPv6Tunnel && c.mayTunnel(sub, set) && (c.IPv4Route == nil || c.IPv4Route()) {
		// The relay would learn the domain only once the connection is up,
		// and a Tunnel decision then resets it: the application does not
		// fall back to IPv4 for a connection it has. A refused SYN makes
		// it (happy eyeballs), and over IPv4 the relay sees the domain.
		// Without an IPv4 route there is nothing to fall back to: the
		// relay decides by the domain as usual, so a site it sends Direct
		// stays reachable.
		c.Blocked.Add(1)
		rec.Set(func(f *flows.Fields) { f.Rule = "IPv6 blocked for tunnel (domain unknown)" })
		c.finish(rec, rules.Block, "rst: IPv6 blocked for tunnel")
		c.rejectSYN(p, addr, key, now)
		return true
	}
	if res.NeedsDomain {
		ent, err := c.NAT.Insert(&nat.Entry{Flow: key, PID: pid, Mode: nat.Sniff, Rec: rec, Meta: proc}, now)
		if err == nil {
			c.NAT.TouchPacket(ent, p, true, addr, now)
			rec.Set(func(f *flows.Fields) { f.Route, f.Outcome, f.Stage = "pending", "reflected: sniff", "sniff" })
			c.Reflected.Add(1)
			nat.ReflectToRelay(p, c.Opt.RelayPort)
			c.injectInbound(p, addr)
			return false
		}
		// Cannot reflect this flow: decide without the domain.
		res = c.pick(set.EvaluateNoDomain(sub), false)
		rec.Set(func(f *flows.Fields) { f.Rule = res.Rule + " (reflect collision)" })
	}
	switch res.Action {
	case rules.Direct:
		rec.Recv.Store(-1) // inbound of Direct flows is not intercepted
		c.mu.Lock()
		c.tcp[key] = &tcpFlow{rec: rec, last: now}
		c.mu.Unlock()
		c.Passed.Add(1)
		c.finish(rec, rules.Direct, "passed")
		rec.Sent.Add(int64(len(p.Payload())))
		c.Inject(p.Buf, addr)
	case rules.Block:
		c.Blocked.Add(1)
		c.finish(rec, rules.Block, "rst: blocked")
		c.rejectSYN(p, addr, key, now)
		return true
	case rules.Tunnel:
		switch t := c.tunnel(res.Profile); {
		case t == nil || !t.Available():
			noteRejected(t)
			c.Rejected.Add(1)
			c.finish(rec, rules.Tunnel, "rst: tunnel unavailable")
			c.rejectSYN(p, addr, key, now)
			return true
		case p.IPv6 && c.Opt.BlockIPv6Tunnel:
			c.Blocked.Add(1)
			c.finish(rec, rules.Block, "rst: IPv6 blocked for tunnel")
			c.rejectSYN(p, addr, key, now)
			return true
		default:
			ent, err := c.NAT.Insert(&nat.Entry{Flow: key, PID: pid, Mode: nat.NoSniff, Profile: res.Profile, Rec: rec, Meta: proc}, now)
			if err != nil {
				// Same (remote IP, local port) already reflected: Tunnel
				// never falls back to Direct.
				c.Rejected.Add(1)
				c.finish(rec, rules.Tunnel, "rst: reflect key collision")
				c.rejectSYN(p, addr, key, now)
				return true
			}
			c.NAT.TouchPacket(ent, p, true, addr, now)
			c.Reflected.Add(1)
			c.finish(rec, rules.Tunnel, "reflected")
			nat.ReflectToRelay(p, c.Opt.RelayPort)
			c.injectInbound(p, addr)
		}
	}
	return false
}

func (c *Core) applyUDP(p *packet.Packet, addr *divert.Address, key nat.FlowKey, sub rules.Subject, set *rules.Set, res rules.Result, rec *flows.Record) {
	now := time.Now()
	uf := &udpFlow{rec: rec, last: now, sub: sub}
	outcome := ""
	if res.NeedsDomain {
		if c.Opt.BlockQUIC && key.Dst.Port() == 443 {
			res = rules.Result{Action: rules.Block, Rule: "block QUIC (domain unknown)"}
			rec.Set(func(f *flows.Fields) { f.Rule = res.Rule })
			outcome = "dropped: QUIC blocked, domain unknown"
		} else {
			res = c.pick(set.EvaluateNoDomain(sub), true)
			rec.Set(func(f *flows.Fields) { f.Rule, f.Profile = res.Rule+" (domain unknown)", res.Profile })
		}
	}
	uf.route, uf.profile = res.Action, res.Profile
	switch res.Action {
	case rules.Direct:
		rec.Recv.Store(-1)
		outcome = "passed"
		c.Passed.Add(1)
	case rules.Block:
		if outcome == "" {
			outcome = "dropped: blocked"
		}
		c.Blocked.Add(1)
	case rules.Tunnel:
		switch t := c.tunnel(res.Profile); {
		case p.IPv6 && c.Opt.BlockIPv6Tunnel:
			uf.route = rules.Block
			outcome = "dropped: IPv6 blocked for tunnel"
			c.Blocked.Add(1)
		case t == nil || !t.Available() || !t.UDPAvailable():
			// As TCP counts a refused SYN. The flow stays on the tunnel:
			// its datagrams go once the tunnel is up (see udpOut).
			noteRejected(t)
			c.Rejected.Add(1)
			uf.refused.Store(true)
			outcome = "dropped: tunnel unavailable"
		default:
			outcome = "tunneled"
		}
	}
	c.finish(rec, uf.route, outcome)
	c.mu.Lock()
	c.udp[key] = uf
	c.mu.Unlock()
	c.udpApply(uf, p, addr, key)
}

func (c *Core) injectInbound(p *packet.Packet, addr *divert.Address) {
	p.FixChecksums()
	a := *addr
	a.SetOutbound(false)
	a.SetChecksumsValid()
	c.Inject(p.Buf, &a)
}

// rejectSYN resets a refused connection attempt and remembers the flow:
// Windows answers a RST to its SYN by retrying the SYN several times
// (~500 ms apart), and each retry is reset again without a new record.
func (c *Core) rejectSYN(p *packet.Packet, addr *divert.Address, key nat.FlowKey, now time.Time) {
	c.mu.Lock()
	c.rejected[key] = now.Add(rejectMemory)
	c.mu.Unlock()
	c.resetApp(p, addr)
}

// rejectMemory is how long after the last refused SYN a retry on the same
// flow is reset without a new decision.
const rejectMemory = 3 * time.Second

// resetApp drops the SYN and injects a RST from the "remote" so the
// application fails fast instead of waiting for SYN timeouts.
func (c *Core) resetApp(p *packet.Packet, addr *divert.Address) {
	rst := packet.BuildRSTFor(p)
	a := *addr
	a.SetOutbound(false)
	a.SetChecksumsValid()
	c.Inject(rst, &a)
}

// mayTunnel reports whether a domain-dependent flow may turn out to go
// through the tunnel. The DNS cache is a hint here even with ExactWeb:
// when every site it has for the address goes elsewhere, the flow is not
// refused (an IPv6-only site sent Direct stays reachable), and should its
// SNI still go to the tunnel, RelayDecide blocks it.
func (c *Core) mayTunnel(sub rules.Subject, set *rules.Set) bool {
	if !set.MayTunnel(sub) {
		return false
	}
	sites := c.DNS.Sites(sub.Dst.Addr())
	for _, site := range sites {
		if set.EvaluateSites(sub, [][]string{site}).Action == rules.Tunnel {
			return true
		}
	}
	return len(sites) == 0
}

// packetSites are the DNS cache names, grouped by site, used for a
// packet-level decision. With ExactWeb, web flows get none: a
// domain-dependent TCP flow then goes to the relay for SNI/Host, and QUIC
// with an unknown domain is dropped so the browser falls back to TCP. The
// cache stays the relay's fallback.
func (c *Core) packetSites(set *rules.Set, proto uint8, dst netip.AddrPort) [][]string {
	if set.ExactWeb {
		if proto == packet.ProtoTCP && rules.WebPort(dst.Port()) {
			return nil
		}
		if proto == packet.ProtoUDP && dst.Port() == 443 && c.Opt.BlockQUIC {
			return nil
		}
	}
	return c.DNS.Sites(dst.Addr())
}

// RelayDecide is the relay's Decide callback for SNIFF entries.
func (c *Core) RelayDecide(e *nat.Entry, domain string, src rules.DomainSource) rules.Result {
	proc, _ := e.Meta.(*procinfo.Info)
	sub := rules.Subject{Proc: proc, Proto: packet.ProtoTCP, Dst: e.Flow.Dst}
	set := c.Rules.Load()
	var res rules.Result
	if src == rules.SrcECH {
		// The relay keeps the outer name as the tunnel's target only when
		// the result says SrcSNI.
		if domain != "" && c.echSite(e.Flow.Dst.Addr(), domain) {
			src = rules.SrcSNI
		} else {
			domain = ""
		}
	}
	if domain != "" {
		res = set.EvaluateDomain(sub, domain, src)
	} else if r := set.EvaluateSites(sub, c.DNS.Sites(e.Flow.Dst.Addr())); !r.NeedsDomain {
		res = r
	} else {
		res = set.EvaluateNoDomain(sub)
		res.Rule += " (domain unknown)"
	}
	res = c.pick(res, false)
	if res.Action == rules.Tunnel && e.Flow.Dst.Addr().Is6() && c.Opt.BlockIPv6Tunnel {
		res.Action, res.Profile, res.Rule = rules.Block, "", res.Rule+" (IPv6 blocked for tunnel)"
	}
	return res
}

// echSite reports whether the outer SNI of an ECH hello to ip names the
// site. Chrome and Firefox send GREASE ECH to every site without an ECH
// config, and then it does. Only a known ECH public name
// (dnscache.PublicName) hides the site, unless the DNS cache holds that
// very name for ip (the application asked for it). A hidden site is
// decided like one without SNI: by the DNS cache names of the address, or
// as an unknown domain. The public name itself never decides: a rule on it
// would catch every site behind the provider.
func (c *Core) echSite(ip netip.Addr, outer string) bool {
	if !c.DNS.PublicName(outer) {
		return true
	}
	return slices.ContainsFunc(c.DNS.Sites(ip), func(site []string) bool { return slices.Contains(site, outer) })
}

// RelayDone is the relay's OnDone callback.
func (c *Core) RelayDone(r relay.Result) {
	// A "rejected" result is counted by the relay itself (relay.Rejected;
	// Session.Stats adds both counters).
	c.NAT.RelayClosed(r.Entry, r.End)
	c.Flows.Close(r.Entry.Rec, r.End)
}

// ResetReflected aborts every application connection that goes through
// the relay by injecting the RST its remote end would send. Call it just
// before the filters are removed: nothing reflects the relay's own FIN or
// RST after that, so the application would keep the socket open and later
// send direct what belonged to the tunnel (a new engine, after a
// reconnect, resets such a connection only at its next segment, see
// untrackedOut).
func (c *Core) ResetReflected() {
	for _, r := range c.NAT.ResetApps() {
		a := r.Addr
		a.SetOutbound(false)
		a.SetChecksumsValid()
		c.Inject(r.Pkt, &a)
	}
}

// HandleSocketEvent feeds SOCKET layer events (attribution).
func (c *Core) HandleSocketEvent(ev divert.Event, sd divert.SocketData) {
	now := time.Now()
	switch ev {
	case divert.EventSocketConnect:
		c.Conns.Connect(attrib.Key5{Proto: sd.Protocol,
			Local:  netip.AddrPortFrom(sd.LocalAddr, sd.LocalPort),
			Remote: netip.AddrPortFrom(sd.RemoteAddr, sd.RemotePort)}, sd.ProcessID, sd.EndpointID, now)
	case divert.EventSocketBind:
		c.Conns.Bind(sd.Protocol, sd.LocalPort, sd.ProcessID, sd.EndpointID, now)
	case divert.EventSocketClose:
		c.Conns.Close(sd.EndpointID)
	}
}

// HandleFlowEvent feeds FLOW layer events: attribution on establish,
// closing "Connections" records on delete.
func (c *Core) HandleFlowEvent(ev divert.Event, sd divert.SocketData) {
	now := time.Now()
	local := netip.AddrPortFrom(sd.LocalAddr, sd.LocalPort)
	remote := netip.AddrPortFrom(sd.RemoteAddr, sd.RemotePort)
	switch ev {
	case divert.EventFlowEstablished:
		c.Conns.Connect(attrib.Key5{Proto: sd.Protocol, Local: local, Remote: remote}, sd.ProcessID, sd.EndpointID, now)
	case divert.EventFlowDeleted:
		key := nat.FlowKey{Src: local, Dst: remote}
		switch sd.Protocol {
		case packet.ProtoTCP:
			c.NAT.FlowDeleted(key, now)
			c.mu.Lock()
			tf := c.tcp[key]
			delete(c.tcp, key)
			delete(c.gone, key)
			delete(c.untracked, key)
			c.mu.Unlock()
			if tf != nil {
				c.Flows.Close(tf.rec, now)
			}
		case packet.ProtoUDP:
			c.mu.Lock()
			uf := c.udp[key]
			delete(c.udp, key)
			c.mu.Unlock()
			if uf != nil {
				c.Flows.Close(uf.rec, now)
			}
		}
	}
}

// HandleDNS takes a packet from the DNS sniff handle. Outbound queries are
// remembered, and an inbound response reaches the cache only when it
// answers one of them: the sniff sees every packet from port 53 before the
// firewall does, spoofed ones included.
func (c *Core) HandleDNS(raw []byte, outbound bool) {
	defer c.guard("dns")
	p, err := packet.Parse(raw)
	if err != nil {
		return
	}
	tcp := p.Proto == packet.ProtoTCP
	switch {
	case outbound && p.DstPort() == 53:
		c.DNS.AddQuery(tcp, p.Src(), p.Dst(), p.Payload())
	case !outbound && p.SrcPort() == 53:
		c.DNS.AddAnswer(tcp, p.Dst(), p.Src(), p.Payload())
	}
}

// Maintain expires idle state; call every few seconds.
func (c *Core) Maintain(now time.Time) {
	// A reflected connection the application may still send on outlives its
	// NAT entry in c.gone (under c.mu with the sweep, so no segment slips
	// through in between): its later segments must not leave direct.
	c.mu.Lock()
	for k, until := range c.gone {
		if now.After(until) {
			delete(c.gone, k)
		}
	}
	swept := c.NAT.Sweep(now)
	var resets []nat.AppReset
	for _, e := range swept {
		if c.NAT.AppMaySend(e) {
			if len(c.gone) >= goneMax {
				// Full: abort the connection now instead of forgetting
				// one. Its relay side is gone, so its next segment would
				// only be answered with a reset anyway.
				resets = append(resets, c.NAT.ResetApp(e)...)
				continue
			}
			c.gone[e.Flow] = now.Add(goneTTL)
		}
	}
	c.mu.Unlock()
	for _, r := range resets {
		a := r.Addr
		a.SetOutbound(false)
		a.SetChecksumsValid()
		c.Inject(r.Pkt, &a)
	}
	for _, e := range swept {
		c.Flows.Close(e.Rec, now)
	}
	c.Conns.Sweep(now, 30*time.Minute)
	c.DNS.Sweep()
	c.snapMu.Lock()
	if now.Sub(c.snapAt) >= snapshotAge {
		c.snap = nil // stale: the next untracked segment reads the table again
	}
	c.snapMu.Unlock()
	var closed []*flows.Record
	var idleSess []*udpSession
	c.mu.Lock()
	for k, tf := range c.tcp {
		if (tf.hasFIN && now.Sub(tf.finAt) > time.Minute) || now.Sub(tf.last) > 2*time.Hour {
			closed = append(closed, tf.rec)
			delete(c.tcp, k)
			// Every flow here is Direct: its later segments (a remote that
			// still sends after the FIN, a long idle connection) keep that
			// decision instead of one without the domain or the owner the
			// first had (see untrackedOut). A SYN on the 4-tuple, or
			// FLOW_DELETED, still forgets it.
			if len(c.untracked) < untrackedMax {
				c.untracked[k] = now.Add(untrackedTTL)
			}
		}
	}
	for k, uf := range c.udp {
		idle := c.Opt.UDPIdle
		if k.Dst.Port() == 53 {
			idle = c.Opt.DNSIdle
		}
		if now.Sub(uf.last) > idle {
			closed = append(closed, uf.rec)
			delete(c.udp, k)
		}
	}
	for k, until := range c.rejected {
		if now.After(until) {
			delete(c.rejected, k)
		}
	}
	for k, until := range c.untracked {
		if now.After(until) {
			delete(c.untracked, k)
		}
	}
	for k, s := range c.sessions {
		if now.Sub(s.lastUsed()) > c.Opt.UDPIdle {
			idleSess = append(idleSess, s)
			delete(c.sessions, k)
		}
	}
	c.mu.Unlock()
	for _, r := range closed {
		c.Flows.Close(r, now)
	}
	for _, s := range idleSess {
		s.close()
	}
}
