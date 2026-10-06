package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/dnsproxy"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/relay"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

// DNS policies (dns, docs/architecture/dns.md). With a policy (Core.DNSPol) the
// engine takes standard recursive queries off the wire: UDP ones on the
// packet loop (udpOut), TCP ones as connections reflected into the relay
// in DNS mode (Core.ServeDNS). A query is passed on as before, answered at
// once (NXDOMAIN, NODATA, SERVFAIL) or resolved upstream: through the
// rule's tunnel, never direct when that fails, or directly over DoH/DoT.
// Without a policy nothing here runs and the packet path is today's.

// DNSResolver resolves what the policy sends upstream (dnsproxy.Resolver).
type DNSResolver interface {
	// Exchange resolves q directly (profile "") or through a profile's
	// tunnel and returns the upstream's answer to dnsproxy.UpstreamQuery(q)
	// (ID 0) and how long it was cached. dnsproxy.ErrTunnelDown when the
	// profile cannot carry it.
	Exchange(ctx context.Context, via dnspolicy.Via, profile string, q dnsproxy.Query) (msg []byte, age time.Duration, err error)
}

// dnsDest is the kind of DNS server a query goes to.
type dnsDest uint8

const (
	dnsNone      dnsDest = iota // not intercepted: today's path
	dnsMain                     // a DNS server of an adapter with a default gateway, or a public non-adapter address
	dnsSecondary                // a DNS server of any other adapter, whatever its range
	// dnsUnknown: a private address the last snapshot lacks (UDP): after
	// a network change it may be the new network's DNS server, so the
	// query waits off the loop for a fresh snapshot (dnsUDP).
	dnsUnknown
)

const (
	dnsMaxInflight = 256              // resolutions and owner waits in flight
	dnsTunnelWait  = 5 * time.Second  // a tunnel resolution
	dnsDirectWait  = 3 * time.Second  // a direct one: a failure must fall back quickly
	dnsKickEvery   = 30 * time.Second // adapter refresh while a policy is set
	// dnsUnknownWait bounds the wait for a fresh snapshot; an address a
	// fresh one lacked is not waited for again for dnsUnknownKeep.
	dnsUnknownWait = 300 * time.Millisecond
	dnsUnknownKeep = 30 * time.Second
	dnsTCPMessages = 32 // per connection
)

var (
	// A DNS-mode connection lasts at most dnsTCPTotal and waits at most
	// dnsTCPIdle between messages and for an answer passed on (variables
	// for tests).
	dnsTCPTotal   = 60 * time.Second
	dnsTCPIdle    = 10 * time.Second
	cgnatPrefix   = netip.MustParsePrefix("100.64.0.0/10")
	errNoResolver = errors.New("dns: no resolver set")
)

// dnsState is the DNS part of Core (embedded).
type dnsState struct {
	// DNSPol is the DNS policy (nil = off: the packet path is today's).
	DNSPol atomic.Pointer[dnspolicy.Policy]
	// Resolver resolves what DNSPol sends upstream (nil = none: tunnel
	// names get SERVFAIL, direct ones pass).
	Resolver DNSResolver
	// SysDNS is the adapter snapshot (nil = none). The encrypted-DNS
	// exclusion (SystemDNS) does not use it.
	SysDNS *SysDNSView
	// DNSPauseUntil is the captive-portal pause, unix nanoseconds (0 =
	// off): while it lasts a tunnel name whose tunnel is unavailable is
	// passed on as before instead of SERVFAIL.
	DNSPauseUntil atomic.Int64
	// OwnName reports one of HyRoute's own hosts, which it is about to
	// contact itself (dnspolicy.OwnNames.Has; nil = none): its lookups,
	// anyone's, are passed on as before meanwhile. Set before Start.
	OwnName func(name string) bool

	dnsSem   chan struct{}
	dnsRows  dnsRows
	kickedAt atomic.Int64 // last periodic adapter refresh (Maintain)
	// dnsNotServer: private addresses a snapshot read after a miss did
	// not list (netip.Addr → unix nanos), see dnsRecheck.
	dnsNotServer sync.Map
}

// ---- which queries ----

// dnsTarget classifies a query's destination: adapter membership first,
// then the range. It reads the last adapter snapshot only; a miss asks
// for a new one in the background.
func (c *Core) dnsTarget(dst netip.AddrPort, tcp bool) dnsDest {
	if dst.Port() != 53 {
		return dnsNone
	}
	a := dst.Addr().Unmap()
	if a.IsUnspecified() || a.IsLoopback() && !c.Opt.NoDefaultExclusions {
		return dnsNone
	}
	if tcp && a.Is6() && a.IsLinkLocalUnicast() {
		return dnsNone // the relay cannot reach a zone
	}
	info := c.SysDNS.Get()
	if info != nil && info.Primary[a] {
		return dnsMain
	}
	if info != nil && info.All[a] {
		return dnsSecondary
	}
	c.SysDNS.Kick() // a network change may have brought a new server
	if !DefaultExclusions(a) && !cgnatPrefix.Contains(a) || a.IsLoopback() {
		return dnsMain // a public resolver a program asks itself
	}
	if tcp || c.SysDNS == nil {
		return dnsNone
	}
	if at, ok := c.dnsNotServer.Load(a); ok && time.Since(time.Unix(0, at.(int64))) < dnsUnknownKeep {
		return dnsNone // a fresh snapshot lacked it a moment ago
	}
	return dnsUnknown
}

// dnsRecheck classifies an address dnsTarget found unknown, by a
// snapshot read after the miss: one it still lacks is remembered as no
// DNS server of an adapter for dnsUnknownKeep.
func (c *Core) dnsRecheck(a netip.Addr) dnsDest {
	info := c.SysDNS.Get()
	switch {
	case info != nil && info.Primary[a]:
		return dnsMain
	case info != nil && info.All[a]:
		return dnsSecondary
	}
	c.dnsNotServer.Store(a, time.Now().UnixNano())
	return dnsNone
}

// dnsHold reports an excluded destination whose fragments must not pass
// unrouted: with a DNS policy on, a private DNS server the policy
// intercepts (the home router). Its fragmented queries are assembled and
// go through the DNS check; other fragmented traffic to it still passes
// unchanged, decided by its first fragment.
func (c *Core) dnsHold(a netip.Addr) bool {
	if c.DNSPol.Load() == nil {
		return false
	}
	d := c.dnsTarget(netip.AddrPortFrom(a, 53), false)
	return d == dnsMain || d == dnsSecondary
}

// ownHysteria: a hysteria.exe HyRoute started.
func (c *Core) ownHysteria(proc *procinfo.Info) bool {
	return c.SelfPID != 0 && proc != nil && proc.Name == "hysteria.exe" && proc.Parent != nil && proc.Parent.PID == c.SelfPID
}

// own reports HyRoute's own traffic: its process, or a Hysteria it started
// (the first two cases of exclusion).
func (c *Core) own(pid uint32, known bool, proc *procinfo.Info) bool {
	return known && (pid == c.SelfPID || c.ownHysteria(proc))
}

// dnsEnv is what the classifier needs from the engine.
func (c *Core) dnsEnv() dnspolicy.Env {
	return dnspolicy.Env{Rules: c.Rules.Load(), Local: c.SysDNS.Local, Transient: c.OwnName, IPv6Blocked: c.Opt.BlockIPv6Tunnel}
}

func (c *Core) requester(pid uint32, known bool, proc *procinfo.Info) dnspolicy.Requester {
	return dnspolicy.Requester{Proc: proc, System: known && pid != 0 && pid == c.DnscachePID.Load()}
}

func (c *Core) classify(pol *dnspolicy.Policy, dest dnsDest, q dnsproxy.Query, req dnspolicy.Requester) dnspolicy.Decision {
	d := pol.Classify(dnspolicy.Question{Name: q.Name, Type: q.Type}, req, c.dnsEnv())
	if dest == dnsSecondary {
		d = dnspolicy.ForSecondary(d)
	}
	return d
}

// ---- UDP ----

// udpQuery is one UDP query the engine took off the wire, with what the
// rows need.
type udpQuery struct {
	pol    *dnspolicy.Policy
	dest   dnsDest
	q      dnsproxy.Query
	p      *packet.Packet
	addr   *divert.Address
	pid    uint32
	known  bool
	proc   *procinfo.Info
	attrib string
	late   bool // off the packet loop (a copy): pass = udpRoute here
}

// dnsUDP handles a UDP query to port 53 while a policy is on and reports
// whether it took the packet (false: udpOut goes on with udpRoute).
func (c *Core) dnsUDP(pol *dnspolicy.Policy, dest dnsDest, p *packet.Packet, addr *divert.Address) bool {
	q, ok := dnsproxy.ParseQuery(p.Payload())
	if !ok {
		return false
	}
	key := nat.FlowKey{Src: p.Src(), Dst: p.Dst()}
	if dest == dnsUnknown {
		// Wait off the loop for a snapshot read after this miss; a full
		// queue lets the query go on as before.
		select {
		case c.dnsSem <- struct{}{}:
		default:
			return false
		}
		mark := c.SysDNS.Mark()
		cp, a := copyPacket(p, addr)
		go func() {
			defer func() { <-c.dnsSem }()
			defer c.guard("dns")
			c.SysDNS.Fresh(mark, dnsUnknownWait)
			dest := c.dnsRecheck(key.Dst.Addr().Unmap())
			if dest == dnsNone {
				c.udpRoute(cp, &a)
				return
			}
			pid, known, stage := c.waitOwner(packet.ProtoUDP, key)
			if stage == "stopped" {
				return
			}
			c.dnsJudge(&udpQuery{pol: pol, dest: dest, q: q, p: cp, addr: &a, pid: pid, known: known, attrib: stage, late: true})
		}()
		return true
	}
	pid, known := c.Conns.Lookup(attrib.Key5{Proto: packet.ProtoUDP, Local: key.Src, Remote: key.Dst})
	if known {
		return c.dnsJudge(&udpQuery{pol: pol, dest: dest, q: q, p: p, addr: addr, pid: pid, known: true, attrib: "packet"})
	}
	// A program's fresh socket: its SOCKET event races the first packet.
	// Wait for the owner off the loop, so a name from one program is
	// judged the same way every time.
	select {
	case c.dnsSem <- struct{}{}:
	default:
		return c.dnsJudge(&udpQuery{pol: pol, dest: dest, q: q, p: p, addr: addr, attrib: "pending-full"})
	}
	cp, a := copyPacket(p, addr)
	go func() {
		defer func() { <-c.dnsSem }()
		defer c.guard("dns")
		pid, known, stage := c.waitOwner(packet.ProtoUDP, key)
		if stage == "stopped" {
			return
		}
		c.dnsJudge(&udpQuery{pol: pol, dest: dest, q: q, p: cp, addr: &a, pid: pid, known: known, attrib: stage, late: true})
	}()
	return true
}

// copyPacket copies a packet the loop owns (its buffer is reused).
func copyPacket(p *packet.Packet, addr *divert.Address) (*packet.Packet, divert.Address) {
	fp, err := packet.Parse(append([]byte(nil), p.Buf...))
	if err != nil {
		fp = *p // cannot happen: it parsed before
	}
	fp.Orig = p.Orig // bigudp: a passed reassembled query leaves as its fragments
	return &fp, *addr
}

// dnsJudge classifies a UDP query and acts on it; the result is dnsUDP's.
func (c *Core) dnsJudge(j *udpQuery) bool {
	if j.known {
		j.proc = c.Procs.Get(j.pid)
		if c.own(j.pid, true, j.proc) {
			return c.dnsPassUDP(j) // HyRoute's and its Hysteria's own DNS
		}
	}
	d := c.classify(j.pol, j.dest, j.q, c.requester(j.pid, j.known, j.proc))
	switch d.Kind {
	case dnspolicy.Answer:
		c.countAnswer(d)
		out := dnsproxy.Synth(j.q, d.Rcode)
		c.noteQuery(j, d, d.Route.Profile, d.Route, d.Outcome, len(out))
		c.answerUDP(j.p, j.addr, out)
		return true
	case dnspolicy.Resolve:
		if j.late {
			c.resolveUDP(j, d)
			return true
		}
		select {
		case c.dnsSem <- struct{}{}:
		default:
			// Too many in flight: a tunnel name fails closed, a direct one
			// goes as before.
			if d.Via == dnspolicy.ViaTunnel {
				c.servfailUDP(j, d, d.Route, dnspolicy.OutFailed)
				return true
			}
			c.DNSPassed.Add(1)
			return c.dnsPassUDP(j)
		}
		cp, a := copyPacket(j.p, j.addr)
		jj := *j
		jj.p, jj.addr, jj.late = cp, &a, true
		go func() {
			defer func() { <-c.dnsSem }()
			defer c.guard("dns")
			c.resolveUDP(&jj, d)
		}()
		return true
	}
	c.DNSPassed.Add(1)
	return c.dnsPassUDP(j)
}

// dnsPassUDP lets the query go on as before: on the loop by returning
// false, off it through udpRoute.
func (c *Core) dnsPassUDP(j *udpQuery) bool {
	if !j.late {
		return false
	}
	c.udpRoute(j.p, j.addr)
	return true
}

func (c *Core) countAnswer(d dnspolicy.Decision) {
	switch d.Rule {
	case dnspolicy.RuleCanary:
		c.DNSDoH.Add(1)
	case dnspolicy.RuleECH, dnspolicy.RuleNoIPv6:
	default:
		if d.Rcode == dnsmessage.RCodeNameError {
			c.DNSBlocked.Add(1)
		}
	}
}

// dnsCtx bounds one resolution and ends it when parent ends (the relay's,
// for a TCP query: its Abort) or the core stops.
func (c *Core) dnsCtx(parent context.Context, via dnspolicy.Via) (context.Context, context.CancelFunc) {
	wait := dnsDirectWait
	if via == dnspolicy.ViaTunnel {
		wait = dnsTunnelWait
	}
	ctx, cancel := context.WithTimeout(parent, wait)
	stop := c.stop
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// dnsResolve asks the resolver; for a tunnel name through the member the
// rule's route picks, as a lookup (groups: a stable choice, no side
// effects). route is the picked route.
func (c *Core) dnsResolve(ctx context.Context, d dnspolicy.Decision, q dnsproxy.Query) (msg []byte, age time.Duration, route rules.Result, err error) {
	if d.Via == dnspolicy.ViaTunnel {
		route, _ = c.pick(d.Route, false, groups.Hint{App: "hyroute:dns", Site: groups.SiteOf(q.Name, nil), Stable: true})
		if t := c.tunnel(route.Profile); t == nil || !t.Available() {
			return nil, 0, route, dnsproxy.ErrTunnelDown
		}
		if c.Resolver == nil {
			return nil, 0, route, dnsproxy.ErrTunnelDown
		}
		msg, age, err = c.Resolver.Exchange(ctx, dnspolicy.ViaTunnel, route.Profile, q)
		return msg, age, route, err
	}
	route = d.Route
	if c.Resolver == nil {
		return nil, 0, route, errNoResolver
	}
	msg, age, err = c.Resolver.Exchange(ctx, dnspolicy.ViaDirect, "", q)
	return msg, age, route, err
}

// dnsFailOutcome is the outcome of a failed tunnel resolution.
func dnsFailOutcome(err error) string {
	switch {
	case errors.Is(err, dnsproxy.ErrTunnelDown):
		return dnspolicy.OutTunnelDown
	case errors.Is(err, dnsproxy.ErrUpstreamDown):
		return dnspolicy.OutUpstreamDown
	}
	return dnspolicy.OutFailed
}

// paused reports the captive-portal pause.
func (c *Core) paused() bool { return time.Now().UnixNano() < c.DNSPauseUntil.Load() }

// resolveUDP resolves a UDP query upstream (off the loop, on a copy) and
// answers it, or passes it on (a direct failure, a negative that another
// adapter's server or the network's may know, the portal pause), or
// answers SERVFAIL (a tunnel name: never sent direct).
func (c *Core) resolveUDP(j *udpQuery, d dnspolicy.Decision) {
	ctx, cancel := c.dnsCtx(context.Background(), d.Via)
	msg, age, route, err := c.dnsResolve(ctx, d, j.q)
	cancel()
	if err == nil && d.PassNegative && dnsproxy.Negative(j.q, msg, d.NegativeAny) {
		c.DNSPassed.Add(1)
		c.udpRoute(j.p, j.addr) // not cached: the other server answers
		return
	}
	if err == nil {
		// TCP to an IPv6 link-local server is not intercepted (dnsTarget):
		// a TC answer would send the retry there, past the policy.
		a := j.p.Dst().Addr().Unmap()
		noTC := a.Is6() && a.IsLinkLocalUnicast()
		out, trunc, rerr := dnsproxy.Reply(j.q, msg, dnsproxy.ReplyOpts{Max: j.q.MaxUDP(), Age: age, Tunnel: d.Via == dnspolicy.ViaTunnel, NoTC: noTC})
		if rerr == nil {
			c.DNS.AddAnswerFor(dnsproxy.UpstreamQuery(j.q), msg)
			outcome := dnspolicy.OutDirect
			if d.Via == dnspolicy.ViaTunnel {
				outcome = dnspolicy.OutTunnel
				c.DNSTunnel.Add(1)
			} else {
				c.DNSDirect.Add(1)
			}
			if trunc {
				c.DNSTruncated.Add(1)
				outcome += dnspolicy.OutTruncated
			}
			c.noteQuery(j, d, route.Profile, route, outcome, len(out))
			c.answerUDP(j.p, j.addr, out)
			return
		}
		err = rerr
	}
	if d.Via != dnspolicy.ViaTunnel {
		c.DNSPassed.Add(1)
		c.udpRoute(j.p, j.addr)
		return
	}
	if errors.Is(err, dnsproxy.ErrTunnelDown) && c.paused() {
		c.DNSPortalPassed.Add(1)
		c.noteQuery(j, d, "", rules.Result{Action: rules.Direct}, dnspolicy.OutPortal, 0)
		c.udpRoute(j.p, j.addr)
		return
	}
	c.servfailUDP(j, d, route, dnsFailOutcome(err))
}

func (c *Core) servfailUDP(j *udpQuery, d dnspolicy.Decision, route rules.Result, outcome string) {
	c.DNSFailed.Add(1)
	out := dnsproxy.Synth(j.q, dnsmessage.RCodeServerFailure)
	c.noteQuery(j, d, route.Profile, route, outcome, len(out))
	c.answerUDP(j.p, j.addr, out)
}

// answerUDP injects payload to the socket that sent the query p, from the
// server it asked; the query itself goes nowhere.
func (c *Core) answerUDP(p *packet.Packet, addr *divert.Address, payload []byte) {
	pkt := packet.BuildUDP(p.Dst(), p.Src(), payload)
	a := *addr
	a.SetOutbound(false)
	a.SetChecksumsValid()
	c.Inject(pkt, &a)
}

// noteQuery counts a UDP query into its DNS row.
func (c *Core) noteQuery(j *udpQuery, d dnspolicy.Decision, profile string, route rules.Result, outcome string, recv int) {
	c.noteRow(j.pid, j.proc, packet.ProtoUDP, j.p.Src(), j.p.Dst(), j.attrib, j.q, d, profile, route, outcome, len(j.p.Payload()), recv)
}

// noteRow counts one answered query into its row.
func (c *Core) noteRow(pid uint32, proc *procinfo.Info, proto uint8, src, dst netip.AddrPort, attribBy string, q dnsproxy.Query,
	d dnspolicy.Decision, profile string, route rules.Result, outcome string, sent, recv int) {
	if attribBy == "packet" && pid != 0 && pid == c.DnscachePID.Load() {
		attribBy = "dnscache"
	}
	action := route.Action.String()
	k := dnsRowKey{pid: pid, proto: proto, name: q.Name, rule: d.Rule, route: action, profile: profile, outcome: outcome}
	c.noteDNS(time.Now(), k, sent, recv, func() *flows.Record {
		rec := &flows.Record{PID: pid, Proto: proto, Src: src, Dst: dst}
		if proc != nil {
			rec.Process, rec.Path = proc.Name, proc.Path
		}
		rec.Set(func(f *flows.Fields) {
			f.Attrib, f.Stage, f.Domain, f.DomainSrc = attribBy, flows.StageDNS, q.Name, rules.SrcQuery.String()
			f.Rule, f.Route, f.Profile, f.Outcome = d.Rule, action, profile, outcome
			f.Group, f.Failover = route.Group, route.Failover
		})
		return rec
	})
}

// ---- TCP ----

// dnsTCP handles a TCP SYN to port 53 in decide: a query connection of a
// DNS server the policy intercepts goes to the relay in DNS mode. It
// reports whether it took the SYN. A SYN to a private address that only
// DNS capture brought here, and that is not taken after all (HyRoute's
// own, the policy went off meanwhile, the adapters changed), goes on as
// before, unrouted.
func (c *Core) dnsTCP(p *packet.Packet, addr *divert.Address, key nat.FlowKey, pid uint32, known bool, proc *procinfo.Info, rec *flows.Record) bool {
	if c.DNSPol.Load() != nil && !c.own(pid, known, proc) {
		if dest := c.dnsTarget(key.Dst, true); dest != dnsNone {
			c.applyDNSTCP(p, addr, key, pid, proc, dest, rec)
			return true
		}
	}
	if c.excluded(key.Dst.Addr()) {
		c.Inject(p.Buf, addr)
		return true
	}
	return false
}

// applyDNSTCP reflects a DNS connection into the relay (ServeDNS answers
// it). Its record is never opened: the rows come per message.
func (c *Core) applyDNSTCP(p *packet.Packet, addr *divert.Address, key nat.FlowKey, pid uint32, proc *procinfo.Info, dest dnsDest, rec *flows.Record) {
	now := time.Now()
	ent, err := c.NAT.Insert(&nat.Entry{Flow: key, PID: pid, Mode: nat.DNS, DNSDest: uint8(dest), Rec: rec, Meta: proc}, now)
	if err != nil {
		// The name is unknown: never direct.
		c.rejectSYN(p, addr, key, now)
		return
	}
	c.NAT.TouchPacket(ent, p, true, addr, now)
	c.Reflected.Add(1)
	nat.ReflectToRelay(p, c.Opt.RelayPort)
	c.injectInbound(p, addr)
}

// dnsConn is one DNS-mode connection being served.
type dnsConn struct {
	c      *Core
	e      *nat.Entry
	client net.Conn
	pass   func(context.Context, rules.Result) (net.Conn, error)
	ctx    context.Context
	proc   *procinfo.Info
	up     net.Conn // the connection passed-on queries use (opened once)
	routed bool     // passRoute computed
	route  rules.Result
}

// ServeDNS is the relay's ServeDNS: it answers the length-prefixed queries
// of a DNS-mode connection (at most dnsTCPMessages, dnsTCPTotal, idle
// dnsTCPIdle) like the UDP path, and passes on what the policy does not
// take over one connection to the original server by the route the
// connection would get today. A policy turned off meanwhile passes every
// later message.
func (c *Core) ServeDNS(ctx context.Context, e *nat.Entry, client net.Conn, pass func(context.Context, rules.Result) (net.Conn, error)) {
	s := &dnsConn{c: c, e: e, client: client, pass: pass, ctx: ctx}
	s.proc, _ = e.Meta.(*procinfo.Info)
	end := time.Now().Add(dnsTCPTotal)
	for range dnsTCPMessages {
		dl := time.Now().Add(dnsTCPIdle)
		if end.Before(dl) {
			dl = end
		}
		_ = client.SetReadDeadline(dl)
		msg, err := readFramed(client)
		if err != nil {
			if errors.Is(err, errBadFrame) {
				relay.Reset(client)
			}
			return
		}
		if !s.message(msg) {
			return
		}
		if !time.Now().Before(end) {
			return
		}
	}
}

var errBadFrame = errors.New("dns: bad TCP message")

// readFramed reads one length-prefixed DNS message.
func readFramed(c net.Conn) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < 12 {
		return nil, errBadFrame // empty, or no DNS header: garbage
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeFramed(c net.Conn, b []byte) error {
	_ = c.SetWriteDeadline(time.Now().Add(dnsTCPIdle))
	_, err := c.Write(append(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(b)), uint16(len(b))), b...))
	return err
}

// message handles one query; false ends the connection.
func (s *dnsConn) message(msg []byte) bool {
	c := s.c
	pol := c.DNSPol.Load()
	q, ok := dnsproxy.ParseQuery(msg)
	if pol == nil || !ok {
		if zoneTransfer(msg) {
			return s.splice(msg)
		}
		return s.passOn(msg)
	}
	d := c.classify(pol, dnsDest(s.e.DNSDest), q, c.requester(s.e.PID, s.proc != nil || s.e.PID != 0, s.proc))
	switch d.Kind {
	case dnspolicy.Answer:
		c.countAnswer(d)
		out := dnsproxy.Synth(q, d.Rcode)
		s.note(q, d, d.Route.Profile, d.Route, d.Outcome, len(msg), len(out))
		return writeFramed(s.client, out) == nil
	case dnspolicy.Resolve:
		ctx, cancel := c.dnsCtx(s.ctx, d.Via)
		up, age, route, err := c.dnsResolve(ctx, d, q)
		cancel()
		if err == nil && d.PassNegative && dnsproxy.Negative(q, up, d.NegativeAny) {
			c.DNSPassed.Add(1)
			return s.passOn(msg)
		}
		if err == nil {
			out, _, rerr := dnsproxy.Reply(q, up, dnsproxy.ReplyOpts{Max: 65535, Age: age, Tunnel: d.Via == dnspolicy.ViaTunnel})
			if rerr == nil {
				c.DNS.AddAnswerFor(dnsproxy.UpstreamQuery(q), up)
				outcome := dnspolicy.OutDirect
				if d.Via == dnspolicy.ViaTunnel {
					outcome = dnspolicy.OutTunnel
					c.DNSTunnel.Add(1)
				} else {
					c.DNSDirect.Add(1)
				}
				s.note(q, d, route.Profile, route, outcome, len(msg), len(out))
				return writeFramed(s.client, out) == nil
			}
			err = rerr
		}
		if d.Via != dnspolicy.ViaTunnel {
			c.DNSPassed.Add(1)
			return s.passOn(msg)
		}
		if errors.Is(err, dnsproxy.ErrTunnelDown) && c.paused() {
			c.DNSPortalPassed.Add(1)
			s.note(q, d, "", rules.Result{Action: rules.Direct}, dnspolicy.OutPortal, len(msg), 0)
			return s.passOn(msg)
		}
		c.DNSFailed.Add(1)
		out := dnsproxy.Synth(q, dnsmessage.RCodeServerFailure)
		s.note(q, d, route.Profile, route, dnsFailOutcome(err), len(msg), len(out))
		return writeFramed(s.client, out) == nil
	}
	c.DNSPassed.Add(1)
	return s.passOn(msg)
}

func (s *dnsConn) note(q dnsproxy.Query, d dnspolicy.Decision, profile string, route rules.Result, outcome string, sent, recv int) {
	attribBy := "packet"
	if s.proc == nil && s.e.PID == 0 {
		attribBy = "pending-timeout"
	}
	s.c.noteRow(s.e.PID, s.proc, packet.ProtoTCP, s.e.Flow.Src, s.e.Flow.Dst, attribBy, q, d, profile, route, outcome, sent, recv)
}

// passRoute is the route the connection would get today: the Windows DNS
// client's goes direct (its exclusion), a private server's too (it was
// never routed), any other by the rules on the address.
func (s *dnsConn) passRoute() rules.Result {
	if s.routed {
		return s.route
	}
	s.routed = true
	c, dst := s.c, s.e.Flow.Dst
	switch {
	case s.e.PID != 0 && s.e.PID == c.DnscachePID.Load(), c.excluded(dst.Addr()):
		s.route = rules.Result{Action: rules.Direct, Rule: "exclusion: system DNS"}
	default:
		set := c.Rules.Load()
		sub := rules.Subject{Proc: s.proc, Proto: packet.ProtoTCP, Dst: dst}
		res := set.EvaluateSites(sub, c.packetSites(set, packet.ProtoTCP, dst))
		if res.NeedsDomain {
			res = set.EvaluateNoDomain(sub)
		}
		// A stable choice without side effects, as for the lookups: no
		// group trial is claimed that a failed dial would have to give back.
		h := c.hint(res, s.proc, "", dst.Addr())
		h.Stable = true
		s.route, _ = c.pick(res, false, h)
	}
	return s.route
}

// dialUp opens the connection passed-on messages use, once, by passRoute;
// false: the client was reset (the route blocks or the dial fails: a
// tunnel route never falls back to direct).
func (s *dnsConn) dialUp() bool {
	if s.up != nil {
		return true
	}
	r := s.passRoute()
	if r.Action == rules.Block {
		relay.Reset(s.client)
		return false
	}
	up, err := s.pass(s.ctx, r)
	if err != nil {
		relay.Reset(s.client)
		return false
	}
	s.up = up
	return true
}

// passOn sends a message to the original server by passRoute and gives
// its answer back; false ends the connection. Answers of another ID (left
// over from an earlier message that had several) are skipped, so the
// connection stays in step.
func (s *dnsConn) passOn(msg []byte) bool {
	if !s.dialUp() {
		return false
	}
	if err := writeFramed(s.up, msg); err != nil {
		relay.Reset(s.client)
		return false
	}
	_ = s.up.SetReadDeadline(time.Now().Add(dnsTCPIdle))
	var ans []byte
	for range dnsTCPMessages {
		a, err := readFramed(s.up)
		if err != nil {
			relay.Reset(s.client)
			return false
		}
		if a[0] == msg[0] && a[1] == msg[1] {
			ans = a
			break
		}
	}
	if ans == nil {
		relay.Reset(s.client)
		return false
	}
	s.c.DNS.AddAnswerFor(msg, ans)
	return writeFramed(s.client, ans) == nil
}

// zoneTransfer reports an AXFR or IXFR query: its answer is many messages.
func zoneTransfer(msg []byte) (xfr bool) {
	defer func() {
		if recover() != nil {
			xfr = false
		}
	}()
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response {
		return false
	}
	q, err := p.Question()
	return err == nil && (q.Type == dnsmessage.TypeAXFR || q.Type == typeIXFR)
}

const typeIXFR dnsmessage.Type = 251

// splice gives the rest of the connection to the original server as it is
// (a zone transfer, whose answer is many messages; the policy never
// judged it): msg goes on, then both ways are copied until either side
// ends, as the relay copies a connection. It always ends the connection.
func (s *dnsConn) splice(msg []byte) bool {
	if !s.dialUp() {
		return false
	}
	if err := writeFramed(s.up, msg); err != nil {
		relay.Reset(s.client)
		return false
	}
	_ = s.client.SetDeadline(time.Time{})
	_ = s.up.SetDeadline(time.Time{})
	socks5.Pipe(s.client, s.up)
	return false
}

// ---- browser DoH ----

// dohBlocked: a browser's connection to a known DoH server, blocked while
// BlockBrowserDoH is on. name is a name the connection showed (SNI/Host),
// or "".
func (c *Core) dohBlocked(proc *procinfo.Info, proto uint8, dst netip.AddrPort, name string) bool {
	pol := c.DNSPol.Load()
	if pol == nil || !pol.Cfg.BlockBrowserDoH || !dnspolicy.IsBrowser(proc) {
		return false
	}
	return c.dohDest(proto, dst, name)
}

// dohDest: TCP or UDP to 443/853 of a DoH address, or of an address or
// name the lists call DoH.
func (c *Core) dohDest(proto uint8, dst netip.AddrPort, name string) bool {
	if proto != packet.ProtoTCP && proto != packet.ProtoUDP || dst.Port() != 443 && dst.Port() != 853 {
		return false
	}
	if dnspolicy.IsDoHAddr(dst.Addr()) || name != "" && dnspolicy.IsDoHHost(name) {
		return true
	}
	for _, n := range c.DNS.Names(dst.Addr()) {
		if dnspolicy.IsDoHHost(n) {
			return true
		}
	}
	return false
}

// browserOf is a record's process for IsBrowser (its exe name).
func browserOf(rec *flows.Record) *procinfo.Info {
	if rec == nil || rec.Process == "" {
		return nil
	}
	return &procinfo.Info{Name: strings.ToLower(rec.Process)}
}

// DropDoH makes the browsers' tracked connections to DoH servers go
// through the blocking hooks once (the session calls it when a policy
// with BlockBrowserDoH replaces one without): direct TCP flows are
// forgotten, so their next segment is reset by untrackedOut; UDP flows
// turn to Block; reflected connections get the application's RST, and the
// returned pred matches them for the relay's AbortWhere.
func (c *Core) DropDoH() func(*nat.Entry) bool {
	now := time.Now()
	var closed []*flows.Record
	c.mu.Lock()
	for k, tf := range c.tcp {
		if c.dohBlocked(browserOf(tf.rec), packet.ProtoTCP, k.Dst, tf.rec.View(now).Domain) {
			delete(c.tcp, k)
			closed = append(closed, tf.rec)
		}
	}
	for k := range c.untracked {
		// The owner is not kept: the next segment is decided again (and
		// reset only for a browser).
		if c.dohDest(packet.ProtoTCP, k.Dst, "") {
			delete(c.untracked, k)
		}
	}
	for k, uf := range c.udp {
		// Closed as the TCP ones, not switched to Block: the packet loop
		// reads a published flow's route without c.mu. The next datagram
		// is decided again, and blocked.
		if uf.route != rules.Block && c.dohBlocked(browserOf(uf.rec), packet.ProtoUDP, k.Dst, "") {
			delete(c.udp, k)
			closed = append(closed, uf.rec)
		}
	}
	c.mu.Unlock()
	for _, r := range closed {
		c.Flows.Close(r, now)
	}
	pred := func(e *nat.Entry) bool {
		if e.Mode == nat.DNS {
			return false
		}
		proc, _ := e.Meta.(*procinfo.Info)
		name := ""
		if e.Rec != nil {
			name = e.Rec.View(now).Domain
		}
		return c.dohBlocked(proc, packet.ProtoTCP, e.Flow.Dst, name)
	}
	c.injectResets(c.NAT.ResetAppsWhere(pred))
	return pred
}

// AbortDNS resets the applications' DNS-mode connections (while the
// filter still reflects the resets) before DNS capture goes.
func (c *Core) AbortDNS() {
	c.injectResets(c.NAT.ResetAppsWhere(func(e *nat.Entry) bool { return e.Mode == nat.DNS }))
}

func (c *Core) injectResets(rs []nat.AppReset) {
	for _, r := range rs {
		a := r.Addr
		a.SetOutbound(false)
		a.SetChecksumsValid()
		c.Inject(r.Pkt, &a)
	}
}

// ---- maintenance ----

// maintainDNS is Maintain's DNS part.
func (c *Core) maintainDNS(now time.Time) {
	if r, ok := c.Resolver.(interface{ Sweep(time.Time) }); ok {
		r.Sweep(now)
	}
	c.sweepDNSRows(now, false)
	if c.DNSPol.Load() != nil && now.Sub(time.Unix(0, c.kickedAt.Load())) >= dnsKickEvery {
		c.kickedAt.Store(now.UnixNano())
		c.SysDNS.Kick()
	}
}
