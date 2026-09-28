package engine

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

const (
	grp1 = "grp-000000000001"
	grp2 = "grp-000000000002"
)

// groupRig is a harness whose rules name groups of fake tunnels.
type groupRig struct {
	*harness
	rt   *groups.Runtime
	mu   sync.Mutex
	now  time.Time
	sw   []groups.SwitchEvent
	tuns map[string]*fakeTunnel
}

func newGroupRig(t *testing.T, cfg rules.Config, opt Options, members []string, gs ...groups.Group) *groupRig {
	t.Helper()
	g := &groupRig{harness: newHarness(t, cfg, opt), now: time.Unix(1_000_000, 0), tuns: map[string]*fakeTunnel{}}
	g.rt = groups.NewRuntime(nil)
	g.rt.SetClock(func() time.Time { g.mu.Lock(); defer g.mu.Unlock(); return g.now })
	g.rt.OnSwitch = func(e groups.SwitchEvent) { g.mu.Lock(); g.sw = append(g.sw, e); g.mu.Unlock() }
	g.rt.SetGroups(gs)
	g.c.Groups = g.rt
	_, client := udpEcho(t, 0)
	for _, m := range members {
		f := &fakeTunnel{client: client}
		f.up.Store(true)
		f.udp.Store(true)
		g.tuns[m], g.extra[m] = f, f
		g.rt.NoteState(m, true)
	}
	return g
}

func (g *groupRig) advance(d time.Duration) { g.mu.Lock(); g.now = g.now.Add(d); g.mu.Unlock() }

func (g *groupRig) usable(id string) bool { return g.c.usable(id, false) }

// syn opens a TCP flow of pid from src to dst and returns its NAT entry
// (nil when it was refused with a RST).
func (g *groupRig) syn(t *testing.T, src, dst string, pid uint32) *nat.Entry {
	t.Helper()
	g.own(6, src, dst, pid)
	g.sendTCP(src, dst, packet.FlagSYN, "")
	i := g.next(t)
	if i.pkt.TCPFlags()&packet.FlagRST != 0 {
		if i.addr.Outbound() {
			t.Fatal("RST sent outbound")
		}
		return nil
	}
	if i.pkt.DstPort() != relayPort {
		t.Fatalf("flow not reflected: %v -> %v", i.pkt.Src(), i.pkt.Dst())
	}
	return g.c.NAT.LookupFlow(flowKey(src, dst))
}

var errFail = errors.New("socks5: host unreachable")

// penalise gives member two failed dials (SwitchAfterErrors 2).
func (g *groupRig) penalise(m string) {
	g.rt.NoteDial(m, "x:1", errFail)
	g.rt.NoteDial(m, "y:1", errFail)
}

func curlTo(target string, fallback ...string) rules.Config {
	return rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "curl", App: &rules.AppMatch{Pattern: "curl.exe"}, Action: rules.Tunnel, Profile: target, Fallback: fallback},
		{Name: "chrome", App: &rules.AppMatch{Pattern: "chrome.exe"}, Action: rules.Tunnel},
	}}
}

func TestGroupTarget(t *testing.T) {
	g := newGroupRig(t, curlTo(grp1, "us"), Options{NoDefaultExclusions: true}, []string{"de", "nl", "us"},
		groups.Group{ID: grp1, Name: "Авто", Strategy: groups.Failover, Members: []string{"de", "nl"}})
	if e := g.syn(t, "192.168.1.5:41001", R, 100); e == nil || e.Profile != "de" || e.Mode != nat.NoSniff {
		t.Fatalf("%+v", e)
	}
	if v := lastRecord(t, g.c); v.Profile != "de" || v.Group != grp1 || v.Failover || v.Rule != "curl" {
		t.Fatalf("%+v", v)
	}
	g.tuns["de"].up.Store(false)
	if e := g.syn(t, "192.168.1.5:41002", R, 100); e == nil || e.Profile != "nl" {
		t.Fatalf("%+v", e)
	}
	if v := lastRecord(t, g.c); v.Profile != "nl" || v.Group != grp1 || !v.Failover {
		t.Fatalf("%+v", v)
	}
	// The whole group down: the rule's fallback server.
	g.tuns["nl"].up.Store(false)
	if e := g.syn(t, "192.168.1.5:41003", R, 100); e == nil || e.Profile != "us" {
		t.Fatalf("%+v", e)
	}
	if v := lastRecord(t, g.c); v.Profile != "us" || v.Group != "" || !v.Failover || v.Rule != "curl (fallback)" {
		t.Fatalf("%+v", v)
	}
	// Nothing usable: refused (RST, nothing else injected), counted for
	// the group.
	g.tuns["us"].up.Store(false)
	if e := g.syn(t, "192.168.1.5:41004", R, 100); e != nil {
		t.Fatalf("%+v", e)
	}
	g.none(t)
	if v := lastRecord(t, g.c); v.Outcome != "rst: tunnel unavailable" || v.Profile != grp1 {
		t.Fatalf("%+v", v)
	}
	if g.c.Rejected.Load() != 1 || g.rt.Snapshot(grp1, g.usable).Rejected != 1 {
		t.Fatalf("rejected %d, group %d", g.c.Rejected.Load(), g.rt.Snapshot(grp1, g.usable).Rejected)
	}
	// The relay counts a sniffed flow refused through the group too.
	tun := g.c.GroupMiss(grp1)
	if tun == nil || tun.Available() || g.c.GroupMiss("grp-00000000000f") != nil || g.c.GroupMiss("de") != nil {
		t.Fatal("GroupMiss")
	}
	tun.(interface{ NoteRejected() }).NoteRejected()
	if g.rt.Snapshot(grp1, g.usable).Rejected != 2 {
		t.Fatal("relay rejection not counted")
	}
}

func TestUnknownGroupRefused(t *testing.T) {
	g := newGroupRig(t, curlTo("grp-00000000000f"), Options{NoDefaultExclusions: true}, []string{"de"},
		groups.Group{ID: grp1, Name: "A", Strategy: groups.Failover, Members: []string{"de"}})
	if e := g.syn(t, "192.168.1.5:41001", R, 100); e != nil {
		t.Fatalf("%+v", e)
	}
	g.none(t)
	if g.c.Rejected.Load() != 1 || g.rt.Snapshot(grp1, g.usable).Rejected != 0 {
		t.Fatal("rejection")
	}
	// Without a runtime at all a group ID is refused too.
	g.c.Groups = nil
	if e := g.syn(t, "192.168.1.5:41002", R, 100); e != nil {
		t.Fatalf("%+v", e)
	}
}

func TestGroupUDP(t *testing.T) {
	dst, client := udpEcho(t, 0)
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "game", App: &rules.AppMatch{Pattern: "game.exe"}, Protocol: "udp", Action: rules.Tunnel, Profile: grp1},
	}}
	g := newGroupRig(t, cfg, Options{NoDefaultExclusions: true}, []string{"a", "b"},
		groups.Group{ID: grp1, Name: "G", Strategy: groups.Failover, Members: []string{"a", "b"}})
	g.tuns["a"].client, g.tuns["b"].client = client, client
	g.tuns["a"].udp.Store(false) // a forbids UDP: skipped
	const app = "10.0.0.2:5000"
	g.own(17, app, dst.String(), 400)
	g.sendUDP(app, dst.String(), []byte("1"))
	if i := g.next(t); string(i.pkt.Payload()) != "re:1" {
		t.Fatalf("%q", i.pkt.Payload())
	}
	g.c.mu.Lock()
	uf := g.c.udp[flowKey(app, dst.String())]
	g.c.mu.Unlock()
	if uf == nil || uf.profile != "b" {
		t.Fatalf("%+v", uf)
	}
	if v := lastRecord(t, g.c); v.Group != grp1 || !v.Failover {
		t.Fatalf("%+v", v)
	}
	// b dies, a gets UDP: the flow moves on its next datagram.
	g.tuns["a"].udp.Store(true)
	g.tuns["b"].up.Store(false)
	g.tuns["b"].udp.Store(false)
	g.sendUDP(app, dst.String(), []byte("2"))
	if i := g.next(t); string(i.pkt.Payload()) != "re:2" {
		t.Fatalf("%q", i.pkt.Payload())
	}
	g.c.mu.Lock()
	uf = g.c.udp[flowKey(app, dst.String())]
	g.c.mu.Unlock()
	if uf == nil || uf.profile != "a" {
		t.Fatalf("%+v", uf)
	}
}

// A sticky group keys QUIC (decided per packet from the DNS cache) and the
// sniffed TCP of one site alike, when the cache holds names of that site
// only.
func TestStickyOneSiteBothPaths(t *testing.T) {
	members := []string{"m1", "m2", "m3", "m4", "m5", "m6", "m7", "m8"}
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "chrome", App: &rules.AppMatch{Pattern: "chrome.exe"}, Action: rules.Tunnel, Profile: grp1},
	}}
	for _, exact := range []bool{false, true} {
		opt := Options{NoDefaultExclusions: true, BlockQUIC: exact}
		g := newGroupRig(t, cfg, opt, members, groups.Group{ID: grp1, Name: "S", Strategy: groups.Sticky, Members: members})
		if exact {
			set := mustCompile(t, cfg)
			set.ExactWeb = true
			g.c.Rules.Swap(set)
		}
		const ip = "198.51.100.7"
		g.c.DNS.AddResponse(dnsResponse(t, "youtube.com.", ip))
		g.c.DNS.AddResponse(dnsResponse(t, "www.youtube.com.", ip))
		chrome := &procinfo.Info{Name: "chrome.exe", Path: `C:\Chrome\chrome.exe`}
		want, _ := g.rt.Peek(grp1, groups.Hint{App: `c:\chrome\chrome.exe`, Site: "youtube.com"}, g.usable)

		// The hint the packet path builds: the joined cache names are not
		// a name of this flow.
		res := rules.Result{Action: rules.Tunnel, Profile: grp1, Domain: "youtube.com,www.youtube.com", DomainSrc: rules.SrcDNS}
		if h := g.c.hint(res, chrome, "", netip.MustParseAddr(ip)); h.Site != "youtube.com" || h.App != `c:\chrome\chrome.exe` {
			t.Fatalf("%+v", h)
		}
		g.own(17, L, ip+":443", 200)
		g.sendUDP(L, ip+":443", []byte("quic"))
		if v := lastRecord(t, g.c); v.Profile != want.Member || v.Group != grp1 {
			t.Fatalf("exact=%v QUIC on %s, want %s", exact, v.Profile, want.Member)
		}
		e := &nat.Entry{Flow: nat.FlowKey{Src: netip.MustParseAddrPort("192.168.1.5:41000"), Dst: netip.MustParseAddrPort(ip + ":443")}, Meta: chrome}
		for _, name := range []string{"www.youtube.com", "m.youtube.com", ""} {
			src := rules.SrcSNI
			if name == "" {
				src = rules.SrcNone
			}
			if r := g.c.RelayDecide(e, name, src); r.Profile != want.Member || r.Group != grp1 {
				t.Fatalf("exact=%v SNI %q on %s, want %s", exact, name, r.Profile, want.Member)
			}
		}
	}
	// An unrelated site cached for the address: the key is the IP.
	g := newGroupRig(t, cfg, Options{NoDefaultExclusions: true}, members, groups.Group{ID: grp1, Name: "S", Strategy: groups.Sticky, Members: members})
	g.c.DNS.AddResponse(dnsResponse(t, "www.youtube.com.", "198.51.100.8"))
	g.c.DNS.AddResponse(dnsResponse(t, "cdn.other.net.", "198.51.100.8"))
	res := rules.Result{Action: rules.Tunnel, Profile: grp1}
	if h := g.c.hint(res, nil, "", netip.MustParseAddr("198.51.100.8")); h.Site != "" || h.IP.String() != "198.51.100.8" {
		t.Fatalf("%+v", h)
	}
	// No group in the chain: no hint at all.
	if h := g.c.hint(rules.Result{Action: rules.Tunnel, Profile: "de"}, nil, "x.com", netip.MustParseAddr("198.51.100.8")); h != (groups.Hint{}) {
		t.Fatalf("%+v", h)
	}
}

// A flow the IPv6 block refuses anyway commits nothing (round robin, trial).
func TestGroupCommitOnlyWhenUsed(t *testing.T) {
	g := newGroupRig(t, curlTo(grp1), Options{NoDefaultExclusions: true, BlockIPv6Tunnel: true}, []string{"a", "b"},
		groups.Group{ID: grp1, Name: "RR", Strategy: groups.RoundRobin, SwitchAfterErrors: 2, Members: []string{"a", "b"}})
	g.penalise("a")
	g.advance(groups.PenaltyFor) // a waits for its trial
	before, _ := g.rt.Peek(grp1, groups.Hint{}, g.usable)
	if e := g.syn(t, L6, R6, 100); e != nil {
		t.Fatalf("%+v", e)
	}
	e6 := &nat.Entry{Flow: nat.FlowKey{Dst: netip.MustParseAddrPort(R6)}, Meta: &procinfo.Info{Name: "curl.exe", Path: `C:\Tools\curl.exe`}}
	if r := g.c.RelayDecide(e6, "a.test", rules.SrcSNI); r.Action != rules.Block {
		t.Fatalf("%+v", r)
	}
	after, _ := g.rt.Peek(grp1, groups.Hint{}, g.usable)
	if after.Member != before.Member || g.rt.Snapshot(grp1, g.usable).Members[0].Reason == "trial" {
		t.Fatalf("IPv6 flows moved the group: %s -> %s", before.Member, after.Member)
	}
}

// A refusal after the pick releases a trial the pick claimed.
func TestGroupAbandonTrial(t *testing.T) {
	g := newGroupRig(t, curlTo(grp1), Options{NoDefaultExclusions: true}, []string{"a", "b"},
		groups.Group{ID: grp1, Name: "F", Strategy: groups.Failover, SwitchAfterErrors: 2, Members: []string{"a", "b"}})
	g.penalise("a")
	g.advance(groups.PenaltyFor)
	trial := func() bool { return g.rt.Snapshot(grp1, g.usable).Members[0].Reason == "trial" }
	// A chrome flow (the main tunnel) holds the reflect key (R's IP, port
	// 40000); curl's flow from another address collides with it.
	g.syn(t, L, R, 200)
	if e := g.syn(t, "10.0.0.9:40000", R, 100); e != nil {
		t.Fatalf("collision not refused: %+v", e)
	}
	if v := lastRecord(t, g.c); v.Outcome != "rst: reflect key collision" || v.Profile != "a" {
		t.Fatalf("%+v", v)
	}
	if trial() {
		t.Fatal("collision kept the trial")
	}
	// The member goes down between the pick and the check.
	flaky := &flakyTunnel{fakeTunnel: g.tuns["a"], left: 2} // the peek and the choice
	g.c.Tunnels = func(p string) Tunnel {
		switch p {
		case "a":
			return flaky
		case "b":
			return g.tuns["b"]
		}
		return nil
	}
	if e := g.syn(t, "192.168.1.5:41010", R, 100); e != nil {
		t.Fatalf("%+v", e)
	}
	if v := lastRecord(t, g.c); v.Outcome != "rst: tunnel unavailable" || v.Profile != "a" {
		t.Fatalf("%+v", v)
	}
	if trial() {
		t.Fatal("unavailable member kept the trial")
	}
}

// flakyTunnel is available for its first left calls.
type flakyTunnel struct {
	fakeTunnel *fakeTunnel
	left       int32
	n          atomic.Int32
}

func (f *flakyTunnel) Available() bool    { return f.n.Add(1) <= f.left }
func (f *flakyTunnel) UDPAvailable() bool { return f.fakeTunnel.UDPAvailable() }
func (f *flakyTunnel) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	return f.fakeTunnel.UDPAssociate(ctx)
}

// Two phases: the chain is peeked, then only the chosen entry commits.
func TestTwoPhaseResolve(t *testing.T) {
	g := newGroupRig(t, curlTo(grp1, grp2), Options{NoDefaultExclusions: true}, []string{"x", "y", "z"},
		groups.Group{ID: grp1, Name: "G1", Strategy: groups.RoundRobin, SwitchAfterErrors: 2, Members: []string{"x", "y"}},
		groups.Group{ID: grp2, Name: "G2", Strategy: groups.Failover, Members: []string{"z"}})
	g.penalise("x")
	g.penalise("y")
	before, _ := g.rt.Peek(grp1, groups.Hint{}, g.usable)
	if e := g.syn(t, "192.168.1.5:41001", R, 100); e == nil || e.Profile != "z" {
		t.Fatalf("%+v", e)
	}
	if after, _ := g.rt.Peek(grp1, groups.Hint{}, g.usable); after.Member != before.Member {
		t.Fatal("a degraded group before the chosen one committed")
	}
	// G2 down: the degraded G1 carries it, committed once.
	g.tuns["z"].up.Store(false)
	if e := g.syn(t, "192.168.1.5:41002", R, 100); e == nil || e.Profile != before.Member {
		t.Fatalf("%+v", e)
	}
	if v := lastRecord(t, g.c); !v.Failover || v.Group != grp1 {
		t.Fatalf("%+v", v)
	}
	if after, _ := g.rt.Peek(grp1, groups.Hint{}, g.usable); after.Member == before.Member {
		t.Fatal("the degraded pick did not commit")
	}
	g.mu.Lock()
	n := len(g.sw)
	g.mu.Unlock()
	if n != 0 {
		t.Fatal("round robin reported a switch")
	}

	// G1's only member goes unusable between the peek and the choice: the
	// flow moves on to the next entry.
	h := newGroupRig(t, curlTo(grp1, "nl"), Options{NoDefaultExclusions: true}, []string{"x", "nl"},
		groups.Group{ID: grp1, Name: "G1", Strategy: groups.Failover, Members: []string{"x"}})
	flaky := &flakyTunnel{fakeTunnel: h.tuns["x"], left: 1}
	h.c.Tunnels = func(p string) Tunnel {
		switch p {
		case "x":
			return flaky
		case "nl":
			return h.tuns["nl"]
		}
		return nil
	}
	if e := h.syn(t, "192.168.1.5:41003", R, 100); e == nil || e.Profile != "nl" {
		t.Fatalf("%+v", e)
	}
}

// The relay's decision keys a sticky group on the sniffed name.
func TestRelayDecideSticky(t *testing.T) {
	members := []string{"a", "b", "c", "d"}
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "sites", Domain: &rules.DomainMatch{Pattern: ".test"}, Action: rules.Tunnel, Profile: grp1},
	}}
	g := newGroupRig(t, cfg, Options{NoDefaultExclusions: true}, members, groups.Group{ID: grp1, Name: "S", Strategy: groups.Sticky, Members: members})
	chrome := &procinfo.Info{Name: "chrome.exe", Path: `C:\Chrome\chrome.exe`}
	for i := range 20 {
		name := "s" + string(rune('a'+i)) + ".test"
		e := &nat.Entry{Flow: nat.FlowKey{Dst: netip.MustParseAddrPort(R)}, Meta: chrome}
		r1 := g.c.RelayDecide(e, name, rules.SrcSNI)
		r2 := g.c.RelayDecide(e, "www."+name, rules.SrcSNI)
		want, _ := g.rt.Peek(grp1, groups.Hint{App: `c:\chrome\chrome.exe`, Site: name}, g.usable)
		if r1.Profile != want.Member || r2.Profile != want.Member {
			t.Fatalf("%s: %s, %s, want %s", name, r1.Profile, r2.Profile, want.Member)
		}
	}
}

// With no group defined, decisions are the v1.0.0 ones: the fallback and
// profile tests pass with an empty runtime too.
func TestNoGroupsUnchanged(t *testing.T) {
	emptyGroups = true
	defer func() { emptyGroups = false }()
	for name, f := range map[string]func(*testing.T){
		"Fallback": TestFallback, "PerProfileTunnels": TestPerProfileTunnels, "UDPFlowMovesToFallback": TestUDPFlowMovesToFallback,
		"TCPRejectBlockAndIPv6": TestTCPRejectBlockAndIPv6, "UDPTunnelDownRefused": TestUDPTunnelDownRefused,
	} {
		t.Run(name, f)
	}
}
