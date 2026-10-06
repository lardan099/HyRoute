package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

const relayPort = 50123

type fakeTunnel struct {
	up, udp  atomic.Bool
	client   *socks5.Client
	rejected atomic.Int64
	sent     atomic.Int64
	recv     atomic.Int64
}

func (f *fakeTunnel) NoteRejected() { f.rejected.Add(1) }
func (f *fakeTunnel) NoteTraffic(sent, recv int64) {
	f.sent.Add(sent)
	f.recv.Add(recv)
}

func (f *fakeTunnel) Available() bool    { return f.up.Load() }
func (f *fakeTunnel) UDPAvailable() bool { return f.udp.Load() }
func (f *fakeTunnel) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	if f.client == nil {
		return nil, errors.New("no SOCKS5 server in this test")
	}
	return f.client.UDPAssociate(ctx)
}

type injected struct {
	pkt  packet.Packet
	addr divert.Address
}

type harness struct {
	c   *Core
	tun *fakeTunnel
	// extra are tunnels of named profiles; "" is tun, anything else nil.
	extra map[string]*fakeTunnel
	out   chan injected
	frags chan []byte // injected IP fragments
}

var procs = map[uint32]string{
	100: `C:\Tools\curl.exe`,
	200: `C:\Chrome\chrome.exe`,
	300: `C:\Windows\System32\svchost.exe`,
	400: `C:\Games\game.exe`,
}

func newHarness(t *testing.T, cfg rules.Config, opt Options) *harness {
	t.Helper()
	pc := procinfo.NewCacheWith(procinfo.System{Query: func(pid uint32) (string, int64, bool) {
		p, ok := procs[pid]
		return p, 1, ok
	}})
	h := &harness{tun: &fakeTunnel{}, extra: map[string]*fakeTunnel{}, out: make(chan injected, 64), frags: make(chan []byte, 64)}
	h.tun.up.Store(true)
	h.tun.udp.Store(true)
	opt.RelayPort = relayPort
	if opt.PendingTimeout == 0 {
		opt.PendingTimeout = 200 * time.Millisecond
	}
	h.c = NewCore(opt, func(profile string) Tunnel {
		if profile == "" {
			return h.tun
		}
		if t := h.extra[profile]; t != nil {
			return t
		}
		return nil
	}, pc, func(b []byte, a *divert.Address) {
		cp := append([]byte(nil), b...)
		p, err := packet.Parse(cp)
		if errors.Is(err, packet.ErrFragment) {
			h.frags <- cp
			return
		}
		if err != nil {
			t.Errorf("injected unparsable packet: %v", err)
			return
		}
		h.out <- injected{p, *a}
	})
	set, err := rules.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.c.Rules.Swap(set)
	if emptyGroups {
		h.c.Groups = groups.NewRuntime(nil)
	}
	t.Cleanup(h.c.Close)
	return h
}

// emptyGroups: harnesses get a runtime without groups (TestNoGroupsUnchanged).
var emptyGroups bool

func (h *harness) own(proto uint8, src, dst string, pid uint32) {
	h.c.Conns.Connect(attrib.Key5{Proto: proto, Local: netip.MustParseAddrPort(src), Remote: netip.MustParseAddrPort(dst)}, pid, uint64(pid)<<16|uint64(netip.MustParseAddrPort(src).Port()), time.Now())
}

func outAddr() *divert.Address {
	var a divert.Address
	a.SetOutbound(true)
	return &a
}

func (h *harness) sendTCP(src, dst string, flags uint8, payload string) {
	b := packet.BuildTCP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), flags, 1000, 0, []byte(payload))
	h.c.HandlePacket(b, outAddr())
}

func (h *harness) sendUDP(src, dst string, payload []byte) {
	b := packet.BuildUDP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), payload)
	h.c.HandlePacket(b, outAddr())
}

func (h *harness) next(t *testing.T) injected {
	t.Helper()
	select {
	case i := <-h.out:
		return i
	case <-time.After(2 * time.Second):
		t.Fatal("no packet injected")
	}
	return injected{}
}

func (h *harness) none(t *testing.T) {
	t.Helper()
	select {
	case i := <-h.out:
		t.Fatalf("unexpected injection %v -> %v", i.pkt.Src(), i.pkt.Dst())
	case <-time.After(50 * time.Millisecond):
	}
}

func lastRecord(t *testing.T, c *Core) flows.View {
	t.Helper()
	all := append(c.Flows.Active(time.Now()), c.Flows.Closed()...)
	if len(all) == 0 {
		t.Fatal("no records")
	}
	last := all[0]
	for _, v := range all {
		if v.ID > last.ID {
			last = v
		}
	}
	return last
}

var appRules = rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
	{Name: "curl", App: &rules.AppMatch{Pattern: "curl.exe"}, Action: rules.Tunnel},
	{Name: "game udp", App: &rules.AppMatch{Pattern: "game.exe"}, Protocol: "udp", Action: rules.Tunnel},
	{Name: "block site", Domain: &rules.DomainMatch{Pattern: ".blocked.test"}, Action: rules.Block},
	{Name: "yt", Domain: &rules.DomainMatch{Pattern: ".youtube.com"}, Action: rules.Tunnel},
}}

const (
	L  = "192.168.1.5:40000"
	R  = "93.184.216.34:443"
	L6 = "[2a00::5]:40000"
	R6 = "[2606:4700::1111]:443"
)

func TestTCPTunnelReflectRoundTrip(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	h.own(6, L, R, 100)
	h.sendTCP(L, R, packet.FlagSYN, "")
	i := h.next(t)
	if i.addr.Outbound() || i.pkt.Src() != netip.MustParseAddrPort("93.184.216.34:40000") || i.pkt.Dst() != netip.MustParseAddrPort("192.168.1.5:50123") {
		t.Fatalf("reflected SYN %v -> %v outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.addr.Outbound())
	}
	if !i.pkt.VerifyChecksums() {
		t.Fatal("checksum")
	}
	// Later app packets follow the NAT entry.
	h.sendTCP(L, R, packet.FlagACK, "hello")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("data not reflected")
	}
	// Relay reply goes back to the app from the original destination.
	h.sendTCP("192.168.1.5:50123", "93.184.216.34:40000", packet.FlagSYN|packet.FlagACK, "")
	i = h.next(t)
	if i.addr.Outbound() || i.pkt.Src() != netip.MustParseAddrPort(R) || i.pkt.Dst() != netip.MustParseAddrPort(L) {
		t.Fatalf("reply %v -> %v", i.pkt.Src(), i.pkt.Dst())
	}
	v := lastRecord(t, h.c)
	if v.Route != "tunnel" || v.Rule != "curl" || v.Process != "curl.exe" || v.Attrib != "packet" || v.Stage != "packet" || v.Outcome != "reflected" {
		t.Fatalf("%+v", v)
	}
}

func TestTCPDirectPassesAndCounts(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	// The DNS cache settles the domain, so chrome is decided at packet level.
	h.c.DNS.AddResponse(dnsResponse(t, "example.org.", "93.184.216.34"))
	h.own(6, L, R, 200)
	syn := packet.BuildTCP(netip.MustParseAddrPort(L), netip.MustParseAddrPort(R), packet.FlagSYN, 1, 0, nil)
	h.c.HandlePacket(syn, outAddr())
	i := h.next(t)
	if !i.addr.Outbound() || string(i.pkt.Buf) != string(syn) {
		t.Fatal("direct SYN must pass unchanged")
	}
	h.sendTCP(L, R, packet.FlagACK|packet.FlagPSH, "12345")
	h.next(t)
	v := lastRecord(t, h.c)
	if v.Route != "direct" || v.Sent != 5 || v.Recv != -1 || v.Rule != "default" || v.Domain != "example.org" {
		t.Fatalf("%+v", v)
	}
	// FLOW_DELETED closes the record.
	h.c.HandleFlowEvent(divert.EventFlowDeleted, divert.SocketData{Protocol: 6,
		LocalAddr: netip.MustParseAddr("192.168.1.5"), LocalPort: 40000,
		RemoteAddr: netip.MustParseAddr("93.184.216.34"), RemotePort: 443})
	if len(h.c.Flows.Active(time.Now())) != 0 || !h.c.Flows.Closed()[0].Closed {
		t.Fatal("record not closed on FLOW_DELETED")
	}
}

func TestTCPRejectBlockAndIPv6(t *testing.T) {
	h := newHarness(t, appRules, Options{BlockIPv6Tunnel: true})
	// Tunnel down: RST, never direct.
	h.tun.up.Store(false)
	h.own(6, L, R, 100)
	h.sendTCP(L, R, packet.FlagSYN, "")
	i := h.next(t)
	if i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 || i.pkt.Src() != netip.MustParseAddrPort(R) {
		t.Fatalf("expected RST from remote, got %v -> %v flags %x", i.pkt.Src(), i.pkt.Dst(), i.pkt.TCPFlags())
	}
	if h.c.Rejected.Load() != 1 || lastRecord(t, h.c).Outcome != "rst: tunnel unavailable" {
		t.Fatal("reject not recorded")
	}
	h.none(t)
	// IPv6 to the tunnel while it is down: blocked, not refused.
	h.own(6, L6, R6, 100)
	h.sendTCP(L6, R6, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.TCPFlags()&packet.FlagRST == 0 || !i.pkt.IPv6 {
		t.Fatal("IPv6 tunnel flow must be reset")
	}
	if v := lastRecord(t, h.c); h.c.Rejected.Load() != 1 || v.Outcome != "rst: IPv6 blocked for tunnel" || v.Route != "block" {
		t.Fatalf("rejected %d, %+v", h.c.Rejected.Load(), v)
	}
	h.c.Maintain(time.Now().Add(rejectMemory + time.Second)) // the reset is remembered
	h.tun.up.Store(true)
	// IPv6 to the tunnel: RST.
	h.own(6, L6, R6, 100)
	h.sendTCP(L6, R6, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.TCPFlags()&packet.FlagRST == 0 || !i.pkt.IPv6 {
		t.Fatal("IPv6 tunnel flow must be reset")
	}
	// Block by DNS-known domain.
	h.c.DNS.AddResponse(dnsResponse(t, "www.blocked.test.", "198.51.100.9"))
	h.own(6, "192.168.1.5:40001", "198.51.100.9:443", 200)
	h.sendTCP("192.168.1.5:40001", "198.51.100.9:443", packet.FlagSYN, "")
	if i := h.next(t); i.pkt.TCPFlags()&packet.FlagRST == 0 {
		t.Fatal("blocked flow must be reset")
	}
	if v := lastRecord(t, h.c); v.Rule != "block site" || v.DomainSrc != "dns" || v.Domain != "www.blocked.test" {
		t.Fatalf("%+v", v)
	}
	// Windows retries a reset SYN: reset again, no new record.
	n := len(h.c.Flows.Closed())
	h.sendTCP("192.168.1.5:40001", "198.51.100.9:443", packet.FlagSYN, "")
	if i := h.next(t); i.pkt.TCPFlags()&packet.FlagRST == 0 {
		t.Fatal("retried SYN must be reset")
	}
	if len(h.c.Flows.Closed()) != n || h.c.SYNRetries.Load() != 1 || h.c.Blocked.Load() != 3 {
		t.Fatalf("retry recorded: closed %d->%d retries %d blocked %d",
			n, len(h.c.Flows.Closed()), h.c.SYNRetries.Load(), h.c.Blocked.Load())
	}
	// After the memory expires the flow is decided again.
	h.c.Maintain(time.Now().Add(rejectMemory + time.Second))
	h.sendTCP("192.168.1.5:40001", "198.51.100.9:443", packet.FlagSYN, "")
	h.next(t)
	if len(h.c.Flows.Closed()) != n+1 {
		t.Fatal("expired reject memory must decide again")
	}
}

func TestDecisionLoggedBeforeClose(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	var order []string
	h.c.OnDecision = func(flows.View) { order = append(order, "decision") }
	h.c.Flows.OnClose = func(flows.View) { order = append(order, "close") }
	h.c.DNS.AddResponse(dnsResponse(t, "x.blocked.test.", "198.51.100.10"))
	h.own(6, "192.168.1.5:40002", "198.51.100.10:443", 200)
	h.sendTCP("192.168.1.5:40002", "198.51.100.10:443", packet.FlagSYN, "")
	h.next(t)
	if strings.Join(order, ",") != "decision,close" {
		t.Fatalf("order %v", order)
	}
}

func TestTCPNeedsDomainGoesToSniff(t *testing.T) {
	h := newHarness(t, appRules, Options{BlockIPv6Tunnel: true})
	h.own(6, L, R, 200) // chrome, unknown IP, domain rules exist
	h.sendTCP(L, R, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("not reflected for sniffing")
	}
	e := h.c.NAT.LookupFlow(nat.FlowKey{Src: netip.MustParseAddrPort(L), Dst: netip.MustParseAddrPort(R)})
	if e == nil || e.Mode != nat.Sniff || e.Rec == nil {
		t.Fatalf("entry %+v", e)
	}
	if r := h.c.RelayDecide(e, "music.youtube.com", rules.SrcSNI); r.Action != rules.Tunnel || r.Rule != "yt" {
		t.Fatalf("%+v", r)
	}
	if r := h.c.RelayDecide(e, "", rules.SrcNone); r.Action != rules.Direct {
		t.Fatalf("no name: %+v", r)
	}
	// SNI decision for IPv6 destination to the tunnel becomes Block.
	e6 := &nat.Entry{Flow: nat.FlowKey{Dst: netip.MustParseAddrPort(R6)}}
	if r := h.c.RelayDecide(e6, "www.youtube.com", rules.SrcSNI); r.Action != rules.Block {
		t.Fatalf("ipv6: %+v", r)
	}
}

// An IPv6 connection that some domain would send through the tunnel is
// refused at its SYN, so the application falls back to IPv4 (where the
// relay sees its domain), instead of being reset once it is up, which it
// would not retry over IPv4.
func TestIPv6NeedsDomainRefusedAtSYN(t *testing.T) {
	h := newHarness(t, appRules, Options{BlockIPv6Tunnel: true})
	h.own(6, L6, R6, 200) // chrome: "yt" may send it through the tunnel
	h.sendTCP(L6, R6, packet.FlagSYN, "")
	i := h.next(t)
	if i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 || i.pkt.Src() != netip.MustParseAddrPort(R6) {
		t.Fatalf("want RST from remote, got %v -> %v flags %x outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.pkt.TCPFlags(), i.addr.Outbound())
	}
	if h.c.NAT.LookupFlow(flowKey(L6, R6)) != nil {
		t.Fatal("reflected for sniffing")
	}
	if v := lastRecord(t, h.c); v.Route != "block" || v.Outcome != "rst: IPv6 blocked for tunnel" || h.c.Blocked.Load() != 1 {
		t.Fatalf("%+v blocked %d", v, h.c.Blocked.Load())
	}
	// Without IPv6 blocking it goes to the relay as usual.
	h = newHarness(t, appRules, Options{})
	h.own(6, L6, R6, 200)
	h.sendTCP(L6, R6, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("not reflected for sniffing")
	}
	// Nor without an IPv4 route (an IPv6-only network): there is no IPv4
	// to fall back to, the relay decides by the domain.
	h = newHarness(t, appRules, Options{BlockIPv6Tunnel: true})
	h.c.IPv4Route = func() bool { return false }
	h.own(6, L6, R6, 200)
	h.sendTCP(L6, R6, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("IPv6-only network: not reflected for sniffing")
	}
	// Nor is a connection no domain sends through the tunnel refused.
	h = newHarness(t, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "block site", Domain: &rules.DomainMatch{Pattern: ".blocked.test"}, Action: rules.Block},
	}}, Options{BlockIPv6Tunnel: true})
	h.own(6, L6, R6, 200)
	h.sendTCP(L6, R6, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("Direct/Block domain rules: not reflected for sniffing")
	}
	// With ExactWeb the DNS cache still hints: when none of its names for
	// the address goes through the tunnel, the connection is sniffed (an
	// IPv6-only site sent Direct stays reachable); one that does is refused.
	set, err := rules.Compile(appRules)
	if err != nil {
		t.Fatal(err)
	}
	set.ExactWeb = true
	for _, c := range []struct {
		name    string
		refused bool
	}{{"www.blocked.test.", false}, {"example.org.", false}, {"www.youtube.com.", true}} {
		h = newHarness(t, appRules, Options{BlockIPv6Tunnel: true})
		h.c.Rules.Swap(set)
		h.c.DNS.AddResponse(dnsResponse(t, c.name, netip.MustParseAddrPort(R6).Addr().String()))
		h.own(6, L6, R6, 200)
		h.sendTCP(L6, R6, packet.FlagSYN, "")
		if i := h.next(t); (i.pkt.TCPFlags()&packet.FlagRST != 0) != c.refused || (i.pkt.DstPort() == relayPort) == c.refused {
			t.Fatalf("cached %s: refused=%v wanted, got flags %x to port %d", c.name, c.refused, i.pkt.TCPFlags(), i.pkt.DstPort())
		}
	}
}

func TestPendingOwnerAndTimeout(t *testing.T) {
	h := newHarness(t, appRules, Options{PendingTimeout: 150 * time.Millisecond})
	// SOCKET event arrives after the SYN.
	h.sendTCP(L, R, packet.FlagSYN, "")
	h.sendTCP(L, R, packet.FlagSYN, "") // retransmit while parked
	time.Sleep(30 * time.Millisecond)
	h.own(6, L, R, 100)
	i := h.next(t)
	if i.pkt.DstPort() != relayPort {
		t.Fatal("late attribution must still tunnel curl")
	}
	h.next(t) // the parked retransmit is replayed through the NAT entry
	if v := lastRecord(t, h.c); v.Attrib != "pending" || v.Process != "curl.exe" {
		t.Fatalf("%+v", v)
	}
	// No event at all: unknown owner, app rules cannot match, but domain
	// rules still can, so the flow is sniffed.
	start := time.Now()
	h.sendTCP("192.168.1.5:40002", R, packet.FlagSYN, "")
	i = h.next(t)
	if i.pkt.DstPort() != relayPort || time.Since(start) < 140*time.Millisecond {
		t.Fatal("unknown owner must be decided after the timeout")
	}
	if v := lastRecord(t, h.c); v.Attrib != "pending-timeout" || v.Stage != "sniff" || v.Process != "" || h.c.Unknown.Load() != 1 {
		t.Fatalf("%+v", v)
	}
	// IP Helper fallback.
	h.c.OwnerFallback = func(proto uint8, l, r netip.AddrPort) (uint32, bool) { return 100, true }
	h.sendTCP("192.168.1.5:40003", R, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("iphelper owner not used")
	}
	if v := lastRecord(t, h.c); v.Attrib != "iphelper" {
		t.Fatalf("%+v", v)
	}
}

func TestSelfAndSystemDNSExclusions(t *testing.T) {
	h := newHarness(t, rules.Config{DefaultAction: rules.Tunnel}, Options{})
	h.c.SelfPID = 999
	h.c.DnscachePID.Store(300)
	h.own(6, L, R, 999)
	h.sendTCP(L, R, packet.FlagSYN, "")
	if i := h.next(t); !i.addr.Outbound() {
		t.Fatal("self must be direct")
	}
	if n := len(h.c.Flows.Active(time.Now())); n != 0 {
		t.Fatalf("self flow shown in connections: %d", n)
	}
	h.own(17, "192.168.1.5:5353", "8.8.8.8:53", 300)
	h.sendUDP("192.168.1.5:5353", "8.8.8.8:53", []byte("q"))
	if i := h.next(t); !i.addr.Outbound() {
		t.Fatal("Dnscache DNS must be direct")
	}
	if v := lastRecord(t, h.c); v.Rule != "exclusion: system DNS" || v.Excluded != "system-dns" {
		t.Fatalf("%+v", v)
	}
}

func TestStrayRelayInboundDropped(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	b := packet.BuildTCP(netip.MustParseAddrPort("203.0.113.1:5555"), netip.MustParseAddrPort("192.168.1.5:50123"), packet.FlagSYN, 1, 0, nil)
	h.c.HandlePacket(b, &divert.Address{})
	h.none(t)
	if h.c.StrayRelay.Load() != 1 {
		t.Fatal("stray counter")
	}
}

func TestUDPQUICBlockAndDirect(t *testing.T) {
	h := newHarness(t, appRules, Options{BlockQUIC: true})
	h.own(17, L, R, 200) // chrome QUIC to unknown IP
	h.sendUDP(L, R, []byte("quic"))
	h.none(t)
	if v := lastRecord(t, h.c); v.Route != "block" || v.Outcome != "dropped: QUIC blocked, domain unknown" {
		t.Fatalf("%+v", v)
	}
	// Same app, UDP to a non-443 port: domain rules skipped, default Direct.
	h.own(17, L, "93.184.216.34:3478", 200)
	h.sendUDP(L, "93.184.216.34:3478", []byte("stun"))
	if i := h.next(t); !i.addr.Outbound() {
		t.Fatal("direct UDP must pass")
	}
	h.sendUDP(L, "93.184.216.34:3478", []byte("again"))
	h.next(t)
	if v := lastRecord(t, h.c); v.Route != "direct" || v.Sent != 9 {
		t.Fatalf("%+v", v)
	}
}

func TestUDPTunnelEndToEnd(t *testing.T) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(append([]byte("re:"), b[:n]...), a)
		}
	}()
	stub := &socks5.Server{}
	if err := stub.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer stub.Close()

	h := newHarness(t, appRules, Options{NoDefaultExclusions: true, BlockIPv6Tunnel: true})
	h.tun.client = &socks5.Client{Server: stub.Addr()}
	dst := echo.LocalAddr().(*net.UDPAddr).AddrPort().String()
	app := "10.0.0.2:5000"
	h.own(17, app, dst, 400) // game.exe, UDP tunnel rule
	var ifAddr divert.Address
	ifAddr.SetOutbound(true)
	b := packet.BuildUDP(netip.MustParseAddrPort(app), netip.MustParseAddrPort(dst), []byte("ping"))
	h.c.HandlePacket(b, &ifAddr)
	h.c.HandlePacket(packet.BuildUDP(netip.MustParseAddrPort(app), netip.MustParseAddrPort(dst), []byte("pong")), &ifAddr)
	got := map[string]bool{}
	for k := 0; k < 2; k++ {
		i := h.next(t)
		if i.addr.Outbound() || i.pkt.Src() != netip.MustParseAddrPort(dst) || i.pkt.Dst() != netip.MustParseAddrPort(app) || !i.pkt.VerifyChecksums() {
			t.Fatalf("reply %v -> %v", i.pkt.Src(), i.pkt.Dst())
		}
		got[string(i.pkt.Payload())] = true
	}
	if !got["re:ping"] || !got["re:pong"] {
		t.Fatalf("replies %v", got)
	}
	// The record counts a reply after injecting it: wait for it to settle.
	v := lastRecord(t, h.c)
	for deadline := time.Now().Add(5 * time.Second); v.Recv != 14 && time.Now().Before(deadline); v = lastRecord(t, h.c) {
		time.Sleep(5 * time.Millisecond)
	}
	if v.Route != "tunnel" || v.Sent != 8 || v.Recv != 14 || h.c.UDPTunneled.Load() != 2 {
		t.Fatalf("%+v", v)
	}
	// Tunnel down: datagrams are dropped, not sent direct.
	h.tun.up.Store(false)
	h.c.HandlePacket(packet.BuildUDP(netip.MustParseAddrPort(app), netip.MustParseAddrPort(dst), []byte("x")), &ifAddr)
	h.none(t)
	if h.c.UDPDropped.Load() != 1 {
		t.Fatal("dropped counter")
	}
	// Idle flows and sessions expire.
	h.c.Maintain(time.Now().Add(2 * time.Minute))
	h.c.mu.Lock()
	n, s := len(h.c.udp), len(h.c.sessions)
	h.c.mu.Unlock()
	if n != 0 || s != 0 {
		t.Fatalf("idle state left: flows %d sessions %d", n, s)
	}
}

func TestDNSSniffFeedsDecisions(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	client, resolver := netip.MustParseAddrPort("192.168.1.5:5353"), netip.MustParseAddrPort("8.8.8.8:53")
	resp := packet.BuildUDP(resolver, client, dnsResponse(t, "www.youtube.com.", "142.250.1.1"))
	// A response nobody asked for (anyone can send from port 53) is ignored.
	h.c.HandleDNS(resp, false)
	if h.c.DNS.Len() != 0 {
		t.Fatal("unsolicited DNS response cached")
	}
	h.c.HandleDNS(packet.BuildUDP(client, resolver, dnsQuery(t, "www.youtube.com.")), true)
	h.c.HandleDNS(resp, false)
	h.own(6, L, "142.250.1.1:443", 200)
	h.sendTCP(L, "142.250.1.1:443", packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("DNS-known youtube IP must tunnel at packet level")
	}
	e := h.c.NAT.LookupFlow(nat.FlowKey{Src: netip.MustParseAddrPort(L), Dst: netip.MustParseAddrPort("142.250.1.1:443")})
	if e == nil || e.Mode != nat.NoSniff {
		t.Fatal("DNS-settled flow must not be sniffed")
	}
}

func dnsQuery(t *testing.T, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestDNSSniffTCP(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	client, resolver := netip.MustParseAddrPort("192.168.1.5:40053"), netip.MustParseAddrPort("8.8.8.8:53")
	framed := func(m []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(m))), m...) }
	h.c.HandleDNS(packet.BuildTCP(client, resolver, packet.FlagACK|packet.FlagPSH, 1, 1, framed(dnsQuery(t, "big.test."))), true)
	h.c.HandleDNS(packet.BuildTCP(resolver, client, packet.FlagACK|packet.FlagPSH, 1, 1, framed(dnsResponse(t, "big.test.", "198.51.100.40"))), false)
	if got := h.c.DNS.Names(netip.MustParseAddr("198.51.100.40")); len(got) != 1 || got[0] != "big.test" {
		t.Fatal(got)
	}
	// A query to port 53 is not an answer, whatever its direction.
	h.c.HandleDNS(packet.BuildUDP(resolver, client, dnsResponse(t, "in.test.", "198.51.100.41")), true)
	if h.c.DNS.Len() != 1 {
		t.Fatal("outbound packet from port 53 cached")
	}
}

// A TCP DNS answer that comes back through the relay (the tunnel) reaches
// the cache: the sniff does not see what the main handle injects.
func TestDNSTCPAnswerThroughTunnel(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	client, resolver := netip.MustParseAddrPort("192.168.1.5:40054"), netip.MustParseAddrPort("8.8.8.8:53")
	framed := func(m []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(m))), m...) }
	h.own(6, client.String(), resolver.String(), 100) // curl: tunnel
	h.sendTCP(client.String(), resolver.String(), packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("not reflected")
	}
	h.c.HandleDNS(packet.BuildTCP(client, resolver, packet.FlagACK|packet.FlagPSH, 1, 1, framed(dnsQuery(t, "tun.test."))), true)
	reflected := netip.AddrPortFrom(resolver.Addr(), client.Port())
	relay := netip.AddrPortFrom(client.Addr(), relayPort)
	h.c.HandlePacket(packet.BuildTCP(relay, reflected, packet.FlagACK|packet.FlagPSH, 1, 1, framed(dnsResponse(t, "tun.test.", "198.51.100.42"))), outAddr())
	if i := h.next(t); i.pkt.Src() != resolver || i.pkt.Dst() != client {
		t.Fatalf("answer %v -> %v", i.pkt.Src(), i.pkt.Dst())
	}
	if got := h.c.DNS.Names(netip.MustParseAddr("198.51.100.42")); len(got) != 1 || got[0] != "tun.test" {
		t.Fatal(got)
	}
}

func dnsResponse(t *testing.T, name, ip string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.StartQuestions()
	addr, typ := netip.MustParseAddr(ip), dnsmessage.TypeA
	if addr.Is6() {
		typ = dnsmessage.TypeAAAA
	}
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	hdr := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET, TTL: 300}
	if addr.Is6() {
		b.AAAAResource(hdr, dnsmessage.AAAAResource{AAAA: addr.As16()})
	} else {
		b.AResource(hdr, dnsmessage.AResource{A: addr.As4()})
	}
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestExactWebIgnoresDNSCacheForWeb(t *testing.T) {
	h := newHarness(t, appRules, Options{BlockQUIC: true})
	set, err := rules.Compile(appRules)
	if err != nil {
		t.Fatal(err)
	}
	set.ExactWeb = true
	h.c.Rules.Swap(set)
	// A shared CDN address cached under a blocked neighbour's name.
	h.c.DNS.AddResponse(dnsResponse(t, "www.blocked.test.", "198.51.100.20"))

	// TCP/443: the cache is not trusted, SNI decides.
	h.own(6, "192.168.1.5:41000", "198.51.100.20:443", 200)
	h.sendTCP("192.168.1.5:41000", "198.51.100.20:443", packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("web flow with a cached name must go to the relay")
	}
	e := h.c.NAT.LookupFlow(nat.FlowKey{Src: netip.MustParseAddrPort("192.168.1.5:41000"), Dst: netip.MustParseAddrPort("198.51.100.20:443")})
	if r := h.c.RelayDecide(e, "allowed.example", rules.SrcSNI); r.Action != rules.Direct {
		t.Fatalf("SNI must win over the cache: %+v", r)
	}
	// No SNI: the cache is the fallback.
	if r := h.c.RelayDecide(e, "", rules.SrcNone); r.Action != rules.Block || r.DomainSrc != rules.SrcDNS {
		t.Fatalf("no SNI must fall back to DNS: %+v", r)
	}

	// Non-web port: decided by the cache at packet level.
	h.own(6, "192.168.1.5:41001", "198.51.100.20:22", 200)
	h.sendTCP("192.168.1.5:41001", "198.51.100.20:22", packet.FlagSYN, "")
	if i := h.next(t); i.pkt.TCPFlags()&packet.FlagRST == 0 {
		t.Fatal("non-web port must be decided by DNS (block)")
	}

	// QUIC to the same address: dropped, the browser falls back to TCP.
	h.own(17, "192.168.1.5:41002", "198.51.100.20:443", 200)
	h.sendUDP("192.168.1.5:41002", "198.51.100.20:443", []byte("quic"))
	h.none(t)
	if v := lastRecord(t, h.c); v.Outcome != "dropped: QUIC blocked, domain unknown" {
		t.Fatalf("%+v", v)
	}
}

func newFakeTunnel(client *socks5.Client) *fakeTunnel {
	f := &fakeTunnel{client: client}
	f.up.Store(true)
	f.udp.Store(true)
	return f
}

// Each rule sends to its own profile; a profile that is down or missing
// refuses only its own flows.
func TestPerProfileTunnels(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "curl", App: &rules.AppMatch{Pattern: "curl.exe"}, Action: rules.Tunnel, Profile: "de"},
		{Name: "svchost", App: &rules.AppMatch{Pattern: "svchost.exe"}, Action: rules.Tunnel, Profile: "deleted"},
		{Name: "a", Domain: &rules.DomainMatch{Pattern: "a.test"}, Action: rules.Tunnel, Profile: "de"},
		{Name: "b", Domain: &rules.DomainMatch{Pattern: "b.test"}, Action: rules.Tunnel, Profile: "nl"},
	}}
	stub := &socks5.Server{}
	if err := stub.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	h := newHarness(t, cfg, Options{NoDefaultExclusions: true})
	de, nl := newFakeTunnel(&socks5.Client{Server: stub.Addr()}), newFakeTunnel(&socks5.Client{Server: stub.Addr()})
	h.extra["de"], h.extra["nl"] = de, nl

	// TCP through "de": the NAT entry carries the profile for the relay.
	h.own(6, L, R, 100)
	h.sendTCP(L, R, packet.FlagSYN, "")
	h.next(t)
	if e := h.c.NAT.LookupFlow(nat.FlowKey{Src: netip.MustParseAddrPort(L), Dst: netip.MustParseAddrPort(R)}); e == nil || e.Profile != "de" {
		t.Fatalf("NAT entry %+v", e)
	}
	if v := lastRecord(t, h.c); v.Profile != "de" || v.Route != "tunnel" {
		t.Fatalf("%+v", v)
	}
	// A deleted profile: RST, counted as rejected.
	h.own(6, "192.168.1.5:40010", R, 300)
	h.sendTCP("192.168.1.5:40010", R, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.TCPFlags()&packet.FlagRST == 0 {
		t.Fatal("missing profile must reset")
	}
	// "de" down: its flows are refused and counted on it; "nl" unaffected.
	de.up.Store(false)
	h.own(6, "192.168.1.5:40011", R, 100)
	h.sendTCP("192.168.1.5:40011", R, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.TCPFlags()&packet.FlagRST == 0 || de.rejected.Load() != 1 {
		t.Fatalf("de down: rejected %d", de.rejected.Load())
	}
	de.up.Store(true)

	// One UDP socket, two destinations, two profiles: two associations.
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(b[:n], a)
		}
	}()
	port := echo.LocalAddr().(*net.UDPAddr).Port
	// Both names resolve to loopback aliases that reach the echo server.
	h.c.DNS.AddResponse(dnsResponse(t, "a.test.", "127.0.0.1"))
	app := "10.0.0.2:5000"
	dstA := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	h.own(17, app, dstA.String(), 400)
	h.c.HandlePacket(packet.BuildUDP(netip.MustParseAddrPort(app), dstA, []byte("1")), outAddr())
	h.next(t)
	h.c.DNS.AddResponse(dnsResponse(t, "b.test.", "127.0.0.2"))
	dstB := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), uint16(port))
	h.own(17, app, dstB.String(), 400)
	h.c.HandlePacket(packet.BuildUDP(netip.MustParseAddrPort(app), dstB, []byte("2")), outAddr())
	h.c.mu.Lock()
	sessions := len(h.c.sessions)
	_, okA := h.c.sessions[sessKey{netip.MustParseAddrPort(app), "de"}]
	_, okB := h.c.sessions[sessKey{netip.MustParseAddrPort(app), "nl"}]
	h.c.mu.Unlock()
	if sessions != 2 || !okA || !okB {
		t.Fatalf("sessions %d de=%v nl=%v", sessions, okA, okB)
	}
	// The reply is counted after it is injected: wait for the counter.
	for deadline := time.Now().Add(2 * time.Second); de.recv.Load() < 1 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if de.sent.Load() != 1 || de.recv.Load() != 1 {
		t.Fatalf("de traffic %d/%d", de.sent.Load(), de.recv.Load())
	}
}

// A panic while handling one packet drops that packet; the engine keeps
// routing (a malformed packet must not turn the filters off).
func TestPanicDropsPacketOnly(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	h.c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	real := h.c.Tunnels
	h.c.Tunnels = func(string) Tunnel { panic("boom") }
	h.own(6, L, R, 100)
	h.sendTCP(L, R, packet.FlagSYN, "") // must not panic
	if h.c.Panics.Load() != 1 {
		t.Fatalf("panics %d", h.c.Panics.Load())
	}
	select {
	case i := <-h.out:
		t.Fatalf("panicking packet was injected: %v", i.pkt.Dst())
	default:
	}
	h.c.Tunnels = real
	h.own(6, "192.168.1.5:40001", R, 100)
	h.sendTCP("192.168.1.5:40001", R, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort && i.addr.Outbound() {
		t.Fatalf("engine stopped routing after a panic: %v -> %v", i.pkt.Src(), i.pkt.Dst())
	}
	h.c.HandleDNS([]byte{0x45}, false) // garbage: ignored, no panic
}

// fragments4 splits a UDP datagram into IPv4 fragments.
func fragments4(src, dst string, size int, id uint16) [][]byte {
	full := packet.BuildUDP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), make([]byte, size))
	body := full[20:]
	var out [][]byte
	for off := 0; off < len(body); off += 1480 {
		end := min(off+1480, len(body))
		h := append([]byte(nil), full[:20]...)
		binary.BigEndian.PutUint16(h[2:], uint16(20+end-off))
		binary.BigEndian.PutUint16(h[4:], id)
		fl := uint16(off / 8)
		if end < len(body) {
			fl |= 0x2000
		}
		binary.BigEndian.PutUint16(h[6:], fl)
		out = append(out, append(h, body[off:end]...))
	}
	return out
}

func (h *harness) fragCount() int {
	n := 0
	for {
		select {
		case <-h.frags:
			n++
		case <-time.After(50 * time.Millisecond):
			return n
		}
	}
}

// Fragmented datagrams follow the route of their flow: direct ones pass as
// their fragments, Tunnel ones go into the tunnel whole and Block ones are
// dropped whole (never sent direct), and fragments without a first
// fragment are dropped.
func TestFragmentsFollowTheRoute(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	h.c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))

	// game.exe UDP -> Tunnel: nothing leaves.
	h.own(17, L, R, 400)
	for _, f := range fragments4(L, R, 3000, 1) {
		h.c.HandlePacket(f, outAddr())
	}
	if n := h.fragCount(); n != 0 {
		t.Fatalf("%d fragments of a Tunnel datagram left directly", n)
	}
	h.none(t)

	// chrome.exe UDP -> default Direct: all fragments pass.
	const L2 = "192.168.1.5:40002"
	h.own(17, L2, R, 200)
	for _, f := range fragments4(L2, R, 3000, 2) {
		h.c.HandlePacket(f, outAddr())
	}
	if n := h.fragCount(); n != 3 {
		t.Fatalf("direct datagram: %d of 3 fragments passed", n)
	}

	// A later fragment without its first one is held, then dropped.
	fr := fragments4(L2, R, 3000, 3)
	h.c.HandlePacket(fr[1], outAddr())
	h.c.Maintain(time.Now().Add(6 * time.Second))
	if n := h.fragCount(); n != 0 || h.c.FragOrphan.Load() != 1 {
		t.Fatalf("orphan fragment passed (%d), orphans %d", n, h.c.FragOrphan.Load())
	}

	// A blocked site known from DNS: its fragments are dropped.
	h.c.DNS.AddResponse(dnsResponse(t, "www.blocked.test.", "198.51.100.30"))
	const L3 = "192.168.1.5:40003"
	h.own(17, L3, "198.51.100.30:443", 200)
	for _, f := range fragments4(L3, "198.51.100.30:443", 2000, 4) {
		h.c.HandlePacket(f, outAddr())
	}
	if n := h.fragCount(); n != 0 {
		t.Fatalf("blocked datagram leaked %d fragments", n)
	}
}

// An outbound packet that matched the filter but does not parse is
// dropped, not passed unrouted.
func TestMalformedOutboundDropped(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	b := packet.BuildUDP(netip.MustParseAddrPort(L), netip.MustParseAddrPort(R), []byte("x"))
	b[0] = 0x4f // IHL 60 bytes > packet
	h.c.HandlePacket(b, outAddr())
	h.none(t)
	if h.c.Malformed.Load() != 1 {
		t.Fatal("not counted")
	}
}

// TestFallback: DE down -> NL; both down -> refused (never direct).
func TestFallback(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "curl", App: &rules.AppMatch{Pattern: "curl.exe"}, Action: rules.Tunnel, Profile: "de", Fallback: []string{"nl"}},
		{Name: "a", Domain: &rules.DomainMatch{Pattern: "a.test"}, Action: rules.Tunnel, Profile: "de", Fallback: []string{"nl"}},
	}}
	h := newHarness(t, cfg, Options{NoDefaultExclusions: true})
	de, nl := &fakeTunnel{}, &fakeTunnel{}
	de.up.Store(true)
	nl.up.Store(true)
	h.extra["de"], h.extra["nl"] = de, nl
	flow := func(src string) *nat.Entry {
		t.Helper()
		h.own(6, src, R, 100)
		h.sendTCP(src, R, packet.FlagSYN, "")
		i := h.next(t)
		if i.pkt.TCPFlags()&packet.FlagRST != 0 {
			return nil
		}
		return h.c.NAT.LookupFlow(nat.FlowKey{Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(R)})
	}
	if e := flow("192.168.1.5:41001"); e == nil || e.Profile != "de" {
		t.Fatalf("primary up: %+v", e)
	}
	de.up.Store(false)
	if e := flow("192.168.1.5:41002"); e == nil || e.Profile != "nl" {
		t.Fatalf("primary down: %+v", e)
	}
	if v := lastRecord(t, h.c); v.Profile != "nl" || v.Rule != "curl (fallback)" {
		t.Fatalf("record %+v", v)
	}
	nl.up.Store(false)
	if e := flow("192.168.1.5:41003"); e != nil {
		t.Fatalf("both down must refuse, got %+v", e)
	}
	if de.rejected.Load() != 1 || nl.rejected.Load() != 0 {
		t.Fatalf("rejected on de %d, nl %d", de.rejected.Load(), nl.rejected.Load())
	}
	// The relay's decision for a sniffed flow picks the fallback too.
	nl.up.Store(true)
	e := &nat.Entry{Flow: nat.FlowKey{Src: netip.MustParseAddrPort("192.168.1.5:41004"), Dst: netip.MustParseAddrPort(R)}}
	if r := h.c.RelayDecide(e, "a.test", rules.SrcSNI); r.Profile != "nl" {
		t.Fatalf("relay decision %+v", r)
	}
}

// A Direct connection that never got past the handshake (its SYNs were
// dropped or refused: the answer is inbound and unseen) ends a minute
// after its last SYN; one that got further lives on until FIN or idle.
func TestTCPDirectSYNOnlyExpires(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	h.c.DNS.AddResponse(dnsResponse(t, "example.org.", "93.184.216.34"))
	const up = "192.168.1.5:40001"
	h.own(6, L, R, 200)
	h.own(6, up, R, 200)
	h.sendTCP(L, R, packet.FlagSYN, "")
	h.next(t)
	h.sendTCP(L, R, packet.FlagSYN, "") // a retransmission
	h.next(t)
	h.sendTCP(up, R, packet.FlagSYN, "")
	h.next(t)
	h.sendTCP(up, R, packet.FlagACK, "")
	h.next(t)
	h.c.Maintain(time.Now().Add(synOnlyTTL + time.Second))
	h.c.mu.Lock()
	_, dead := h.c.tcp[nat.FlowKey{Src: netip.MustParseAddrPort(L), Dst: netip.MustParseAddrPort(R)}]
	_, live := h.c.tcp[nat.FlowKey{Src: netip.MustParseAddrPort(up), Dst: netip.MustParseAddrPort(R)}]
	h.c.mu.Unlock()
	if dead || !live {
		t.Fatalf("SYN-only kept %v, established kept %v", dead, live)
	}
	if n := len(h.c.Flows.Active(time.Now())); n != 1 {
		t.Fatalf("%d active records", n)
	}
}

// A flow that needs its domain but collides with a live reflect key
// (R's IP, local port) is decided by the DNS cache, as the relay does
// without SNI: a cached tunnel site is refused, not sent direct.
func TestReflectCollisionUsesDNSCache(t *testing.T) {
	set, err := rules.Compile(appRules)
	if err != nil {
		t.Fatal(err)
	}
	set.ExactWeb = true
	h := newHarness(t, appRules, Options{})
	h.c.Rules.Swap(set)
	h.c.DNS.AddResponse(dnsResponse(t, "www.youtube.com.", netip.MustParseAddrPort(R).Addr().String()))
	const other = "10.0.0.9:40000"
	h.own(6, L, R, 200)
	h.own(6, other, R, 200)
	h.sendTCP(L, R, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("first flow not reflected for sniffing")
	}
	h.sendTCP(other, R, packet.FlagSYN, "")
	i := h.next(t)
	v := lastRecord(t, h.c)
	if i.pkt.TCPFlags()&packet.FlagRST == 0 || v.Route != "tunnel" || v.Outcome != "rst: reflect key collision" || h.c.KeyCollisions.Load() != 1 {
		t.Fatalf("flags %x: %+v", i.pkt.TCPFlags(), v)
	}
}
