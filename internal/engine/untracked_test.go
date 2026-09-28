package engine

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/dnscache"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/rules"
)

// Connections the engine holds no state for (opened before start):
// Direct passes, Tunnel and Block are reset instead of leaking direct.

var untrackedRules = rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
	{Name: "curl", App: &rules.AppMatch{Pattern: "curl.exe"}, Action: rules.Tunnel},
	{Name: "game", App: &rules.AppMatch{Pattern: "game.exe"}, Action: rules.Block},
	{Name: "yt", Domain: &rules.DomainMatch{Pattern: ".youtube.com"}, Action: rules.Tunnel},
}}

// osTable fakes the OS table of TCP connections and counts its reads.
type osTable struct {
	mu    sync.Mutex
	rows  []attrib.TCPRow
	reads int
}

func withTable(h *harness) *osTable {
	o := &osTable{}
	h.c.TCPTable = o.read
	return o
}

func (o *osTable) read() ([]attrib.TCPRow, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.reads++
	return append([]attrib.TCPRow(nil), o.rows...), nil
}

func (o *osTable) conn(local, remote string, pid uint32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rows = append(o.rows, attrib.TCPRow{Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote), State: 5, PID: pid})
}

func (o *osTable) listen(local string, pid uint32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rows = append(o.rows, attrib.TCPRow{Local: netip.MustParseAddrPort(local), State: attrib.TCPStateListen, PID: pid})
}

func (o *osTable) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.reads
}

// wantReset checks a RST the application accepts: from the remote,
// inbound, with the sequence number the application acknowledged last.
func wantReset(t *testing.T, i injected, src, dst string, seq uint32) {
	t.Helper()
	if i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 || i.pkt.Src() != netip.MustParseAddrPort(src) ||
		i.pkt.Dst() != netip.MustParseAddrPort(dst) || i.pkt.Seq() != seq || !i.pkt.VerifyChecksums() {
		t.Fatalf("want reset %s -> %s seq %d, got %v -> %v flags %x seq %d outbound=%v",
			src, dst, seq, i.pkt.Src(), i.pkt.Dst(), i.pkt.TCPFlags(), i.pkt.Seq(), i.addr.Outbound())
	}
}

// wantPassed checks that b left unchanged.
func wantPassed(t *testing.T, i injected, b []byte) {
	t.Helper()
	if !i.addr.Outbound() || string(i.pkt.Buf) != string(b) {
		t.Fatalf("not passed unchanged: %v -> %v flags %x outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.pkt.TCPFlags(), i.addr.Outbound())
	}
}

func segment(src, dst string, flags uint8, seq, ack uint32, payload string) []byte {
	return packet.BuildTCP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), flags, seq, ack, []byte(payload))
}

// Regression test: a connection the previous engine reflected
// (HyRoute crashed, or its engine failed, before resetting it) reaches a
// new engine with its next request. That request must not leave direct:
// the application gets a RST it accepts and reconnects through the tunnel.
func TestUntrackedTunnelFlowReset(t *testing.T) {
	old := newHarness(t, untrackedRules, Options{})
	reflected(t, old)

	h := newHarness(t, untrackedRules, Options{})
	o := withTable(h)
	o.conn(L, R, 100) // curl, known to the OS tables only
	h.seg(L, R, packet.FlagACK|packet.FlagPSH, 1001, 5006, "GET /secret2")
	wantReset(t, h.next(t), R, L, 5006)
	h.none(t)
	if h.c.UntrackedReset.Load() != 1 {
		t.Fatalf("untracked resets: %d", h.c.UntrackedReset.Load())
	}
	// Segments still in flight are reset from memory.
	h.seg(L, R, packet.FlagACK|packet.FlagPSH, 1013, 5006, "more")
	wantReset(t, h.next(t), R, L, 5006)
	if n := o.count(); n != 1 {
		t.Fatalf("table read %d times", n)
	}
	// The application's own RST is dropped, not answered.
	h.seg(L, R, packet.FlagRST, 1017, 0, "")
	h.none(t)
	// The application reconnects on the same 4-tuple: decided as usual.
	h.own(6, L, R, 100)
	h.seg(L, R, packet.FlagSYN, 3000, 0, "")
	if i := h.next(t); i.addr.Outbound() || i.pkt.DstPort() != relayPort {
		t.Fatalf("new connection: %v -> %v outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.addr.Outbound())
	}
}

// Block resets too; the owner may come from a SOCKET event instead of the
// OS tables, and a FIN is answered like data.
func TestUntrackedBlockedFlowReset(t *testing.T) {
	h := newHarness(t, untrackedRules, Options{})
	o := withTable(h)
	h.own(6, L, R, 400) // game.exe
	h.seg(L, R, packet.FlagFIN|packet.FlagACK, 1001, 7000, "")
	wantReset(t, h.next(t), R, L, 7000)
	h.none(t)
	if o.count() != 1 {
		t.Fatalf("table read %d times", o.count())
	}
}

// Direct passes unchanged, and later segments pass from memory. FLOW_DELETED
// and a new connection on the 4-tuple forget it.
func TestUntrackedDirectFlowPasses(t *testing.T) {
	h := newHarness(t, untrackedRules, Options{})
	o := withTable(h)
	const L2 = "192.168.1.5:40001"
	o.conn(L, R, 200) // chrome, default Direct
	o.conn(L2, R, 200)
	for n := range 3 {
		b := segment(L, R, packet.FlagACK|packet.FlagPSH, 1001+uint32(n), 9000, "x")
		h.c.HandlePacket(b, outAddr())
		wantPassed(t, h.next(t), b)
	}
	if o.count() != 1 || h.c.UntrackedReset.Load() != 0 {
		t.Fatalf("table reads %d, resets %d", o.count(), h.c.UntrackedReset.Load())
	}
	h.c.HandleFlowEvent(divert.EventFlowDeleted, divert.SocketData{Protocol: 6,
		LocalAddr: netip.MustParseAddr("192.168.1.5"), LocalPort: 40000,
		RemoteAddr: netip.MustParseAddr("93.184.216.34"), RemotePort: 443})
	h.c.mu.Lock()
	_, remembered := h.c.untracked[flowKey(L, R)]
	h.c.mu.Unlock()
	if remembered {
		t.Fatal("FLOW_DELETED must forget the connection")
	}

	// The RST of an untracked Direct connection passes too.
	rst := segment(L, "93.184.216.34:80", packet.FlagRST|packet.FlagACK, 1, 1, "")
	h.c.HandlePacket(rst, outAddr())
	wantPassed(t, h.next(t), rst)

	// Port reuse: a SYN is a new connection with its own decision.
	h.c.HandlePacket(segment(L2, R, packet.FlagACK, 1, 1, ""), outAddr())
	h.next(t)
	h.own(6, L2, R, 100) // curl now
	h.seg(L2, R, packet.FlagSYN, 5, 0, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("SYN after an untracked connection must be decided again")
	}
}

// Mandatory exclusions pass whatever the rules say.
func TestUntrackedExclusionsPass(t *testing.T) {
	h := newHarness(t, rules.Config{DefaultAction: rules.Tunnel}, Options{})
	o := withTable(h)
	h.c.SelfPID = 999
	h.c.DnscachePID.Store(300)
	h.c.SystemDNS = func(a netip.Addr) bool { return a == netip.MustParseAddr("1.1.1.1") }
	const dot, other = "192.168.1.5:40001", "192.168.1.5:40002"
	o.conn(L, R, 999)
	o.conn(dot, "1.1.1.1:853", 300)
	o.conn(other, R, 300)
	for _, c := range [][2]string{{L, R}, {dot, "1.1.1.1:853"}} {
		b := segment(c[0], c[1], packet.FlagACK|packet.FlagPSH, 1, 1, "x")
		h.c.HandlePacket(b, outAddr())
		wantPassed(t, h.next(t), b)
	}
	// Dnscache elsewhere follows the rules.
	h.seg(other, R, packet.FlagACK, 1, 77, "")
	wantReset(t, h.next(t), R, other, 77)
}

// A local server's side of a connection from outside is not routed: its
// SYN-ACK, or its process listening on its local port, tells it apart.
func TestUntrackedLocalServerPasses(t *testing.T) {
	h := newHarness(t, rules.Config{DefaultAction: rules.Tunnel}, Options{})
	o := withTable(h)
	const srv, client = "192.168.1.5:3389", "203.0.113.7:51000"
	const eph = "192.168.1.5:50000"
	o.listen("0.0.0.0:8080", 100)
	o.conn("192.168.1.5:8080", client, 100) // curl: the default says Tunnel
	o.listen("127.0.0.1:40000", 200)
	o.conn(L, R, 100)
	o.listen("[::]:50000", 300)
	o.conn(eph, R, 100)

	synack := segment(srv, client, packet.FlagSYN|packet.FlagACK, 1, 2, "")
	h.c.HandlePacket(synack, outAddr())
	wantPassed(t, h.next(t), synack)
	data := segment(srv, client, packet.FlagACK|packet.FlagPSH, 2, 2, "hello")
	h.c.HandlePacket(data, outAddr())
	wantPassed(t, h.next(t), data)
	if o.count() != 0 {
		t.Fatalf("SYN-ACK: table read %d times", o.count())
	}

	// Accepted before start: the listening socket tells.
	b := segment("192.168.1.5:8080", client, packet.FlagACK, 1, 1, "")
	h.c.HandlePacket(b, outAddr())
	wantPassed(t, h.next(t), b)

	// A listener on another address does not make a client connection
	// from the same port one of a server.
	h.seg(L, R, packet.FlagACK, 1, 42, "")
	wantReset(t, h.next(t), R, L, 42)

	// Nor does another program's listener on the port: a [::] socket
	// leaves IPv4 free by default, where curl got it as an ephemeral one.
	h.seg(eph, R, packet.FlagACK, 1, 43, "")
	wantReset(t, h.next(t), R, eph, 43)
}

// The bind of the connection's port number is another socket's: a
// connection opened before start has no events of its own. Its owner comes
// from the OS tables, not from the program that took the port since.
func TestUntrackedIgnoresBindOfPort(t *testing.T) {
	h := newHarness(t, untrackedRules, Options{})
	o := withTable(h)
	o.conn(L, R, 100) // curl: through the tunnel
	// Since start chrome (Direct) listens on the port number where a [::]
	// socket leaves IPv4 free.
	h.c.Conns.Bind(6, netip.MustParseAddrPort(L).Port(), 200, 1, time.Now())
	o.listen("[::]:40000", 200)
	h.seg(L, R, packet.FlagACK|packet.FlagPSH, 1001, 5006, "GET /secret2")
	wantReset(t, h.next(t), R, L, 5006)
	h.none(t)
}

// The domain comes from the DNS cache only; with exact web domains a web
// connection is decided without it, as there is nothing to sniff.
func TestUntrackedDomainFromDNSCache(t *testing.T) {
	h := newHarness(t, untrackedRules, Options{})
	withTable(h).conn(L, R, 200)
	h.c.DNS.AddResponse(dnsResponse(t, "www.youtube.com.", "93.184.216.34"))
	h.seg(L, R, packet.FlagACK, 1, 11, "")
	wantReset(t, h.next(t), R, L, 11)

	set, err := rules.Compile(untrackedRules)
	if err != nil {
		t.Fatal(err)
	}
	set.ExactWeb = true
	h.c.Rules.Swap(set)
	const L2 = "192.168.1.5:40001"
	h.own(6, L2, R, 200)
	b := segment(L2, R, packet.FlagACK, 1, 1, "")
	h.c.HandlePacket(b, outAddr())
	wantPassed(t, h.next(t), b)
}

// Hundreds of connections opened before start cost one read of the OS
// table; it is read again only once the snapshot is old.
func TestUntrackedTableReadOnce(t *testing.T) {
	h := newHarness(t, untrackedRules, Options{})
	o := withTable(h)
	local := func(i int) string {
		return netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(20000+i)).String()
	}
	const n = 300
	for i := range n {
		pid := uint32(200)
		if i%2 == 0 {
			pid = 100
		}
		o.conn(local(i), R, pid)
	}
	resets := 0
	for i := range n {
		h.seg(local(i), R, packet.FlagACK, 1, 1, "")
		if i := h.next(t); !i.addr.Outbound() {
			resets++
		}
	}
	if o.count() != 1 || resets != n/2 {
		t.Fatalf("table read %d times, %d resets", o.count(), resets)
	}
	h.c.snapMu.Lock()
	h.c.snapAt = h.c.snapAt.Add(-snapshotAge)
	h.c.snapMu.Unlock()
	h.seg(local(n), R, packet.FlagACK, 1, 1, "")
	h.next(t)
	if o.count() != 2 {
		t.Fatalf("old snapshot: table read %d times", o.count())
	}
}

// The memory of decisions is bounded: a full set forgets an entry for the
// new one (Direct is decided again later), and a full c.gone still resets.
func TestUntrackedMemoryBounded(t *testing.T) {
	h := newHarness(t, untrackedRules, Options{})
	o := withTable(h)
	const L2 = "192.168.1.5:40001"
	o.conn(L, R, 200)
	o.conn(L2, R, 100)
	now := time.Now()
	h.c.mu.Lock()
	for i := range max(untrackedMax, goneMax) {
		k := flowKey(L, R)
		k.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 1)
		if i < untrackedMax {
			h.c.untracked[k] = now.Add(untrackedTTL)
		}
		if i < goneMax {
			h.c.gone[k] = now.Add(goneTTL)
		}
	}
	h.c.mu.Unlock()

	b := segment(L, R, packet.FlagACK, 1, 1, "")
	h.c.HandlePacket(b, outAddr())
	wantPassed(t, h.next(t), b)
	h.seg(L2, R, packet.FlagACK, 1, 5, "")
	wantReset(t, h.next(t), R, L2, 5)

	h.c.mu.Lock()
	_, direct := h.c.untracked[flowKey(L, R)]
	nu, ng := len(h.c.untracked), len(h.c.gone)
	h.c.mu.Unlock()
	if !direct || nu != untrackedMax || ng != goneMax {
		t.Fatalf("remembered %v, sizes %d/%d, want %d/%d", direct, nu, ng, untrackedMax, goneMax)
	}
	// Idle entries expire.
	h.c.Maintain(now.Add(untrackedTTL + time.Minute))
	h.c.mu.Lock()
	nu = len(h.c.untracked)
	h.c.mu.Unlock()
	if nu != 0 {
		t.Fatalf("%d untracked connections after expiry", nu)
	}
}

// Inbound packets of connections the engine does not know are not routed.
func TestUntrackedInboundUntouched(t *testing.T) {
	h := newHarness(t, untrackedRules, Options{})
	o := withTable(h)
	b := segment(R, L, packet.FlagACK|packet.FlagPSH, 1, 1, "reply")
	h.c.HandlePacket(b, &divert.Address{})
	if i := h.next(t); i.addr.Outbound() || string(i.pkt.Buf) != string(b) {
		t.Fatal("inbound must pass unchanged")
	}
	if o.count() != 0 {
		t.Fatal("inbound must not be decided")
	}
}

// A connection missing from the snapshot (it came up after the read) is
// looked up in a newer one before its owner counts as unknown.
func TestUntrackedOwnerAfterSnapshot(t *testing.T) {
	h := newHarness(t, untrackedRules, Options{})
	o := withTable(h)
	const L2 = "192.168.1.5:40001"
	o.conn(L, R, 200)
	b := segment(L, R, packet.FlagACK, 1, 1, "")
	h.c.HandlePacket(b, outAddr())
	wantPassed(t, h.next(t), b)
	o.conn(L2, R, 100) // curl, established after the read
	h.c.snapMu.Lock()
	h.c.snapAt = h.c.snapAt.Add(-snapshotFresh)
	h.c.snapMu.Unlock()
	h.seg(L2, R, packet.FlagACK, 1, 9, "")
	wantReset(t, h.next(t), R, L2, 9)
	if o.count() != 2 {
		t.Fatalf("table read %d times", o.count())
	}
}

// ResetUnknownDomain (after an engine failure, over a kill switch block):
// a connection whose route needs its domain is reset rather than sent on
// direct without it; one the rules decide without a domain is not.
func TestUntrackedResetUnknownDomain(t *testing.T) {
	cfg := untrackedRules
	cfg.Rules = append([]rules.Rule{{Name: "svchost", App: &rules.AppMatch{Pattern: "svchost.exe"}, Action: rules.Direct}}, cfg.Rules...)
	h := newHarness(t, cfg, Options{ResetUnknownDomain: true})
	o := withTable(h)
	const L2 = "192.168.1.5:40001"
	o.conn(L, R, 200)  // chrome: only the youtube rule could send it to the tunnel
	o.conn(L2, R, 300) // svchost: Direct whatever the domain
	h.seg(L, R, packet.FlagACK|packet.FlagPSH, 1, 21, "x")
	wantReset(t, h.next(t), R, L, 21)
	b := segment(L2, R, packet.FlagACK|packet.FlagPSH, 1, 1, "x")
	h.c.HandlePacket(b, outAddr())
	wantPassed(t, h.next(t), b)
	// Known from the DNS cache: decided as usual.
	h2 := newHarness(t, untrackedRules, Options{ResetUnknownDomain: true})
	withTable(h2).conn(L, R, 200)
	h2.c.DNS.AddResponse(dnsResponse(t, "example.com.", "93.184.216.34"))
	b = segment(L, R, packet.FlagACK, 1, 1, "")
	h2.c.HandlePacket(b, outAddr())
	wantPassed(t, h2.next(t), b)
}

// A Direct flow whose record expired (idle for hours, or a minute after
// its FIN) keeps its decision: the domain or owner it was decided by may
// be gone, and deciding it again would reset a connection the rules send
// direct.
func TestDirectFlowExpiryKeepsDecision(t *testing.T) {
	const ssh = "93.184.216.34:22"
	h := newHarness(t, rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "ru", Domain: &rules.DomainMatch{Pattern: ".example.ru"}, Action: rules.Direct},
	}}, Options{})
	h.c.DNS.AddResponse(dnsResponse(t, "ssh.example.ru.", "93.184.216.34"))
	h.own(6, L, ssh, 100)
	syn := segment(L, ssh, packet.FlagSYN, 1, 0, "")
	h.c.HandlePacket(syn, outAddr())
	wantPassed(t, h.next(t), syn)

	h.c.Maintain(time.Now().Add(2*time.Hour + time.Minute))
	h.c.DNS = dnscache.New() // the name expired meanwhile
	b := segment(L, ssh, packet.FlagACK|packet.FlagPSH, 2, 1, "ls")
	h.c.HandlePacket(b, outAddr())
	wantPassed(t, h.next(t), b)
	if n := h.c.UntrackedReset.Load(); n != 0 {
		t.Fatalf("%d untracked resets", n)
	}
	// A new connection on the 4-tuple is decided again.
	h.c.HandlePacket(syn, outAddr())
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("SYN after an expired Direct flow must be decided again")
	}
}
