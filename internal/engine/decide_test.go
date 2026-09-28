package engine

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/relay"
	"github.com/lardan099/hyroute/internal/rules"
)

// With encrypted DNS, Dnscache resolves over DoH (TCP 443) or DoT (TCP
// 853) to the system's DNS servers: that is system DNS too, and must not
// depend on the tunnel it is needed to start.
func TestSystemDNSEncryptedExcluded(t *testing.T) {
	h := newHarness(t, rules.Config{DefaultAction: rules.Tunnel}, Options{})
	h.c.DnscachePID.Store(300)
	h.c.SystemDNS = func(a netip.Addr) bool { return a == netip.MustParseAddr("1.1.1.1") }
	for n, dst := range []string{"1.1.1.1:443", "1.1.1.1:853"} {
		src := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(41000+n)).String()
		h.own(6, src, dst, 300)
		h.sendTCP(src, dst, packet.FlagSYN, "")
		if i := h.next(t); !i.addr.Outbound() {
			t.Fatalf("Dnscache to %s must be direct", dst)
		}
		if v := lastRecord(t, h.c); v.Rule != "exclusion: system DNS" || v.Excluded != "system-dns" || v.Route != "direct" {
			t.Fatalf("%s: %+v", dst, v)
		}
	}
	// Other ports of the same process follow the rules.
	h.own(6, "192.168.1.5:41010", "1.1.1.1:8443", 300)
	h.sendTCP("192.168.1.5:41010", "1.1.1.1:8443", packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("Dnscache on another port must follow the rules")
	}
	// So does HTTPS to other addresses: Dnscache may share its svchost
	// with other services.
	h.own(6, "192.168.1.5:41011", "93.184.216.34:443", 300)
	h.sendTCP("192.168.1.5:41011", "93.184.216.34:443", packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("Dnscache's svchost to a non-DNS address must follow the rules")
	}
}

// Packets of a parked flow wait for its first packet's decision even when
// the owner is known by then: deciding them again would open a second,
// never-closed record.
func TestPendingFlowDecidedOnce(t *testing.T) {
	h := newHarness(t, rules.Config{DefaultAction: rules.Direct}, Options{})
	h.c.Procs = procinfo.NewCacheWith(procinfo.System{Query: func(pid uint32) (string, int64, bool) {
		time.Sleep(50 * time.Millisecond) // OpenProcess + snapshot of a new process
		p, ok := procs[pid]
		return p, 1, ok
	}})
	const dst = "93.184.216.34:3478"
	h.sendUDP(L, dst, []byte("1")) // no owner yet: parked
	h.own(17, L, dst, 200)
	time.Sleep(10 * time.Millisecond) // the parked flow is being decided
	h.sendUDP(L, dst, []byte("2"))
	got := ""
	for range 2 {
		i := h.next(t)
		got += string(i.pkt.Payload())
	}
	if got != "12" {
		t.Fatalf("datagrams %q, want in order", got)
	}
	if n := len(h.c.Flows.Active(time.Now())); n != 1 {
		t.Fatalf("%d records for one flow", n)
	}
	h.c.Maintain(time.Now().Add(time.Hour))
	if n := len(h.c.Flows.Active(time.Now())); n != 0 {
		t.Fatalf("%d records left after the flow expired", n)
	}
}

// With the pending queue full, a flow is not decided as unknown while the
// OS tables already name its owner: HyRoute's own dials must stay
// excluded.
func TestPendingFullAsksOwnerTables(t *testing.T) {
	h := newHarness(t, rules.Config{DefaultAction: rules.Block}, Options{})
	h.c.SelfPID = 999
	for range cap(h.c.sem) {
		h.c.sem <- struct{}{}
	}
	h.c.OwnerFallback = func(proto uint8, l, r netip.AddrPort) (uint32, bool) {
		if l.Port() == 40000 {
			return 999, true
		}
		return 0, false
	}
	h.sendTCP(L, R, packet.FlagSYN, "")
	if i := h.next(t); !i.addr.Outbound() || i.pkt.TCPFlags() != packet.FlagSYN {
		t.Fatal("HyRoute's own dial must pass")
	}
	if n := len(h.c.Flows.Active(time.Now())) + len(h.c.Flows.Closed()); n != 0 || h.c.PendingFull.Load() != 1 {
		t.Fatalf("records %d, pending-full %d", n, h.c.PendingFull.Load())
	}
	// Nobody knows the owner: unknown, as before.
	h.sendTCP("192.168.1.5:40001", R, packet.FlagSYN, "")
	if i := h.next(t); i.pkt.TCPFlags()&packet.FlagRST == 0 {
		t.Fatal("unknown owner must follow the rules (block)")
	}
	if v := lastRecord(t, h.c); v.Attrib != "pending-full" || h.c.Unknown.Load() != 1 {
		t.Fatalf("%+v", v)
	}
}

// A panic while deciding a parked flow costs its packets, not the process,
// and leaves no parked state behind.
func TestPendingPanicRecovered(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	h.c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	h.c.Tunnels = func(string) Tunnel { panic("boom") }
	h.sendTCP(L, R, packet.FlagSYN, "") // parked
	h.own(6, L, R, 100)                 // curl: Tunnel, the tunnel lookup panics
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.c.mu.Lock()
		parked := len(h.c.pending)
		h.c.mu.Unlock()
		if h.c.Panics.Load() == 1 && parked == 0 && len(h.c.sem) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("panics %d, parked %d, sem %d", h.c.Panics.Load(), parked, len(h.c.sem))
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.none(t)
}

// Hysteria processes started by HyRoute are excluded like HyRoute itself:
// their traffic never loops into a tunnel. Another hysteria.exe is not.
func TestHysteriaChildExcluded(t *testing.T) {
	h := newHarness(t, rules.Config{DefaultAction: rules.Tunnel}, Options{})
	paths := map[uint32]string{
		1:   `C:\Windows\explorer.exe`,
		999: `C:\HyRoute\HyRoute.exe`,
		500: `C:\HyRoute\core\hysteria.exe`,
		501: `C:\Other\hysteria.exe`,
	}
	h.c.Procs = procinfo.NewCacheWith(procinfo.System{
		Query: func(pid uint32) (string, int64, bool) {
			p, ok := paths[pid]
			return p, 1, ok
		},
		Snapshot: func() []procinfo.ProcEntry {
			return []procinfo.ProcEntry{{PID: 1}, {PID: 999, PPID: 1}, {PID: 500, PPID: 999}, {PID: 501, PPID: 1}}
		},
	})
	h.c.SelfPID = 999
	h.own(6, L, "203.0.113.7:443", 500)
	h.sendTCP(L, "203.0.113.7:443", packet.FlagSYN, "")
	if i := h.next(t); !i.addr.Outbound() {
		t.Fatal("our Hysteria must go direct")
	}
	if v := lastRecord(t, h.c); v.Rule != "exclusion: hysteria" || v.Excluded != "hysteria" {
		t.Fatalf("%+v", v)
	}
	h.own(6, "192.168.1.5:40001", "203.0.113.7:443", 501)
	h.sendTCP("192.168.1.5:40001", "203.0.113.7:443", packet.FlagSYN, "")
	if i := h.next(t); i.pkt.DstPort() != relayPort {
		t.Fatal("another hysteria.exe must follow the rules")
	}
}

// A connection the relay rejected is counted once: by the relay
// (Session.Stats adds the relay's counter to the engine's).
func TestRelayRejectCountedOnce(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	e := reflected(t, h)
	h.c.RelayDone(relay.Result{Entry: e, Route: "rejected", End: time.Now()})
	if n := h.c.Rejected.Load(); n != 0 {
		t.Fatalf("engine counted %d relay rejections", n)
	}
}

// TestExclusionKinds: exclusion reports its kind, decide records it on the
// flow, and nothing keys on the rule text: a user rule named like an
// exclusion is an ordinary rule.
func TestExclusionKinds(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "exclusion: self", App: &rules.AppMatch{Pattern: "curl.exe"}, Action: rules.Direct},
	}}
	h := newHarness(t, cfg, Options{})
	h.c.SelfPID = 999
	h.c.DnscachePID.Store(300)
	dns := netip.MustParseAddrPort("8.8.8.8:53")
	for _, c := range []struct {
		pid   uint32
		known bool
		proc  *procinfo.Info
		want  string
	}{
		{999, true, nil, "self"},
		{999, false, nil, ""},
		{500, true, &procinfo.Info{Name: "hysteria.exe", Parent: &procinfo.Info{PID: 999}}, "hysteria"},
		{501, true, &procinfo.Info{Name: "hysteria.exe", Parent: &procinfo.Info{PID: 1}}, ""},
		{300, true, nil, "system-dns"},
		{100, true, nil, ""},
	} {
		res, kind := h.c.exclusion(c.pid, c.known, c.proc, packet.ProtoUDP, dns)
		if kind != c.want || (kind != "") != (res.Action == rules.Direct && res.Rule != "") {
			t.Errorf("pid %d: %q %+v, want %q", c.pid, kind, res, c.want)
		}
	}

	// The user's rule named "exclusion: self" decides curl's flow.
	h.own(6, L, R, 100)
	h.sendTCP(L, R, packet.FlagSYN, "")
	if i := h.next(t); !i.addr.Outbound() {
		t.Fatal("curl must go direct by its rule")
	}
	if v := lastRecord(t, h.c); v.Rule != "exclusion: self" || v.Excluded != "" {
		t.Fatalf("%+v", v)
	}
	// A normal flow is not excluded.
	h.own(6, "192.168.1.5:40100", R, 200)
	h.sendTCP("192.168.1.5:40100", R, packet.FlagSYN, "")
	h.next(t)
	if v := lastRecord(t, h.c); v.Excluded != "" || v.Process != "chrome.exe" {
		t.Fatalf("%+v", v)
	}
}
