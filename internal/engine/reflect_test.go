package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/relay"
)

// The relay's side of the reflected flow L -> R: L:relayPort -> R:lp.
const relaySide, relayPeer = "192.168.1.5:50123", "93.184.216.34:40000"

func (h *harness) seg(src, dst string, flags uint8, seq, ack uint32, payload string) {
	h.c.HandlePacket(packet.BuildTCP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), flags, seq, ack, []byte(payload)), outAddr())
}

func flowKey(src, dst string) nat.FlowKey {
	return nat.FlowKey{Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst)}
}

// reflected opens the curl flow L -> R through the relay: handshake, then
// "hello" from the relay that the application has not acknowledged yet.
func reflected(t *testing.T, h *harness) *nat.Entry {
	t.Helper()
	h.own(6, L, R, 100)
	h.seg(L, R, packet.FlagSYN, 1000, 0, "")
	h.seg(relaySide, relayPeer, packet.FlagSYN|packet.FlagACK, 5000, 1001, "")
	h.seg(L, R, packet.FlagACK, 1001, 5001, "")
	h.seg(relaySide, relayPeer, packet.FlagACK|packet.FlagPSH, 5001, 1001, "hello")
	for range 4 {
		h.next(t)
	}
	e := h.c.NAT.LookupFlow(flowKey(L, R))
	if e == nil {
		t.Fatal("flow not reflected")
	}
	return e
}

// A new connection on the 4-tuple of a reflected one that ended gets its
// own decision and NAT entry; the old entry's grace period must not cut it
// off later and send its data direct.
func TestSYNOnClosedEntryDecidedAgain(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	old := reflected(t, h)
	now := time.Now()
	h.c.RelayDone(relay.Result{Entry: old, Route: "tunnel", End: now})

	h.seg(L, R, packet.FlagSYN, 9000, 0, "")
	if i := h.next(t); i.addr.Outbound() || i.pkt.DstPort() != relayPort {
		t.Fatalf("new SYN: %v -> %v outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.addr.Outbound())
	}
	e := h.c.NAT.LookupFlow(flowKey(L, R))
	if e == nil || e == old {
		t.Fatal("the new connection must get its own NAT entry")
	}
	active := h.c.Flows.Active(time.Now())
	if len(active) != 1 || active[0].ID != e.Rec.ID || old.Rec.ID == e.Rec.ID {
		t.Fatalf("records: %d active, want the new one only", len(active))
	}
	// Past the old entry's grace period the connection still goes to the
	// relay.
	h.c.Maintain(now.Add(31 * time.Second))
	h.seg(L, R, packet.FlagACK|packet.FlagPSH, 9001, 7001, "GET / HTTP/1.1")
	if i := h.next(t); i.addr.Outbound() || i.pkt.DstPort() != relayPort {
		t.Fatalf("data after the old grace period: %v -> %v outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.addr.Outbound())
	}
}

// Before the filters go, every application connection that goes through
// the relay gets the RST its remote end would send: otherwise it stays
// open and a new engine (after a reconnect) passes its segments direct.
func TestResetReflectedAbortsApps(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	reflected(t, h)
	// A second reflected flow whose socket is already gone gets nothing.
	const L2 = "192.168.1.5:40001"
	h.own(6, L2, R, 100)
	h.seg(L2, R, packet.FlagSYN, 1, 0, "")
	h.next(t)
	h.c.HandleFlowEvent(divert.EventFlowDeleted, divert.SocketData{Protocol: 6,
		LocalAddr: netip.MustParseAddr("192.168.1.5"), LocalPort: 40001,
		RemoteAddr: netip.MustParseAddr("93.184.216.34"), RemotePort: 443})

	h.c.ResetReflected()
	seqs := map[uint32]bool{}
	for range 2 {
		i := h.next(t)
		if i.addr.Outbound() || i.pkt.Src() != netip.MustParseAddrPort(R) || i.pkt.Dst() != netip.MustParseAddrPort(L) ||
			i.pkt.TCPFlags() != packet.FlagRST|packet.FlagACK || i.pkt.Ack() != 1001 || !i.pkt.VerifyChecksums() {
			t.Fatalf("reset %v -> %v flags %x ack %d outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.pkt.TCPFlags(), i.pkt.Ack(), i.addr.Outbound())
		}
		seqs[i.pkt.Seq()] = true
	}
	// The relay's next sequence number, and the application's last
	// acknowledgment ("hello" is not acknowledged yet).
	if !seqs[5006] || !seqs[5001] {
		t.Fatalf("reset sequence numbers %v", seqs)
	}
	h.none(t)
}

// A reflected connection whose NAT entry expired while the application may
// still send on it is reset, never passed direct like a connection opened
// before start.
func TestExpiredReflectedFlowNeverLeaksDirect(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	e := reflected(t, h)
	now := time.Now()
	// The relay ended (tunnel error); the application did not see it.
	h.c.RelayDone(relay.Result{Entry: e, Route: "tunnel", End: now})
	h.c.Maintain(now.Add(31 * time.Second))
	if h.c.NAT.LookupFlow(flowKey(L, R)) != nil {
		t.Fatal("entry not swept")
	}
	h.seg(L, R, packet.FlagACK|packet.FlagPSH, 1001, 5006, "secret")
	i := h.next(t)
	if i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 || i.pkt.Src() != netip.MustParseAddrPort(R) || i.pkt.Seq() != 5006 {
		t.Fatalf("leaked or wrong reset: %v -> %v flags %x outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.pkt.TCPFlags(), i.addr.Outbound())
	}
	// The application's own RST is dropped, not answered.
	h.seg(L, R, packet.FlagRST, 1007, 0, "")
	h.none(t)
	// A new connection on the same 4-tuple is decided as usual.
	h.seg(L, R, packet.FlagSYN, 3000, 0, "")
	if i := h.next(t); i.addr.Outbound() || i.pkt.DstPort() != relayPort {
		t.Fatal("new connection not reflected")
	}

	// The application closed its side before the entry expired: nothing
	// is remembered (FIN_WAIT sends no data), and FLOW_DELETED clears a
	// remembered flow.
	const L2 = "192.168.1.5:40001"
	h.own(6, L2, R, 100)
	h.seg(L2, R, packet.FlagSYN, 1, 0, "")
	h.next(t)
	e2 := h.c.NAT.LookupFlow(flowKey(L2, R))
	h.seg(L2, R, packet.FlagFIN|packet.FlagACK, 2, 1, "")
	h.next(t)
	h.c.RelayDone(relay.Result{Entry: e2, Route: "tunnel", End: now})
	h.c.Maintain(now.Add(31 * time.Second))
	h.c.mu.Lock()
	_, remembered := h.c.gone[flowKey(L2, R)]
	_, first := h.c.gone[flowKey(L, R)]
	h.c.mu.Unlock()
	if remembered || first {
		t.Fatalf("remembered: closed by the app %v, reused by a SYN %v", remembered, first)
	}
}

// With the set of expired flows full, the next one is reset at once: the
// set is never cleared (that would let the remembered connections leak
// direct).
func TestExpiredReflectedFlowResetWhenGoneFull(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	e := reflected(t, h)
	now := time.Now()
	h.c.RelayDone(relay.Result{Entry: e, Route: "tunnel", End: now})
	h.c.mu.Lock()
	for i := range goneMax {
		k := flowKey(L, R)
		k.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 1)
		h.c.gone[k] = now.Add(goneTTL)
	}
	h.c.mu.Unlock()
	h.c.Maintain(now.Add(31 * time.Second))
	i := h.next(t)
	if i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 || i.pkt.Dst() != netip.MustParseAddrPort(L) {
		t.Fatalf("no reset: %v -> %v flags %x outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.pkt.TCPFlags(), i.addr.Outbound())
	}
	h.c.mu.Lock()
	n := len(h.c.gone)
	h.c.mu.Unlock()
	if n != goneMax {
		t.Fatalf("remembered flows: %d, want %d", n, goneMax)
	}
}
