package nat

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/packet"
)

func udpLike(t *testing.T, src, dst string) packet.Packet {
	t.Helper()
	// The rewrite helpers only touch IPs and ports, so a UDP packet will do.
	b := packet.BuildUDP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), []byte("x"))
	p, err := packet.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReflectRoundTripV4V6(t *testing.T) {
	const relay = 50123
	for _, c := range [][2]string{
		{"192.168.1.10:51000", "93.184.216.34:443"},
		{"[2001:db8::10]:51000", "[2606:4700::1111]:8443"},
	} {
		L, R := netip.MustParseAddrPort(c[0]), netip.MustParseAddrPort(c[1])
		tbl := NewTable()
		now := time.Now()
		e, err := tbl.Insert(&Entry{Flow: FlowKey{Src: L, Dst: R}}, now)
		if err != nil {
			t.Fatal(err)
		}

		// App -> relay.
		p := udpLike(t, c[0], c[1])
		ReflectToRelay(&p, relay)
		p.FixChecksums()
		if p.Src() != netip.AddrPortFrom(R.Addr(), L.Port()) || p.Dst() != netip.AddrPortFrom(L.Addr(), relay) {
			t.Fatalf("to relay: %v -> %v", p.Src(), p.Dst())
		}
		if !p.VerifyChecksums() {
			t.Fatal("checksum")
		}
		// Relay accept sees peer = p.Src().
		if got := tbl.LookupReflect(p.Src().Addr(), p.Src().Port()); got != e {
			t.Fatal("reflect lookup failed")
		}

		// Relay -> app: L:relay -> R:lp.
		q := udpLike(t, netip.AddrPortFrom(L.Addr(), relay).String(), netip.AddrPortFrom(R.Addr(), L.Port()).String())
		re := tbl.LookupReflect(q.DstIP(), q.DstPort())
		if re != e {
			t.Fatal("reverse lookup failed")
		}
		ReflectFromRelay(&q, re)
		if q.Src() != R || q.Dst() != L {
			t.Fatalf("to app: %v -> %v", q.Src(), q.Dst())
		}
	}
}

func TestInsertDuplicateAndCollision(t *testing.T) {
	tbl := NewTable()
	now := time.Now()
	L := netip.MustParseAddrPort("192.168.1.10:51000")
	R1 := netip.MustParseAddrPort("1.2.3.4:443")
	R2 := netip.MustParseAddrPort("1.2.3.4:8443") // same R, same lp, other rp
	e1, err := tbl.Insert(&Entry{Flow: FlowKey{L, R1}}, now)
	if err != nil {
		t.Fatal(err)
	}
	// SYN retransmit returns the existing entry.
	if e, _ := tbl.Insert(&Entry{Flow: FlowKey{L, R1}}, now); e != e1 {
		t.Fatal("retransmit should return existing entry")
	}
	if _, err := tbl.Insert(&Entry{Flow: FlowKey{L, R2}}, now); err != ErrCollision {
		t.Fatalf("want collision, got %v", err)
	}
	// IPv4-mapped keys are normalized.
	mapped := FlowKey{
		Src: netip.MustParseAddrPort("[::ffff:192.168.1.10]:51000"),
		Dst: netip.MustParseAddrPort("[::ffff:1.2.3.4]:443"),
	}
	if tbl.LookupFlow(mapped) != e1 {
		t.Fatal("mapped lookup")
	}
	// After close + grace the key becomes free.
	tbl.RelayClosed(e1, now)
	if got := tbl.Sweep(now.Add(tbl.Grace)); len(got) != 1 || tbl.Len() != 0 {
		t.Fatalf("sweep removed %d, len %d", len(got), tbl.Len())
	}
	if _, err := tbl.Insert(&Entry{Flow: FlowKey{L, R2}}, now); err != nil {
		t.Fatal(err)
	}
}

func TestClosedEntryReplacedOnPortReuse(t *testing.T) {
	tbl := NewTable()
	now := time.Now()
	k := FlowKey{netip.MustParseAddrPort("10.0.0.2:40000"), netip.MustParseAddrPort("8.8.8.8:443")}
	e1, _ := tbl.Insert(&Entry{Flow: k}, now)
	tbl.Touch(e1, false, packet.FlagRST, now)
	e2, err := tbl.Insert(&Entry{Flow: k}, now.Add(time.Second))
	if err != nil || e2 == e1 {
		t.Fatalf("closed entry must be replaced: %v", err)
	}
	if tbl.LookupReflect(k.Dst.Addr(), k.Src.Port()) != e2 {
		t.Fatal("reflect index must point at new entry")
	}
}

func TestFinBothSidesAndSweep(t *testing.T) {
	tbl := NewTable()
	now := time.Now()
	k := FlowKey{netip.MustParseAddrPort("10.0.0.2:40001"), netip.MustParseAddrPort("8.8.4.4:80")}
	e, _ := tbl.Insert(&Entry{Flow: k}, now)
	tbl.Touch(e, true, packet.FlagFIN|packet.FlagACK, now)
	if len(tbl.Sweep(now.Add(time.Hour))) != 0 {
		t.Fatal("half-closed flow must stay (idle timeout is longer)")
	}
	tbl.Touch(e, false, packet.FlagFIN|packet.FlagACK, now.Add(time.Hour))
	if len(tbl.Sweep(now.Add(time.Hour+tbl.Grace-time.Second))) != 0 {
		t.Fatal("grace not respected")
	}
	if len(tbl.Sweep(now.Add(time.Hour+tbl.Grace))) != 1 {
		t.Fatal("closed flow must be swept after grace")
	}
	// Idle removal.
	tbl.Insert(&Entry{Flow: k}, now)
	if len(tbl.Sweep(now.Add(tbl.Idle))) != 1 {
		t.Fatal("idle flow must be swept")
	}
	// FLOW_DELETED closes.
	tbl.Insert(&Entry{Flow: k}, now)
	tbl.FlowDeleted(k, now)
	if len(tbl.Sweep(now.Add(tbl.Grace))) != 1 {
		t.Fatal("flow deleted must close")
	}
}

// seg is a TCP segment of k: from the application, or from the relay (its
// side of the reflection, as the engine sees it before rewriting).
func seg(t *testing.T, k FlowKey, fromApp bool, flags uint8, seq, ack uint32, payload string) *packet.Packet {
	t.Helper()
	src, dst := k.Src, k.Dst
	if !fromApp {
		src, dst = netip.AddrPortFrom(k.Src.Addr(), 50123), netip.AddrPortFrom(k.Dst.Addr(), k.Src.Port())
	}
	p, err := packet.Parse(packet.BuildTCP(src, dst, flags, seq, ack, []byte(payload)))
	if err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestResetAppsSequenceNumbers(t *testing.T) {
	tbl := NewTable()
	now := time.Now()
	k := FlowKey{netip.MustParseAddrPort("10.0.0.2:40000"), netip.MustParseAddrPort("8.8.8.8:443")}
	var addr divert.Address
	addr.SetOutbound(true)
	e, _ := tbl.Insert(&Entry{Flow: k}, now)
	tbl.TouchPacket(e, seg(t, k, true, packet.FlagSYN, 100, 0, ""), true, &addr, now)
	// SYN_SENT: the reset acknowledges the SYN.
	if r := tbl.ResetApps(); len(r) != 1 || r[0].Addr != addr {
		t.Fatalf("SYN_SENT: %d resets", len(r))
	} else if p, _ := packet.Parse(r[0].Pkt); p.Ack() != 101 || p.Src() != k.Dst || p.Dst() != k.Src || p.TCPFlags() != packet.FlagRST|packet.FlagACK {
		t.Fatalf("SYN_SENT reset %v -> %v ack %d", p.Src(), p.Dst(), p.Ack())
	}
	tbl.TouchPacket(e, seg(t, k, false, packet.FlagSYN|packet.FlagACK, 700, 101, ""), false, nil, now)
	tbl.TouchPacket(e, seg(t, k, true, packet.FlagACK, 101, 701, "abc"), true, &addr, now)
	tbl.TouchPacket(e, seg(t, k, false, packet.FlagACK, 701, 104, "hello"), false, nil, now)
	// A retransmission with an older acknowledgment changes nothing.
	tbl.TouchPacket(e, seg(t, k, true, packet.FlagACK, 101, 700, "abc"), true, &addr, now)
	seqs := map[uint32]bool{}
	for _, r := range tbl.ResetApps() {
		p, _ := packet.Parse(r.Pkt)
		if p.Ack() != 104 || !p.VerifyChecksums() {
			t.Fatalf("ack %d", p.Ack())
		}
		seqs[p.Seq()] = true
	}
	if len(seqs) != 2 || !seqs[706] || !seqs[701] {
		t.Fatalf("reset sequence numbers %v, want the relay's next and the app's acknowledgment", seqs)
	}
	tbl.FlowDeleted(k, now)
	if r := tbl.ResetApps(); len(r) != 0 {
		t.Fatalf("socket gone, still %d resets", len(r))
	}
}

func TestAppMaySendAndRemoveClosed(t *testing.T) {
	tbl := NewTable()
	now := time.Now()
	k := FlowKey{netip.MustParseAddrPort("10.0.0.2:40002"), netip.MustParseAddrPort("8.8.8.8:443")}
	for _, c := range []struct {
		name    string
		touch   func(e *Entry)
		closed  bool
		maySend bool
	}{
		{"open", func(*Entry) {}, false, true},
		{"relay FIN", func(e *Entry) { tbl.Touch(e, false, packet.FlagFIN, now) }, false, true},
		{"relay RST", func(e *Entry) { tbl.Touch(e, false, packet.FlagRST, now) }, true, true},
		{"relay done", func(e *Entry) { tbl.RelayClosed(e, now) }, true, true},
		{"app FIN", func(e *Entry) { tbl.Touch(e, true, packet.FlagFIN, now) }, false, false},
		{"app RST", func(e *Entry) { tbl.Touch(e, true, packet.FlagRST, now) }, true, false},
		{"socket gone", func(*Entry) { tbl.FlowDeleted(k, now) }, true, false},
	} {
		e, err := tbl.Insert(&Entry{Flow: k}, now)
		if err != nil {
			t.Fatal(err)
		}
		c.touch(e)
		if got := tbl.AppMaySend(e); got != c.maySend {
			t.Errorf("%s: may send %v", c.name, got)
		}
		if got := tbl.RemoveClosed(e); got != c.closed {
			t.Errorf("%s: removed %v", c.name, got)
		}
		if got := tbl.LookupFlow(k) == nil && tbl.LookupReflect(k.Dst.Addr(), k.Src.Port()) == nil; got != c.closed {
			t.Errorf("%s: gone from the table %v", c.name, got)
		}
		tbl.RelayClosed(e, now)
		tbl.RemoveClosed(e)
	}
}
