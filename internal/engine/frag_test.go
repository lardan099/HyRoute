package engine

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
)

// fragments6 splits the part of an IPv6 packet after its fixed header
// (body, whose first header is next) into fragments.
func fragments6(src, dst string, next uint8, body []byte, id uint32) [][]byte {
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	var out [][]byte
	for off := 0; off < len(body); off += 1232 {
		end := min(off+1232, len(body))
		b := make([]byte, 48+end-off)
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:], uint16(8+end-off))
		b[6], b[7] = 44, 64
		copy(b[8:], s[:])
		copy(b[24:], d[:])
		b[40] = next
		fo := uint16(off/8) << 3
		if end < len(body) {
			fo |= 1
		}
		binary.BigEndian.PutUint16(b[42:], fo)
		binary.BigEndian.PutUint32(b[44:], id)
		copy(b[48:], body[off:end])
		out = append(out, b)
	}
	return out
}

// Fragments of protocols the engine does not route (a large ping, IPsec
// ESP, GRE) pass unchanged, like their whole packets; TCP/UDP fragments
// are still routed.
func TestNonTCPUDPFragmentsPass(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	h.c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))

	// ping -l 3000: ICMP echo in 3 IPv4 fragments.
	for _, f := range fragments4(L, R, 3000, 7) {
		f[9] = 1 // ICMP
		h.c.HandlePacket(f, outAddr())
	}
	if n := h.fragCount(); n != 3 {
		t.Fatalf("ICMP: %d of 3 fragments passed", n)
	}
	// ping -6 -l 3000, and ESP.
	for _, proto := range []uint8{58, 50} {
		for _, f := range fragments6("2a00::5", "2606:4700::1111", proto, make([]byte, 3000), 8) {
			h.c.HandlePacket(f, outAddr())
		}
		if n := h.fragCount(); n != 3 {
			t.Fatalf("IPv6 protocol %d: %d of 3 fragments passed", proto, n)
		}
	}
	if h.c.FragOrphan.Load() != 0 || h.c.FragDropped.Load() != 0 {
		t.Fatalf("orphans %d, dropped %d", h.c.FragOrphan.Load(), h.c.FragDropped.Load())
	}

	// IPv6 UDP of a Tunnel program: reassembled and tunneled whole (this
	// harness has no SOCKS5 server: nothing leaves).
	h.own(17, L6, R6, 400)
	full := packet.BuildUDP(netip.MustParseAddrPort(L6), netip.MustParseAddrPort(R6), make([]byte, 3000))
	for _, f := range fragments6("2a00::5", "2606:4700::1111", 17, full[40:], 9) {
		h.c.HandlePacket(f, outAddr())
	}
	if n := h.c.FragReassembled.Load(); n != 1 {
		t.Fatalf("IPv6 UDP: reassembled %d", n)
	}
	// An extension header after the fragment header may hide TCP/UDP: not
	// passed either.
	for _, f := range fragments6("2a00::5", "2606:4700::1111", 60, make([]byte, 3000), 10) {
		h.c.HandlePacket(f, outAddr())
	}
	if n := h.fragCount(); n != 0 {
		t.Fatalf("%d TCP/UDP fragments left directly", n)
	}

	// With «Не пускать IPv6 в VPN» the whole datagram is decided Block.
	h = newHarness(t, appRules, Options{BlockIPv6Tunnel: true})
	h.c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	h.own(17, L6, R6, 400)
	for _, f := range fragments6("2a00::5", "2606:4700::1111", 17, full[40:], 11) {
		h.c.HandlePacket(f, outAddr())
	}
	if n := h.fragCount(); n != 0 {
		t.Fatalf("IPv6 blocked for tunnel: %d fragments left", n)
	}
	if v := lastRecord(t, h.c); v.Outcome != "dropped: IPv6 blocked for tunnel" {
		t.Fatalf("%+v", v)
	}
}

// The first fragment of a new flow whose SOCKET event is late takes the
// owner from the OS tables: a program's Tunnel rule must not miss it.
func TestFragmentOwnerFromOSTables(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	h.c.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	h.c.OwnerFallback = func(proto uint8, l, r netip.AddrPort) (uint32, bool) { return 400, true } // game.exe
	for _, f := range fragments4(L, R, 3000, 11) {
		h.c.HandlePacket(f, outAddr())
	}
	if n := h.fragCount(); n != 0 {
		t.Fatalf("%d fragments of a Tunnel datagram left directly", n)
	}
}

// IPv6 TCP under IPsec AH (captured: WinDivert looks through AH) cannot be
// rewritten; it goes on unchanged instead of being dropped as malformed.
func TestIPv6AHPassesUnchanged(t *testing.T) {
	var got [][]byte
	c := NewCore(Options{RelayPort: relayPort}, nil, procinfo.NewCacheWith(procinfo.System{
		Query: func(uint32) (string, int64, bool) { return "", 0, false },
	}), func(b []byte, a *divert.Address) {
		if a.Outbound() {
			got = append(got, append([]byte(nil), b...))
		}
	})
	defer c.Close()
	tcp := packet.BuildTCP(netip.MustParseAddrPort(L6), netip.MustParseAddrPort(R6), packet.FlagSYN, 1, 0, nil)[40:]
	ah := make([]byte, 24) // 12-byte ICV
	ah[0], ah[1] = packet.ProtoTCP, 24/4-2
	b := append(append(append([]byte(nil), packet.BuildTCP(netip.MustParseAddrPort(L6), netip.MustParseAddrPort(R6), 0, 0, 0, nil)[:40]...), ah...), tcp...)
	b[6] = 51
	binary.BigEndian.PutUint16(b[4:], uint16(len(ah)+len(tcp)))
	c.HandlePacket(b, outAddr())
	if len(got) != 1 || string(got[0]) != string(b) || c.Malformed.Load() != 0 {
		t.Fatalf("injected %d, malformed %d", len(got), c.Malformed.Load())
	}
}
