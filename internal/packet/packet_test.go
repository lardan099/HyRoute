package packet

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
)

// tcpSYN builds a raw TCP SYN with an options block and correct checksums.
func tcpSYN(t *testing.T, src, dst netip.AddrPort) []byte {
	t.Helper()
	v6 := src.Addr().Is6() && !src.Addr().Is4In6()
	hl := 20
	if v6 {
		hl = 40
	}
	b := make([]byte, hl+24)
	writeIPHeader(b, v6, ProtoTCP, len(b))
	p := Packet{Buf: b, IPv6: v6, Proto: ProtoTCP, L4: hl}
	p.SetSrcIP(src.Addr())
	p.SetDstIP(dst.Addr())
	p.SetSrcPort(src.Port())
	p.SetDstPort(dst.Port())
	binary.BigEndian.PutUint32(b[hl+4:], 1000)
	b[hl+12] = 6 << 4
	b[hl+13] = FlagSYN
	binary.BigEndian.PutUint16(b[hl+14:], 64240)
	copy(b[hl+20:], []byte{2, 4, 0x05, 0xb4}) // MSS 1460
	p.FixChecksums()
	return b
}

func TestIPv4HeaderChecksumKnownVector(t *testing.T) {
	// Classic example: 4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8 00c7
	h, _ := hex.DecodeString("450000730000400040110000c0a80001c0a800c7")
	if got := ^fold(sum(h, 0)); got != 0xb861 {
		t.Fatalf("checksum = %04x, want b861", got)
	}
}

// naive reference implementation of the Internet checksum over pseudo header + L4.
func refL4Checksum(p *Packet) uint16 {
	var buf []byte
	buf = append(buf, p.SrcIP().AsSlice()...)
	buf = append(buf, p.DstIP().AsSlice()...)
	l := len(p.Buf) - p.L4
	if p.IPv6 {
		buf = binary.BigEndian.AppendUint32(buf, uint32(l))
		buf = append(buf, 0, 0, 0, p.Proto)
	} else {
		buf = append(buf, 0, p.Proto)
		buf = binary.BigEndian.AppendUint16(buf, uint16(l))
	}
	seg := append([]byte(nil), p.Buf[p.L4:]...)
	ck := 16
	if p.Proto == ProtoUDP {
		ck = 6
	}
	seg[ck], seg[ck+1] = 0, 0
	buf = append(buf, seg...)
	if len(buf)%2 == 1 {
		buf = append(buf, 0)
	}
	var s uint64
	for i := 0; i < len(buf); i += 2 {
		s += uint64(binary.BigEndian.Uint16(buf[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func TestParseAndChecksumV4V6(t *testing.T) {
	cases := []struct{ src, dst string }{
		{"192.168.1.10:51000", "93.184.216.34:443"},
		{"[2001:db8::10]:51000", "[2606:4700::1111]:443"},
	}
	for _, c := range cases {
		src, dst := netip.MustParseAddrPort(c.src), netip.MustParseAddrPort(c.dst)
		b := tcpSYN(t, src, dst)
		p, err := Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if p.Src() != src || p.Dst() != dst {
			t.Fatalf("parsed %v -> %v", p.Src(), p.Dst())
		}
		if !p.IsSYN() || p.Seq() != 1000 {
			t.Fatalf("flags/seq wrong")
		}
		if !p.VerifyChecksums() {
			t.Fatalf("checksum invalid")
		}
		ck := binary.BigEndian.Uint16(p.Buf[p.L4+16:])
		if ref := refL4Checksum(&p); ck != ref {
			t.Fatalf("tcp checksum %04x, ref %04x", ck, ref)
		}
		// Rewrite and re-verify.
		p.SwapIPs()
		p.SetDstPort(40000)
		if p.VerifyChecksums() {
			t.Fatalf("checksum should be stale after rewrite")
		}
		p.FixChecksums()
		if !p.VerifyChecksums() {
			t.Fatalf("checksum invalid after fix")
		}
		if p.SrcIP() != dst.Addr() || p.DstIP() != src.Addr() || p.DstPort() != 40000 {
			t.Fatalf("rewrite wrong: %v -> %v", p.Src(), p.Dst())
		}
	}
}

func TestParseRejects(t *testing.T) {
	b := tcpSYN(t, netip.MustParseAddrPort("10.0.0.1:1"), netip.MustParseAddrPort("10.0.0.2:2"))
	if _, err := Parse(b[:30]); err != ErrShort {
		t.Fatalf("truncated: %v", err)
	}
	f := append([]byte(nil), b...)
	binary.BigEndian.PutUint16(f[6:], 0x2000) // MF
	if _, err := Parse(f); err != ErrFragment {
		t.Fatalf("fragment: %v", err)
	}
	f = append([]byte(nil), b...)
	f[9] = 1 // ICMP
	if _, err := Parse(f); err != ErrUnsupported {
		t.Fatalf("icmp: %v", err)
	}
	if _, err := Parse([]byte{0x50}); err != ErrVersion {
		t.Fatalf("version: %v", err)
	}
	// Trailing padding beyond IP total length is ignored.
	padded := append(append([]byte(nil), b...), 0, 0, 0, 0)
	p, err := Parse(padded)
	if err != nil || len(p.Buf) != len(b) {
		t.Fatalf("padding: %v len=%d", err, len(p.Buf))
	}
}

func TestIPv6ExtensionHeader(t *testing.T) {
	src, dst := netip.MustParseAddrPort("[2001:db8::1]:5000"), netip.MustParseAddrPort("[2001:db8::2]:53")
	u := BuildUDP(src, dst, []byte("hello"))
	// Insert an 8-byte hop-by-hop header.
	b := make([]byte, 0, len(u)+8)
	b = append(b, u[:40]...)
	b[6] = 0 // next header: hop-by-hop
	b = append(b, ProtoUDP, 0, 1, 4, 0, 0, 0, 0)
	b = append(b, u[40:]...)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)-40))
	p, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.Proto != ProtoUDP || p.L4 != 48 || string(p.Payload()) != "hello" || p.Dst() != dst {
		t.Fatalf("ext header parse: proto=%d l4=%d", p.Proto, p.L4)
	}
}

func TestBuildUDP(t *testing.T) {
	for _, c := range [][2]string{{"8.8.8.8:53", "192.168.1.5:61000"}, {"[2001:4860:4860::8888]:53", "[2001:db8::5]:61000"}} {
		src, dst := netip.MustParseAddrPort(c[0]), netip.MustParseAddrPort(c[1])
		b := BuildUDP(src, dst, []byte{1, 2, 3})
		p, err := Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if p.Src() != src || p.Dst() != dst || string(p.Payload()) != "\x01\x02\x03" {
			t.Fatalf("udp build mismatch %v %v", p.Src(), p.Dst())
		}
		if !p.VerifyChecksums() {
			t.Fatal("udp checksum")
		}
		if ck := binary.BigEndian.Uint16(p.Buf[p.L4+6:]); ck != refL4Checksum(&p) && !(ck == 0xffff && refL4Checksum(&p) == 0) {
			t.Fatalf("udp checksum %04x ref %04x", ck, refL4Checksum(&p))
		}
	}
	// IPv4-mapped input produces an IPv4 packet.
	b := BuildUDP(netip.MustParseAddrPort("[::ffff:1.2.3.4]:1"), netip.MustParseAddrPort("[::ffff:5.6.7.8]:2"), nil)
	if b[0]>>4 != 4 {
		t.Fatal("mapped address should produce IPv4")
	}
}

func TestBuildRSTForSYN(t *testing.T) {
	src, dst := netip.MustParseAddrPort("192.168.1.10:51000"), netip.MustParseAddrPort("1.1.1.1:443")
	syn, _ := Parse(tcpSYN(t, src, dst))
	r, err := Parse(BuildRSTFor(&syn))
	if err != nil {
		t.Fatal(err)
	}
	if r.Src() != dst || r.Dst() != src {
		t.Fatalf("rst addrs %v -> %v", r.Src(), r.Dst())
	}
	if r.TCPFlags() != FlagRST|FlagACK || r.Ack() != 1001 || !r.VerifyChecksums() {
		t.Fatalf("rst flags=%x ack=%d", r.TCPFlags(), r.Ack())
	}
}

// WinDivert looks through AH and the mobility header as it does through
// the other IPv6 extension headers. A packet under AH cannot be rewritten
// (its ICV covers it): Parse says so instead of "unsupported".
func TestIPv6AHAndMobilityHeader(t *testing.T) {
	src, dst := netip.MustParseAddrPort("[2001:db8::1]:5000"), netip.MustParseAddrPort("[2001:db8::2]:443")
	tcp := BuildTCP(src, dst, FlagSYN, 1, 0, nil)
	with := func(next uint8, hdr []byte) []byte {
		b := append(append(append([]byte(nil), tcp[:40]...), hdr...), tcp[40:]...)
		b[6] = next
		binary.BigEndian.PutUint16(b[4:], uint16(len(b)-40))
		return b
	}
	ah := make([]byte, 24)
	ah[0], ah[1] = ProtoTCP, 24/4-2
	if _, err := Parse(with(51, ah)); err != ErrIPsec {
		t.Fatalf("AH: %v", err)
	}
	mh := []byte{ProtoTCP, 0, 0, 0, 0, 0, 0, 0}
	p, err := Parse(with(135, mh))
	if err != nil || p.Proto != ProtoTCP || p.L4 != 48 || p.Dst() != dst {
		t.Fatalf("mobility header: %v proto=%d l4=%d", err, p.Proto, p.L4)
	}
}
