package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// BuildFragments4 splits an IPv4 UDP datagram into fragments of at most
// mtu bytes (tests).
func v4frags(t *testing.T, src, dst netip.AddrPort, payload []byte, id uint16) [][]byte {
	t.Helper()
	full := BuildUDP(src, dst, payload)
	ihl := int(full[0]&0x0f) * 4
	body := full[ihl:]
	var out [][]byte
	for off := 0; off < len(body); off += 1480 {
		end := min(off+1480, len(body))
		h := append([]byte(nil), full[:ihl]...)
		binary.BigEndian.PutUint16(h[2:], uint16(ihl+end-off))
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

func TestParseFragment4(t *testing.T) {
	src, dst := netip.MustParseAddrPort("192.168.1.5:40000"), netip.MustParseAddrPort("93.184.216.34:443")
	fr := v4frags(t, src, dst, make([]byte, 3000), 0x1234)
	if len(fr) != 3 {
		t.Fatalf("%d fragments", len(fr))
	}
	for i, b := range fr {
		if _, err := Parse(b); !errors.Is(err, ErrFragment) {
			t.Fatalf("fragment %d parsed as a packet: %v", i, err)
		}
		f, err := ParseFragment(b)
		if err != nil {
			t.Fatal(err)
		}
		if f.Src != src.Addr() || f.Dst != dst.Addr() || f.ID != 0x1234 || f.Proto != ProtoUDP || f.Offset != i*1480 || f.More != (i < 2) {
			t.Fatalf("%d: %+v", i, f)
		}
		if f.HasPorts != (i == 0) || (i == 0 && (f.SrcPort != 40000 || f.DstPort != 443)) {
			t.Fatalf("%d ports: %+v", i, f)
		}
	}
	if _, err := ParseFragment(BuildUDP(src, dst, []byte("x"))); err == nil {
		t.Fatal("whole packet parsed as a fragment")
	}
}

func TestParseFragment6(t *testing.T) {
	src, dst := netip.MustParseAddr("2a00::5"), netip.MustParseAddr("2606:4700::1111")
	mk := func(off int, more bool, payload []byte) []byte {
		b := make([]byte, 48+len(payload))
		b[0] = 6 << 4
		binary.BigEndian.PutUint16(b[4:], uint16(8+len(payload)))
		b[6], b[7] = 44, 64
		copy(b[8:], src.AsSlice())
		copy(b[24:], dst.AsSlice())
		b[40] = ProtoUDP
		fo := uint16(off/8) << 3
		if more {
			fo |= 1
		}
		binary.BigEndian.PutUint16(b[42:], fo)
		binary.BigEndian.PutUint32(b[44:], 0xabcdef)
		copy(b[48:], payload)
		return b
	}
	first := mk(0, true, append([]byte{0x9c, 0x40, 0x01, 0xbb, 0, 0, 0, 0}, make([]byte, 1224)...))
	f, err := ParseFragment(first)
	if err != nil || !f.HasPorts || f.SrcPort != 40000 || f.DstPort != 443 || f.ID != 0xabcdef || !f.More || f.Src != src {
		t.Fatalf("%v %+v", err, f)
	}
	later, err := ParseFragment(mk(1232, false, make([]byte, 100)))
	if err != nil || later.HasPorts || later.Offset != 1232 || later.Key() != f.Key() {
		t.Fatalf("%v %+v", err, later)
	}
}

// Only fragments that may carry TCP or UDP are routed; in IPv6 an extension
// header after the fragment header may still hide one.
func TestFragmentRoutable(t *testing.T) {
	v4, v6 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700::1111")
	for _, c := range []struct {
		dst   netip.Addr
		proto uint8
		want  bool
	}{
		{v4, ProtoTCP, true}, {v4, ProtoUDP, true}, {v4, 1, false}, {v4, 47, false}, {v4, 50, false}, {v4, 60, false},
		{v6, ProtoUDP, true}, {v6, 58, false}, {v6, 50, false}, {v6, 51, false}, {v6, 60, true}, {v6, 43, true}, {v6, 135, true},
	} {
		f := Fragment{Dst: c.dst, Proto: c.proto}
		if got := f.Routable(); got != c.want {
			t.Errorf("%v proto %d: routable %v", c.dst, c.proto, got)
		}
	}
}
