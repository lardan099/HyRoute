package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// noDF clears DF (reassembly clears the flags, so the rebuilt packet then
// equals the original byte for byte).
func noDF(b []byte) []byte {
	b = append([]byte(nil), b...)
	b[6], b[7] = 0, 0
	b[10], b[11] = 0, 0
	binary.BigEndian.PutUint16(b[10:], ^fold(sum(b[:int(b[0]&0x0f)*4], 0)))
	return b
}

func TestFragmentIP(t *testing.T) {
	for _, c := range []struct {
		name string
		pkt  []byte
		mtu  int
		n    int
	}{
		{"v4", noDF(BuildUDP(rsrc4, rdst4, payload(4096))), 1500, 3},
		{"v4 options", noDF(withOption4(BuildUDP(rsrc4, rdst4, payload(4096)))), 1500, 3},
		{"v6", BuildUDP(rsrc6, rdst6, payload(4096)), 1280, 4},
	} {
		frs, err := FragmentIP(c.pkt, c.mtu, 0xbeef)
		if err != nil || len(frs) != c.n {
			t.Fatalf("%s: %d fragments, %v", c.name, len(frs), err)
		}
		v6 := c.pkt[0]>>4 == 6
		for i, b := range frs {
			f := mustFrag(t, b)
			if len(b) > c.mtu || f.Offset%8 != 0 || f.More != (i < len(frs)-1) {
				t.Fatalf("%s %d: len %d %+v", c.name, i, len(b), f)
			}
			if v6 {
				if f.ID != 0xbeef || !f.Simple {
					t.Fatalf("%s %d: %+v", c.name, i, f)
				}
			} else {
				if binary.BigEndian.Uint16(b[6:])&0x4000 != 0 || fold(sum(b[:f.HdrLen], 0)) != 0xffff {
					t.Fatalf("%s %d: DF set or header checksum", c.name, i)
				}
				if binary.BigEndian.Uint16(b[4:]) != binary.BigEndian.Uint16(c.pkt[4:]) {
					t.Fatalf("%s %d: ID changed", c.name, i)
				}
				if i > 0 && f.HdrLen != 20 {
					t.Fatalf("%s %d: a non-copied option repeated", c.name, i)
				}
			}
		}
		// Back through reassembly, in reverse: the identical packet.
		order := seq(len(frs))
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
		whole, _, _, err := assemble(t, frs, order).Build()
		if err != nil || !bytes.Equal(whole, c.pkt) {
			t.Fatalf("%s: rebuilt packet differs (%v)", c.name, err)
		}
	}
	// A packet that fits comes back as itself.
	small := BuildUDP(rsrc4, rdst4, payload(100))
	if frs, err := FragmentIP(small, 1500, 1); err != nil || len(frs) != 1 || !bytes.Equal(frs[0], small) {
		t.Fatalf("small: %v", err)
	}
	// MTU below the minimum; IPv6 with an extension header.
	if _, err := FragmentIP(BuildUDP(rsrc4, rdst4, payload(4096)), 60, 1); err == nil {
		t.Fatal("IPv4 MTU 60 accepted")
	}
	if _, err := FragmentIP(BuildUDP(rsrc6, rdst6, payload(4096)), 1200, 1); err == nil {
		t.Fatal("IPv6 MTU 1200 accepted")
	}
	ext := BuildUDP(rsrc6, rdst6, payload(4096))
	ext[6] = 60
	if _, err := FragmentIP(ext, 1280, 1); err == nil {
		t.Fatal("IPv6 extension header accepted")
	}
}

// A copied option (the copy flag set) is repeated in every fragment.
func TestFragmentIPCopiedOption(t *testing.T) {
	p := withOption4(BuildUDP(rsrc4, rdst4, payload(3000)))
	p[20] = 0x94 // router alert, copied
	p = noDF(p)
	frs, err := FragmentIP(p, 1500, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range frs {
		if f := mustFrag(t, b); f.HdrLen != 24 || !bytes.Equal(b[20:24], p[20:24]) {
			t.Fatalf("%d: header %d", i, f.HdrLen)
		}
	}
}
