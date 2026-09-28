package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net/netip"
	"testing"
)

var (
	rsrc4, rdst4 = netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("93.184.216.34:3478")
	rsrc6, rdst6 = netip.MustParseAddrPort("[2a00::5]:40000"), netip.MustParseAddrPort("[2606:4700::1111]:3478")
)

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

// withOption4 inserts a 4-byte option (timestamp type, copied flag clear)
// into the header of an IPv4 packet.
func withOption4(b []byte) []byte {
	out := make([]byte, 0, len(b)+4)
	out = append(out, b[:20]...)
	out = append(out, 0x44, 4, 5, 0)
	out = append(out, b[20:]...)
	out[0] = 0x46
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	out[10], out[11] = 0, 0
	binary.BigEndian.PutUint16(out[10:], ^fold(sum(out[:24], 0)))
	return out
}

// split cuts a whole IPv4 or IPv6 packet into fragments: sizes are the
// data lengths of all fragments but the last, which takes the rest. IPv4
// options stay in the first fragment only (not copied); IPv6 gets a
// fragment header right after the fixed header.
func split(whole []byte, sizes []int, id uint32) [][]byte {
	v6 := whole[0]>>4 == 6
	hl := int(whole[0]&0x0f) * 4
	if v6 {
		hl = 40
	}
	body := whole[hl:]
	var out [][]byte
	off := 0
	for i := 0; off < len(body); i++ {
		n := len(body) - off
		if i < len(sizes) {
			n = sizes[i]
		}
		more := off+n < len(body)
		if v6 {
			b := make([]byte, 48+n)
			copy(b, whole[:40])
			binary.BigEndian.PutUint16(b[4:], uint16(8+n))
			b[6] = 44
			b[40] = whole[6]
			fo := uint16(off/8) << 3
			if more {
				fo |= 1
			}
			binary.BigEndian.PutUint16(b[42:], fo)
			binary.BigEndian.PutUint32(b[44:], id)
			copy(b[48:], body[off:off+n])
			out = append(out, b)
		} else {
			h := whole[:hl]
			if off > 0 {
				h = whole[:20]
			}
			b := append(append([]byte(nil), h...), body[off:off+n]...)
			b[0] = 0x40 | byte(len(h)/4)
			binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
			binary.BigEndian.PutUint16(b[4:], uint16(id))
			fl := uint16(off / 8)
			if more {
				fl |= 0x2000
			}
			binary.BigEndian.PutUint16(b[6:], fl)
			b[10], b[11] = 0, 0
			binary.BigEndian.PutUint16(b[10:], ^fold(sum(b[:len(h)], 0)))
			out = append(out, b)
		}
		off += n
	}
	return out
}

func mustFrag(t testing.TB, b []byte) Fragment {
	t.Helper()
	f, err := ParseFragment(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// assemble adds the fragments in the given order; it fails on any error.
func assemble(t *testing.T, frs [][]byte, order []int) *Assembly[int] {
	t.Helper()
	a := NewAssembly[int]()
	for _, i := range order {
		f := mustFrag(t, frs[i])
		if err := a.Add(frs[i], &f, i); err != nil {
			t.Fatalf("fragment %d: %v", i, err)
		}
	}
	return a
}

func seq(n int) []int {
	o := make([]int, n)
	for i := range o {
		o[i] = i
	}
	return o
}

func TestParseFragmentGeometry(t *testing.T) {
	whole := BuildUDP(rsrc4, rdst4, payload(3000))
	frs := split(whole, []int{1480, 1480}, 9)
	for i, b := range frs {
		f := mustFrag(t, b)
		wantUDP := 0
		if i == 0 {
			wantUDP = 3008
		}
		if f.Data != 20 || f.HdrLen != 20 || f.Len != len(b) || !f.Simple || f.UDPLen != wantUDP || !f.Reassemblable() {
			t.Fatalf("%d: %+v", i, f)
		}
	}
	// IPv4 options: still Simple (reassembled), header 24 bytes.
	fo := mustFrag(t, split(withOption4(whole), []int{1480}, 9)[0])
	if fo.HdrLen != 24 || fo.Data != 24 || !fo.Simple || fo.UDPLen != 3008 {
		t.Fatalf("options: %+v", fo)
	}
	// Trailing bytes past the total length are not part of the fragment.
	f := mustFrag(t, append(append([]byte(nil), frs[1]...), 1, 2, 3))
	if f.Len != len(frs[1]) {
		t.Fatalf("trailing bytes counted: %+v", f)
	}
	// Total length past the buffer.
	short := append([]byte(nil), frs[0]...)
	binary.BigEndian.PutUint16(short[2:], uint16(len(short)+1))
	if _, err := ParseFragment(short); !errors.Is(err, ErrShort) {
		t.Fatalf("truncated: %v", err)
	}

	w6 := BuildUDP(rsrc6, rdst6, payload(3000))
	for i, b := range split(w6, []int{1232, 1232}, 77) {
		f := mustFrag(t, b)
		if f.Data != 48 || f.HdrLen != 40 || f.Len != len(b) || !f.Simple || (i == 0) != (f.UDPLen == 3008) {
			t.Fatalf("v6 %d: %+v", i, f)
		}
	}
	// Hop-by-hop in front of the fragment header: not Simple.
	hbh := hopByHop6(split(w6, []int{1232}, 77)[0])
	fh := mustFrag(t, hbh)
	if fh.Simple || fh.Data != 56 || fh.Reassemblable() || !fh.HasPorts {
		t.Fatalf("hop-by-hop: %+v", fh)
	}
	// Payload length 0 (jumbogram marker).
	jumbo := append([]byte(nil), split(w6, []int{1232}, 77)[0]...)
	jumbo[4], jumbo[5] = 0, 0
	if _, err := ParseFragment(jumbo); !errors.Is(err, ErrShort) {
		t.Fatalf("jumbogram: %v", err)
	}
	// A payload length that ends inside the headers.
	cut := append([]byte(nil), hbh...)
	binary.BigEndian.PutUint16(cut[4:], 8)
	if _, err := ParseFragment(cut); !errors.Is(err, ErrShort) {
		t.Fatalf("payload length inside the headers: %v", err)
	}
}

// hopByHop6 inserts an 8-byte hop-by-hop header in front of the fragment
// header of an IPv6 fragment.
func hopByHop6(fr []byte) []byte {
	out := append([]byte(nil), fr[:40]...)
	out = append(out, 44, 0, 1, 4, 0, 0, 0, 0) // next: fragment; PadN
	out = append(out, fr[40:]...)
	out[6] = 0
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
	return out
}

func checkWhole(t *testing.T, a *Assembly[int], want []byte, id uint32) {
	t.Helper()
	if !a.Complete() {
		t.Fatal("not complete")
	}
	whole, raws, metas, err := a.Build()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(whole)
	if err != nil {
		t.Fatal(err)
	}
	wp, _ := Parse(want)
	if !bytes.Equal(p.Payload(), wp.Payload()) || p.Src() != wp.Src() || p.Dst() != wp.Dst() {
		t.Fatal("payload or addresses differ")
	}
	if !bytes.Equal(whole[p.L4:p.L4+8], want[wp.L4:wp.L4+8]) {
		t.Fatal("UDP header changed")
	}
	if !p.VerifyChecksums() {
		t.Fatal("checksums")
	}
	if !p.IPv6 {
		if binary.BigEndian.Uint16(whole[4:]) != uint16(id) || binary.BigEndian.Uint16(whole[6:]) != 0 {
			t.Fatalf("id %x flags %x", whole[4:6], whole[6:8])
		}
		if p.L4 != wp.L4 || !bytes.Equal(whole[20:p.L4], want[20:wp.L4]) {
			t.Fatal("options lost")
		}
	}
	if len(raws) != len(metas) || len(raws) != a.Pieces() {
		t.Fatalf("raws %d metas %d", len(raws), len(metas))
	}
}

func TestAssemblyOrders(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	for _, c := range []struct {
		name  string
		whole []byte
		sizes []int
	}{
		{"v4", BuildUDP(rsrc4, rdst4, payload(3000)), []int{1480, 1480}},
		{"v4 unequal", BuildUDP(rsrc4, rdst4, payload(5000)), []int{1480, 8, 600, 1000}},
		{"v4 options", withOption4(BuildUDP(rsrc4, rdst4, payload(3000))), []int{1472, 1480}},
		{"v6", BuildUDP(rsrc6, rdst6, payload(3000)), []int{1232, 1232}},
		{"v6 small", BuildUDP(rsrc6, rdst6, payload(3000)), []int{600, 600, 600, 600}},
	} {
		frs := split(c.whole, c.sizes, 0x4321)
		n := len(frs)
		rev := seq(n)
		for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
			rev[i], rev[j] = rev[j], rev[i]
		}
		shuf := seq(n)
		r.Shuffle(n, func(i, j int) { shuf[i], shuf[j] = shuf[j], shuf[i] })
		dup := append(seq(n), 0, n-1)
		for _, order := range [][]int{seq(n), rev, shuf, dup} {
			t.Run(c.name, func(t *testing.T) {
				a := assemble(t, frs, order)
				checkWhole(t, a, c.whole, 0x4321)
				_, raws, metas, _ := a.Build()
				for k := range raws {
					if metas[k] != order[k] || !bytes.Equal(raws[k], frs[order[k]]) {
						t.Fatalf("original %d: meta %d, want %d", k, metas[k], order[k])
					}
				}
				if a.First() < 0 || metas[a.First()] != 0 {
					t.Fatalf("first %d", a.First())
				}
			})
		}
	}
	// UDP checksum 0 (IPv4 senders may omit it): kept.
	w := BuildUDP(rsrc4, rdst4, payload(2000))
	w[26], w[27] = 0, 0
	a := assemble(t, split(w, []int{1480}, 1), []int{1, 0})
	whole, _, _, err := a.Build()
	if err != nil || whole[26] != 0 || whole[27] != 0 {
		t.Fatalf("%v %x", err, whole[26:28])
	}
	// The options of the first fragment are kept.
	wo := withOption4(BuildUDP(rsrc4, rdst4, payload(2000)))
	whole, _, _, _ = assemble(t, split(wo, []int{1472}, 1), []int{1, 0}).Build()
	if whole[0] != 0x46 || !bytes.Equal(whole[20:24], wo[20:24]) || !bytes.Equal(whole[24:], wo[24:]) {
		t.Fatal("options not kept")
	}
}

func addAll(frs [][]byte) error {
	a := NewAssembly[int]()
	for i, b := range frs {
		f, err := ParseFragment(b)
		if err != nil {
			return err
		}
		if err := a.Add(b, &f, i); err != nil {
			return err
		}
	}
	if !a.Complete() {
		return errors.New("incomplete")
	}
	_, _, _, err := a.Build()
	return err
}

func TestAssemblyRejects(t *testing.T) {
	w := BuildUDP(rsrc4, rdst4, payload(3000))
	frs := split(w, []int{1480, 1480}, 3)
	mod := func(i int, fn func(b []byte)) [][]byte {
		out := make([][]byte, len(frs))
		for k := range frs {
			out[k] = append([]byte(nil), frs[k]...)
		}
		fn(out[i])
		out[i][10], out[i][11] = 0, 0
		return out
	}
	setOff := func(b []byte, off int, more bool) {
		fl := uint16(off / 8)
		if more {
			fl |= 0x2000
		}
		binary.BigEndian.PutUint16(b[6:], fl)
	}
	// Overlap: the second fragment starts 8 bytes early.
	if err := addAll(mod(1, func(b []byte) { setOff(b, 1472, true) })); !errors.Is(err, ErrFragOverlap) {
		t.Errorf("overlap: %v", err)
	}
	// A second, different offset-0 fragment.
	other := split(BuildUDP(rsrc4, rdst4, payload(3001)), []int{1480, 1480}, 3)
	if err := addAll([][]byte{frs[0], other[0]}); err == nil {
		t.Error("second offset-0 fragment accepted")
	}
	// A middle fragment whose size is not a multiple of 8.
	odd := split(w, []int{1480, 1479}, 3)
	if err := addAll(odd); !errors.Is(err, ErrFragInvalid) {
		t.Errorf("odd middle: %v", err)
	}
	// Two different last fragments.
	last2 := mod(1, func(b []byte) { setOff(b, 1480, false) })
	if err := addAll(last2); !errors.Is(err, ErrFragInvalid) {
		t.Errorf("two last fragments: %v", err)
	}
	// Data past a known end.
	late := [][]byte{frs[2], frs[0], frs[1]}
	late[2] = append([]byte(nil), frs[1]...)
	setOff(late[2], 1480+1488, true)
	if err := addAll(late); err == nil {
		t.Error("data past the end accepted")
	}
	// UDP length not the assembled size, both ways.
	for _, d := range []int{-8, 8} {
		bad := mod(0, func(b []byte) { binary.BigEndian.PutUint16(b[24:], uint16(3008+d)) })
		if err := addAll(bad); !errors.Is(err, ErrFragInvalid) {
			t.Errorf("UDP length %+d: %v", d, err)
		}
	}
	// UDP length below the header.
	if err := addAll(mod(0, func(b []byte) { binary.BigEndian.PutUint16(b[24:], 4) })); !errors.Is(err, ErrFragInvalid) {
		t.Errorf("UDP length 4: %v", err)
	}
	// 129 pieces.
	big := BuildUDP(rsrc4, rdst4, payload(129*8))
	sizes := make([]int, 128)
	for i := range sizes {
		sizes[i] = 8
	}
	sizes[0] = 16 // UDP header + 8
	if err := addAll(split(big, sizes, 4)); !errors.Is(err, ErrFragInvalid) {
		t.Errorf("129 pieces: %v", err)
	}
	// A first fragment shorter than a UDP header (RFC 7112).
	// An IPv6 atomic fragment (offset 0, M clear) with 4 bytes of data.
	fr := split(BuildUDP(rsrc6, rdst6, payload(100)), []int{8}, 5)[0][:52]
	binary.BigEndian.PutUint16(fr[4:], 12)
	fr[42], fr[43] = 0, 0
	if f := mustFrag(t, fr); f.UDPLen != 0 || NewAssembly[int]().Add(fr, &f, 0) == nil {
		t.Errorf("short first fragment accepted: %+v", f)
	}
	// A hand-made Fragment with Data past Len: rejected, no panic.
	g := mustFrag(t, frs[1])
	g.Data = g.Len + 1
	if err := NewAssembly[int]().Add(frs[1], &g, 0); !errors.Is(err, ErrFragInvalid) {
		t.Errorf("Data > Len: %v", err)
	}
	// Build before Complete.
	b := NewAssembly[int]()
	f0 := mustFrag(t, frs[0])
	_ = b.Add(frs[0], &f0, 0)
	if _, _, _, err := b.Build(); err == nil || b.Complete() {
		t.Error("incomplete datagram built")
	}
}

// edgeFrags makes the two fragments of a datagram of dataLen bytes (UDP
// header included) with the given UDP length field, for the size edges.
// The first IPv4 fragment has an ihl-byte header, the second 20 bytes.
func edgeFrags(v6 bool, ihl, firstLen, dataLen, udpLen int) [][]byte {
	mk := func(ihl, off int, more bool, data []byte) []byte {
		if v6 {
			b := make([]byte, 48+len(data))
			b[0] = 0x60
			binary.BigEndian.PutUint16(b[4:], uint16(8+len(data)))
			b[6], b[7] = 44, 64
			copy(b[8:], rsrc6.Addr().AsSlice())
			copy(b[24:], rdst6.Addr().AsSlice())
			b[40] = ProtoUDP
			fo := uint16(off/8) << 3
			if more {
				fo |= 1
			}
			binary.BigEndian.PutUint16(b[42:], fo)
			binary.BigEndian.PutUint32(b[44:], 1)
			copy(b[48:], data)
			return b
		}
		b := make([]byte, ihl+len(data))
		b[0] = 0x40 | byte(ihl/4)
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		fl := uint16(off / 8)
		if more {
			fl |= 0x2000
		}
		binary.BigEndian.PutUint16(b[6:], fl)
		b[8], b[9] = 64, ProtoUDP
		copy(b[12:], rsrc4.Addr().AsSlice())
		copy(b[16:], rdst4.Addr().AsSlice())
		copy(b[ihl:], data)
		return b
	}
	first := make([]byte, firstLen)
	binary.BigEndian.PutUint16(first[0:], 40000)
	binary.BigEndian.PutUint16(first[2:], 3478)
	binary.BigEndian.PutUint16(first[4:], uint16(udpLen))
	return [][]byte{mk(ihl, 0, true, first), mk(20, firstLen, false, make([]byte, dataLen-firstLen))}
}

func TestAssemblySizeEdges(t *testing.T) {
	for _, c := range []struct {
		name          string
		v6            bool
		ihl, first, n int
		ok            bool
	}{
		{"v4 65515", false, 20, 65512, 65515, true},
		{"v4 65516", false, 20, 65512, 65516, false},
		{"v4 options 65511", false, 24, 65504, 65511, true},
		{"v4 options 65512", false, 24, 65504, 65512, false},
		// An IPv6 fragment carries at most 65527 bytes (payload length).
		{"v6 65535", true, 40, 65520, 65535, true},
		{"v6 65536", true, 40, 65520, 65536, false},
	} {
		udpLen := min(c.n, 65535)
		frs := edgeFrags(c.v6, c.ihl, c.first, c.n, udpLen)
		for _, order := range [][]int{{0, 1}, {1, 0}} {
			err := addAll([][]byte{frs[order[0]], frs[order[1]]})
			if c.ok != (err == nil) {
				t.Errorf("%s order %v: %v", c.name, order, err)
			}
		}
	}
}

// Seeds: fragments as a prefix-length stream (see fragStream).
func fragStream(frs ...[]byte) []byte {
	var out []byte
	for _, b := range frs {
		out = binary.BigEndian.AppendUint16(out, uint16(len(b)))
		out = append(out, b...)
	}
	return out
}

func FuzzAssembly(f *testing.F) {
	w4 := BuildUDP(rsrc4, rdst4, payload(3000))
	fr4 := split(w4, []int{1480, 1480}, 1)
	f.Add(fragStream(fr4...))
	f.Add(fragStream(fr4[2], fr4[1], fr4[0]))
	f.Add(fragStream(fr4[0], fr4[0], fr4[1], fr4[2]))
	fr6 := split(BuildUDP(rsrc6, rdst6, payload(3000)), []int{1232, 1232}, 1)
	f.Add(fragStream(fr6...))
	f.Add(fragStream(split(withOption4(w4), []int{1472}, 1)...))
	f.Add(fragStream(edgeFrags(false, 20, 65512, 65515, 65515)...))
	f.Fuzz(func(t *testing.T, stream []byte) {
		a := NewAssembly[int]()
		held := 0
		for i := 0; len(stream) >= 2; i++ {
			n := int(binary.BigEndian.Uint16(stream))
			stream = stream[2:]
			if n > len(stream) {
				break
			}
			raw := stream[:n]
			stream = stream[n:]
			fr, err := ParseFragment(raw)
			if err != nil || !fr.Reassemblable() {
				continue
			}
			if a.Add(raw, &fr, i) != nil {
				break
			}
			held += len(raw)
		}
		if a.Bytes() > held || a.Pieces() > maxPieces {
			t.Fatalf("bytes %d of %d, pieces %d", a.Bytes(), held, a.Pieces())
		}
		whole, _, _, err := a.Build()
		if !a.Complete() && err == nil {
			t.Fatal("built before complete")
		}
		if err == nil {
			if _, err := Parse(whole); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzParseFragment(f *testing.F) {
	w6 := BuildUDP(rsrc6, rdst6, payload(3000))
	for _, b := range append(split(BuildUDP(rsrc4, rdst4, payload(3000)), []int{1480}, 1), split(w6, []int{1232}, 2)...) {
		f.Add(b)
	}
	f.Add(split(withOption4(BuildUDP(rsrc4, rdst4, payload(3000))), []int{1472}, 1)[0])
	hbh := hopByHop6(split(w6, []int{1232}, 2)[0])
	f.Add(hbh)
	cut := append([]byte(nil), hbh...)
	binary.BigEndian.PutUint16(cut[4:], 8)
	f.Add(cut)
	jumbo := append([]byte(nil), split(w6, []int{1232}, 2)[0]...)
	jumbo[4], jumbo[5] = 0, 0
	f.Add(jumbo)
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, err := ParseFragment(b)
		if err != nil {
			return
		}
		if fr.HdrLen > fr.Data || fr.Data > fr.Len || fr.Len > len(b) {
			t.Fatalf("geometry %d %d %d of %d", fr.HdrLen, fr.Data, fr.Len, len(b))
		}
		a := NewAssembly[int]()
		_ = a.Add(b, &fr, 0)
	})
}
