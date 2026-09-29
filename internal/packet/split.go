package packet

import "encoding/binary"

// FragmentIP splits an IPv4 or IPv6 packet into fragments whose IP length
// is at most mtu (IPv4: mtu >= 68; IPv6: mtu >= 1280), for injecting a reply
// larger than the interface MTU if Windows ever refuses it whole (bigudp
// §0.4). A packet that already fits is returned as the only element. IPv4:
// the header (options dropped from later fragments unless copied, RFC 791)
// is repeated with MF/offset set, DF cleared, checksum recomputed; the ID
// is the packet's own. IPv6: a fragment header (next header = the
// packet's, identification id) follows the fixed header; extension headers
// are not supported (ErrFragInvalid): BuildUDP never writes any.
//
// Not called by the engine in this release: replies are injected whole, as
// in 1.0.0 (docs/architecture/routing.md «UDP»).
func FragmentIP(pkt []byte, mtu int, id uint32) ([][]byte, error) {
	if len(pkt) < 1 {
		return nil, ErrShort
	}
	switch pkt[0] >> 4 {
	case 4:
		return fragment4(pkt, mtu)
	case 6:
		return fragment6(pkt, mtu, id)
	}
	return nil, ErrVersion
}

func fragment4(pkt []byte, mtu int) ([][]byte, error) {
	if mtu < 68 {
		return nil, ErrFragInvalid
	}
	if len(pkt) < 20 {
		return nil, ErrShort
	}
	ihl := int(pkt[0]&0x0f) * 4
	total := 0
	if len(pkt) >= 4 {
		total = int(binary.BigEndian.Uint16(pkt[2:]))
	}
	if ihl < 20 || total < ihl || total > len(pkt) {
		return nil, ErrShort
	}
	if binary.BigEndian.Uint16(pkt[6:])&0x3fff != 0 {
		return nil, ErrFragInvalid // already a fragment
	}
	if total <= mtu {
		return [][]byte{pkt[:total]}, nil
	}
	first := pkt[:ihl]
	later := laterHeader4(first)
	body := pkt[ihl:total]
	var out [][]byte
	for off := 0; off < len(body); {
		h := first
		if off > 0 {
			h = later
		}
		n := len(body) - off
		if len(h)+n > mtu {
			n = (mtu - len(h)) &^ 7
		}
		b := make([]byte, len(h)+n)
		copy(b, h)
		copy(b[len(h):], body[off:off+n])
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		fl := uint16(off / 8)
		if off+n < len(body) {
			fl |= 0x2000 // MF; DF cleared
		}
		binary.BigEndian.PutUint16(b[6:], fl)
		b[10], b[11] = 0, 0
		binary.BigEndian.PutUint16(b[10:], ^fold(sum(b[:len(h)], 0)))
		out = append(out, b)
		off += n
	}
	return out, nil
}

// laterHeader4 is the header of the fragments after the first: only the
// options with the copied flag (RFC 791), padded to 4 bytes.
func laterHeader4(h []byte) []byte {
	opts := []byte{}
	for i := 20; i < len(h); {
		t := h[i]
		if t == 0 { // end of options
			break
		}
		if t == 1 { // no-operation, not copied
			i++
			continue
		}
		if i+1 >= len(h) {
			break
		}
		l := int(h[i+1])
		if l < 2 || i+l > len(h) {
			break
		}
		if t&0x80 != 0 {
			opts = append(opts, h[i:i+l]...)
		}
		i += l
	}
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}
	out := append(append([]byte(nil), h[:20]...), opts...)
	out[0] = 0x40 | byte(len(out)/4)
	return out
}

func fragment6(pkt []byte, mtu int, id uint32) ([][]byte, error) {
	if mtu < 1280 {
		return nil, ErrFragInvalid
	}
	if len(pkt) < 40 {
		return nil, ErrShort
	}
	total := 40 + int(binary.BigEndian.Uint16(pkt[4:]))
	if total > len(pkt) {
		return nil, ErrShort
	}
	switch next := pkt[6]; next {
	case 0, 43, 44, 50, 51, 60, 135:
		return nil, ErrFragInvalid // extension headers
	}
	if total <= mtu {
		return [][]byte{pkt[:total]}, nil
	}
	body := pkt[40:total]
	var out [][]byte
	for off := 0; off < len(body); {
		n := len(body) - off
		if 48+n > mtu {
			n = (mtu - 48) &^ 7
		}
		b := make([]byte, 48+n)
		copy(b, pkt[:40])
		binary.BigEndian.PutUint16(b[4:], uint16(8+n))
		b[6] = 44
		b[40] = pkt[6]
		fo := uint16(off/8) << 3
		if off+n < len(body) {
			fo |= 1
		}
		binary.BigEndian.PutUint16(b[42:], fo)
		binary.BigEndian.PutUint32(b[44:], id)
		copy(b[48:], body[off:off+n])
		out = append(out, b)
		off += n
	}
	return out, nil
}
