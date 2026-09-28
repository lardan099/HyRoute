package packet

import (
	"encoding/binary"
	"net/netip"
)

// Fragment describes an IP fragment (Parse returns ErrFragment for it).
// Only the first fragment carries the transport header, so only it has
// ports; the others are matched to it by addresses, protocol and ID.
type Fragment struct {
	Src, Dst netip.Addr
	ID       uint32
	Proto    uint8
	Offset   int // in bytes
	More     bool
	HasPorts bool
	SrcPort  uint16
	DstPort  uint16
	// bigudp: the geometry reassembly needs. A successful parse always has
	// HdrLen <= Data <= Len <= len(b).
	Data   int // offset of the fragment's data (after the IPv4 header / IPv6 fragment header)
	Len    int // bytes of the packet that belong to it (IPv4 total length, IPv6 40+payload length)
	HdrLen int // IPv4 header length (options included); 40 for IPv6
	// Simple: IPv4 (options allowed), or IPv6 whose fragment header directly
	// follows the fixed header. RFC 8200 repeats the unfragmentable part in
	// every fragment, so this is a property of the datagram.
	Simple bool
	UDPLen int // UDP length field of a UDP first fragment with >= 8 bytes of UDP header, else 0
}

// FragKey identifies all fragments of one datagram.
type FragKey struct {
	Src, Dst netip.Addr
	ID       uint32
	Proto    uint8
}

func (f *Fragment) Key() FragKey { return FragKey{f.Src, f.Dst, f.ID, f.Proto} }

// Routable reports whether the fragment may belong to a TCP or UDP
// datagram, the only traffic the engine routes. In IPv6 an extension
// header after the fragment header may still hide the TCP/UDP header, so
// those count too. Other protocols (ICMP, ESP, GRE) do not, nor does IPsec
// AH, whose whole packets the engine passes unchanged as well.
func (f *Fragment) Routable() bool {
	switch f.Proto {
	case ProtoTCP, ProtoUDP:
		return true
	case 0, 43, 44, 60, 135: // hop-by-hop, routing, fragment, destination options, mobility
		return f.Dst.Is6()
	}
	return false
}

// ParseFragment parses an IPv4 or IPv6 fragment.
func ParseFragment(b []byte) (Fragment, error) {
	var f Fragment
	if len(b) < 1 {
		return f, ErrShort
	}
	var l4 int
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return f, ErrShort
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return f, ErrShort
		}
		frag := binary.BigEndian.Uint16(b[6:])
		if frag&0x3fff == 0 {
			return f, ErrUnsupported // not a fragment
		}
		f.Src = netip.AddrFrom4([4]byte(b[12:16]))
		f.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		f.ID = uint32(binary.BigEndian.Uint16(b[4:]))
		f.Proto = b[9]
		f.Offset = int(frag&0x1fff) * 8
		f.More = frag&0x2000 != 0
		l4 = ihl
		f.Len = int(binary.BigEndian.Uint16(b[2:]))
		if f.Len < ihl || f.Len > len(b) {
			return f, ErrShort
		}
		f.Data, f.HdrLen, f.Simple = ihl, ihl, true
	case 6:
		if len(b) < 40 {
			return f, ErrShort
		}
		f.Src = netip.AddrFrom16([16]byte(b[8:24]))
		f.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		// Payload length 0 is the jumbogram marker: never a fragment here.
		pl := int(binary.BigEndian.Uint16(b[4:]))
		if pl == 0 || 40+pl > len(b) {
			return f, ErrShort
		}
		f.Len, f.HdrLen = 40+pl, 40
		next, off := b[6], 40
		for {
			switch next {
			case 0, 43, 60, 135:
				if len(b) < off+8 {
					return f, ErrShort
				}
				next = b[off]
				off += (int(b[off+1]) + 1) * 8
				continue
			case 44:
				if len(b) < off+8 {
					return f, ErrShort
				}
				fo := binary.BigEndian.Uint16(b[off+2:])
				f.Proto = b[off]
				f.Offset = int(fo>>3) * 8
				f.More = fo&1 != 0
				f.ID = binary.BigEndian.Uint32(b[off+4:])
				l4 = off + 8
				if f.Len < l4 {
					return f, ErrShort // the headers end past the payload length
				}
				f.Data, f.Simple = l4, off == 40
			default:
				return f, ErrUnsupported // not a fragment
			}
			break
		}
	default:
		return f, ErrVersion
	}
	if f.Offset == 0 && (f.Proto == ProtoTCP || f.Proto == ProtoUDP) && f.Len >= l4+4 {
		f.HasPorts = true
		f.SrcPort = binary.BigEndian.Uint16(b[l4:])
		f.DstPort = binary.BigEndian.Uint16(b[l4+2:])
		if f.Proto == ProtoUDP && f.Len >= l4+8 {
			f.UDPLen = int(binary.BigEndian.Uint16(b[l4+4:]))
		}
	}
	return f, nil
}

// Reassemblable reports whether the datagram can be reassembled here: UDP,
// Simple headers. Everything else keeps the per-fragment routing.
func (f *Fragment) Reassemblable() bool { return f.Proto == ProtoUDP && f.Simple }
