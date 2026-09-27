package packet

import (
	"encoding/binary"
	"net/netip"
)

const defaultTTL = 64

// BuildUDP assembles an IPv4 or IPv6 UDP packet src -> dst with valid
// checksums. Both addresses must be of the same family (IPv4-mapped IPv6
// addresses count as IPv4).
func BuildUDP(src, dst netip.AddrPort, payload []byte) []byte {
	v6 := !src.Addr().Unmap().Is4()
	hl := 20
	if v6 {
		hl = 40
	}
	b := make([]byte, hl+8+len(payload))
	writeIPHeader(b, v6, ProtoUDP, len(b))
	p := Packet{Buf: b, IPv6: v6, Proto: ProtoUDP, L4: hl, Data: hl + 8}
	p.SetSrcIP(src.Addr())
	p.SetDstIP(dst.Addr())
	p.SetSrcPort(src.Port())
	p.SetDstPort(dst.Port())
	copy(b[hl+8:], payload)
	p.FixChecksums()
	return b
}

// BuildTCP assembles a TCP segment src -> dst (20-byte header, no options)
// with valid checksums.
func BuildTCP(src, dst netip.AddrPort, flags uint8, seq, ack uint32, payload []byte) []byte {
	v6 := !src.Addr().Unmap().Is4()
	hl := 20
	if v6 {
		hl = 40
	}
	b := make([]byte, hl+20+len(payload))
	writeIPHeader(b, v6, ProtoTCP, len(b))
	p := Packet{Buf: b, IPv6: v6, Proto: ProtoTCP, L4: hl, Data: hl + 20}
	p.SetSrcIP(src.Addr())
	p.SetDstIP(dst.Addr())
	p.SetSrcPort(src.Port())
	p.SetDstPort(dst.Port())
	binary.BigEndian.PutUint32(b[hl+4:], seq)
	binary.BigEndian.PutUint32(b[hl+8:], ack)
	b[hl+12] = 5 << 4
	b[hl+13] = flags
	binary.BigEndian.PutUint16(b[hl+14:], 65535)
	copy(b[hl+20:], payload)
	p.FixChecksums()
	return b
}

// BuildRSTFor builds the RST that the remote end would send in reply to the
// outbound TCP segment p: addresses and ports are swapped. For a SYN the
// reply is RST|ACK acknowledging the SYN, so the application gets
// "connection refused" immediately.
func BuildRSTFor(p *Packet) []byte {
	hl := 20
	if p.IPv6 {
		hl = 40
	}
	b := make([]byte, hl+20)
	writeIPHeader(b, p.IPv6, ProtoTCP, len(b))
	r := Packet{Buf: b, IPv6: p.IPv6, Proto: ProtoTCP, L4: hl, Data: hl + 20}
	r.SetSrcIP(p.DstIP())
	r.SetDstIP(p.SrcIP())
	r.SetSrcPort(p.DstPort())
	r.SetDstPort(p.SrcPort())
	b[hl+12] = 5 << 4
	seg := uint32(len(p.Payload()))
	f := p.TCPFlags()
	if f&FlagSYN != 0 {
		seg++
	}
	if f&FlagFIN != 0 {
		seg++
	}
	if f&FlagACK != 0 {
		// RFC 793: RST takes its sequence number from the ACK field.
		binary.BigEndian.PutUint32(b[hl+4:], p.Ack())
		b[hl+13] = FlagRST
	} else {
		binary.BigEndian.PutUint32(b[hl+8:], p.Seq()+seg)
		b[hl+13] = FlagRST | FlagACK
	}
	r.FixChecksums()
	return b
}

func writeIPHeader(b []byte, v6 bool, proto uint8, total int) {
	if v6 {
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:], uint16(total-40))
		b[6] = proto
		b[7] = defaultTTL
		return
	}
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[6:], 0x4000) // DF
	b[8] = defaultTTL
	b[9] = proto
}
