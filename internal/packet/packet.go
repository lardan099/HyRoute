// Package packet parses and rewrites raw IPv4/IPv6 TCP/UDP packets as they
// come out of WinDivert (no link-layer header) and builds synthetic packets
// (UDP replies, TCP RST) for injection.
package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	ProtoTCP = 6
	ProtoUDP = 17
)

// TCP flags.
const (
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
)

var (
	ErrShort       = errors.New("packet: truncated")
	ErrVersion     = errors.New("packet: unknown IP version")
	ErrFragment    = errors.New("packet: IP fragment")
	ErrUnsupported = errors.New("packet: unsupported L4 protocol")
	// ErrIPsec: an IPv6 packet with an IPsec AH header. WinDivert's
	// tcp/udp fields look through AH (and the filter captures it), but
	// such a packet cannot be rewritten: the ICV covers the addresses and
	// the transport header.
	ErrIPsec = errors.New("packet: IPsec AH")
)

// Packet is a parsed view over a raw IP packet. Setters modify Buf in place;
// call FixChecksums after all modifications.
type Packet struct {
	Buf   []byte
	IPv6  bool
	Proto uint8
	L4    int // offset of the TCP/UDP header
	Data  int // offset of the L4 payload
}

// Parse parses an IPv4 or IPv6 packet carrying TCP or UDP.
func Parse(b []byte) (Packet, error) {
	if len(b) < 1 {
		return Packet{}, ErrShort
	}
	p := Packet{Buf: b}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, ErrShort
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return p, ErrShort
		}
		if total := int(binary.BigEndian.Uint16(b[2:])); total < ihl || total > len(b) {
			return p, ErrShort
		} else {
			p.Buf = b[:total]
		}
		frag := binary.BigEndian.Uint16(b[6:])
		if frag&0x3fff != 0 { // MF set or non-zero offset
			return p, ErrFragment
		}
		p.Proto = b[9]
		p.L4 = ihl
	case 6:
		if len(b) < 40 {
			return p, ErrShort
		}
		if total := 40 + int(binary.BigEndian.Uint16(b[4:])); total > len(b) {
			return p, ErrShort
		} else {
			p.Buf = b[:total]
		}
		p.IPv6 = true
		next, off := b[6], 40
	ext:
		for {
			switch next {
			case 0, 43, 60, 135: // hop-by-hop, routing, destination options, mobility
				if len(p.Buf) < off+8 {
					return p, ErrShort
				}
				next = p.Buf[off]
				off += (int(p.Buf[off+1]) + 1) * 8
			case 44:
				return p, ErrFragment
			case 51:
				return p, ErrIPsec
			default:
				break ext
			}
		}
		p.Proto = next
		p.L4 = off
	default:
		return p, ErrVersion
	}
	switch p.Proto {
	case ProtoTCP:
		if len(p.Buf) < p.L4+20 {
			return p, ErrShort
		}
		doff := int(p.Buf[p.L4+12]>>4) * 4
		if doff < 20 || len(p.Buf) < p.L4+doff {
			return p, ErrShort
		}
		p.Data = p.L4 + doff
	case ProtoUDP:
		if len(p.Buf) < p.L4+8 {
			return p, ErrShort
		}
		p.Data = p.L4 + 8
	default:
		return p, ErrUnsupported
	}
	return p, nil
}

func (p *Packet) srcOff() (int, int) {
	if p.IPv6 {
		return 8, 16
	}
	return 12, 4
}

func (p *Packet) dstOff() (int, int) {
	if p.IPv6 {
		return 24, 16
	}
	return 16, 4
}

func (p *Packet) addr(off, n int) netip.Addr {
	if n == 4 {
		return netip.AddrFrom4([4]byte(p.Buf[off : off+4]))
	}
	return netip.AddrFrom16([16]byte(p.Buf[off : off+16]))
}

func (p *Packet) setAddr(off, n int, a netip.Addr) {
	if n == 4 {
		b := a.Unmap().As4()
		copy(p.Buf[off:], b[:])
		return
	}
	b := a.As16()
	copy(p.Buf[off:], b[:])
}

func (p *Packet) SrcIP() netip.Addr { return p.addr(p.srcOff()) }
func (p *Packet) DstIP() netip.Addr { return p.addr(p.dstOff()) }

// SetSrcIP / SetDstIP keep the address family of the packet; a is unmapped
// for IPv4 packets.
func (p *Packet) SetSrcIP(a netip.Addr) { off, n := p.srcOff(); p.setAddr(off, n, a) }
func (p *Packet) SetDstIP(a netip.Addr) { off, n := p.dstOff(); p.setAddr(off, n, a) }

// SwapIPs exchanges source and destination addresses.
func (p *Packet) SwapIPs() {
	s, d := p.SrcIP(), p.DstIP()
	p.SetSrcIP(d)
	p.SetDstIP(s)
}

func (p *Packet) SrcPort() uint16     { return binary.BigEndian.Uint16(p.Buf[p.L4:]) }
func (p *Packet) DstPort() uint16     { return binary.BigEndian.Uint16(p.Buf[p.L4+2:]) }
func (p *Packet) SetSrcPort(v uint16) { binary.BigEndian.PutUint16(p.Buf[p.L4:], v) }
func (p *Packet) SetDstPort(v uint16) { binary.BigEndian.PutUint16(p.Buf[p.L4+2:], v) }

func (p *Packet) Src() netip.AddrPort { return netip.AddrPortFrom(p.SrcIP(), p.SrcPort()) }
func (p *Packet) Dst() netip.AddrPort { return netip.AddrPortFrom(p.DstIP(), p.DstPort()) }

// TCPFlags returns the TCP flag byte (0 for UDP).
func (p *Packet) TCPFlags() uint8 {
	if p.Proto != ProtoTCP {
		return 0
	}
	return p.Buf[p.L4+13]
}

func (p *Packet) Seq() uint32 { return binary.BigEndian.Uint32(p.Buf[p.L4+4:]) }
func (p *Packet) Ack() uint32 { return binary.BigEndian.Uint32(p.Buf[p.L4+8:]) }

// Payload returns the L4 payload.
func (p *Packet) Payload() []byte { return p.Buf[p.Data:] }

// IsSYN reports a pure connection-opening SYN (SYN without ACK).
func (p *Packet) IsSYN() bool {
	f := p.TCPFlags()
	return f&FlagSYN != 0 && f&FlagACK == 0
}

// FixChecksums recomputes the IPv4 header checksum and the TCP/UDP checksum.
func (p *Packet) FixChecksums() {
	b := p.Buf
	if !p.IPv6 {
		b[10], b[11] = 0, 0
		binary.BigEndian.PutUint16(b[10:], ^fold(sum(b[:p.L4], 0)))
	}
	ck := p.L4 + 16
	if p.Proto == ProtoUDP {
		ck = p.L4 + 6
		binary.BigEndian.PutUint16(b[p.L4+4:], uint16(len(b)-p.L4))
	}
	b[ck], b[ck+1] = 0, 0
	c := ^fold(sum(b[p.L4:], p.pseudo()))
	if c == 0 && p.Proto == ProtoUDP {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(b[ck:], c)
}

// VerifyChecksums reports whether the IP (v4) and L4 checksums are valid.
func (p *Packet) VerifyChecksums() bool {
	if !p.IPv6 && fold(sum(p.Buf[:p.L4], 0)) != 0xffff {
		return false
	}
	if p.Proto == ProtoUDP && !p.IPv6 && binary.BigEndian.Uint16(p.Buf[p.L4+6:]) == 0 {
		return true
	}
	return fold(sum(p.Buf[p.L4:], p.pseudo())) == 0xffff
}

func (p *Packet) pseudo() uint32 {
	var s uint32
	so, n := p.srcOff()
	do, _ := p.dstOff()
	s = sum(p.Buf[so:so+n], s)
	s = sum(p.Buf[do:do+n], s)
	l := uint32(len(p.Buf) - p.L4)
	s += uint32(p.Proto) + (l >> 16) + (l & 0xffff)
	return s
}

func sum(b []byte, s uint32) uint32 {
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if n%2 == 1 {
		s += uint32(b[n-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return uint16(s)
}
