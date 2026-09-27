package geodata

import (
	"encoding/binary"
	"net/netip"
	"slices"
)

type u128 struct{ hi, lo uint64 }

func (a u128) cmp(b u128) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	}
	return 0
}

func (a u128) next() (u128, bool) {
	if a.lo == ^uint64(0) {
		if a.hi == ^uint64(0) {
			return a, false
		}
		return u128{a.hi + 1, 0}, true
	}
	return u128{a.hi, a.lo + 1}, true
}

type r4 struct{ lo, hi uint32 }
type r6 struct{ lo, hi u128 }

// IPSet is one geoip category (or a list of prefixes).
type IPSet struct {
	v4      []r4 // sorted, merged
	v6      []r6
	reverse bool
}

// Len is the number of merged ranges.
func (s *IPSet) Len() int { return len(s.v4) + len(s.v6) }

// Contains reports whether ip is in the set.
func (s *IPSet) Contains(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	in := false
	if ip.Is4() {
		b := ip.As4()
		v := binary.BigEndian.Uint32(b[:])
		i, _ := slices.BinarySearchFunc(s.v4, v, func(r r4, v uint32) int {
			if r.hi < v {
				return -1
			}
			if r.lo > v {
				return 1
			}
			return 0
		})
		in = i < len(s.v4) && s.v4[i].lo <= v && v <= s.v4[i].hi
	} else {
		v := to128(ip)
		i, _ := slices.BinarySearchFunc(s.v6, v, func(r r6, v u128) int {
			if r.hi.cmp(v) < 0 {
				return -1
			}
			if r.lo.cmp(v) > 0 {
				return 1
			}
			return 0
		})
		in = i < len(s.v6) && s.v6[i].lo.cmp(v) <= 0 && v.cmp(s.v6[i].hi) <= 0
	}
	return in != s.reverse
}

func to128(ip netip.Addr) u128 {
	b := ip.As16()
	return u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
}

// NewIPSet builds a set from prefixes.
func NewIPSet(prefixes []netip.Prefix) *IPSet {
	s := &IPSet{}
	for _, p := range prefixes {
		s.add(p)
	}
	s.finish()
	return s
}

func (s *IPSet) add(p netip.Prefix) {
	if !p.IsValid() {
		return // Bits() is -1: the shifts below would panic
	}
	p = p.Masked()
	a := p.Addr()
	if a.Is4() {
		b := a.As4()
		lo := binary.BigEndian.Uint32(b[:])
		host := uint32(0)
		if p.Bits() < 32 {
			host = ^uint32(0) >> p.Bits()
		}
		s.v4 = append(s.v4, r4{lo, lo | host})
		return
	}
	lo := to128(a)
	hi := lo
	bits := p.Bits()
	switch {
	case bits == 0:
		hi = u128{^uint64(0), ^uint64(0)}
	case bits < 64:
		hi = u128{lo.hi | ^uint64(0)>>bits, ^uint64(0)}
	case bits < 128:
		hi = u128{lo.hi, lo.lo | ^uint64(0)>>(bits-64)}
	}
	s.v6 = append(s.v6, r6{lo, hi})
}

// finish sorts and merges overlapping or adjacent ranges.
func (s *IPSet) finish() {
	slices.SortFunc(s.v4, func(a, b r4) int {
		switch {
		case a.lo < b.lo:
			return -1
		case a.lo > b.lo:
			return 1
		}
		return 0
	})
	var m4 []r4
	for _, r := range s.v4 {
		if n := len(m4); n > 0 && (m4[n-1].hi == ^uint32(0) || r.lo <= m4[n-1].hi+1) {
			m4[n-1].hi = max(m4[n-1].hi, r.hi)
			continue
		}
		m4 = append(m4, r)
	}
	s.v4 = m4
	slices.SortFunc(s.v6, func(a, b r6) int { return a.lo.cmp(b.lo) })
	var m6 []r6
	for _, r := range s.v6 {
		if n := len(m6); n > 0 {
			nx, ok := m6[n-1].hi.next()
			if !ok || r.lo.cmp(nx) <= 0 {
				if r.hi.cmp(m6[n-1].hi) > 0 {
					m6[n-1].hi = r.hi
				}
				continue
			}
		}
		m6 = append(m6, r)
	}
	s.v6 = m6
}

// decodeIP decodes a GeoIP message.
func decodeIP(b []byte) (_ *IPSet, err error) {
	defer recoverDecode(&err)
	s := &IPSet{}
	p := pb{b}
	for !p.done() {
		num, wire, err := p.field()
		if err != nil {
			return nil, err
		}
		switch {
		case num == 2 && wire == 2:
			raw, err := p.bytes()
			if err != nil {
				return nil, err
			}
			if pfx, ok := decodeCIDR(raw); ok {
				s.add(pfx)
			}
		case num == 3 && wire == 0:
			v, err := p.varint()
			if err != nil {
				return nil, err
			}
			s.reverse = v != 0
		default:
			if err := p.skip(wire); err != nil {
				return nil, err
			}
		}
	}
	s.finish()
	return s, nil
}

func decodeCIDR(b []byte) (netip.Prefix, bool) {
	p := pb{b}
	var ip []byte
	var bits uint64
	for !p.done() {
		num, wire, err := p.field()
		if err != nil {
			return netip.Prefix{}, false
		}
		switch {
		case num == 1 && wire == 2:
			if ip, err = p.bytes(); err != nil {
				return netip.Prefix{}, false
			}
		case num == 2 && wire == 0:
			if bits, err = p.varint(); err != nil {
				return netip.Prefix{}, false
			}
		default:
			if p.skip(wire) != nil {
				return netip.Prefix{}, false
			}
		}
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	// Compare as uint64: a huge varint would turn negative as an int.
	if bits > uint64(a.BitLen()) {
		return netip.Prefix{}, false
	}
	pfx := netip.PrefixFrom(a, int(bits))
	return pfx, pfx.IsValid()
}

// Private is the built-in "geoip:private": LAN, loopback, link-local,
// CGNAT and other non-routable ranges. It works without a database.
var Private = NewIPSet(mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"255.255.255.255/32",
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
))

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}
