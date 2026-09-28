package rules

import (
	"net/netip"
	"strings"
)

// A DNS query tells only a name (and, for a program's own DNS client, the
// program). EvaluateName walks the rules with that alone; which of its
// answers count for the name is the DNS policy's decision
// (internal/dnspolicy).

// NameCond says which parts of a rule are unknown for a name alone.
type NameCond uint8

const (
	CondProto NameCond = 1 << iota // tcp/udp, and ports: never known for a name
	CondApp                        // programs: unknown when sub.Proc == nil
	CondAddr                       // the rule can match only through its address items (IP, network, geoip:)
)

// NameAlt is a conditional rule above the winner whose known parts match.
type NameAlt struct {
	Result        // s.result(r): the route it would give
	Pos       int // rule index
	Cond      NameCond
	AddrLocal bool // CondAddr only: every address item covers local ranges only
}

// NameResult is EvaluateName's answer.
type NameResult struct {
	Result           // the winner, or the default; Domain = domain, DomainSrc = src
	Pos    int       // winner's rule index; len(rules) for the default
	Alt    []NameAlt // in rule order, all above Pos
}

// EvaluateName decides for a name alone, e.g. a DNS query. The protocol,
// the port and the address are unknown; the program is unknown when
// sub.Proc is nil (the Windows DNS client asks for everyone). A rule whose
// known parts match and that has no unknown part wins. A rule with an
// unknown part is listed in Alt when its known parts match and it has
// either a site item that matches the name or address items (CondAddr).
// A rule with an unknown part and no destination items at all
// (program-only, protocol-only) is skipped without a trace.
func (s *Set) EvaluateName(sub Subject, domain string, src DomainSource) NameResult {
	domain = NormalizeDomain(domain)
	var out NameResult
	for i := range s.rules {
		r := &s.rules[i]
		var cond NameCond
		if r.hasApp() {
			if sub.Proc == nil {
				cond |= CondApp
			} else if !r.matchApp(sub.Proc) {
				continue
			}
		}
		if r.proto != 0 || len(r.ports) > 0 {
			cond |= CondProto
		}
		switch {
		case !r.hasDest():
			if cond != 0 {
				continue
			}
		case domain != "" && r.matchDomain(domain):
			if cond != 0 {
				out.Alt = append(out.Alt, NameAlt{Result: s.result(r), Pos: i, Cond: cond})
				continue
			}
		case len(r.ips) > 0:
			out.Alt = append(out.Alt, NameAlt{Result: s.result(r), Pos: i, Cond: cond | CondAddr, AddrLocal: r.addrLocal})
			continue
		default:
			continue
		}
		out.Result, out.Pos = s.result(r), i
		out.Domain, out.DomainSrc = domain, src
		return out
	}
	out.Result, out.Pos = s.result(nil), len(s.rules)
	out.Domain, out.DomainSrc = domain, src
	return out
}

// cgnat is the shared address space (RFC 6598), local like RFC 1918.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// localOnly reports whether every address item covers local ranges only:
// private (RFC 1918, ULA), loopback, link-local, unspecified or CGNAT
// networks, the geoip category "private", or a geoip category that is
// missing (it matches nothing). False without address items.
func localOnly(ips []ipPat) bool {
	if len(ips) == 0 {
		return false
	}
	for i := range ips {
		p := &ips[i]
		if !p.pfx.IsValid() {
			if p.geo != nil && !strings.EqualFold(p.src, "geoip:private") {
				return false
			}
			continue
		}
		if !localPrefix(p.pfx) {
			return false
		}
	}
	return true
}

// localPrefix: the whole of p is in one local range.
func localPrefix(p netip.Prefix) bool {
	a := p.Masked().Addr()
	last := lastOf(p)
	local := func(x netip.Addr) bool {
		return x.IsPrivate() || x.IsLoopback() || x.IsLinkLocalUnicast() || x.IsUnspecified() || cgnat.Contains(x)
	}
	if !local(a) || !local(last) {
		return false
	}
	// Both ends local is not enough for a wide prefix spanning public
	// space (0.0.0.0/0 starts and ends in local ranges): the prefix must
	// fit inside the range its first address is in.
	for _, r := range localRanges {
		if r.Contains(a) {
			return r.Bits() <= p.Bits()
		}
	}
	return false
}

// localRanges are the ranges localPrefix accepts, for the containment
// check (IPv4 and IPv6).
var localRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("0.0.0.0/32"),
	cgnat,
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::/128"),
}

// lastOf is the last address of p.
func lastOf(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
