package divert

import (
	"fmt"
	"net/netip"
	"strings"
)

// Exclusion ranges that never enter user space (loopback, RFC1918,
// link-local, multicast, broadcast/reserved, unique-local).
var (
	ExcludedV4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"), // includes 255.255.255.255
	}
	ExcludedV6 = []netip.Prefix{
		netip.MustParsePrefix("::/127"), // :: and ::1
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("ff00::/8"),
	}
	// CGNAT / Tailscale; optional, off by default.
	CGNAT = netip.MustParsePrefix("100.64.0.0/10")
)

// FilterOptions describes the main NETWORK handle (H1).
type FilterOptions struct {
	RelayPort uint16
	// ServerIPs are the Hysteria server addresses (all resolved records).
	ServerIPs    []netip.Addr
	ExcludeCGNAT bool
	// TCPOnly restricts capture to TCP (PoC); UDP comes in step 3.
	TCPOnly bool
	// dns
	// DNS also captures DNS (UDP and TCP port 53) to private and
	// link-local destinations (the home router), fragments to them (only
	// the first fragment of a query has the port), and the relay's replies
	// to such a destination. Hysteria server IPs and loopback stay out.
	DNS bool
}

// MainFilter builds the H1 filter:
//
//	(outbound and !loopback and (tcp or udp) and <not excluded>)
//	or (inbound and tcp.DstPort == RELAY)
//
// Two WinDivert filter-language rules shape the exclusions:
//   - "not"/"!" applies to a single test only; "not (a and b)" is a parse
//     error (WinDivertOpen fails with ERROR_INVALID_PARAMETER), so ranges
//     are negated by De Morgan: "x < lo or x > hi".
//   - a test on a field the packet does not have (ip.* on IPv6) is false,
//     so each exclusion also lets the other family through explicitly.
func MainFilter(o FilterOptions) string {
	var excl, servers []string
	v4 := ExcludedV4
	if o.ExcludeCGNAT {
		v4 = append(v4[:len(v4):len(v4)], CGNAT)
	}
	for _, p := range v4 {
		excl = append(excl, outsideRange("ipv6", "ip.DstAddr", p))
	}
	for _, p := range ExcludedV6 {
		excl = append(excl, outsideRange("ip", "ipv6.DstAddr", p))
	}
	for _, ip := range o.ServerIPs {
		ip = ip.Unmap()
		if ip.Is4() {
			servers = append(servers, fmt.Sprintf("(ipv6 or ip.DstAddr != %s)", ip))
		} else {
			servers = append(servers, fmt.Sprintf("(ip or ipv6.DstAddr != %s)", ip))
		}
	}
	// Fragments without the transport header match neither tcp nor udp;
	// they are captured too, so a fragmented datagram cannot bypass the
	// routing (Core.fragOut). Fragments of other protocols (ICMP, ESP...)
	// match as well; Core.fragOut passes them unchanged.
	proto := "(tcp or udp or fragment)"
	if o.TCPOnly {
		proto = "tcp"
	}
	if o.DNS {
		return dnsFilter(o, proto, excl, servers)
	}
	return fmt.Sprintf("(outbound and !loopback and %s and %s) or (inbound and tcp.DstPort == %d)",
		proto, strings.Join(append(excl, servers...), " and "), o.RelayPort)
}

// outsideRange matches packets of the other family or with field outside p.
func outsideRange(otherFamily, field string, p netip.Prefix) string {
	lo := p.Masked().Addr()
	hi := lastAddr(p)
	if lo == netip.IPv4Unspecified() || lo == netip.IPv6Unspecified() {
		return fmt.Sprintf("(%s or %s > %s)", otherFamily, field, hi)
	}
	return fmt.Sprintf("(%s or %s < %s or %s > %s)", otherFamily, field, lo, field, hi)
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	bits := p.Bits()
	for i := range b {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				b[i] |= 0x80 >> j
			}
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// SocketFilter is the SOCKET layer (H3) filter used for PID attribution.
const SocketFilter = "!loopback and (event == CONNECT or event == BIND or event == CLOSE)"

// FlowFilter is the FLOW layer (H4) filter.
const FlowFilter = "!loopback"

// DNSFilter is the NETWORK sniff handle (H2) that feeds the DNS cache. It
// takes the queries going out as well as the responses coming in: a
// response counts only when it answers a query seen here (Core.HandleDNS).
// TCP segments without payload carry no DNS and are left out.
const DNSFilter = "!loopback and (" +
	"(outbound and (udp.DstPort == 53 or (tcp.DstPort == 53 and tcp.PayloadLength > 0))) or " +
	"(inbound and (udp.SrcPort == 53 or (tcp.SrcPort == 53 and tcp.PayloadLength > 0))))"

// dnsFilter is MainFilter with DNS capture (dns):
//
//	(outbound and !loopback and (tcp or udp or fragment) and <server IP exclusions>
//	   and ((<range exclusions>) or udp.DstPort == 53 or fragment
//	        or tcp.DstPort == 53 or tcp.SrcPort == RELAY))
//	or (inbound and tcp.DstPort == RELAY)
//
// DNS to private and link-local destinations is captured, and the relay's
// replies to a reflected private destination come back. WinDivert reads
// ports only in a first fragment, so every fragment to a private
// destination is captured too (Core.dnsHold decides which are held).
func dnsFilter(o FilterOptions, proto string, ranges, servers []string) string {
	dns := []string{"(" + strings.Join(ranges, " and ") + ")"}
	if !o.TCPOnly {
		dns = append(dns, "udp.DstPort == 53", "fragment")
	}
	dns = append(dns, "tcp.DstPort == 53", fmt.Sprintf("tcp.SrcPort == %d", o.RelayPort))
	cond := append([]string{"!loopback", proto}, servers...)
	cond = append(cond, "("+strings.Join(dns, " or ")+")")
	return fmt.Sprintf("(outbound and %s) or (inbound and tcp.DstPort == %d)", strings.Join(cond, " and "), o.RelayPort)
}
