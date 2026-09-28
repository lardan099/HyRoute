// Package killswitch keeps the internet closed when HyRoute's routing is
// gone without the user turning it off: a crash, a hung or failed packet
// engine, the process being killed.
//
// It uses Windows Filtering Platform filters in a sublayer of its own:
//
//   - block: every connection, inbound and outbound, IPv4 and IPv6. Added
//     in a normal (non-dynamic) session, so they outlive the process and
//     last until HyRoute removes them or Windows restarts. HyRoute removes
//     them when Windows ends the session: a shutdown with Fast Startup
//     keeps the filter engine as it was. A block left anyway (HyRoute
//     ended first) is found at sign-in (Leftover).
//   - exceptions: loopback, the local network, DNS and DHCP of Windows'
//     own clients (DNS, encrypted too, to the adapters' DNS servers), and
//     HyRoute's own programs (HyRoute.exe, hysteria.exe), so HyRoute can
//     reconnect. The port of HyRoute's relay stays closed to other hosts
//     all the same: its connections have the real remote hosts for peers.
//   - pass: permit everything, weighted above the block. Added in a dynamic
//     session while the packet engine works: Windows deletes it the moment
//     that session closes, which includes the process dying. HyRoute
//     closes it itself when the engine fails.
//
// While the engine works the pass filter makes the block invisible and the
// engine routes as usual (per app, per domain). When the pass filter goes,
// the block remains.
//
// The filters have fixed IDs, the same for every HyRoute on the machine:
// the first one running owns them, another one (in another Windows
// session) leaves them alone until it exits.
package killswitch

import "net/netip"

// LAN is the local traffic the block leaves alone: private, link-local,
// multicast and broadcast addresses.
var LAN = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("ff00::/8"),
}

// Ports are the remote ports of DNS and DHCP (v4 and v6) the block leaves
// open to Windows' DNS and DHCP clients (svchost.exe), not to other
// programs: HyRoute resolves the server name through the Windows
// resolver, so the query leaves from the DNS client service, not from
// hysteria.exe. With svchost's app ID known, DHCP goes from the client's
// port to the server's only and DNS to the adapters' DNS servers only
// (while none is known, outbound to port 53 of any host).
var Ports = []uint16{53, 67, 68, 546, 547}

// SecureDNSPorts are the ports of encrypted DNS (DoH, DoT) the block
// leaves open to Windows' DNS client towards the adapters' DNS servers
// only: when Windows requires encrypted DNS, nothing goes to port 53.
var SecureDNSPorts = []uint16{443, 853}
