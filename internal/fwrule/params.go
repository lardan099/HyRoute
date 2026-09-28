// Package fwrule manages the inbound Windows Firewall rule the relay needs:
// reflected SYNs arrive as inbound packets and pass ALE_AUTH_RECV_ACCEPT,
// where the firewall would otherwise prompt or block. It also keeps the
// rules that let devices of the local network reach local proxies.
package fwrule

import (
	"strconv"
	"strings"
)

// ProxyName and ProxyUDPName are the local proxy rules (TCP and UDP): they
// let devices of the local network reach HyRoute's local proxies (private
// and domain networks only, never public Wi-Fi; and only from the subnets
// of this PC, not from the internet over a global IPv6 address or a public
// IPv4 one). v1.2.0 used the same names.
const (
	ProxyName    = "HyRoute local proxies (TCP)"
	ProxyUDPName = "HyRoute local proxies (UDP)"
)

// proxyRuleMark is in the description of the proxy rules this version
// writes. v1.2.0 wrote them without a description, so a UDP rule without
// the mark is v1.2.0's: it opened UDP on every LAN proxy port (see
// LegacyProxyUDP).
const proxyRuleMark = "hyroute-proxy-rule-2"

// proxyParams builds the netsh parameters of a proxy rule: program,
// protocol, exactly these local ports, local subnets, private/domain.
func proxyParams(exe, proto string, ports []int) []string {
	list := make([]string, len(ports))
	for i, p := range ports {
		list[i] = strconv.Itoa(p)
	}
	return []string{"dir=in", "action=allow", "program=" + exe, "protocol=" + proto,
		"localport=" + strings.Join(list, ","), "remoteip=localsubnet", "profile=private,domain", "enable=yes",
		"description=HyRoute: local proxies from the local network (" + proxyRuleMark + ")"}
}
