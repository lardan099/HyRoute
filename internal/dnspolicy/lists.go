package dnspolicy

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
)

// Curated lists, re-checked against the providers' documentation when
// they change. Browser DoH blocking only uses them for browsers on ports
// 443 and 853, so a stale entry costs little.

// dohHosts are DoH/DoT host names: a name matches when it equals an entry
// or is under it.
var dohHosts = []string{
	"dns.google", "dns.google.com", "8888.google",
	"cloudflare-dns.com", "one.one.one.one",
	"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
	"doh.opendns.com", "doh.familyshield.opendns.com", "doh.umbrella.com",
	"dns.nextdns.io",
	"dns.adguard.com", "dns.adguard-dns.com", "dns-unfiltered.adguard.com", "dns-family.adguard.com",
	"doh.cleanbrowsing.org",
	"dot.dns.yandex.net",
	"doh.dns.sb",
	"dns.alidns.com", "doh.pub", "dns.pub", "doh.360.cn",
	"dns.controld.com", "freedns.controld.com",
	"doh.mullvad.net", "dns.mullvad.net",
	"dns0.eu",
}

// dohAddrs are the addresses of those resolvers (dedicated resolver
// addresses only, never shared CDN ones), sorted.
var dohAddrs = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		// Cloudflare
		"1.1.1.1", "1.1.1.2", "1.1.1.3", "1.0.0.1", "1.0.0.2", "1.0.0.3", "104.16.248.249", "104.16.249.249",
		"2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002",
		"2606:4700:4700::1113", "2606:4700:4700::1003",
		// Google
		"8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844", "2001:4860:4860::6464", "2001:4860:4860::64",
		// Quad9
		"9.9.9.9", "9.9.9.10", "9.9.9.11", "149.112.112.9", "149.112.112.10", "149.112.112.11", "149.112.112.112",
		"2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11",
		// OpenDNS
		"208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123", "146.112.41.2",
		"2620:119:35::35", "2620:119:53::53", "2620:119:fc::2",
		// AdGuard
		"94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16", "94.140.14.140", "94.140.14.141",
		"2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff", "2a10:50c0::1:ff", "2a10:50c0::2:ff",
		// Yandex
		"77.88.8.1", "77.88.8.2", "77.88.8.3", "77.88.8.7", "77.88.8.8", "77.88.8.88",
		"2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff", "2a02:6b8::feed:bad", "2a02:6b8:0:1::feed:bad",
		"2a02:6b8::feed:a11", "2a02:6b8:0:1::feed:a11",
		// NextDNS
		"45.90.28.0/24", "45.90.30.0/24", "2a07:a8c0::/32", "2a07:a8c1::/32",
		// CleanBrowsing
		"185.228.168.0/24", "185.228.169.0/24",
		// DNS.SB
		"185.222.222.222", "45.11.45.11",
		// Mullvad
		"194.242.2.0/28",
		// ControlD
		"76.76.2.0/24", "76.76.10.0/24",
		// dns0.eu
		"193.110.81.0/24", "185.253.5.0/24",
	} {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a := netip.MustParseAddr(s)
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p.Masked())
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return out
}()

// browsers are the exe names of browsers (helper processes carry the same
// name).
var browsers = map[string]bool{
	"chrome.exe": true, "msedge.exe": true, "firefox.exe": true, "browser.exe": true, // Yandex
	"brave.exe": true, "opera.exe": true, "vivaldi.exe": true, "chromium.exe": true, "thorium.exe": true,
	"librewolf.exe": true, "waterfox.exe": true, "floorp.exe": true, "zen.exe": true, "arc.exe": true,
}

// canary is Firefox's: NXDOMAIN for it turns its default DoH off.
const canary = "use-application-dns.net"

// localSuffixes are names that only a local network answers.
var localSuffixes = []string{
	"local", "lan", "home", "home.arpa", "internal", "intranet", "localdomain", "localhost", "invalid", "test", "arpa",
}

// routerNames are the login names home routers and extenders answer
// themselves (exact names).
var routerNames = map[string]bool{
	"tplinkwifi.net": true, "tplinklogin.net": true, "tplinkrepeater.net": true, "tplinkmodem.net": true,
	"routerlogin.net": true, "routerlogin.com": true, "orbilogin.com": true, "orbilogin.net": true,
	"my.keenetic.net": true, "router.asus.com": true, "repeater.asus.com": true,
	"miwifi.com": true, "router.miwifi.com": true, "mywifiext.net": true,
	"mymodem.home": true, "fritz.box": true, "myfritz.box": true,
}

// serviceNames are the names Windows needs at any time, whoever asks: the
// connectivity and time probes (a captive portal is detected through
// them). Exact names.
var serviceNames = []string{
	"www.msftconnecttest.com", "ipv6.msftconnecttest.com", "dns.msftncsi.com", "www.msftncsi.com", "time.windows.com",
}

// under reports whether name equals suffix or is under it.
func under(name, suffix string) bool {
	return name == suffix || strings.HasSuffix(name, "."+suffix)
}

// IsDoHHost reports a DoH/DoT server name (normalized; suffix match).
func IsDoHHost(name string) bool {
	name = rules.NormalizeDomain(name)
	if name == "" {
		return false
	}
	for _, h := range dohHosts {
		if under(name, h) {
			return true
		}
	}
	return false
}

// IsDoHAddr reports a known DoH resolver address.
func IsDoHAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range dohAddrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsBrowser reports whether p is a browser (nil: no).
func IsBrowser(p *procinfo.Info) bool { return p != nil && browsers[strings.ToLower(p.Name)] }

// IsCanary reports Firefox's DoH canary name or a name under it.
func IsCanary(name string) bool { return under(rules.NormalizeDomain(name), canary) }

// IsLocalName reports a name only the local network knows: a single
// label, a name under a local suffix, or a router's login name.
func IsLocalName(name string) bool {
	name = rules.NormalizeDomain(name)
	if name == "" || !strings.Contains(name, ".") {
		return true
	}
	for _, s := range localSuffixes {
		if under(name, s) {
			return true
		}
	}
	return routerNames[name]
}

// IsServiceName reports a fixed name Windows itself needs (exact).
func IsServiceName(name string) bool {
	return slices.Contains(serviceNames, rules.NormalizeDomain(name))
}
