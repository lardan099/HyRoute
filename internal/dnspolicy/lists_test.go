package dnspolicy

import (
	"net/netip"
	"testing"

	"github.com/lardan099/hyroute/internal/procinfo"
)

func TestLists(t *testing.T) {
	local := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("::1/128"),
	}
	if len(dohAddrs) < 60 {
		t.Fatalf("only %d DoH prefixes", len(dohAddrs))
	}
	for _, p := range dohAddrs {
		for _, l := range local {
			if p.Overlaps(l) {
				t.Errorf("DoH prefix %s overlaps the local range %s", p, l)
			}
		}
	}
	for _, c := range []struct {
		name string
		doh  bool
	}{
		{"dns.google", true}, {"mozilla.cloudflare-dns.com", true}, {"Cloudflare-DNS.com.", true}, {"abc.dns.nextdns.io", true},
		{"notcloudflare-dns.com", false}, {"google.com", false}, {"dns.google.evil.example", false}, {"", false},
	} {
		if IsDoHHost(c.name) != c.doh {
			t.Errorf("IsDoHHost(%q) = %v", c.name, !c.doh)
		}
	}
	for _, c := range []struct {
		ip  string
		doh bool
	}{
		{"1.1.1.1", true}, {"::ffff:8.8.8.8", true}, {"45.90.28.17", true}, {"2a07:a8c0::1", true}, {"194.242.2.9", true},
		{"1.1.1.4", false}, {"8.8.8.9", false}, {"93.184.216.34", false}, {"194.242.2.16", false},
	} {
		if IsDoHAddr(netip.MustParseAddr(c.ip)) != c.doh {
			t.Errorf("IsDoHAddr(%s) = %v", c.ip, !c.doh)
		}
	}
	if !IsBrowser(&procinfo.Info{Name: "chrome.exe"}) || !IsBrowser(&procinfo.Info{Name: "Firefox.exe"}) || !IsBrowser(&procinfo.Info{Name: "browser.exe"}) ||
		IsBrowser(&procinfo.Info{Name: "telegram.exe"}) || IsBrowser(nil) {
		t.Fatal("IsBrowser")
	}
	if !IsCanary("use-application-dns.net") || !IsCanary("x.Use-Application-DNS.net.") || IsCanary("application-dns.net") {
		t.Fatal("IsCanary")
	}
	for _, c := range []struct {
		name  string
		local bool
	}{
		{"nas", true}, {"printer.local", true}, {"router.lan", true}, {"x.home.arpa", true}, {"1.168.192.in-addr.arpa", true},
		{"tplinkwifi.net", true}, {"my.keenetic.net", true}, {"fritz.box", true}, {"localhost", true}, {"a.test", true},
		{"www.tplinkwifi.net", false}, {"example.com", false}, {"keenetic.net", false}, {"home.example", false},
	} {
		if IsLocalName(c.name) != c.local {
			t.Errorf("IsLocalName(%q) = %v", c.name, !c.local)
		}
	}
	if !IsServiceName("www.msftconnecttest.com") || IsServiceName("msftconnecttest.com") || IsServiceName("github.com") {
		t.Fatal("IsServiceName")
	}
}
