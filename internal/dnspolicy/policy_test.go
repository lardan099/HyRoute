package dnspolicy

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
)

type siteCat map[string]bool

func (s siteCat) Match(n string) bool {
	for {
		if s[n] {
			return true
		}
		i := strings.IndexByte(n, '.')
		if i < 0 {
			return false
		}
		n = n[i+1:]
	}
}

type ipCat []netip.Prefix

func (c ipCat) Contains(a netip.Addr) bool {
	for _, p := range c {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

type testGeo struct{}

func (testGeo) Site(n string) (rules.DomainMatcher, error) {
	switch n {
	case "category-ads-all":
		return siteCat{"ads.example": true}, nil
	case "youtube":
		return siteCat{"youtube.com": true}, nil
	}
	return nil, errors.New("нет")
}

func (testGeo) IP(n string) (rules.IPMatcher, error) {
	switch n {
	case "ru":
		return ipCat{netip.MustParsePrefix("77.88.0.0/18")}, nil
	case "private":
		return ipCat{netip.MustParsePrefix("192.168.0.0/16")}, nil
	case "telegram":
		return ipCat{netip.MustParsePrefix("91.108.4.0/22")}, nil
	}
	return nil, errors.New("нет")
}

func ruleSet(t *testing.T, def rules.Action, rs ...rules.Rule) *rules.Set {
	t.Helper()
	rules.SetGeo(testGeo{})
	s, err := rules.Compile(rules.Config{DefaultAction: def, Rules: rs})
	if err != nil {
		t.Fatal(err)
	}
	s.Main = "main"
	return s
}

func policy(t *testing.T, cfg Config) *Policy {
	t.Helper()
	p, err := Compile(cfg, Names{Servers: []string{"Hy.Server.example.", "203.0.113.5"}, Service: []string{"my-doh.example"}})
	if err != nil || p == nil {
		t.Fatalf("compile: %v %v", p, err)
	}
	return p
}

var (
	system  = Requester{System: true}
	chrome  = Requester{Proc: &procinfo.Info{Name: "chrome.exe", Path: `C:\Chrome\chrome.exe`}}
	firefox = Requester{Proc: &procinfo.Info{Name: "firefox.exe", Path: `C:\Firefox\firefox.exe`}}
)

func a(name string) Question    { return Question{Name: name, Type: dnsmessage.TypeA} }
func aaaa(name string) Question { return Question{Name: name, Type: dnsmessage.TypeAAAA} }

func TestClassify(t *testing.T) {
	byRules := Config{ByRules: true}
	blockAll := ruleSet(t, rules.Tunnel, rules.Rule{Name: "block all", Domains: []string{"geosite:category-ads-all", ".server.example", ".github.com", "tplinkwifi.net"}, Action: rules.Block})
	env := Env{Rules: blockAll}
	check := func(label string, d Decision, kind Kind, via Via, rule, local string) {
		t.Helper()
		if d.Kind != kind || d.Kind == Resolve && d.Via != via || rule != "*" && d.Rule != rule || d.Local != local {
			t.Errorf("%s: %+v, want kind %d via %d rule %q local %q", label, d, kind, via, rule, local)
		}
	}
	p := policy(t, byRules)
	// Step 3: HyRoute's and Windows' names pass whatever the rules say.
	check("server", p.Classify(a("hy.server.example"), system, env), Pass, 0, "", "server")
	check("service", p.Classify(a("www.msftconnecttest.com"), system, env), Pass, 0, "", "service")
	check("custom upstream host", p.Classify(a("my-doh.example"), system, env), Pass, 0, "", "service")
	transient := Env{Rules: blockAll, Transient: func(n string) bool { return n == "github.com" }}
	check("transient", p.Classify(a("GitHub.com."), system, transient), Pass, 0, "", "service")
	check("not transient", p.Classify(a("api.github.com"), system, transient), Answer, 0, "block all", "")
	// Step 4: local names.
	for _, n := range []string{"nas", "printer.lan", "4.3.2.1.in-addr.arpa", "x.home.arpa", "tplinkwifi.net"} {
		check(n, p.Classify(a(n), system, env), Pass, 0, "", "local")
	}
	envSuffix := Env{Rules: blockAll, Local: func(n string) bool { return strings.HasSuffix(n, ".corp.example") }}
	check("adapter suffix", p.Classify(a("wiki.corp.example"), system, envSuffix), Pass, 0, "", "local")
	// Step 5, 6: the canary and ECH only with their options.
	check("canary off", p.Classify(a("use-application-dns.net"), system, Env{}), Pass, 0, "default", "")
	pd := policy(t, Config{BlockBrowserDoH: true})
	d := pd.Classify(a("use-application-dns.net"), system, Env{})
	check("canary", d, Answer, 0, RuleCanary, "")
	if d.Rcode != dnsmessage.RCodeNameError || d.Outcome != OutCanary || d.Route.Action != rules.Block {
		t.Fatalf("canary: %+v", d)
	}
	https := Question{Name: "example.com", Type: dnsmessage.TypeHTTPS}
	check("ECH without strip", pd.Classify(https, system, Env{}), Pass, 0, "default", "")
	check("strip without doh", policy(t, Config{StripECH: true, ByRules: true}).Classify(https, system, Env{Rules: blockAll}), Resolve, ViaTunnel, "default", "")
	pe := policy(t, Config{BlockBrowserDoH: true, StripECH: true})
	for _, q := range []Question{https, {Name: "example.com", Type: dnsmessage.TypeSVCB}} {
		if d := pe.Classify(q, system, Env{}); d.Kind != Answer || d.Rcode != dnsmessage.RCodeSuccess || d.Rule != RuleECH || d.Outcome != OutECH {
			t.Fatalf("ECH: %+v", d)
		}
	}
	check("A with ECH off", pe.Classify(a("example.com"), system, Env{}), Pass, 0, "default", "")
	// Step 7: ByRules off → direct.
	check("by rules off", pd.Classify(a("ads.example"), system, env), Pass, 0, "default", "")
	// Step 8: by the rules.
	d = p.Classify(a("x.ads.example"), system, env)
	check("block", d, Answer, 0, "block all", "")
	if d.Rcode != dnsmessage.RCodeNameError || d.Outcome != OutBlocked {
		t.Fatalf("block: %+v", d)
	}
	d = p.Classify(a("example.org"), system, env)
	check("tunnel", d, Resolve, ViaTunnel, "default", "")
	if d.Route.Profile != "main" || d.PassNegative {
		t.Fatalf("tunnel: %+v", d)
	}
	ipv6 := Env{Rules: blockAll, IPv6Blocked: true}
	d = p.Classify(aaaa("example.org"), system, ipv6)
	check("AAAA blocked", d, Answer, 0, RuleNoIPv6, "")
	if d.Rcode != dnsmessage.RCodeSuccess || d.Outcome != OutNoIPv6 || d.Route.Action != rules.Tunnel {
		t.Fatalf("AAAA: %+v", d)
	}
	check("A with IPv6 blocked", p.Classify(a("example.org"), system, ipv6), Resolve, ViaTunnel, "default", "")
	directSet := ruleSet(t, rules.Direct)
	check("direct", p.Classify(a("example.org"), system, Env{Rules: directSet}), Pass, 0, "default", "")
	// Step 9: the direct upstream.
	pu := policy(t, Config{ByRules: true, Direct: Upstream{Preset: "quad9"}})
	d = pu.Classify(a("example.org"), system, Env{Rules: directSet})
	check("upstream", d, Resolve, ViaDirect, "default", "")
	if !d.PassNegative || d.NegativeAny {
		t.Fatalf("upstream negatives: %+v", d)
	}
	if pu.DirectSpec == nil || pu.DirectSpec.Name != "Quad9" || pu.TunnelSpec.Name != "Cloudflare" {
		t.Fatalf("specs: %+v %+v", pu.DirectSpec, pu.TunnelSpec)
	}
	check("upstream, rules off", policy(t, Config{Direct: Upstream{Preset: "quad9"}}).Classify(a("ads.example"), system, env), Resolve, ViaDirect, "default", "")

	// A program's own rules: a program + site rule with Direct above a
	// generic block keeps the name out of NXDOMAIN.
	adsException := ruleSet(t, rules.Direct,
		rules.Rule{Name: "chrome ads", Apps: []rules.AppMatch{{Pattern: "chrome.exe"}}, Domains: []string{"ads.example"}, Action: rules.Direct},
		rules.Rule{Name: "ads", Domains: []string{"geosite:category-ads-all"}, Action: rules.Block})
	e := Env{Rules: adsException}
	check("exception, system", p.Classify(a("ads.example"), system, e), Pass, 0, "chrome ads", "")
	check("exception, chrome", p.Classify(a("ads.example"), chrome, e), Pass, 0, "chrome ads", "")
	check("exception, firefox", p.Classify(a("ads.example"), firefox, e), Answer, 0, "ads", "")
	check("unknown owner", p.Classify(a("ads.example"), Requester{}, e), Pass, 0, "chrome ads", "")
	// A program + site tunnel rule: the DNS client resolves through it.
	ffTunnel := ruleSet(t, rules.Direct, rules.Rule{Name: "ff", Apps: []rules.AppMatch{{Pattern: "firefox.exe"}}, Domains: []string{"example.com"}, Action: rules.Tunnel, Profile: "de"})
	d = p.Classify(a("example.com"), system, Env{Rules: ffTunnel})
	check("ff tunnel, system", d, Resolve, ViaTunnel, "ff", "")
	if d.Route.Profile != "de" || d.Cond&rules.CondApp == 0 || d.Pos != 0 {
		t.Fatalf("ff tunnel: %+v", d)
	}
	check("ff tunnel, firefox", p.Classify(a("example.com"), firefox, Env{Rules: ffTunnel}), Resolve, ViaTunnel, "ff", "")
	check("ff tunnel, chrome", p.Classify(a("example.com"), chrome, Env{Rules: ffTunnel}), Pass, 0, "default", "")
	// A program-only rule does not count for names.
	tg := ruleSet(t, rules.Direct, rules.Rule{Name: "tg", Apps: []rules.AppMatch{{Pattern: "telegram.exe"}}, Action: rules.Tunnel})
	check("program only", p.Classify(a("t.me"), system, Env{Rules: tg}), Pass, 0, "default", "")
	// A protocol rule with a site: conditional, VPN wins.
	proto := ruleSet(t, rules.Direct, rules.Rule{Name: "udp yt", Domains: []string{"geosite:youtube"}, Protocol: "udp", Action: rules.Tunnel})
	d = p.Classify(a("www.youtube.com"), system, Env{Rules: proto})
	check("proto alt", d, Resolve, ViaTunnel, "udp yt", "")
	if d.Cond&rules.CondProto == 0 {
		t.Fatalf("proto cond: %+v", d)
	}
	// Block only when every candidate blocks.
	allBlock := ruleSet(t, rules.Direct,
		rules.Rule{Name: "tcp ads", Domains: []string{"ads.example"}, Protocol: "tcp", Action: rules.Block},
		rules.Rule{Name: "ads", Domains: []string{"geosite:category-ads-all"}, Action: rules.Block})
	check("all block", p.Classify(a("ads.example"), system, Env{Rules: allBlock}), Answer, 0, "tcp ads", "")

	// Address rules: geoip:ru direct above «Всё остальное» → VPN.
	ru := ruleSet(t, rules.Tunnel,
		rules.Rule{Name: "lan", Domains: []string{"geoip:private"}, Action: rules.Direct},
		rules.Rule{Name: "yt", Domains: []string{"geosite:youtube"}, Action: rules.Tunnel},
		rules.Rule{Name: "ru", Domains: []string{"geoip:ru"}, Action: rules.Direct},
		rules.Rule{Name: "ads", Domains: []string{"geosite:category-ads-all"}, Action: rules.Block},
		rules.Rule{Name: "tg", Domains: []string{"geoip:telegram"}, Action: rules.Tunnel})
	d = p.Classify(a("shop.example"), system, Env{Rules: ru})
	check("addr", d, Pass, 0, "ru", "addr")
	check("addr off", policy(t, Config{ByRules: true, IgnoreAddrRules: true}).Classify(a("shop.example"), system, Env{Rules: ru}), Resolve, ViaTunnel, "default", "")
	check("site above addr", p.Classify(a("www.youtube.com"), system, Env{Rules: ru}), Resolve, ViaTunnel, "yt", "")
	check("block below addr", p.Classify(a("ads.example"), system, Env{Rules: ru}), Pass, 0, "ru", "addr")
	onlyLocal := ruleSet(t, rules.Tunnel, rules.Rule{Name: "lan", Domains: []string{"geoip:private"}, Action: rules.Direct})
	check("local-only address rule", p.Classify(a("shop.example"), system, Env{Rules: onlyLocal}), Resolve, ViaTunnel, "default", "")
	vpnAddr := ruleSet(t, rules.Direct, rules.Rule{Name: "tg", Domains: []string{"geoip:telegram"}, Action: rules.Tunnel})
	check("VPN address rule", p.Classify(a("shop.example"), system, Env{Rules: vpnAddr}), Pass, 0, "default", "")

	// Other adapters' servers.
	if s := ForSecondary(pu.Classify(a("example.org"), system, Env{Rules: directSet})); s.Kind != Pass {
		t.Fatalf("secondary direct: %+v", s)
	}
	if s := ForSecondary(p.Classify(a("example.org"), system, env)); s.Kind != Resolve || !s.PassNegative || !s.NegativeAny {
		t.Fatalf("secondary tunnel: %+v", s)
	}
	if s := ForSecondary(p.Classify(a("ads.example"), system, env)); s.Kind != Answer {
		t.Fatalf("secondary block: %+v", s)
	}
	// Off: no policy.
	if p, err := Compile(Config{StripECH: true}, Names{}); p != nil || err != nil {
		t.Fatalf("off: %v %v", p, err)
	}
}
