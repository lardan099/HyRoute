package rules

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type fakeSite map[string]bool

func (f fakeSite) Match(n string) bool {
	for s := n; ; {
		if f[s] {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return false
		}
		s = s[i+1:]
	}
}

type fakeIP []netip.Prefix

func (f fakeIP) Contains(ip netip.Addr) bool {
	for _, p := range f {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type fakeGeo struct{}

func (fakeGeo) Site(n string) (DomainMatcher, error) {
	if n == "youtube" {
		return fakeSite{"youtube.com": true, "googlevideo.com": true}, nil
	}
	return nil, errors.New("категории нет")
}

func (fakeGeo) IP(n string) (IPMatcher, error) {
	if n == "ru" {
		return fakeIP{netip.MustParsePrefix("77.88.0.0/18")}, nil
	}
	return nil, errors.New("категории нет")
}

func withGeo(t *testing.T, g Geo) {
	t.Helper()
	old := geo.Load()
	SetGeo(g)
	t.Cleanup(func() { geo.Store(old) })
}

func at(ip string) Subject {
	return Subject{Proto: 6, Dst: netip.AddrPortFrom(netip.MustParseAddr(ip), 443)}
}

func TestAddressRules(t *testing.T) {
	withGeo(t, fakeGeo{})
	s := mustCompile(t, Config{DefaultAction: Tunnel, Rules: []Rule{
		{Name: "lan", Domains: []string{"geoip:private", "192.168.0.0/16", "10.1.2.3"}, Action: Direct},
		{Name: "ru", Domains: []string{"geoip:ru", "geosite:youtube"}, Action: Block},
	}})
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "geoip:private") {
		// fakeGeo has no "private": a warning, the rule still compiles.
		t.Fatalf("warnings %v", s.Warnings)
	}
	cases := []struct {
		ip, dns string
		want    Action
		needs   bool
	}{
		{"192.168.1.5", "", Direct, false},
		{"10.1.2.3", "", Direct, false},
		{"10.1.2.4", "", Tunnel, true}, // "ru" still depends on the name
		{"77.88.8.8", "", Block, false},
		{"8.8.8.8", "www.youtube.com", Block, false},
		{"8.8.8.8", "example.com", Tunnel, false},
	}
	for _, c := range cases {
		var names []string
		if c.dns != "" {
			names = []string{c.dns}
		}
		r := s.Evaluate(at(c.ip), names)
		if r.NeedsDomain != c.needs || (!c.needs && r.Action != c.want) {
			t.Errorf("%s %s: %+v", c.ip, c.dns, r)
		}
	}
	// SNI path: the address still counts.
	if r := s.EvaluateDomain(at("77.88.8.8"), "example.com", SrcSNI); r.Action != Block {
		t.Errorf("sni: %+v", r)
	}
	if r := s.EvaluateNoDomain(at("10.1.2.4")); r.Action != Tunnel {
		t.Errorf("no domain: %+v", r)
	}
}

func TestAddressOnlyRuleNeverNeedsDomain(t *testing.T) {
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Domains: []string{"1.1.1.0/24"}, Action: Tunnel},
	}})
	s.Main = "p"
	if r := s.Evaluate(at("1.1.1.1"), nil); r.NeedsDomain || r.Action != Tunnel {
		t.Fatalf("%+v", r)
	}
	if r := s.Evaluate(at("1.1.2.1"), nil); r.NeedsDomain || r.Action != Direct {
		t.Fatalf("%+v", r)
	}
}

func TestTypedDomains(t *testing.T) {
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Domains: []string{"keyword:torrent", "regexp:^ads?[0-9]*\\.", "full:only.example", "domain:sub.example"}, Action: Block},
	}})
	for name, want := range map[string]Action{
		"cool-torrent.site": Block, "ad7.example.org": Block, "only.example": Block, "www.only.example": Direct,
		"sub.example": Block, "a.sub.example": Block, "example.org": Direct,
	} {
		if r := s.EvaluateDomain(at("8.8.8.8"), name, SrcSNI); r.Action != want {
			t.Errorf("%s: %v", name, r.Action)
		}
	}
	for _, bad := range []string{"regexp:(", "geosite:", "geoip:", "keyword:", "999.1.1.1/8"} {
		if _, err := Compile(Config{Rules: []Rule{{Domains: []string{bad}, Action: Block}}}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Names are compared in punycode; keyword: and regexp: in Cyrillic still
// match the Unicode form.
func TestTypedDomainsUnicode(t *testing.T) {
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "kw", Domains: []string{"keyword:Банк"}, Action: Tunnel},
		{Name: "re", Domains: []string{`regexp:\.рф$`}, Action: Block},
		{Name: "ascii", Domains: []string{"keyword:shop"}, Action: Tunnel, Profile: "p"},
	}})
	for name, want := range map[string]string{
		"мойбанк.рф": "kw", "www.банк.рус": "kw", "почта.рф": "re", "bank.ru": "default",
		"shop.example": "ascii", "магазин.рф": "re", "xn--80abxggjd.xn--p1ai": "kw",
	} {
		if r := s.EvaluateDomain(at("8.8.8.8"), name, SrcSNI); r.Rule != want {
			t.Errorf("%s: %s, want %s", name, r.Rule, want)
		}
	}
	issues := Lint(Config{Rules: []Rule{
		{Name: "kw", Domains: []string{"keyword:банк"}, Action: Tunnel},
		{Name: "site", Domains: []string{".мойбанк.рф"}, Action: Tunnel},
	}})
	if len(issues) != 1 || issues[0].Index != 1 {
		t.Errorf("keyword:банк covers .мойбанк.рф: %+v", issues)
	}
}

func TestGeoWithoutData(t *testing.T) {
	withGeo(t, nil)
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "yt", Domains: []string{"geosite:youtube"}, Action: Block},
	}})
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "не скачана") {
		t.Fatalf("%v", s.Warnings)
	}
	if r := s.EvaluateDomain(at("8.8.8.8"), "youtube.com", SrcSNI); r.Action != Direct {
		t.Fatal("a category without data must match nothing")
	}
	issues := Lint(Config{Rules: []Rule{{Name: "yt", Domains: []string{"geosite:youtube"}, Action: Block}}})
	if len(issues) != 1 || !strings.Contains(issues[0].Text, "не скачана") {
		t.Fatalf("%+v", issues)
	}
}

func TestExplainAddress(t *testing.T) {
	withGeo(t, fakeGeo{})
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "ru", Domains: []string{"geoip:ru"}, Action: Tunnel},
	}}
	ex := Explain(c, "main", Query{Domain: "ya.ru", IP: netip.MustParseAddr("77.88.8.8"), Proto: 6})
	if !ex.Winner.Winner || ex.Winner.Index != 0 || !strings.Contains(ex.Winner.Reason, "geoip:ru") {
		t.Fatalf("%+v", ex.Winner)
	}
	ex = Explain(c, "main", Query{Domain: "ya.ru", Proto: 6})
	if ex.Winner.Index != -1 || !strings.Contains(ex.Steps[0].Reason, "IP-адрес неизвестен") {
		t.Fatalf("%+v", ex.Steps[0])
	}
}

func TestLintAddresses(t *testing.T) {
	withGeo(t, fakeGeo{})
	issues := Lint(Config{Rules: []Rule{
		{Name: "wide", Domains: []string{"10.0.0.0/8", "geosite:youtube"}, Action: Direct},
		{Name: "narrow", Domains: []string{"10.1.0.0/16"}, Action: Tunnel},
		{Name: "yt", Domains: []string{"geosite:youtube"}, Action: Tunnel},
		{Name: "kw", Domains: []string{"keyword:tube"}, Action: Tunnel},
		{Name: "under", Domains: []string{"youtube.com"}, Action: Tunnel},
	}})
	got := map[int]bool{}
	for _, is := range issues {
		got[is.Index] = true
	}
	if !got[1] || !got[2] || got[3] || !got[4] {
		t.Fatalf("%+v", issues)
	}
}
