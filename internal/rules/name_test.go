package rules

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/lardan099/hyroute/internal/procinfo"
)

// nameGeo has the categories the name tests use.
type nameGeo struct{}

func (nameGeo) Site(n string) (DomainMatcher, error) {
	if n == "ads" {
		return fakeSite{"ads.example": true}, nil
	}
	return nil, errors.New("категории нет")
}

func (nameGeo) IP(n string) (IPMatcher, error) {
	switch n {
	case "ru":
		return fakeIP{netip.MustParsePrefix("77.88.0.0/18")}, nil
	case "private":
		return fakeIP{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16")}, nil
	}
	return nil, errors.New("категории нет")
}

func compileNames(t *testing.T, c Config) *Set {
	t.Helper()
	s, err := compileWith(c, nameGeo{})
	if err != nil {
		t.Fatal(err)
	}
	s.Main = "main"
	return s
}

func TestEvaluateName(t *testing.T) {
	chrome := &procinfo.Info{Name: "chrome.exe", Path: `C:\Chrome\chrome.exe`}
	firefox := &procinfo.Info{Name: "firefox.exe", Path: `C:\Firefox\firefox.exe`}
	off := false
	s := compileNames(t, Config{DefaultAction: Tunnel, DefaultFallback: []string{"fb"}, Rules: []Rule{
		/*0*/ {Name: "disabled", Domains: []string{"example.com"}, Action: Block, Enabled: &off},
		/*1*/ {Name: "lan", Domains: []string{"geoip:private"}, Action: Direct},
		/*2*/ {Name: "tcp site", Domains: []string{"tcp.example"}, Protocol: "tcp", Action: Tunnel, Profile: "de"},
		/*3*/ {Name: "chrome site", Apps: []AppMatch{{Pattern: "chrome.exe"}}, Domains: []string{"app.example"}, Action: Direct},
		/*4*/ {Name: "telegram", Apps: []AppMatch{{Pattern: "telegram.exe"}}, Action: Tunnel},
		/*5*/ {Name: "udp only", Protocol: "udp", Ports: PortList{"5000"}, Action: Block},
		/*6*/ {Name: "port rule", Domains: []string{"port.example"}, Ports: PortList{"443"}, Action: Block},
		/*7*/ {Name: "ru", Domains: []string{"geoip:ru"}, Action: Direct},
		/*8*/ {Name: "mixed", Domains: []string{"mixed.example", "8.8.8.0/24"}, Action: Tunnel, Profile: "nl", Fallback: []string{"de"}},
		/*9*/ {Name: "ads", Domains: []string{"geosite:ads"}, Action: Block},
	}})
	type alt struct {
		pos   int
		cond  NameCond
		local bool
	}
	check := func(label string, r NameResult, pos int, alts ...alt) {
		t.Helper()
		if r.Pos != pos {
			t.Errorf("%s: winner %d (%s), want %d", label, r.Pos, r.Rule, pos)
		}
		if len(r.Alt) != len(alts) {
			t.Fatalf("%s: alt %+v, want %+v", label, r.Alt, alts)
		}
		for i, a := range alts {
			if g := r.Alt[i]; g.Pos != a.pos || g.Cond != a.cond || g.AddrLocal != a.local || g.Pos >= r.Pos {
				t.Errorf("%s: alt[%d] = %+v, want %+v", label, i, g, a)
			}
		}
	}
	// Address-only rules are listed (lan, ru); the default decides.
	addr := []alt{{0, CondAddr, true}, {6, CondAddr, false}, {7, CondAddr, false}}
	r := s.EvaluateName(Subject{}, "other.test", SrcQuery)
	check("default", r, 9, addr...)
	if r.Rule != "default" || r.Action != Tunnel || r.Profile != "main" || len(r.Fallback) != 1 || r.Fallback[0] != "fb" || r.Domain != "other.test" || r.DomainSrc != SrcQuery {
		t.Fatalf("default result %+v", r.Result)
	}
	// Protocol-conditioned site rule: alt with CondProto, the default wins.
	check("tcp", s.EvaluateName(Subject{}, "tcp.example", SrcQuery), 9, alt{0, CondAddr, true}, alt{1, CondProto, false}, alt{6, CondAddr, false}, alt{7, CondAddr, false})
	// Program rule, unknown program: CondApp; the right program: winner;
	// another program: skipped.
	check("app unknown", s.EvaluateName(Subject{}, "app.example", SrcQuery), 9, alt{0, CondAddr, true}, alt{2, CondApp, false}, alt{6, CondAddr, false}, alt{7, CondAddr, false})
	if r := s.EvaluateName(Subject{Proc: chrome}, "app.example", SrcQuery); r.Rule != "chrome site" || r.Action != Direct {
		t.Fatalf("chrome: %+v", r)
	}
	check("app other", s.EvaluateName(Subject{Proc: firefox}, "app.example", SrcQuery), 9, addr...)
	// Program-only and protocol-only rules leave no trace.
	for _, a := range s.EvaluateName(Subject{}, "t.me", SrcQuery).Alt {
		if a.Rule == "telegram" || a.Rule == "udp only" {
			t.Fatalf("program/protocol-only rule in alt: %+v", a)
		}
	}
	// The port clause (ports): a port rule above is conditional.
	check("port", s.EvaluateName(Subject{}, "port.example", SrcQuery), 9, alt{0, CondAddr, true}, alt{5, CondProto, false}, alt{6, CondAddr, false}, alt{7, CondAddr, false})
	// A site and an address: the site item wins the rule; resolution as
	// Evaluate (profile, fallbacks).
	r = s.EvaluateName(Subject{}, "Mixed.Example.", SrcQuery)
	check("mixed", r, 7, alt{0, CondAddr, true}, alt{6, CondAddr, false})
	if r.Profile != "nl" || len(r.Fallback) != 1 || r.Fallback[0] != "de" {
		t.Fatalf("mixed result %+v", r.Result)
	}
	// A geosite rule below the address rules wins by its site.
	check("geosite", s.EvaluateName(Subject{}, "x.ads.example", SrcQuery), 8, addr...)
	// The disabled rule is gone (index 0 is "lan").
	if r := s.EvaluateName(Subject{}, "example.com", SrcQuery); r.Rule != "default" {
		t.Fatalf("disabled rule decided: %+v", r)
	}
	// A rule without an unknown part and without destinations wins at once.
	s2 := compileNames(t, Config{DefaultAction: Direct, Rules: []Rule{{Name: "chrome", Apps: []AppMatch{{Pattern: "chrome.exe"}}, Action: Tunnel}}})
	if r := s2.EvaluateName(Subject{Proc: chrome}, "a.test", SrcQuery); r.Rule != "chrome" || r.Pos != 0 || r.Profile != "main" {
		t.Fatalf("program winner: %+v", r)
	}
	if r := s2.EvaluateName(Subject{}, "a.test", SrcQuery); r.Rule != "default" || len(r.Alt) != 0 || r.Pos != 1 {
		t.Fatalf("program-only for the DNS client: %+v", r)
	}
}

func TestAddrLocal(t *testing.T) {
	for _, c := range []struct {
		items []string
		local bool
	}{
		{[]string{"geoip:private"}, true},
		{[]string{"GeoIP:Private"}, true},
		{[]string{"192.168.0.0/16"}, true},
		{[]string{"10.1.2.3", "fd00::/8", "fe80::1"}, true},
		{[]string{"100.64.0.0/10"}, true},
		{[]string{"127.0.0.1"}, true},
		{[]string{"geoip:missing"}, true}, // matches nothing
		{[]string{"geoip:ru"}, false},
		{[]string{"8.8.8.0/24"}, false},
		{[]string{"192.168.0.0/16", "8.8.8.8"}, false},
		{[]string{"geoip:private", "geoip:ru"}, false},
		{[]string{"0.0.0.0/0"}, false},
		{[]string{"::/0"}, false},
		{[]string{"10.0.0.0/7"}, false},
	} {
		s := compileNames(t, Config{Rules: []Rule{{Name: "r", Domains: c.items, Action: Direct}}})
		r := s.EvaluateName(Subject{}, "name.test", SrcQuery)
		if len(r.Alt) != 1 || r.Alt[0].Cond != CondAddr || r.Alt[0].AddrLocal != c.local {
			t.Errorf("%v: %+v, want AddrLocal %v", c.items, r.Alt, c.local)
		}
	}
}
