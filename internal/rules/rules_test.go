package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/procinfo"
)

func proc(path string, parent *procinfo.Info) *procinfo.Info {
	in := &procinfo.Info{Path: path, Parent: parent}
	if path != "" {
		b := path[len(path)-1:]
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == '\\' {
				b = path[i+1:]
				break
			}
		}
		in.Name = lower(b)
	}
	return in
}

func lower(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 32
		}
	}
	return string(out)
}

func mustCompile(t *testing.T, c Config) *Set {
	t.Helper()
	s, err := Compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sub(p *procinfo.Info, proto uint8) Subject {
	return Subject{Proc: p, Proto: proto, Dst: netip.MustParseAddrPort("93.184.216.34:443")}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM.":    "example.com",
		" example.com ":   "example.com",
		"пример.рф":       "xn--e1afmkfd.xn--p1ai",
		"XN--E1AFMKFD.РФ": "xn--e1afmkfd.xn--p1ai",
		"":                "",
		".":               "",
	} {
		if got := NormalizeDomain(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestDomainPatterns(t *testing.T) {
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "exact", Domain: &DomainMatch{"Example.com."}, Action: Tunnel},
		{Name: "sub", Domain: &DomainMatch{"*.sub.org"}, Action: Block},
		{Name: "suffix", Domain: &DomainMatch{".suffix.net"}, Action: Tunnel},
		{Name: "idn", Domain: &DomainMatch{"*.пример.рф"}, Action: Tunnel},
	}})
	cases := map[string]string{
		"example.com":               "exact",
		"EXAMPLE.COM.":              "exact",
		"www.example.com":           "default",
		"sub.org":                   "default",
		"a.sub.org":                 "sub",
		"a.b.sub.org":               "sub",
		"xsub.org":                  "default",
		"suffix.net":                "suffix",
		"a.suffix.net":              "suffix",
		"notsuffix.net":             "default",
		"www.пример.рф":             "idn",
		"www.xn--e1afmkfd.xn--p1ai": "idn",
	}
	for d, want := range cases {
		if got := s.EvaluateDomain(sub(nil, 6), d, SrcSNI).Rule; got != want {
			t.Errorf("%q: got %q want %q", d, got, want)
		}
	}
}

func TestAppMatchingAndInheritance(t *testing.T) {
	launcher := proc(`C:\Launcher\Launcher.exe`, nil)
	game := proc(`C:\Games\Foo\Bin\game.exe`, launcher)
	chrome := proc(`C:\Program Files\Google\Chrome\Application\chrome.exe`, nil)
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "launcher tree", App: &AppMatch{Pattern: "launcher.exe", InheritChildren: true}, Action: Tunnel},
		{Name: "games glob", App: &AppMatch{Pattern: `C:\Games\*`}, Protocol: "udp", Action: Block},
		{Name: "chrome path", App: &AppMatch{Pattern: `c:/program files/google/chrome/application/CHROME.EXE`}, Action: Tunnel},
	}})
	if r := s.EvaluateNoDomain(sub(game, 6)); r.Rule != "launcher tree" {
		t.Fatalf("inherit: %+v", r)
	}
	if r := s.EvaluateNoDomain(sub(chrome, 17)); r.Rule != "chrome path" {
		t.Fatalf("path: %+v", r)
	}
	// Without inheritance the parent does not count.
	s2 := mustCompile(t, Config{Rules: []Rule{{Name: "l", App: &AppMatch{Pattern: "launcher.exe"}, Action: Tunnel}}})
	if r := s2.EvaluateNoDomain(sub(game, 6)); r.Rule != "default" {
		t.Fatalf("no inherit: %+v", r)
	}
	// Glob matches nested folders; protocol filter applies.
	s3 := mustCompile(t, Config{Rules: []Rule{{Name: "g", App: &AppMatch{Pattern: `C:\Games\*`}, Protocol: "udp", Action: Block}}})
	if r := s3.EvaluateNoDomain(sub(game, 17)); r.Rule != "g" {
		t.Fatalf("glob udp: %+v", r)
	}
	if r := s3.EvaluateNoDomain(sub(game, 6)); r.Rule != "default" {
		t.Fatalf("glob tcp must not match: %+v", r)
	}
	// Unknown process never matches app rules.
	if r := s.EvaluateNoDomain(sub(nil, 6)); r.Rule != "default" {
		t.Fatalf("unknown proc: %+v", r)
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		p, s string
		ok   bool
	}{
		{`c:\games\*`, `c:\games\a\b.exe`, true},
		{`c:\games\*.exe`, `c:\games\x\y.exe`, true},
		{`c:\games\*.exe`, `c:\games\x\y.dll`, false},
		{`c:\g?mes\*`, `c:\games\a`, true},
		{`*chrome.exe`, `c:\x\chrome.exe`, true},
		{`c:\games\*`, `c:\gamesx`, false},
		{`*`, ``, true},
		{`a*b*c`, `axxbyyc`, true},
		{`a*b*c`, `axxbyy`, false},
		// ? is one character, not one byte of UTF-8.
		{`c:\игр?\*`, `c:\игры\game.exe`, true},
		{`c:\игр??\*`, `c:\игры\game.exe`, false},
		{`c:\*?ры\x.exe`, `c:\игры\x.exe`, true},
		{`*???`, `ыы`, false},
		{`*??`, `ыы`, true},
	} {
		if globMatch(c.p, c.s) != c.ok {
			t.Errorf("%s ~ %s: want %v", c.p, c.s, c.ok)
		}
	}
}

func TestFirstMatchAndComposite(t *testing.T) {
	discord := proc(`C:\Discord\Discord.exe`, nil)
	chrome := proc(`C:\Chrome\chrome.exe`, nil)
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "discord gg", App: &AppMatch{Pattern: "discord.exe"}, Domain: &DomainMatch{"*.discord.gg"}, Action: Tunnel},
		{Name: "chrome company", App: &AppMatch{Pattern: "chrome.exe"}, Domain: &DomainMatch{"company.local"}, Action: Direct},
		{Name: "youtube", Domain: &DomainMatch{"*.youtube.com"}, Action: Tunnel},
		{Name: "chrome all", App: &AppMatch{Pattern: "chrome.exe"}, Action: Block},
	}})
	for _, c := range []struct {
		p    *procinfo.Info
		d    string
		rule string
	}{
		{discord, "gateway.discord.gg", "discord gg"},
		{discord, "www.youtube.com", "youtube"},
		{discord, "example.org", "default"},
		{chrome, "company.local", "chrome company"},
		{chrome, "www.youtube.com", "youtube"},
		{chrome, "example.org", "chrome all"},
		{nil, "m.youtube.com", "youtube"},
	} {
		if got := s.EvaluateDomain(sub(c.p, 6), c.d, SrcSNI).Rule; got != c.rule {
			t.Errorf("%v %s: got %s want %s", c.p != nil, c.d, got, c.rule)
		}
	}
	// Disabled rules are skipped.
	off := false
	s2 := mustCompile(t, Config{Rules: []Rule{{Name: "x", Enabled: &off, Domain: &DomainMatch{"a.b"}, Action: Block}}})
	if s2.EvaluateDomain(sub(nil, 6), "a.b", SrcSNI).Rule != "default" {
		t.Fatal("disabled rule matched")
	}
}

func TestTriStateEvaluate(t *testing.T) {
	chrome := proc(`C:\Chrome\chrome.exe`, nil)
	curl := proc(`C:\curl.exe`, nil)
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "curl", App: &AppMatch{Pattern: "curl.exe"}, Action: Tunnel},
		{Name: "yt", Domain: &DomainMatch{".youtube.com"}, Action: Tunnel},
		{Name: "chrome direct", App: &AppMatch{Pattern: "chrome.exe"}, Action: Direct},
	}})
	// App-only rule before any domain rule: final at packet level.
	if r := s.Evaluate(sub(curl, 6), nil); r.NeedsDomain || r.Action != Tunnel || r.Rule != "curl" {
		t.Fatalf("app-only: %+v", r)
	}
	// Unknown IP, outcome depends on domain.
	if r := s.Evaluate(sub(chrome, 6), nil); !r.NeedsDomain {
		t.Fatalf("expected NeedsDomain: %+v", r)
	}
	// DNS names that all agree settle it.
	if r := s.Evaluate(sub(chrome, 6), []string{"www.youtube.com", "youtube.com"}); r.NeedsDomain || r.Action != Tunnel || r.DomainSrc != SrcDNS {
		t.Fatalf("dns agree: %+v", r)
	}
	// CDN IP with names that disagree: NeedsDomain.
	if r := s.Evaluate(sub(chrome, 6), []string{"www.youtube.com", "example.org"}); !r.NeedsDomain {
		t.Fatalf("dns disagree: %+v", r)
	}
	// Branches that converge are final even without a domain.
	s2 := mustCompile(t, Config{DefaultAction: Tunnel, Rules: []Rule{
		{Name: "yt", Domain: &DomainMatch{".youtube.com"}, Action: Tunnel},
	}})
	if r := s2.Evaluate(sub(chrome, 6), nil); r.NeedsDomain || r.Action != Tunnel || r.Rule != "default" {
		t.Fatalf("converging: %+v", r)
	}
	// No domain rules at all: always final.
	s3 := mustCompile(t, Config{DefaultAction: Direct})
	if r := s3.Evaluate(sub(chrome, 17), nil); r.NeedsDomain || r.Rule != "default" {
		t.Fatalf("empty: %+v", r)
	}
	// Fallback without a domain skips domain rules.
	if r := s.EvaluateNoDomain(sub(chrome, 6)); r.Rule != "chrome direct" {
		t.Fatalf("no-domain fallback: %+v", r)
	}
	// Domain rules restricted to another app do not create ambiguity.
	s4 := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "d", App: &AppMatch{Pattern: "discord.exe"}, Domain: &DomainMatch{"*.discord.gg"}, Action: Tunnel},
	}})
	if r := s4.Evaluate(sub(chrome, 6), nil); r.NeedsDomain {
		t.Fatal("rule for another app made chrome ambiguous")
	}
}

// The names of one CNAME chain are one site: the first rule that matches
// any of them decides it. Only different sites on an address can disagree.
func TestEvaluateSites(t *testing.T) {
	chrome := proc(`C:\Chrome\chrome.exe`, nil)
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "yt", Domain: &DomainMatch{".youtube.com"}, Action: Tunnel},
		{Name: "cdn", Domain: &DomainMatch{".cdn.test"}, Action: Block},
		{Name: "chrome direct", App: &AppMatch{Pattern: "chrome.exe"}, Action: Direct},
	}})
	chain := []string{"www.youtube.com", "youtube-ui.l.google.com"}
	if r := s.EvaluateSites(sub(chrome, 17), [][]string{chain}); r.NeedsDomain || r.Rule != "yt" || r.DomainSrc != SrcDNS || r.Domain != "www.youtube.com,youtube-ui.l.google.com" {
		t.Fatalf("chain: %+v", r)
	}
	// As separate names they disagree.
	if r := s.Evaluate(sub(chrome, 17), chain); !r.NeedsDomain {
		t.Fatalf("names: %+v", r)
	}
	// A rule on the CDN name applies too; the earlier rule wins.
	if r := s.EvaluateSites(sub(chrome, 6), [][]string{{"a.example", "edge.cdn.test"}}); r.Rule != "cdn" {
		t.Fatalf("cdn name: %+v", r)
	}
	if r := s.EvaluateSites(sub(chrome, 6), [][]string{{"edge.cdn.test", "www.youtube.com"}}); r.Rule != "yt" {
		t.Fatalf("rule order: %+v", r)
	}
	// Two sites on one address with different routes: NeedsDomain.
	if r := s.EvaluateSites(sub(chrome, 6), [][]string{chain, {"other.example"}}); !r.NeedsDomain {
		t.Fatalf("neighbours: %+v", r)
	}
	if r := s.EvaluateSites(sub(chrome, 6), [][]string{chain, {"m.youtube.com"}}); r.NeedsDomain || r.Action != Tunnel {
		t.Fatalf("agreeing neighbours: %+v", r)
	}
}

// Explain agrees with EvaluateSites: a CNAME chain is one site, matched by
// a rule on any of its names; only different sites can split.
func TestExplainSites(t *testing.T) {
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "yt", Domains: []string{".youtube.com"}, Action: Tunnel},
	}}
	s := mustCompile(t, c)
	ip := netip.MustParseAddr("142.250.1.2")
	chain := []string{"www.youtube.com", "youtube-ui.l.google.com"}
	for _, proto := range []uint8{6, 17} {
		sub := Subject{Proto: proto, Dst: netip.AddrPortFrom(ip, 443)}
		want := s.EvaluateSites(sub, [][]string{chain})
		ex := Explain(c, "main", Query{IP: ip, Sites: [][]string{chain}, Proto: proto})
		if want.Rule != "yt" || ex.Winner.Name != want.Rule || !strings.Contains(ex.Winner.Reason, "www.youtube.com") ||
			!strings.Contains(strings.Join(ex.Notes, " "), "CNAME") || strings.Contains(strings.Join(ex.Notes, " "), "расходятся") {
			t.Fatalf("proto %d: engine %+v, explain %+v %v", proto, want, ex.Winner, ex.Notes)
		}
		// Another site with another route on the address: a split.
		sites := [][]string{chain, {"other.example"}}
		if !s.EvaluateSites(sub, sites).NeedsDomain {
			t.Fatal("neighbours agree")
		}
		ex = Explain(c, "main", Query{IP: ip, Sites: sites, Proto: proto})
		if !strings.Contains(strings.Join(ex.Notes, " "), "расходятся") {
			t.Fatalf("proto %d: split not reported: %v", proto, ex.Notes)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	for _, r := range []Rule{
		{Name: "empty"},
		{Name: "app", App: &AppMatch{Pattern: " "}},
		{Name: "kind", App: &AppMatch{Pattern: "a.exe", Kind: "regex"}},
		{Name: "dom", Domain: &DomainMatch{"a.*.com"}},
		{Name: "dom2", Domain: &DomainMatch{"*."}},
		{Name: "proto", Domain: &DomainMatch{"a.com"}, Protocol: "icmp"},
	} {
		if _, err := Compile(Config{Rules: []Rule{r}}); err == nil {
			t.Errorf("%s: expected error", r.Name)
		}
	}
}

func TestLoadJSON(t *testing.T) {
	c, err := Load([]byte(`{"defaultAction":"tunnel","rules":[{"name":"x","app":{"pattern":"a.exe","inheritChildren":true},"domain":{"pattern":".x.com"},"protocol":"tcp","action":"block"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.DefaultAction != Tunnel || c.Rules[0].Action != Block || !c.Rules[0].App.InheritChildren {
		t.Fatalf("%+v", c)
	}
	if _, err := Load([]byte(`{"defaultAction":"sideways"}`)); err == nil {
		t.Fatal("bad action accepted")
	}
}

func TestFallbackResolved(t *testing.T) {
	s := mustCompile(t, Config{
		DefaultAction:   Tunnel,
		DefaultFallback: []string{"nl", "", "nl"},
		Rules: []Rule{
			{Name: "yt", Domains: []string{"youtube.com"}, Action: Tunnel, Profile: "de", Fallback: []string{"de", "nl", "us"}},
			{Name: "direct", Domains: []string{"example.org"}, Action: Direct, Fallback: []string{"nl"}},
		},
	})
	s.Main = "main"
	r := s.EvaluateDomain(sub(nil, 6), "youtube.com", SrcSNI)
	if r.Profile != "de" || strings.Join(r.Fallback, ",") != "nl,us" {
		t.Fatalf("rule: %+v", r)
	}
	// The default route: "" is the main profile, repeats are dropped.
	r = s.EvaluateDomain(sub(nil, 6), "other.com", SrcSNI)
	if r.Profile != "main" || strings.Join(r.Fallback, ",") != "nl" {
		t.Fatalf("default: %+v", r)
	}
	if r := s.EvaluateDomain(sub(nil, 6), "example.org", SrcSNI); r.Fallback != nil {
		t.Fatalf("direct has no fallback: %+v", r)
	}
	// Fallback profiles are started with the rest.
	if got := strings.Join(s.Profiles(), ","); got != "de,main,nl,us" {
		t.Fatal(got)
	}
}

// ---- ports ----

func TestCompilePortRules(t *testing.T) {
	off := false
	if _, err := Compile(Config{Rules: []Rule{{Protocol: "tcp", Ports: PortList{"22"}, Action: Direct}}}); err != nil {
		t.Fatalf("port-only: %v", err)
	}
	if _, err := Compile(Config{Rules: []Rule{{Name: "x", Protocol: "udp", Action: Direct}}}); err == nil || err.Error() != "x: укажите программу, сайт или порт" {
		t.Fatalf("protocol only: %v", err)
	}
	if _, err := Compile(Config{Rules: []Rule{{Name: "SSH", Domains: []string{"a.com"}, Ports: PortList{"0"}, Action: Direct}}}); err == nil || !strings.HasPrefix(err.Error(), "SSH: неверный порт «0»") {
		t.Fatalf("bad port: %v", err)
	}
	// Ports of disabled rules are validated; their other conditions are not.
	if _, err := Compile(Config{Rules: []Rule{{Name: "d", Enabled: &off, Ports: PortList{"0"}, Action: Direct}}}); err == nil || !strings.HasPrefix(err.Error(), "d: ") {
		t.Fatalf("disabled bad port: %v", err)
	}
	if _, err := Compile(Config{Rules: []Rule{{Name: "d", Enabled: &off, Domains: []string{"regexp:("}, Action: Direct}}}); err != nil {
		t.Fatalf("disabled bad regexp: %v", err)
	}
	many := make(PortList, MaxPortItems+1)
	for i := range many {
		many[i] = fmt.Sprint(i + 1)
	}
	// A stored list is not bounded (v1.2.0 had no limit); typed input is.
	if _, err := Compile(Config{Rules: []Rule{{Name: "many", Ports: many, Action: Direct}}}); err != nil {
		t.Fatalf("257: %v", err)
	}
	if _, err := ParsePortList(strings.Join(many, ",")); !errors.Is(err, ErrTooManyPorts) {
		t.Fatalf("257 typed: %v", err)
	}
}

func TestRuleNamePorts(t *testing.T) {
	for _, c := range []struct {
		r    Rule
		want string
	}{
		{Rule{Protocol: "tcp", Ports: PortList{"22"}}, "TCP 22"},
		{Rule{Ports: PortList{"443"}}, "порт 443"},
		{Rule{Ports: PortList{"0"}}, "правило 3"},
		{Rule{Apps: []AppMatch{{Pattern: "a.exe"}}, Ports: PortList{"22"}}, "правило 3"},
		{Rule{Name: "SSH", Ports: PortList{"22"}}, "SSH"},
	} {
		if got := ruleName(2, c.r); got != c.want {
			t.Errorf("%+v: %q", c.r, got)
		}
	}
	// The label reaches the result (Connections, the log).
	s := mustCompile(t, Config{DefaultAction: Tunnel, Rules: []Rule{{Protocol: "tcp", Ports: PortList{"22"}, Action: Direct}}})
	if r := s.EvaluateNoDomain(Subject{Proto: 6, Dst: netip.MustParseAddrPort("1.2.3.4:22")}); r.Rule != "TCP 22" || r.Action != Direct {
		t.Fatalf("%+v", r)
	}
}

func TestEvaluatePorts(t *testing.T) {
	discord := proc(`C:\Discord\Discord.exe`, nil)
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "discord", Apps: []AppMatch{{Pattern: "discord.exe"}}, Protocol: "udp", Ports: PortList{"50000-65535"}, Action: Tunnel},
	}})
	at := func(p *procinfo.Info, proto uint8, port uint16) Result {
		return s.Evaluate(Subject{Proc: p, Proto: proto, Dst: netip.AddrPortFrom(netip.MustParseAddr("1.2.3.4"), port)}, nil)
	}
	for _, c := range []struct {
		p     *procinfo.Info
		proto uint8
		port  uint16
		want  Action
	}{
		{discord, 17, 50001, Tunnel},
		{discord, 17, 443, Direct},
		{discord, 6, 50001, Direct},
		{nil, 17, 50001, Direct},
		{discord, 17, 0, Direct}, // an unknown port never matches
	} {
		if r := at(c.p, c.proto, c.port); r.NeedsDomain || r.Action != c.want {
			t.Errorf("%v %d %d: %+v", c.p != nil, c.proto, c.port, r)
		}
	}
}

// A port condition is decided at packet level: a flow to a port the domain
// rule does not cover never waits for its name.
func TestTriStatePorts(t *testing.T) {
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "yt", Domains: []string{".youtube.com"}, Protocol: "tcp", Ports: PortList{"443"}, Action: Tunnel},
	}})
	ip := netip.MustParseAddr("1.2.3.4")
	s80 := Subject{Proto: 6, Dst: netip.AddrPortFrom(ip, 80)}
	s443 := Subject{Proto: 6, Dst: netip.AddrPortFrom(ip, 443)}
	if r := s.Evaluate(s80, nil); r.NeedsDomain || r.Action != Direct {
		t.Fatalf(":80 %+v", r)
	}
	if r := s.Evaluate(s443, nil); !r.NeedsDomain {
		t.Fatalf(":443 %+v", r)
	}
	if r := s.EvaluateDomain(s443, "www.youtube.com", SrcSNI); r.Action != Tunnel {
		t.Fatalf("sni :443 %+v", r)
	}
	if r := s.EvaluateDomain(s80, "www.youtube.com", SrcHost); r.Action != Direct {
		t.Fatalf("host :80 %+v", r)
	}
}

// Rules without ports keep the v1.0.0 JSON: no "ports" key.
func TestPortlessRuleJSON(t *testing.T) {
	b, err := json.Marshal(Rule{Name: "x", Domains: []string{".a.com"}, Protocol: "tcp", Action: Tunnel})
	if err != nil || strings.Contains(string(b), "ports") {
		t.Fatalf("%s %v", b, err)
	}
	b, _ = json.Marshal(Rule{Name: "x", Domains: []string{".a.com"}, Ports: PortList{}, Action: Tunnel})
	if strings.Contains(string(b), "ports") {
		t.Fatalf("empty: %s", b)
	}
}
