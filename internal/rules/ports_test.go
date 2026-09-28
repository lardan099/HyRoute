package rules

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParsePorts(t *testing.T) {
	for in, want := range map[string][]PortRange{
		"":                     nil,
		"443":                  {{443, 443}},
		" 80, 443 ":            {{80, 80}, {443, 443}},
		"27000-27200 27015;22": {{27000, 27200}, {27015, 27015}, {22, 22}},
		"1-65535":              {{1, 65535}},
	} {
		got, err := ParsePorts(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"0", "65536", "a", "5-1", "1-", "-5", "+22", "22/tcp"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got := FormatPorts(" 80;443  27000-27200"); got != "80,443,27000-27200" {
		t.Fatal(got)
	}
}

func withDst(s Subject, addr string) Subject {
	s.Dst = netip.MustParseAddrPort(addr)
	return s
}

func TestPortRules(t *testing.T) {
	ssh := proc(`C:\Windows\System32\OpenSSH\ssh.exe`, nil)
	game := proc(`C:\Games\game.exe`, nil)
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "ssh", Apps: []AppMatch{{Pattern: "ssh.exe"}}, Ports: "22", Action: Tunnel, Profile: "de"},
		{Name: "game", Apps: []AppMatch{{Pattern: "game.exe"}}, Protocol: "udp", Ports: "27000-27200", Action: Tunnel, Profile: "nl"},
		{Name: "web", Domains: []string{".example.com"}, Protocol: "tcp", Ports: "443", Action: Tunnel, Profile: "us"},
		{Name: "dns", Protocol: "udp", Ports: "53", Action: Block},
	}})
	base := Subject{Proto: 6}
	for _, c := range []struct {
		sub    Subject
		domain string
		rule   string
	}{
		{withDst(Subject{Proc: ssh, Proto: 6}, "203.0.113.5:22"), "", "ssh"},
		{withDst(Subject{Proc: ssh, Proto: 6}, "203.0.113.5:2222"), "", "default"},
		{withDst(Subject{Proc: game, Proto: 17}, "203.0.113.5:27015"), "", "game"},
		{withDst(Subject{Proc: game, Proto: 17}, "203.0.113.5:27201"), "", "default"},
		{withDst(Subject{Proc: game, Proto: 6}, "203.0.113.5:27015"), "", "default"},
		{withDst(base, "93.184.216.34:443"), "www.example.com", "web"},
		{withDst(base, "93.184.216.34:8443"), "www.example.com", "default"},
		{withDst(Subject{Proc: game, Proto: 17}, "8.8.8.8:53"), "", "dns"},
		{withDst(Subject{Proto: 6}, "8.8.8.8:53"), "", "default"},
	} {
		if got := s.EvaluateDomain(c.sub, c.domain, SrcSNI).Rule; got != c.rule {
			t.Errorf("%v %s: got %s want %s", c.sub.Dst, c.domain, got, c.rule)
		}
	}
	// A port rule decides at packet level: another port never needs the
	// name of the site.
	if r := s.Evaluate(withDst(base, "93.184.216.34:80"), nil); r.NeedsDomain || r.Rule != "default" {
		t.Fatalf("%+v", r)
	}
	if r := s.Evaluate(withDst(base, "93.184.216.34:443"), nil); !r.NeedsDomain {
		t.Fatalf("%+v", r)
	}
}

func TestPortRuleValidation(t *testing.T) {
	if _, err := Compile(Config{Rules: []Rule{{Name: "x", Ports: "70000", Action: Block}}}); err == nil || !strings.Contains(err.Error(), "порт") {
		t.Fatal(err)
	}
	if _, err := Compile(Config{Rules: []Rule{{Name: "x", Action: Block}}}); err == nil {
		t.Fatal("a rule without programs, sites and ports compiled")
	}
	if _, err := Compile(Config{Rules: []Rule{{Name: "x", Ports: "53", Action: Block}}}); err != nil {
		t.Fatal(err)
	}
}

func TestPortExplainAndLint(t *testing.T) {
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "wide", Ports: "20-30, 31-40", Action: Tunnel},
		{Name: "narrow", Apps: []AppMatch{{Pattern: "ssh.exe"}}, Ports: "22,35", Action: Tunnel},
		{Name: "other", Ports: "41", Action: Block},
	}}
	issues := Lint(c)
	if len(issues) != 1 || issues[0].Index != 1 {
		t.Fatalf("%+v", issues)
	}
	ex := Explain(c, "main", Query{App: "ssh.exe", Proto: 6, Port: 22})
	if ex.Winner.Name != "wide" || !strings.Contains(ex.Winner.Reason, "порт 22") {
		t.Fatalf("%+v", ex.Winner)
	}
	ex = Explain(c, "main", Query{App: "ssh.exe", Proto: 6, Port: 41})
	if ex.Winner.Name != "other" || !strings.Contains(ex.Steps[0].Reason, "порт 41") {
		t.Fatalf("%+v", ex.Steps)
	}
	ex = Explain(c, "main", Query{App: "ssh.exe", Proto: 6})
	if ex.Winner.Index != -1 || !strings.Contains(ex.Steps[0].Reason, "порт не указан") || len(ex.Notes) == 0 {
		t.Fatalf("%+v", ex)
	}
}
