package rules

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/procinfo"
)

// Explain and Lint of rules with ports.

func TestExplainPorts(t *testing.T) {
	off := false
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "web", Domains: []string{".x.com"}, Ports: PortList{"80", "443"}, Action: Tunnel},
		{Name: "ssh", Protocol: "tcp", Ports: PortList{"22"}, Action: Block},
		{Name: "games", Ports: PortList{"27000-27100", "443"}, Action: Tunnel, Enabled: &off},
	}}
	ex := Explain(c, "main", Query{Domain: "x.com", Proto: 6, Port: 443})
	if ex.Winner.Name != "web" || !strings.Contains(ex.Winner.Reason, "порт 443") || !ex.PortRules {
		t.Fatalf("443: %+v", ex.Winner)
	}
	ex = Explain(c, "main", Query{Domain: "x.com", Proto: 6, Port: 8080})
	if ex.Winner.Index != -1 || ex.Steps[0].Reason != "порт 8080 не из списка правила: 80, 443" {
		t.Fatalf("8080: %+v", ex.Steps[0])
	}
	ex = Explain(c, "main", Query{Domain: "x.com", Proto: 6})
	notes := strings.Join(ex.Notes, " ")
	if ex.Winner.Index != -1 || ex.Steps[0].Reason != "порт не указан, а правило только для портов 80, 443" ||
		ex.Steps[1].Reason != "порт не указан, а правило только для порта 22" || !strings.Contains(notes, "Порт не указан, поэтому") {
		t.Fatalf("no port: %+v %v", ex.Steps, ex.Notes)
	}
	// A port-only question.
	if ex = Explain(c, "main", Query{Proto: 6, Port: 22}); ex.Winner.Name != "ssh" {
		t.Fatalf("22: %+v", ex.Winner)
	}
	// Only enabled port rules count for the note and PortRules.
	c2 := Config{Rules: []Rule{c.Rules[2], {Name: "a", Domains: []string{".a.com"}, Action: Tunnel}}}
	if ex = Explain(c2, "main", Query{Domain: "a.com", Proto: 6}); ex.PortRules || strings.Contains(strings.Join(ex.Notes, " "), "Порт не указан") {
		t.Fatalf("disabled: %+v %v", ex.PortRules, ex.Notes)
	}
}

func TestLintPorts(t *testing.T) {
	off := false
	issues := func(c Config) map[int][]Issue {
		m := map[int][]Issue{}
		for _, is := range LintWith(c, LintOptions{}) {
			m[is.Index] = append(m[is.Index], is)
		}
		return m
	}
	c := Config{Rules: []Rule{
		{Name: "wide", Domains: []string{"a.com"}, Protocol: "tcp", Ports: PortList{"1-1000"}, Action: Tunnel},
		{Name: "narrow", Domains: []string{"a.com"}, Protocol: "tcp", Ports: PortList{"22"}, Action: Tunnel},
		{Name: "p22", Ports: PortList{"22"}, Action: Direct},
		{Name: "portless", Domains: []string{"b.com"}, Action: Tunnel},
		{Name: "all", Ports: PortList{"1-65535"}, Action: Direct},
		{Name: "portless2", Domains: []string{"c.com"}, Action: Tunnel},
	}}
	got := issues(c)
	if len(got[1]) != 1 || !strings.Contains(got[1][0].Text, "Лишнее") {
		t.Fatalf("narrow: %+v", got)
	}
	if len(got[3]) != 0 || len(got[5]) != 1 || !strings.Contains(got[5][0].Text, "Никогда не сработает") {
		t.Fatalf("portless: %+v", got)
	}
	// Replies of local UDP servers: info for a UDP/any range touching
	// 49152-65535 without a program.
	for _, c := range []struct {
		r    Rule
		want int
	}{
		{Rule{Protocol: "udp", Ports: PortList{"50000-65535"}}, 1},
		{Rule{Ports: PortList{"60000"}}, 1},
		{Rule{Apps: []AppMatch{{Pattern: "discord.exe"}}, Protocol: "udp", Ports: PortList{"50000-65535"}}, 0},
		{Rule{Protocol: "tcp", Ports: PortList{"50000-65535"}}, 0},
		{Rule{Ports: PortList{"443"}}, 0},
		{Rule{Protocol: "udp", Ports: PortList{"50000-65535"}, Enabled: &off}, 0},
	} {
		is := issues(Config{Rules: []Rule{c.r}})[0]
		if len(is) != c.want || c.want == 1 && (is[0].Severity != "info" || !strings.Contains(is[0].Text, "49152–65535")) {
			t.Errorf("%+v: %+v", c.r, is)
		}
	}
}

func TestLintQUIC(t *testing.T) {
	off := false
	cfg := func(r Rule) Config {
		r.Name, r.Action = "r", Tunnel
		return Config{Rules: []Rule{r}}
	}
	for _, c := range []struct {
		r    Rule
		o    bool
		want bool
	}{
		{Rule{Domains: []string{".youtube.com"}, Protocol: "udp", Ports: PortList{"443"}}, true, true},
		{Rule{Domains: []string{".youtube.com"}, Protocol: "udp", Ports: PortList{"443"}}, false, false},
		{Rule{Domains: []string{".youtube.com"}, Protocol: "udp", Ports: PortList{"400-500"}}, true, true},
		{Rule{Domains: []string{".youtube.com"}, Protocol: "udp", Ports: PortList{"50000-65535"}}, true, false},
		{Rule{Domains: []string{".youtube.com"}, Ports: PortList{"443"}}, true, false},
		{Rule{Domains: []string{".youtube.com"}, Protocol: "tcp", Ports: PortList{"443"}}, true, false},
		{Rule{Domains: []string{"8.8.8.8"}, Protocol: "udp", Ports: PortList{"443"}}, true, false},
		{Rule{Domains: []string{"geoip:ru"}, Protocol: "udp", Ports: PortList{"443"}}, true, false},
		{Rule{Apps: []AppMatch{{Pattern: "chrome.exe"}}, Protocol: "udp", Ports: PortList{"443"}}, true, false},
		{Rule{Apps: []AppMatch{{Pattern: "chrome.exe"}}, Domains: []string{".youtube.com"}, Protocol: "udp", Ports: PortList{"443"}}, true, true},
		{Rule{Domains: []string{".youtube.com"}, Protocol: "udp", Ports: PortList{"443"}, Enabled: &off}, true, false},
	} {
		warn := false
		for _, is := range LintWith(cfg(c.r), LintOptions{QUICNameless: c.o}) {
			if strings.Contains(is.Text, "QUIC") {
				warn = is.Severity == "warn"
			}
		}
		if warn != c.want {
			t.Errorf("%+v %v: %v", c.r, c.o, warn)
		}
	}
	c := cfg(Rule{Domains: []string{".youtube.com"}, Protocol: "udp", Ports: PortList{"443"}})
	if a, b := Lint(c), LintWith(c, LintOptions{QUICNameless: true}); len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Fatalf("Lint: %+v %+v", a, b)
	}
}

func TestNamelessUDP(t *testing.T) {
	for _, exact := range []bool{false, true} {
		for _, block := range []bool{false, true} {
			for _, proto := range []uint8{6, 17} {
				for _, port := range []uint16{443, 444} {
					want := exact && block && proto == 17 && port == 443
					if NamelessUDP(exact, block, proto, port) != want {
						t.Errorf("%v %v %d %d", exact, block, proto, port)
					}
				}
			}
		}
	}
}

// Explain decides UDP 443 without the name when the engine does, and
// agrees with Set.Evaluate: the winner is «Блокировка QUIC» exactly when
// Evaluate needs the domain.
func TestExplainQUICNameless(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	nip := netip.MustParseAddr("198.51.100.1")
	yt := Rule{Name: "yt", Domains: []string{".youtube.com"}, Protocol: "udp", Ports: PortList{"443"}, Action: Tunnel, Profile: "de"}
	chrome := Rule{Name: "chrome", Apps: []AppMatch{{Pattern: "chrome.exe"}}, Protocol: "udp", Ports: PortList{"443"}, Action: Tunnel, Profile: "de"}
	portOnly := Rule{Name: "p", Ports: PortList{"443"}, Protocol: "udp", Action: Tunnel, Profile: "de"}
	network := Rule{Name: "net", Domains: []string{"198.51.100.0/24"}, Protocol: "udp", Ports: PortList{"443"}, Action: Tunnel, Profile: "de"}
	for _, c := range []struct {
		name  string
		rules []Rule
		q     Query
		block bool
		win   string
		note  string
	}{
		{"site", []Rule{yt}, Query{Domain: "youtube.com", Proto: 17, Port: 443, QUICNameless: true}, true, "", "блокируется"},
		{"site ip", []Rule{yt}, Query{Domain: "youtube.com", IP: ip, Proto: 17, Port: 443, QUICNameless: true}, true, "", "блокируется"},
		{"settings off", []Rule{yt}, Query{Domain: "youtube.com", Proto: 17, Port: 443}, false, "yt", ""},
		{"tcp", []Rule{yt}, Query{Domain: "youtube.com", Proto: 6, Port: 443, QUICNameless: true}, false, "по умолчанию", ""},
		{"app", []Rule{chrome}, Query{App: "chrome.exe", Domain: "youtube.com", Proto: 17, Port: 443, QUICNameless: true}, false, "chrome", "ответ дан без имени"},
		{"port only", []Rule{portOnly}, Query{Domain: "youtube.com", Proto: 17, Port: 443, QUICNameless: true}, false, "p", "ответ дан без имени"},
		{"network", []Rule{network}, Query{Domain: "youtube.com", IP: nip, Proto: 17, Port: 443, QUICNameless: true}, false, "net", "ответ дан без имени"},
		{"site below app", []Rule{chrome, yt}, Query{App: "chrome.exe", Domain: "youtube.com", Proto: 17, Port: 443, QUICNameless: true}, false, "chrome", ""},
		{"network unknown ip", []Rule{network, yt}, Query{Domain: "youtube.com", Proto: 17, Port: 443, QUICNameless: true}, true, "", "блокируется"},
		{"other port", []Rule{yt}, Query{Domain: "youtube.com", Proto: 17, Port: 444, QUICNameless: true}, false, "по умолчанию", ""},
	} {
		cfg := Config{DefaultAction: Direct, Rules: c.rules}
		ex := Explain(cfg, "main", c.q)
		notes := strings.Join(ex.Notes, " ")
		if c.block != (ex.Winner.Index == StepQUICBlock) || c.block && ex.Winner.Action != Block || !c.block && ex.Winner.Name != c.win ||
			c.note != "" && !strings.Contains(notes, c.note) {
			t.Errorf("%s: %+v %v", c.name, ex.Winner, ex.Notes)
			continue
		}
		winners := 0
		for _, st := range ex.Steps {
			if st.Winner {
				winners++
			}
		}
		if winners != 1 || c.block && ex.Steps[0].Index != StepQUICBlock {
			t.Errorf("%s: steps %+v", c.name, ex.Steps)
		}
		// Parity with the engine's packet-level decision.
		if c.q.QUICNameless && c.q.Proto == 17 && c.q.Port == 443 {
			var p *procinfo.Info
			if c.q.App != "" {
				p = &procinfo.Info{Name: c.q.App}
			}
			sub := Subject{Proc: p, Proto: 17, Dst: netip.AddrPortFrom(c.q.IP, c.q.Port)}
			if r := mustCompile(t, cfg).Evaluate(sub, nil); r.NeedsDomain != c.block {
				t.Errorf("%s: engine %+v", c.name, r)
			}
		}
	}
}
