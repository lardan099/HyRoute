package rules

import (
	"net/netip"
	"strings"
	"testing"
)

func TestExplain(t *testing.T) {
	off := false
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "games", App: &AppMatch{Pattern: `C:\Games\*`}, Action: Tunnel, Profile: "nl"},
		{Name: "off", Domain: &DomainMatch{Pattern: ".youtube.com"}, Action: Block, Enabled: &off},
		{Name: "yt", Domain: &DomainMatch{Pattern: "*.youtube.com"}, Action: Tunnel, Profile: "de"},
		{Name: "discord udp", App: &AppMatch{Pattern: "discord.exe"}, Protocol: "udp", Action: Tunnel},
		{Name: "discord", App: &AppMatch{Pattern: "discord.exe"}, Action: Direct},
	}}
	ex := Explain(c, "main", Query{App: "chrome.exe", Domain: "www.youtube.com", Proto: 6})
	if ex.Winner.Name != "yt" || ex.Winner.Profile != "de" || ex.Winner.Action != Tunnel {
		t.Fatalf("%+v", ex.Winner)
	}
	if !strings.Contains(ex.Steps[0].Reason, "только имя файла") || !strings.Contains(ex.Steps[1].Reason, "выключено") {
		t.Fatalf("%+v", ex.Steps)
	}
	// *.youtube.com does not cover youtube.com itself.
	ex = Explain(c, "main", Query{App: "chrome.exe", Domain: "youtube.com", Proto: 6})
	if ex.Winner.Index != -1 || !strings.Contains(ex.Steps[2].Reason, "только поддомены") {
		t.Fatalf("%+v", ex.Steps[2])
	}
	ex = Explain(c, "main", Query{App: `C:\Users\u\Discord\Discord.exe`, Proto: 17})
	if ex.Winner.Name != "discord udp" || ex.Winner.Profile != "main" {
		t.Fatalf("%+v", ex.Winner)
	}
	if s := ex.Steps[4]; s.Winner || !strings.Contains(s.Reason, "выше уже сработало") {
		t.Fatalf("%+v", s)
	}
	ex = Explain(c, "main", Query{App: `C:\Games\x\game.exe`, Proto: 6})
	if ex.Winner.Name != "games" {
		t.Fatalf("%+v", ex.Winner)
	}
}

// An address with several cached names: when the names lead to different
// routes, the engine decides UDP without a name (EvaluateNoDomain), and
// Explain shows the same.
func TestExplainSeveralNames(t *testing.T) {
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "yt", Domains: []string{".youtube.com"}, Action: Tunnel},
	}}
	s := mustCompile(t, c)
	ip := netip.MustParseAddr("1.2.3.4")
	split := []string{"www.youtube.com", "other.org"}

	sub := Subject{Proto: 17, Dst: netip.AddrPortFrom(ip, 443)}
	if r := s.Evaluate(sub, split); !r.NeedsDomain {
		t.Fatalf("engine: %+v", r)
	}
	want := s.EvaluateNoDomain(sub)
	ex := Explain(c, "main", Query{IP: ip, Names: split, Proto: 17})
	if ex.Winner.Index != -1 || want.Rule != "default" || !strings.Contains(strings.Join(ex.Notes, " "), "UDP") {
		t.Fatalf("udp: %+v %+v", ex.Winner, ex.Notes)
	}
	// TCP: the result without a name (no SNI/Host), as the engine decides
	// then; the notes give the result for each name.
	ex = Explain(c, "main", Query{IP: ip, Names: split, Proto: 6})
	if ex.Winner.Index != -1 || !strings.Contains(strings.Join(ex.Notes, " "), "www.youtube.com — «yt»; other.org — «по умолчанию»") {
		t.Fatalf("tcp: %+v %+v", ex.Winner, ex.Notes)
	}
	// The same route for every name: that route, as the engine decides.
	ex = Explain(c, "main", Query{IP: ip, Names: []string{"www.youtube.com", "m.youtube.com"}, Proto: 17})
	if ex.Winner.Name != "yt" || !strings.Contains(strings.Join(ex.Notes, " "), "одинаковый") {
		t.Fatalf("agree: %+v %+v", ex.Winner, ex.Notes)
	}
	// The same server with other fallbacks is another route for the engine.
	c = Config{DefaultAction: Tunnel, Rules: []Rule{
		{Name: "yt", Domains: []string{".youtube.com"}, Action: Tunnel, Fallback: []string{"nl"}},
	}}
	if r := mustCompile(t, c).Evaluate(sub, split); !r.NeedsDomain {
		t.Fatalf("engine: %+v", r)
	}
	if ex = Explain(c, "main", Query{IP: ip, Names: split, Proto: 17}); ex.Winner.Index != -1 || strings.Contains(strings.Join(ex.Notes, " "), "одинаковый") {
		t.Fatalf("fallback: %+v %+v", ex.Winner, ex.Notes)
	}
}

func TestLint(t *testing.T) {
	c := Config{Rules: []Rule{
		{Name: "all yt", Domain: &DomainMatch{Pattern: ".youtube.com"}, Action: Tunnel},
		{Name: "music", Domain: &DomainMatch{Pattern: "music.youtube.com"}, Action: Direct},
		{Name: "games", App: &AppMatch{Pattern: `C:\Games\*`}, Action: Tunnel},
		{Name: "one game", App: &AppMatch{Pattern: `C:\Games\a\a.exe`}, Protocol: "udp", Action: Tunnel},
		{Name: "chrome", App: &AppMatch{Pattern: "chrome.exe"}, Action: Direct},
		{Name: "chrome yt", App: &AppMatch{Pattern: "chrome.exe"}, Domain: &DomainMatch{Pattern: "*.example.org"}, Action: Tunnel},
		{Name: "sub", Domain: &DomainMatch{Pattern: "*.x.org"}, Action: Block},
		{Name: "apex", Domain: &DomainMatch{Pattern: "x.org"}, Action: Block},
		{Name: "bad", Domain: &DomainMatch{Pattern: "a b"}, Action: Block},
	}}
	got := map[int]string{}
	for _, is := range Lint(c) {
		got[is.Index] = is.Text
	}
	if !strings.Contains(got[1], "Никогда не сработает") || !strings.Contains(got[3], "Лишнее") || !strings.Contains(got[5], "chrome") {
		t.Fatalf("%v", got)
	}
	if _, ok := got[7]; ok {
		t.Fatalf("*.x.org does not cover x.org: %v", got)
	}
	if !strings.Contains(got[8], "неверный шаблон") || len(got) != 4 {
		t.Fatalf("%v", got)
	}
}

// A program typed without .exe, as the hint suggests ("chrome"), is
// checked as chrome.exe: the name rules are saved with; a name that a rule
// has as is (vmmem) is checked as is.
func TestExplainAppWithoutExe(t *testing.T) {
	c := Config{DefaultAction: Tunnel, Rules: []Rule{
		{Name: "chrome", Apps: []AppMatch{{Pattern: "chrome.exe", InheritChildren: true}}, Action: Direct},
		{Name: "my.app", Apps: []AppMatch{{Pattern: "my.app"}}, Action: Block},
		// Processes without an extension: a rule for the bare name.
		{Name: "wsl", Apps: []AppMatch{{Pattern: "vmmem"}}, Action: Tunnel},
		{Name: "sys", Apps: []AppMatch{{Pattern: "System", Kind: "name"}}, Action: Block},
	}}
	for app, want := range map[string]string{"chrome": "chrome", "Chrome": "chrome", "chrome.exe": "chrome", "my.app": "my.app",
		"vmmem": "wsl", "System": "sys", "vmmem.exe": "по умолчанию"} {
		if ex := Explain(c, "main", Query{App: app, Domain: "example.com", Proto: 6}); ex.Winner.Name != want {
			t.Errorf("%s: %+v %v", app, ex.Winner, ex.Notes)
		}
	}
}

// Site names with an empty part or a character no name has compile (saved
// settings still load) but never match: Lint says so.
func TestSiteProblem(t *testing.T) {
	for _, p := range []string{"..example.com", "example..com", "domain:.example.com", "full:.example.com", "*..a.com",
		".«youtube.com»", ".(youtube.com)", "youtube.com!", "a'b.com"} {
		if SiteProblem(p) == "" {
			t.Errorf("%q: no problem", p)
		}
		c := Config{Rules: []Rule{{Name: "x", Domains: []string{p}, Action: Direct}}}
		s := mustCompile(t, c)
		if r := s.EvaluateDomain(Subject{Proto: 6}, "www.example.com", SrcSNI); r.Rule != "default" {
			t.Errorf("%q matched", p)
		}
		if is := Lint(c); len(is) != 1 || !strings.Contains(is[0].Text, "в имени сайта") {
			t.Errorf("%q: lint %+v", p, is)
		}
	}
	for _, p := range []string{".example.com", "*.example.com", "example.com", "example.com.", ".рф", "пример.рф", "_dmarc.example.com",
		"localhost", "domain:example.com", "full:a.b", "geosite:youtube", "keyword:a..b", `regexp:^a\.\.`, "1.2.3.4", "2001:db8::", "geoip:ru",
		"a b", "*.*.ru", "col·legi.cat", "ab\u200ccd.com", "a\u30fbb.jp", "א\u05f4ב.il"} {
		if w := SiteProblem(p); w != "" {
			t.Errorf("%q: %s", p, w)
		}
	}
}
