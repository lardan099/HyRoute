package rules

import (
	"strings"
	"testing"
)

func TestRuleLists(t *testing.T) {
	s := mustCompile(t, Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "YouTube", Domains: []string{".youtube.com", ".googlevideo.com", "youtu.be"}, Action: Tunnel, Profile: "nl"},
		{Name: "Discord", Apps: []AppMatch{{Pattern: "discord.exe", InheritChildren: true}, {Pattern: `C:\Games\*`}}, Action: Tunnel, Profile: "de"},
		// Old single form still works next to the lists.
		{Name: "old", App: &AppMatch{Pattern: "curl.exe"}, Domain: &DomainMatch{Pattern: "ifconfig.me"}, Action: Block},
	}})
	chrome := sub(proc(`C:\chrome.exe`, nil), 6)
	for dom, want := range map[string]string{"rr3---sn.googlevideo.com": "nl", "youtu.be": "nl", "www.youtu.be": "", "example.org": ""} {
		r := s.EvaluateDomain(chrome, dom, SrcSNI)
		if r.Profile != want {
			t.Errorf("%s: %+v", dom, r)
		}
	}
	child := proc(`C:\Users\u\AppData\Local\Discord\app-1\Discord.exe`, nil)
	child = proc(`C:\x\helper.exe`, child)
	if r := s.EvaluateNoDomain(sub(child, 17)); r.Profile != "de" {
		t.Fatalf("inherited: %+v", r)
	}
	if r := s.EvaluateNoDomain(sub(proc(`C:\Games\a\b.exe`, nil), 6)); r.Profile != "de" {
		t.Fatalf("glob: %+v", r)
	}
	if r := s.EvaluateDomain(sub(proc(`C:\curl.exe`, nil), 6), "ifconfig.me", SrcSNI); r.Action != Block {
		t.Fatalf("legacy: %+v", r)
	}
	if _, err := Compile(Config{Rules: []Rule{{Name: "bad", Domains: []string{"ok.com", "a b"}}}}); err == nil {
		t.Fatal("bad list item accepted")
	}

	issues := Lint(Config{Rules: []Rule{
		{Name: "google", Domains: []string{".google.com", ".googlevideo.com", ".youtube.com"}, Action: Tunnel},
		{Name: "yt", Domains: []string{"www.youtube.com", "rr1.googlevideo.com"}, Action: Direct},
		{Name: "mixed", Domains: []string{"www.youtube.com", "other.org"}, Action: Direct},
	}})
	if len(issues) != 1 || issues[0].Index != 1 || !strings.Contains(issues[0].Text, "google") {
		t.Fatalf("%+v", issues)
	}
	ex := Explain(Config{Rules: []Rule{{Name: "YouTube", Domains: []string{".youtube.com", "youtu.be"}, Action: Tunnel}}}, "m", Query{Domain: "vk.com", Proto: 6})
	if !strings.Contains(ex.Steps[0].Reason, "ни под один сайт") {
		t.Fatal(ex.Steps[0].Reason)
	}
}
