package rules

import (
	"reflect"
	"testing"
)

func TestTunnelProfileResolution(t *testing.T) {
	s := mustCompile(t, Config{
		DefaultAction: Tunnel,
		Rules: []Rule{
			{Name: "discord", App: &AppMatch{Pattern: "discord.exe"}, Action: Tunnel, Profile: "nl"},
			{Name: "yt", Domain: &DomainMatch{Pattern: ".youtube.com"}, Action: Tunnel, Profile: "de"},
			{Name: "main", Domain: &DomainMatch{Pattern: "example.com"}, Action: Tunnel},
			{Name: "direct", Domain: &DomainMatch{Pattern: "ya.ru"}, Action: Direct, Profile: "ignored"},
		},
	})
	s.Main = "m"
	chrome := proc(`C:\chrome.exe`, nil)
	for _, c := range []struct {
		p       Subject
		dom     string
		act     Action
		profile string
	}{
		{sub(proc(`C:\Discord\Discord.exe`, nil), 6), "", Tunnel, "nl"},
		{sub(chrome, 6), "www.youtube.com", Tunnel, "de"},
		{sub(chrome, 6), "example.com", Tunnel, "m"},
		{sub(chrome, 6), "ya.ru", Direct, ""},
		{sub(chrome, 6), "other.org", Tunnel, "m"},
	} {
		r := s.EvaluateDomain(c.p, c.dom, SrcSNI)
		if r.Action != c.act || r.Profile != c.profile {
			t.Errorf("%s: got %v/%q want %v/%q", c.dom, r.Action, r.Profile, c.act, c.profile)
		}
	}
	if got := s.Profiles(); !reflect.DeepEqual(got, []string{"de", "m", "nl"}) {
		t.Fatalf("profiles %v", got)
	}
}

// Two Tunnel outcomes through different profiles are different routes: the
// packet level must not pick one.
func TestDifferentProfilesNeedDomain(t *testing.T) {
	s := mustCompile(t, Config{
		DefaultAction: Tunnel, DefaultProfile: "nl",
		Rules: []Rule{{Name: "yt", Domain: &DomainMatch{Pattern: ".youtube.com"}, Action: Tunnel, Profile: "de"}},
	})
	chrome := sub(proc(`C:\chrome.exe`, nil), 6)
	if r := s.Evaluate(chrome, nil); !r.NeedsDomain {
		t.Fatalf("unknown domain: %+v", r)
	}
	if r := s.Evaluate(chrome, []string{"www.youtube.com", "other.org"}); !r.NeedsDomain {
		t.Fatalf("names disagree on profile: %+v", r)
	}
	// Same profile on both branches: final.
	s2 := mustCompile(t, Config{
		DefaultAction: Tunnel, DefaultProfile: "de",
		Rules: []Rule{{Name: "yt", Domain: &DomainMatch{Pattern: ".youtube.com"}, Action: Tunnel, Profile: "de"}},
	})
	if r := s2.Evaluate(chrome, nil); r.NeedsDomain || r.Profile != "de" {
		t.Fatalf("same profile: %+v", r)
	}
	if got := s2.Profiles(); !reflect.DeepEqual(got, []string{"de"}) {
		t.Fatalf("profiles %v", got)
	}
}

func TestNoMainProfile(t *testing.T) {
	s := mustCompile(t, Config{DefaultAction: Tunnel})
	r := s.EvaluateNoDomain(sub(nil, 6))
	if r.Action != Tunnel || r.Profile != "" {
		t.Fatalf("%+v", r)
	}
	if len(s.Profiles()) != 0 {
		t.Fatal(s.Profiles())
	}
}
