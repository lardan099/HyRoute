package app

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
)

var unicodeNames = []string{
	"🇳🇱 Netherlands",
	"🇩🇪 DE Frankfurt",
	"🇯🇵 日本",
	"🚀 Fast EU",
	"Netflix 🍿",
	"Мой сервер 🔥",
	"👩‍💻 Работа — NL/США", // ZWJ sequence, em dash, slash
}

func linksWithNames(raw bool) string {
	var b strings.Builder
	for i, n := range unicodeNames {
		frag := n
		if !raw {
			frag = (&url.URL{Fragment: n}).EscapedFragment()
		}
		b.WriteString("hy2://secret@h" + string(rune('a'+i)) + ".example:443/?sni=s.example&mport=20000-50000#" + frag + "\n")
	}
	return b.String()
}

// Names with spaces, emoji, flags, ZWJ sequences and CJK survive import
// (raw or percent-encoded fragments), storage, subscriptions and
// renaming; rules keep pointing at the same profile by ID.
func TestUnicodeNames(t *testing.T) {
	for _, raw := range []bool{true, false} {
		l := ParseLinks(linksWithNames(raw))
		if len(l.Profiles) != len(unicodeNames) || len(l.Warnings) != 0 {
			t.Fatalf("raw=%v: %d profiles, warnings %v", raw, len(l.Profiles), l.Warnings)
		}
		for i, p := range l.Profiles {
			if p.Name != unicodeNames[i] {
				t.Fatalf("raw=%v: %q != %q", raw, p.Name, unicodeNames[i])
			}
		}
	}
	// Several links on one line, separated by spaces, still split.
	if l := ParseLinks("hy2://a@h1.example#🚀 Fast EU hy2://b@h2.example#Netflix 🍿"); len(l.Profiles) != 2 || l.Profiles[0].Name != "🚀 Fast EU" || l.Profiles[1].Name != "Netflix 🍿" {
		t.Fatalf("%+v", l.Profiles)
	}

	c, _ := newCtl(t)
	body := base64.StdEncoding.EncodeToString([]byte(linksWithNames(true)))
	c.Fetch = func(context.Context, string) (FetchResult, error) {
		return FetchResult{Body: []byte(body), Title: "🌍 Мир VPN"}, nil
	}
	pv, err := c.PreviewSubscription("https://sub.example/x")
	if err != nil {
		t.Fatal(err)
	}
	sv, err := c.AddSubscription(SubInput{Token: pv.Token, Enabled: true, Interval: "manual"})
	if err != nil || sv.Name != "🌍 Мир VPN" {
		t.Fatalf("%+v %v", sv, err)
	}
	ps := c.Profiles()
	jp := ps[2]
	if jp.Name != "🇯🇵 日本" || jp.SourceName != "🌍 Мир VPN" {
		t.Fatalf("%+v", jp)
	}
	st := c.Settings()
	st.Rules = []rules.Rule{{Name: "аниме 🎌", Domain: &rules.DomainMatch{Pattern: ".example.jp"}, Action: rules.Tunnel, Profile: jp.ID}}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	// Rename by hand; the rule still uses the same ID.
	p, _ := c.Profile(jp.ID)
	p.Name = "🐸 мой японец"
	if _, err := c.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	// Reload from disk: names intact.
	c2 := New(c.Store, c.Start, c.Base, nil)
	c2.Fetch = c.Fetch
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range c2.Profiles() {
		got[p.ID] = p.Name
	}
	if got[jp.ID] != "🐸 мой японец" || got[ps[6].ID] != "👩‍💻 Работа — NL/США" {
		t.Fatalf("%v", got)
	}
	if c2.Settings().Rules[0].Name != "аниме 🎌" {
		t.Fatal("rule name")
	}
	// A subscription update brings the server's own name back but keeps
	// the ID (matched by connection), so the rule is untouched.
	if _, err := c2.UpdateSubscription(sv.ID); err != nil {
		t.Fatal(err)
	}
	for _, p := range c2.Profiles() {
		if p.ID == jp.ID && (p.Name != "🇯🇵 日本" || p.Missing) {
			t.Fatalf("%+v", p)
		}
	}
	if w := c2.RuleWarnings(); len(w) != 0 {
		t.Fatalf("%+v", w)
	}
}
