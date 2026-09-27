package app

import (
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
)

// A direct or block route never uses its server or fallbacks: stale ones
// left there (the rule was switched from "через VPN") must not keep the
// server from being deleted. Tunnel rules, turned off ones too, still do.
func TestDeleteProfileIgnoresNonTunnelRefs(t *testing.T) {
	c, _ := newCtl(t)
	res, err := c.ImportURIs(link + "\nhy2://x@h2.example:8443\nhy2://y@h3.example:8443")
	if err != nil || len(res.Added) != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	a, b, d := res.Added[0].ID, res.Added[1].ID, res.Added[2].ID
	off := false
	st := c.Settings()
	st.Rules = []rules.Rule{
		{Name: "yt", Domains: []string{".youtube.com"}, Action: rules.Direct, Profile: b, Fallback: []string{b}},
		{Name: "ads", Domains: []string{".ads.example"}, Action: rules.Block, Fallback: []string{b}},
		{Name: "off", Domains: []string{".off.example"}, Action: rules.Tunnel, Enabled: &off, Fallback: []string{d}},
	}
	st.DefaultAction, st.DefaultFallback = rules.Direct, []string{b}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if u := c.Profiles()[1].UsedBy; len(u) != 0 {
		t.Fatalf("usedBy %v", u)
	}
	if err := c.DeleteProfile(d); err == nil || !strings.Contains(err.Error(), "off (запасной сервер)") {
		t.Fatalf("delete a fallback of a turned off tunnel rule: %v", err)
	}
	if err := c.DeleteProfile(b); err != nil {
		t.Fatalf("delete a server named only by direct/block routes: %v", err)
	}

	st = c.Settings()
	st.DefaultAction, st.DefaultFallback = rules.Tunnel, []string{a}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteProfile(a); err == nil || !strings.Contains(err.Error(), "маршрут по умолчанию (запасной сервер)") {
		t.Fatalf("delete a fallback of the tunnel default route: %v", err)
	}
}
