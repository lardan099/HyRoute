package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
)

func browserCtl(t *testing.T) *Controller {
	t.Helper()
	c, _ := newCtl(t)
	if err := c.SetBrowserOn(true); err != nil {
		t.Fatal(err)
	}
	return c
}

func ruleNames(c *Controller) string {
	var out []string
	for _, r := range c.Settings().Config.Rules {
		out = append(out, r.Name+"="+strings.Join(r.Domains, ","))
	}
	return strings.Join(out, " | ")
}

func TestBrowserOff(t *testing.T) {
	c, _ := newCtl(t)
	if c.BrowserOn() {
		t.Fatal("on by default")
	}
	if _, err := c.BrowserAdd(BrowserEdit{Sites: []string{".example.com"}, To: "vpn"}); !errors.Is(err, ErrBrowserOff) {
		t.Fatalf("%v", err)
	}
	if _, err := c.BrowserRemove(BrowserEdit{Sites: []string{".example.com"}}); !errors.Is(err, ErrBrowserOff) {
		t.Fatalf("%v", err)
	}
	if err := c.SetBrowserOn(true); err != nil || !c.BrowserOn() || c.Prefs().Browser != "on" {
		t.Fatalf("%v %+v", err, c.Prefs())
	}
	if err := c.SetBrowserOn(false); err != nil || c.BrowserOn() {
		t.Fatal(err)
	}
}

func TestBrowserAddTiers(t *testing.T) {
	c := browserCtl(t)
	if _, err := c.SaveRulesIn(EditGuard{}, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "mine", Domains: []string{".other.example"}, Action: rules.Block},
	}}); err != nil {
		t.Fatal(err)
	}
	res, err := c.BrowserAdd(BrowserEdit{Sites: []string{".example.com", ".Example.com."}, To: "vpn"})
	if err != nil || res.Added != 1 || res.Rule != "Из браузера: VPN" || len(res.Lost) != 0 || res.Rev == 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: VPN=.example.com | mine=.other.example" {
		t.Fatal(got)
	}
	// An address goes above the sites: it decides its own name.
	if res, err = c.BrowserAdd(BrowserEdit{Sites: []string{"www.example.com"}, To: "direct"}); err != nil || res.Added != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: напрямую (адреса)=www.example.com | Из браузера: VPN=.example.com | mine=.other.example" {
		t.Fatal(got)
	}
	info, err := c.BrowserInfo(BrowserQuery{App: "chrome.exe", Hosts: []string{"www.example.com", "cdn.example.com", "WWW.example.com", "1.2.3.4", "", "a.other.example", "x.test"}})
	if err != nil || len(info.Sites) != 4 {
		t.Fatalf("%+v %v", info, err)
	}
	want := []struct{ host, to, pattern, site string }{
		{"www.example.com", "direct", "www.example.com", "example.com"},
		{"cdn.example.com", "vpn", ".example.com", "example.com"},
		{"a.other.example", "block", "", "other.example"},
		{"x.test", "direct", "", "x.test"},
	}
	for i, w := range want {
		s := info.Sites[i]
		if s.Host != w.host || s.Route.To != w.to || s.Route.Pattern != w.pattern || s.Site != w.site || s.Route.Browser != (w.pattern != "") {
			t.Errorf("%d: %+v", i, s)
		}
	}
	if info.Sites[3].Route.Index != -1 || info.Sites[2].Route.Rule != "mine" || info.Ruleset == "" {
		t.Fatalf("%+v", info)
	}
	// The whole site elsewhere: out of the VPN rule, its address with it.
	before := c.SettingsRev()
	if res, err = c.BrowserAdd(BrowserEdit{Sites: []string{".example.com"}, To: "direct"}); err != nil || res.Moved != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: напрямую=.example.com | mine=.other.example" {
		t.Fatal(got)
	}
	if c.SettingsRev() == before {
		t.Fatal("not saved")
	}
	// Again: nothing to do, nothing saved.
	before = c.SettingsRev()
	if res, err = c.BrowserAdd(BrowserEdit{Sites: []string{".example.com"}, To: "direct"}); err != nil || res.Same != 1 || c.SettingsRev() != before {
		t.Fatalf("%+v %v", res, err)
	}
	// Removed: the rule goes with its last site.
	if res, err = c.BrowserRemove(BrowserEdit{Sites: []string{".example.com", "nothere.example"}}); err != nil || res.Removed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "mine=.other.example" {
		t.Fatal(got)
	}
}

func TestBrowserAddServerAndLost(t *testing.T) {
	c := browserCtl(t)
	add, err := c.ImportURIs(link)
	if err != nil || len(add.Added) != 1 {
		t.Fatalf("%+v %v", add, err)
	}
	de := add.Added[0].ID
	// The user moved the extension's rule below a rule of their own, and
	// gave another rule the extension's name with a program in it.
	if _, err := c.SaveRulesIn(EditGuard{}, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "blocked", Domains: []string{".example.org"}, Action: rules.Block},
		{Name: "Из браузера: DE one", Domains: []string{".a.example"}, Action: rules.Tunnel, Profile: de},
		{Name: "Из браузера: блок", Apps: []rules.AppMatch{{Pattern: "chrome.exe"}}, Domains: []string{".b.example"}, Action: rules.Block},
	}}); err != nil {
		t.Fatal(err)
	}
	res, err := c.BrowserAdd(BrowserEdit{Sites: []string{".example.org", "x.example.net"}, To: "id:" + de})
	if err != nil || res.Added != 2 || len(res.Lost) != 1 || res.Lost[0].Pattern != ".example.org" || res.Lost[0].Rule != "blocked" {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: DE one (адреса)=x.example.net | blocked=.example.org | Из браузера: DE one=.a.example,.example.org | Из браузера: блок=.b.example" {
		t.Fatal(got)
	}
	// The rule with a program is the user's: never edited.
	if _, err := c.BrowserAdd(BrowserEdit{Sites: []string{".b.example"}, To: "vpn"}); err != nil {
		t.Fatal(err)
	}
	if got := ruleNames(c); !strings.Contains(got, "Из браузера: блок=.b.example") {
		t.Fatal(got)
	}
	info, _ := c.BrowserInfo(BrowserQuery{Hosts: []string{"x.example.net"}})
	if r := info.Sites[0].Route; r.To != "id:"+de || r.Server != "DE one" || !r.Browser {
		t.Fatalf("%+v", r)
	}
	if len(info.Targets) != 1 || info.Targets[0].To != "id:"+de || info.Targets[0].Name != "DE one" || info.Main != "DE one" {
		t.Fatalf("%+v", info)
	}
	for _, bad := range []BrowserEdit{
		{Sites: []string{".x.example"}, To: "id:gone"},
		{Sites: []string{".x.example"}, To: "somewhere"},
		{Sites: []string{"192.0.2.1"}, To: "vpn"},
		{Sites: []string{"*.x.example"}, To: "vpn"},
		{Sites: []string{"bad name.example"}, To: "vpn"},
		{Sites: nil, To: "vpn"},
	} {
		if _, err := c.BrowserAdd(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if _, err := c.BrowserInfo(BrowserQuery{Hosts: make([]string, maxBrowserHosts+1)}); err == nil {
		t.Error("too many hosts")
	}
}

func TestBrowserUnicodeNames(t *testing.T) {
	c := browserCtl(t)
	if _, err := c.BrowserAdd(BrowserEdit{Sites: []string{".пример.рф"}, To: "block"}); err != nil {
		t.Fatal(err)
	}
	info, err := c.BrowserInfo(BrowserQuery{Hosts: []string{"www.пример.рф"}})
	if err != nil || len(info.Sites) != 1 {
		t.Fatal(err)
	}
	s := info.Sites[0]
	if s.Host != "www.xn--e1afmkfd.xn--p1ai" || s.Label != "www.пример.рф" || s.SiteLabel != "пример.рф" || s.Route.To != "block" {
		t.Fatalf("%+v", s)
	}
}
