package app

import (
	"errors"
	"strconv"
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
	if _, err := c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".example.com"}, To: "vpn"}); !errors.Is(err, ErrBrowserOff) {
		t.Fatalf("%v", err)
	}
	if _, err := c.BrowserRemove(BrowserEdit{App: "chrome.exe", Sites: []string{".example.com"}}); !errors.Is(err, ErrBrowserOff) {
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
	res, err := c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".example.com", ".Example.com."}, To: "vpn"})
	if err != nil || res.Added != 1 || res.Rule != "Из браузера: VPN [chrome.exe]" || len(res.Lost) != 0 || res.Rev == 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: VPN [chrome.exe]=.example.com | mine=.other.example" {
		t.Fatal(got)
	}
	// An address goes above the sites: it decides its own name.
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{"www.example.com"}, To: "direct"}); err != nil || res.Added != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: напрямую [chrome.exe] (адреса)=www.example.com | Из браузера: VPN [chrome.exe]=.example.com | mine=.other.example" {
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
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".example.com"}, To: "direct"}); err != nil || res.Moved != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: напрямую [chrome.exe]=.example.com | mine=.other.example" {
		t.Fatal(got)
	}
	if c.SettingsRev() == before {
		t.Fatal("not saved")
	}
	// Again: nothing to do, nothing saved.
	before = c.SettingsRev()
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".example.com"}, To: "direct"}); err != nil || res.Same != 1 || c.SettingsRev() != before {
		t.Fatalf("%+v %v", res, err)
	}
	// Removed: the rule goes with its last site.
	if res, err = c.BrowserRemove(BrowserEdit{App: "chrome.exe", Sites: []string{".example.com", "nothere.example"}}); err != nil || res.Removed != 1 {
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
		{Name: "Из браузера: DE one [chrome.exe]", Apps: browserAppMatches("chrome.exe"), Domains: []string{".a.example"}, Action: rules.Tunnel, Profile: de},
		{Name: "Из браузера: блок", Apps: []rules.AppMatch{{Pattern: "chrome.exe"}}, Domains: []string{".b.example"}, Action: rules.Block},
	}}); err != nil {
		t.Fatal(err)
	}
	// The user's rule above still decided the site: the extension's rules
	// go above it, and say so.
	res, err := c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".example.org", "x.example.net"}, To: "id:" + de})
	if err != nil || res.Added != 2 || len(res.Lost) != 0 || res.Raised != "blocked" || res.Rule != "Из браузера: DE one [chrome.exe]" {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: DE one [chrome.exe] (адреса)=x.example.net | Из браузера: DE one [chrome.exe]=.a.example,.example.org | blocked=.example.org | Из браузера: блок=.b.example" {
		t.Fatal(got)
	}
	if info, _ := c.BrowserInfo(BrowserQuery{App: "chrome.exe", Hosts: []string{"www.example.org"}}); info.Sites[0].Route.To != "id:"+de || !info.Sites[0].Route.Browser {
		t.Fatalf("%+v", info.Sites[0])
	}
	// Nothing above any more: nothing raised.
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".c.example"}, To: "id:" + de}); err != nil || res.Raised != "" || len(res.Lost) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	// The rule with a program is the user's: never edited.
	if _, err := c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".b.example"}, To: "vpn"}); err != nil {
		t.Fatal(err)
	}
	if got := ruleNames(c); !strings.Contains(got, "Из браузера: блок=.b.example") {
		t.Fatal(got)
	}
	info, _ := c.BrowserInfo(BrowserQuery{App: "chrome.exe", Hosts: []string{"x.example.net"}})
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
		bad.App = "chrome.exe"
		if _, err := c.BrowserAdd(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	if _, err := c.BrowserInfo(BrowserQuery{App: "chrome.exe", Hosts: make([]string, maxBrowserHosts+1)}); err == nil {
		t.Error("too many hosts")
	}
}

func TestBrowserEditScope(t *testing.T) {
	c := browserCtl(t)
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "Из браузера: ingest.example", Domains: []string{".legacy.example"}, Action: rules.Tunnel},
	}}
	if _, err := c.SaveRulesIn(EditGuard{}, cfg); err != nil {
		t.Fatal(err)
	}
	edit := BrowserEdit{Page: "ingest.example", Sites: []string{".ingest.example"}, To: "vpn"}
	if _, err := c.BrowserAdd(edit); !errors.Is(err, errBrowserApp) {
		t.Fatalf("unknown browser: %v", err)
	}
	for _, app := range []string{"chrome.exe", "msedge.exe"} {
		edit.App = app
		if result, err := c.BrowserAdd(edit); err != nil || result.Added != 1 {
			t.Fatalf("%s: %+v %v", app, result, err)
		}
	}
	edit.App, edit.To = "chrome.exe", "block"
	if result, err := c.BrowserAdd(edit); err != nil || result.Moved != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	check := func(app, want string, items int) {
		t.Helper()
		info, err := c.BrowserInfo(BrowserQuery{App: app, Page: edit.Page, Hosts: []string{edit.Page}})
		if err != nil || len(info.Sites) != 1 || info.Sites[0].Route.To != want || info.Page == nil || info.Page.Items != items {
			t.Fatalf("%s: %+v %+v %v", app, info.Page, info.Sites, err)
		}
	}
	check("chrome.exe", "block", 1)
	check("msedge.exe", "vpn", 1)
	check("obs64.exe", "direct", 0)
	if _, err := c.BrowserRemove(BrowserEdit{Page: edit.Page}); !errors.Is(err, errBrowserApp) {
		t.Fatalf("unknown browser: %v", err)
	}
	if res, err := c.BrowserRemove(BrowserEdit{App: edit.App, Page: edit.Page}); err != nil || res.Removed != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	check("chrome.exe", "direct", 0)
	check("msedge.exe", "vpn", 1)
	if !strings.Contains(ruleNames(c), "Из браузера: ingest.example=.legacy.example") {
		t.Fatal(ruleNames(c))
	}
}

func TestBrowserInfoUsesHTTPSPort(t *testing.T) {
	c := browserCtl(t)
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "Other port", Ports: rules.PortList{"8443"}, Action: rules.Tunnel},
		{Name: "HTTPS", Ports: rules.PortList{"443"}, Action: rules.Block},
	}}
	if _, err := c.SaveRulesIn(EditGuard{}, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := c.BrowserInfo(BrowserQuery{App: "chrome.exe", Hosts: []string{"shop.example"}})
	if err != nil || len(info.Sites) != 1 || info.Sites[0].Route.Rule != "HTTPS" {
		t.Fatalf("%+v %v", info, err)
	}
}

// A page's sites live in the rules of its site: one rule per route, read
// and removed as one.
func TestBrowserPageRules(t *testing.T) {
	c := browserCtl(t)
	if _, err := c.SaveRulesIn(EditGuard{}, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "mine", Domains: []string{".mine.example"}, Action: rules.Block},
	}}); err != nil {
		t.Fatal(err)
	}
	res, err := c.BrowserAdd(BrowserEdit{App: "chrome.exe", Page: "WWW.Example.com", Sites: []string{".example.com", ".cdn.test", ".fonts.test"}, To: "vpn"})
	if err != nil || res.Added != 3 || res.Rule != "Из браузера: example.com [chrome.exe]" || res.Raised != "" {
		t.Fatalf("%+v %v", res, err)
	}
	// Another site loads the same CDN the same way: both rules hold it.
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Page: "shop.other.org", Sites: []string{".other.org", ".cdn.test"}, To: "vpn"}); err != nil || res.Added != 2 || res.Moved != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: other.org [chrome.exe]=.other.org,.cdn.test | Из браузера: example.com [chrome.exe]=.example.com,.cdn.test,.fonts.test | mine=.mine.example" {
		t.Fatal(got)
	}
	// Another route for a name: the last choice is the only one.
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Page: "shop.other.org", Sites: []string{".fonts.test"}, To: "direct"}); err != nil || res.Moved != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	// An address of the page: the site's address rule, above the sites.
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Page: "www.example.com", Sites: []string{"api.example.com"}, To: "block"}); err != nil || res.Added != 1 || res.Rule != "Из браузера: example.com [chrome.exe] (адреса)" {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: example.com [chrome.exe] (адреса)=api.example.com | Из браузера: other.org [chrome.exe]=.fonts.test | "+
		"Из браузера: other.org [chrome.exe]=.other.org,.cdn.test | Из браузера: example.com [chrome.exe]=.example.com,.cdn.test | mine=.mine.example" {
		t.Fatal(got)
	}
	info, err := c.BrowserInfo(BrowserQuery{App: "chrome.exe", Page: "shop.other.org", Hosts: []string{"shop.other.org", "api.example.com", "x.fonts.test"}})
	if err != nil || info.Page == nil || info.Page.Site != "other.org" || info.Page.Label != "other.org" || info.Page.Items != 3 {
		t.Fatalf("%+v %v", info.Page, err)
	}
	if info.Sites[0].Route.To != "vpn" || info.Sites[1].Route.To != "block" || info.Sites[2].Route.To != "direct" {
		t.Fatalf("%+v", info.Sites)
	}
	// A page with no site (an address) and an edit without a page: the
	// rules by route, as before.
	if info, _ = c.BrowserInfo(BrowserQuery{App: "chrome.exe", Page: "192.0.2.1"}); info.Page != nil {
		t.Fatalf("%+v", info.Page)
	}
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Page: "192.0.2.1", Sites: []string{".plain.example"}, To: "vpn"}); err != nil || res.Rule != "Из браузера: VPN [chrome.exe]" {
		t.Fatalf("%+v %v", res, err)
	}
	// Sent again from its page, a site leaves the rule by route for the
	// page's rule: the old heaps empty out as the sites are visited.
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Page: "plain.example", Sites: []string{".plain.example", ".cdn.test"}, To: "vpn"}); err != nil || res.Moved != 1 || res.Added != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); strings.Contains(got, "Из браузера: VPN [chrome.exe]") || !strings.Contains(got, "Из браузера: plain.example [chrome.exe]=.plain.example,.cdn.test") {
		t.Fatal(got)
	}
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Page: "192.0.2.1", Sites: []string{".plain.example"}, To: "vpn"}); err != nil || res.Rule != "Из браузера: VPN [chrome.exe]" {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err = c.BrowserRemove(BrowserEdit{App: "chrome.exe", Page: "plain.example"}); err != nil {
		t.Fatal(err)
	}
	// The site goes as one: its rules, nothing of the others'.
	if res, err = c.BrowserRemove(BrowserEdit{App: "chrome.exe", Page: "other.org"}); err != nil || res.Removed != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	if got := ruleNames(c); got != "Из браузера: example.com [chrome.exe] (адреса)=api.example.com | Из браузера: VPN [chrome.exe]=.plain.example | "+
		"Из браузера: example.com [chrome.exe]=.example.com,.cdn.test | mine=.mine.example" {
		t.Fatal(got)
	}
	before := c.SettingsRev()
	if res, err = c.BrowserRemove(BrowserEdit{App: "chrome.exe", Page: "other.org"}); err != nil || res.Removed != 0 || c.SettingsRev() != before {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err = c.BrowserRemove(BrowserEdit{App: "chrome.exe", Page: "192.0.2.1"}); err == nil {
		t.Fatal("nothing to remove accepted")
	}
	// A whole page at once.
	many := make([]string, maxBrowserEdit)
	for i := range many {
		many[i] = ".s" + strconv.Itoa(i) + ".example"
	}
	if res, err = c.BrowserAdd(BrowserEdit{App: "chrome.exe", Page: "big.example", Sites: many, To: "vpn"}); err != nil || res.Added != maxBrowserEdit {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestBrowserUnicodeNames(t *testing.T) {
	c := browserCtl(t)
	if _, err := c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".пример.рф"}, To: "block"}); err != nil {
		t.Fatal(err)
	}
	info, err := c.BrowserInfo(BrowserQuery{App: "chrome.exe", Hosts: []string{"www.пример.рф"}})
	if err != nil || len(info.Sites) != 1 {
		t.Fatal(err)
	}
	s := info.Sites[0]
	if s.Host != "www.xn--e1afmkfd.xn--p1ai" || s.Label != "www.пример.рф" || s.SiteLabel != "пример.рф" || s.Route.To != "block" {
		t.Fatalf("%+v", s)
	}
	// The site's rule is named as people read it, and found by that name.
	res, err := c.BrowserAdd(BrowserEdit{App: "chrome.exe", Page: "www.пример.рф", Sites: []string{".пример.рф", ".cdn.test"}, To: "vpn"})
	if err != nil || res.Rule != "Из браузера: пример.рф [chrome.exe]" || res.Moved != 1 || res.Added != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if info, _ = c.BrowserInfo(BrowserQuery{App: "chrome.exe", Page: "xn--e1afmkfd.xn--p1ai"}); info.Page == nil || info.Page.Label != "пример.рф" || info.Page.Items != 2 {
		t.Fatalf("%+v", info.Page)
	}
}

// Servers of the same name are told apart by where they come from: in the
// extension's list and in the rules it makes.
func TestBrowserSameNames(t *testing.T) {
	c := browserCtl(t)
	add, err := c.ImportURIs("hysteria2://p1@a.example:443#NL\nhysteria2://p2@b.example:443#NL\nhysteria2://p3@c.example:443#DE")
	if err != nil || len(add.Added) != 3 {
		t.Fatalf("%+v %v", add, err)
	}
	info, _ := c.BrowserInfo(BrowserQuery{App: "chrome.exe"})
	var names []string
	for _, tg := range info.Targets {
		names = append(names, tg.Name)
	}
	if got := strings.Join(names, ","); got != "NL · добавлен вручную,NL · добавлен вручную,DE" {
		t.Fatal(got)
	}
	if c.profileName(add.Added[2].ID) != "DE" {
		t.Fatal(c.profileName(add.Added[2].ID))
	}
	res, err := c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".x.example"}, To: "id:" + add.Added[0].ID})
	if err != nil || res.Rule != "Из браузера: NL · добавлен вручную [chrome.exe]" {
		t.Fatalf("%+v %v", res, err)
	}
}
