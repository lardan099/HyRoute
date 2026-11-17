package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
)

// The extension's rules by route as a few months leave them: a server
// renamed, lists added by hand, names an earlier merge joined, spare
// servers. One suggestion of «Навести порядок» puts them right, and the
// extension keeps the result again.
func TestTidyBrowserRules(t *testing.T) {
	c := geoCtl(t) // a database: whether a list may hold a site is known
	if err := c.SetBrowserOn(true); err != nil {
		t.Fatal(err)
	}
	add, err := c.ImportURIs("hysteria2://p1@a.example:443#NL\nhysteria2://p2@b.example:443#US")
	if err != nil || len(add.Added) != 2 {
		t.Fatalf("%+v %v", add, err)
	}
	nl, us := add.Added[0].ID, add.Added[1].ID
	st := c.Settings()
	st.Config.DefaultAction = rules.Direct
	st.Rules = []rules.Rule{
		{ID: "old", Name: "Из браузера: Старое имя", Domains: []string{".a.example", ".b.example"}, Action: rules.Tunnel, Profile: nl},
		{ID: "voice", Name: ZapretRulePrefix + "Discord (голос)", Apps: []rules.AppMatch{{Pattern: "Discord.exe"}}, Protocol: "udp",
			Ports: rules.PortList{"50000-50100"}, Action: rules.Direct},
		{ID: "vpn", Name: "Из браузера: VPN", Domains: []string{".c.example", "geosite:ads"}, Action: rules.Tunnel},
		{ID: "nl", Name: "Из браузера: NL", Domains: []string{".d.example", ".a.example"}, Action: rules.Tunnel, Profile: nl},
		{ID: "lan", Name: "Из браузера: напрямую, Локальная сеть", Domains: []string{"192.168.0.0/16"}, Action: rules.Direct},
		{ID: "spare", Name: "Из браузера: VPN", Domains: []string{".e.example"}, Action: rules.Tunnel, Fallback: []string{us}},
		{ID: "site", Name: "Из браузера: example.org", Domains: []string{".example.org", ".cdn.example"}, Action: rules.Tunnel},
		{ID: "site2", Name: "Из браузера: example.net", Domains: []string{".example.net", "geosite:openai"}, Action: rules.Tunnel, Profile: nl},
		{ID: "prog", Name: "Из браузера: блок", Apps: []rules.AppMatch{{Pattern: "chrome.exe"}}, Domains: []string{".p.example"}, Action: rules.Block},
		{ID: "us1", Name: "Из браузера: US", Domains: []string{".f.example"}, Action: rules.Tunnel, Profile: us},
		{ID: "own", Name: "Своё", Domains: []string{"www.g.example"}, Action: rules.Direct},
		{ID: "us2", Name: "Из браузера: US", Domains: []string{".g.example"}, Action: rules.Tunnel, Profile: us},
		{ID: "gone", Name: "Из браузера: Удалённый", Domains: []string{".h.example"}, Action: rules.Tunnel, Profile: "nosuch"},
	}
	v := c.TidyRules(st, nil)
	i := slices.IndexFunc(v.Items, func(t rules.Tidy) bool { return t.ID == TidyBrowser })
	if i < 0 || v.Items[i].Kind != TidyBrowser || !v.Items[i].Changes {
		t.Fatalf("%+v", v.Items)
	}
	// No merge or geosite list is offered for the extension's rules: the
	// one suggestion is theirs.
	for _, it := range v.Items {
		if it.Kind == rules.TidyMerge || it.Kind == rules.TidyGeo {
			t.Errorf("%+v", it)
		}
	}
	det := strings.Join(v.Items[i].Details, "\n")
	for _, want := range []string{
		"«Из браузера: Старое имя» переименовано в «Из браузера: NL»: так этот маршрут называется сейчас.",
		"«Из браузера: VPN»: geosite:ads — в отдельное правило без названия сразу под ним; сайты остаются в «Из браузера: VPN», и расширение снова может его вести.",
		"«Из браузера: напрямую, Локальная сеть» переименовано в «Локальная сеть»: в нём только списки и сети, расширение его не ведёт.",
		"«Из браузера: VPN» переименовано в «Из браузера: VPN (с запасными)»",
		"«Из браузера: NL»: 2 правила с этим маршрутом собраны в одно (3 сайта). Между ними стоит «Обход DPI: Discord (голос)»",
	} {
		if !strings.Contains(det, want) {
			t.Errorf("no %q in\n%s", want, det)
		}
	}
	if !strings.Contains(det, "«Из браузера: example.net»: geosite:openai — в отдельное правило без названия сразу под ним; сайты остаются в «Из браузера: example.net», и расширение снова может его вести.") {
		t.Errorf("%s", det)
	}
	if strings.Contains(det, "example.org") || strings.Contains(det, "блок") || strings.Contains(det, "Удалённый") || strings.Contains(det, "US") {
		t.Errorf("%s", det)
	}
	out := c.TidyRules(st, []string{TidyBrowser})
	var got []string
	for _, r := range out.Rules {
		got = append(got, r.Name+"="+strings.Join(r.AllDomains(), ","))
	}
	want := []string{
		"Из браузера: NL=.a.example,.b.example,.d.example",
		ZapretRulePrefix + "Discord (голос)=",
		"Из браузера: VPN=.c.example",
		"=geosite:ads",
		"Локальная сеть=192.168.0.0/16",
		"Из браузера: VPN (с запасными)=.e.example",
		"Из браузера: example.org=.example.org,.cdn.example",
		"Из браузера: example.net=.example.net", // a site's rule keeps its name, and the extension keeps it again
		"=geosite:openai",
		"Из браузера: блок=.p.example",
		"Из браузера: US=.f.example",
		"Своё=www.g.example",
		"Из браузера: US=.g.example", // «Своё» decides www.g.example another way: it stays below
		"Из браузера: Удалённый=.h.example",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s", strings.Join(got, "\n"))
	}
	// The new rule has an ID of its own, the others keep theirs.
	if out.Rules[3].ID == "" || out.Rules[3].ID == "vpn" || out.Rules[2].ID != "vpn" || out.Rules[0].ID != "old" {
		t.Fatalf("%q %q", out.Rules[2].ID, out.Rules[3].ID)
	}
	// Done: nothing more to put right.
	st.Rules = out.Rules
	if again := c.TidyRules(st, nil); slices.ContainsFunc(again.Items, func(t rules.Tidy) bool { return t.ID == TidyBrowser }) {
		t.Fatalf("%+v", again.Items)
	}
	// A site without a page goes into the rule of its route for this
	// browser. The tidied legacy rule keeps its global scope and domains.
	if _, err := c.SaveRulesIn(EditGuard{}, st.Config); err != nil {
		t.Fatal(err)
	}
	res, err := c.BrowserAdd(BrowserEdit{App: "chrome.exe", Sites: []string{".z.example"}, To: "id:" + nl})
	if err != nil || res.Rule != "Из браузера: NL [chrome.exe]" || res.Added != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	gotRules := c.Settings().Rules
	if scoped, legacy := gotRules[0], gotRules[1]; !browserRuleFor(scoped, "chrome.exe") ||
		!slices.Contains(scoped.Domains, ".z.example") || legacy.ID != "old" || slices.Contains(legacy.Domains, ".z.example") {
		t.Fatalf("%+v", gotRules[:2])
	}
}
