package app

import (
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
)

func TestImportRulesPAC(t *testing.T) {
	c, _ := newCtl(t)
	add, err := c.ImportURIs(link)
	if err != nil || len(add.Added) != 1 {
		t.Fatalf("%+v %v", add, err)
	}
	de := add.Added[0].ID
	pac := `var FindProxyForURL = function(init, profiles) {
    return function(url, host) { return init; };
}("+auto switch", {
    "+auto switch": function(url, host, scheme) {
        "use strict";
        if (/(?:^|\.)example\.com$/.test(host)) return "+My proxy";
        if (/^exact\.example\.org$/.test(host)) return "+My proxy";
        if (/(?:^|\.)direct\.example$/.test(host)) return "DIRECT";
        return "DIRECT";
    },
    "+My proxy": function(url, host, scheme) {
        "use strict";
        if (/^127\.0\.0\.1$/.test(host) || /^::1$/.test(host) || /^localhost$/.test(host)) return "DIRECT";
        return "PROXY 127.0.0.1:8080";
    }
});`
	res, err := c.ImportRules(pac, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "pac" || res.Count != 2 || len(res.Targets) != 2 || len(res.Formats) == 0 {
		t.Fatalf("%+v", res)
	}
	if res.Targets[0].Name != "My proxy" || res.Targets[0].To != "vpn" || res.Targets[0].Rules != 1 || res.Targets[0].Detail != "PROXY 127.0.0.1:8080" {
		t.Fatalf("targets %+v", res.Targets)
	}
	if res.Targets[1].To != "direct" || res.Default != "DIRECT" || res.DefaultLine != "* -> напрямую" {
		t.Fatalf("default %+v %q %q", res.Targets, res.Default, res.DefaultLine)
	}
	if !strings.Contains(res.Text, "PAC My proxy: example.com =exact.example.org -> vpn\n") || !strings.Contains(res.Text, "PAC DIRECT: direct.example -> напрямую\n") {
		t.Fatalf("%s", res.Text)
	}
	if strings.Contains(res.Text, "* ->") {
		t.Fatalf("the default route is in the text: %s", res.Text)
	}

	// The proxy to a server: the rules name it.
	res, err = c.ImportRules(pac, "pac", map[string]string{"My proxy": "id:" + de, "DIRECT": "block"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Text, "-> DE one\n") || res.DefaultLine != "* -> блок" {
		t.Fatalf("%s\n%s", res.Text, res.DefaultLine)
	}
	got := c.ParseRulesText(res.Text + "\n" + res.DefaultLine)
	if len(got.Errors) != 0 || len(got.Rules) != 2 || !got.HasDefault || got.DefaultAction != rules.Block {
		t.Fatalf("%+v", got)
	}
	if got.Rules[0].Profile != de || got.Rules[0].Action != rules.Tunnel || got.Rules[1].Action != rules.Block {
		t.Fatalf("%+v", got.Rules)
	}
	// A server deleted since: back to the suggestion.
	res, _ = c.ImportRules(pac, "pac", map[string]string{"My proxy": "id:gone"})
	if res.Targets[0].To != "vpn" {
		t.Fatalf("%+v", res.Targets)
	}
}

func TestImportRulesV2RayN(t *testing.T) {
	c, _ := newCtl(t)
	text := strings.Join([]string{
		"True\tTorrent\t\tdirect\t\tbittorrent\t\t\t",
		"True\tAds\t\tblock\t\t\t\t\tgeosite:category-ads-all",
		"False\tOff: rule\t\tdirect\t\t\t\t\tdomain:off.example",
		"True\tMine\t\tproxy\t\t\t\t\tdomain:example.com,full:exact.example.org,word,regexp:^a\\.example$,192.0.2.0/24,app.exe",
		"True\tGames\t\tproxy\t27000-27100\t\t\tudp\t",
	}, "\n")
	res, err := c.ImportRules(text, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Ads: geosite:category-ads-all -> блок",
		`"Off: rule": off.example -> напрямую | выкл`,
		`Mine: example.com =exact.example.org keyword:word regexp:^a\.example$ 192.0.2.0/24 -> vpn`,
		"Mine (программы): app.exe -> vpn",
		"Games: * -> vpn | udp 27000-27100",
	}
	for _, w := range want {
		if !strings.Contains(res.Text, w+"\n") {
			t.Fatalf("no %q in\n%s", w, res.Text)
		}
	}
	got := c.ParseRulesText(res.Text)
	if len(got.Errors) != 0 || len(got.Rules) != 5 || got.HasDefault {
		t.Fatalf("%+v", got)
	}
	if got.Rules[1].Enabled == nil || *got.Rules[1].Enabled {
		t.Fatalf("the rule that was off is on: %+v", got.Rules[1])
	}
	if res.DefaultLine != "" || len(res.Warnings) != 1 || len(res.Notes) != 2 {
		t.Fatalf("%q %v %v", res.DefaultLine, res.Warnings, res.Notes)
	}
}

func TestImportRulesHysteria(t *testing.T) {
	c := geoCtl(t)
	res, err := c.ImportRules("acl:\n  inline:\n    - my_nl(suffix:example.com)\n    - direct(all)\n", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != "hysteria" || res.Count != 1 || res.DefaultLine != "* -> напрямую" || strings.Contains(res.Text, "* ->") {
		t.Fatalf("%+v", res)
	}
	if _, err := c.ImportRules("  ", "", nil); err == nil {
		t.Fatal("empty text imported")
	}
}

func TestImportRulesGuessServer(t *testing.T) {
	c, _ := newCtl(t)
	add, err := c.ImportURIs(strings.Join([]string{
		"hysteria2://p1@nl.example:443#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam",
		"hysteria2://p2@kz.example:443#%D0%9A%D0%B0%D0%B7%D0%B0%D1%85%D1%81%D1%82%D0%B0%D0%BD",
		"hysteria2://p3@us.example:443#Hysteria%20US",
		"hysteria2://p4@de1.example:443#DE%201",
		"hysteria2://p5@de2.example:443#DE%202",
	}, "\n"))
	if err != nil || len(add.Added) != 5 {
		t.Fatalf("%+v %v", add, err)
	}
	id := map[string]string{}
	for _, a := range add.Added {
		id[a.Name] = a.ID
	}
	text := "*.a.example +hyst\n*.b.example +kazah\n*.c.example +nl\n*.d.example +de\n*.e.example +other\n* +direct\n"
	res, err := c.ImportRules(text, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"hyst": "id:" + id["Hysteria US"], "kazah": "id:" + id["Казахстан"], "nl": "id:" + id["🇳🇱 Amsterdam"],
		"de": "vpn", "other": "vpn", "direct": "direct", // two DE servers: no guess
	}
	for _, tg := range res.Targets {
		if tg.To != want[tg.Name] || tg.Guess != strings.HasPrefix(want[tg.Name], "id:") {
			t.Errorf("%s: to %q guess %v, want %q", tg.Name, tg.To, tg.Guess, want[tg.Name])
		}
	}
	if !strings.Contains(res.Text, "Omega kazah: b.example -> Казахстан\n") {
		t.Fatalf("%s", res.Text)
	}
	// The user's choice wins over the guess.
	res, _ = c.ImportRules(text, "", map[string]string{"kazah": "id:" + id["🇳🇱 Amsterdam"]})
	for _, tg := range res.Targets {
		if tg.Name == "kazah" && (tg.To != "id:"+id["🇳🇱 Amsterdam"] || tg.Guess) {
			t.Fatalf("%+v", tg)
		}
	}
}

func TestNameWords(t *testing.T) {
	for in, want := range map[string]string{
		"🇳🇱 NL-Amsterdam #2": "nl nl amsterdam 2", "Казахстан": "kazahstan", "Подъезд": "podezd", "+IsHosting": "ishosting",
	} {
		if got := strings.Join(nameWords(in), " "); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	if wordMatch("kazah", "kazakhstan") != 1 || wordMatch("nl", "nld") != 0 || wordMatch("hyst", "hysteria") != 2 || wordMatch("us", "us") != 3 {
		t.Error("wordMatch")
	}
}
