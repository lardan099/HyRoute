package app

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/geodata/geodatatest"
	"github.com/lardan099/hyroute/internal/rules"
)

func geoCtl(t *testing.T) *Controller {
	t.Helper()
	c, _ := newCtl(t)
	dir := filepath.Join(c.Store.Dir, "geo")
	if err := geodatatest.WriteSite(dir, map[string][]string{
		"openai":               {"domain:openai.com", "domain:chatgpt.com", "keyword:openaiapi"},
		"category-ai-chat-!cn": {"domain:openai.com", "domain:chatgpt.com", "domain:claude.ai"},
		"geolocation-!cn":      {"domain:chatgpt.com", "domain:youtube.com"},
		"youtube":              {"domain:youtube.com", "full:youtu.be", "regexp:^yt[0-9]\\.example$"},
		"ads":                  {"domain:ads.co.uk @ads"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := geodatatest.WriteIP(dir, map[string][]string{
		"telegram": {"149.154.160.0/20"},
		"nl":       {"149.154.160.0/21"},
	}); err != nil {
		t.Fatal(err)
	}
	c.geo.db.Forget()
	return c
}

func TestInspectSite(t *testing.T) {
	c := geoCtl(t)
	s := c.Settings()
	s.Rules = []rules.Rule{{Name: "ИИ", Domains: []string{"geosite:openai"}, Action: rules.Tunnel}}
	if _, err := c.SaveSettings(s); err != nil {
		t.Fatal(err)
	}
	res, err := c.Inspect("https://chatgpt.com/c/123")
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, h := range res.Site {
		tags = append(tags, h.Tag)
	}
	// Specific first, the region list last.
	if strings.Join(tags, " ") != "geosite:openai geosite:category-ai-chat-!cn geosite:geolocation-!cn" {
		t.Fatalf("%v", tags)
	}
	if res.Host != "chatgpt.com" || res.Site[0].Entry != "domain:chatgpt.com" || res.Site[0].Size != 3 ||
		len(res.Site[0].UsedBy) != 1 || !strings.Contains(res.Site[0].UsedBy[0], "«ИИ» → VPN") || !res.Site[2].Broad {
		t.Fatalf("%+v", res.Site)
	}
	if res.Route == nil {
		t.Fatal("no route explanation")
	}
}

func TestInspectIPAndList(t *testing.T) {
	c := geoCtl(t)
	res, err := c.Inspect("149.154.167.51")
	if err != nil || len(res.IP) != 2 || res.IP[0].Tag != "geoip:telegram" || res.IP[0].Entry != "149.154.160.0/20" {
		t.Fatalf("%v %+v", err, res.IP)
	}
	res, err = c.Inspect("geosite:youtube")
	if err != nil || res.List == nil || res.List.Total != 3 || res.List.Entries[1] != "full:youtu.be" {
		t.Fatalf("%v %+v", err, res.List)
	}
	l, err := c.GeoList("site", "ads", "", 0, 10)
	if err != nil || l.Entries[0] != "domain:ads.co.uk @ads" {
		t.Fatalf("%v %+v", err, l)
	}
	l, _ = c.GeoList("site", "category-ai-chat-!cn", "claude", 0, 10)
	if l.Matched != 1 || l.Total != 3 {
		t.Fatalf("%+v", l)
	}
	if _, err := c.Inspect("geosite:youtbe"); err == nil || !strings.Contains(err.Error(), "youtube") {
		t.Fatalf("typo: %v", err)
	}
}

func TestConvertACLToDomains(t *testing.T) {
	c := geoCtl(t)
	acl := `acl:
  inline:
    - proxy(geosite:openai)
    - proxy(suffix:api.telegram.org)
    - direct(full:www.bbc.co.uk)
    - proxy(geoip:telegram)
    - reject(geosite:ads)
    - direct(all)`
	res, err := c.ConvertACL(acl, "domains", "+hyst", "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "*.openai.com +hyst\n*.chatgpt.com +hyst\n*.telegram.org +hyst" {
		t.Fatalf("%q", res.Text)
	}
	if len(res.Warnings) != 2 { // keyword in openai, geoip
		t.Fatalf("%v", res.Warnings)
	}
	all, _ := c.ConvertACL(acl, "domains", "+hyst", "")
	if !strings.Contains(all.Text, "*.bbc.co.uk +hyst") || !strings.Contains(all.Text, "*.ads.co.uk +hyst") {
		t.Fatalf("%q", all.Text)
	}
	if _, err := c.ConvertACL("hello", "domains", "", ""); err == nil {
		t.Fatal("no rules must be an error")
	}
}

func TestConvertACLToRules(t *testing.T) {
	c := geoCtl(t)
	res, err := c.ConvertACL(`- direct(geoip:private)
- direct(geosite:category-ru)
- my_nl(geosite:openai)
- my_nl(suffix:claude.ai)
- reject(all, udp/443)
- reject(example.com)
- direct(all)`, "rules", "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := "ACL direct: geoip:private geosite:category-ru -> напрямую\nACL my_nl: geosite:openai claude.ai -> vpn\nACL reject: =example.com -> блок\n* -> напрямую\n"
	if !strings.HasSuffix(res.Text, want) {
		t.Fatalf("%s", res.Text)
	}
	if len(res.Warnings) != 1 { // all with udp/443
		t.Fatalf("%v", res.Warnings)
	}
	// The output is valid rules text.
	parsed := parseRulesText(res.Text, nil)
	if len(parsed.Errors) != 0 || len(parsed.Rules) != 3 || !parsed.HasDefault {
		t.Fatalf("%+v", parsed)
	}
}

func TestRootDomain(t *testing.T) {
	for in, want := range map[string]string{
		"api.telegram.org": "telegram.org", "*.www.bbc.co.uk": "bbc.co.uk", "example.com.": "example.com", "localhost": "", "a.b.com.au": "b.com.au",
	} {
		if got := rootDomain(in); got != want {
			t.Errorf("%s: %q", in, got)
		}
	}
}
