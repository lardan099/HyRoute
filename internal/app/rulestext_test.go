package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
)

var textProfiles = []hysteria.Profile{
	{ID: "nl1", Name: "🇳🇱 Нидерланды напрямую"},
	{ID: "nl2", Name: "🇳🇱 NL up to 10 Gb/s"},
	{ID: "de", Name: "🇩🇪 DE up to 10 Gb/s"},
}

func TestParseRulesText(t *testing.T) {
	text := `# comment
YouTube: youtube.com, googlevideo.com ytimg.com -> нидерланды
discord -> DE
*.ru -> напрямую
ads.example.com -> блок | tcp | выкл

[chrome.exe]
instagram.com -> 🇩🇪
=example.org -> vpn | без дочерних

["C:\Program Files\App\app.exe"]
x.com -> id:nl2

[*]
"C:\Games\*" -> блок | udp
* -> vpn
`
	res := parseRulesText(text, serverTargets(textProfiles))
	if len(res.Errors) != 0 {
		t.Fatalf("%+v", res.Errors)
	}
	if len(res.Rules) != 8 || !res.HasDefault || res.DefaultAction != rules.Tunnel || res.DefaultProfile != "" {
		t.Fatalf("%d rules %+v", len(res.Rules), res)
	}
	r := res.Rules
	if r[0].Name != "YouTube" || strings.Join(r[0].Domains, " ") != ".youtube.com .googlevideo.com .ytimg.com" || r[0].Profile != "nl1" {
		t.Fatalf("%+v", r[0])
	}
	if r[1].Apps[0].Pattern != "discord.exe" || r[1].Profile != "de" {
		t.Fatalf("%+v", r[1])
	}
	if r[2].Domains[0] != "*.ru" || r[2].Action != rules.Direct {
		t.Fatalf("%+v", r[2])
	}
	if r[3].Action != rules.Block || r[3].Protocol != "tcp" || *r[3].Enabled {
		t.Fatalf("%+v", r[3])
	}
	if r[4].Apps[0].Pattern != "chrome.exe" || r[4].Domains[0] != ".instagram.com" || r[4].Profile != "de" {
		t.Fatalf("%+v", r[4])
	}
	if r[5].Domains[0] != "example.org" || r[5].Apps[0].InheritChildren || r[5].Profile != "" {
		t.Fatalf("%+v", r[5])
	}
	if r[6].Apps[0].Pattern != `C:\Program Files\App\app.exe` || r[6].Profile != "nl2" {
		t.Fatalf("%+v", r[6])
	}

	// Errors carry line numbers; ambiguous server names are refused.
	bad := parseRulesText("youtube.com -> 🇳🇱\nfoo.com\nbar.com -> марс\nqux.com -> vpn | быстро\n[chrome.exe]\n* -> vpn", serverTargets(textProfiles))
	lines := map[int]string{}
	for _, e := range bad.Errors {
		lines[e.Line] = e.Text
	}
	if !strings.Contains(lines[1], "нескольким") || !strings.Contains(lines[2], "стрелки") || !strings.Contains(lines[3], "не найден") ||
		!strings.Contains(lines[4], "опция") || !strings.Contains(lines[6], "вне блока") {
		t.Fatalf("%v", lines)
	}
}

// Text export and import give the same rules back.
func TestRulesTextRoundTrip(t *testing.T) {
	off := false
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "YouTube", Domains: []string{".youtube.com", "youtu.be", "*.googlevideo.com"}, Action: rules.Tunnel, Profile: "nl2"},
		{Apps: []rules.AppMatch{{Pattern: "chrome.exe", InheritChildren: true}}, Domains: []string{".instagram.com"}, Action: rules.Tunnel, Profile: "de"},
		{Apps: []rules.AppMatch{{Pattern: "chrome.exe", InheritChildren: true}}, Domains: []string{".x.com"}, Action: rules.Block, Protocol: "udp", Enabled: &off},
		{Apps: []rules.AppMatch{{Pattern: `C:\Program Files\Discord\Discord.exe`, InheritChildren: false}}, Action: rules.Tunnel},
		{App: &rules.AppMatch{Pattern: "curl.exe", InheritChildren: true}, Domain: &rules.DomainMatch{Pattern: "ifconfig.me"}, Action: rules.Tunnel},
	}}
	text := formatRulesText(cfg, serverTargets(textProfiles))
	if !strings.Contains(text, "[chrome.exe]") {
		t.Fatal(text)
	}
	res := parseRulesText(text, serverTargets(textProfiles))
	if len(res.Errors) != 0 {
		t.Fatalf("%v\n%s", res.Errors, text)
	}
	want, _ := rules.Compile(cfg)
	got, _ := rules.Compile(rules.Config{DefaultAction: res.DefaultAction, DefaultProfile: res.DefaultProfile, Rules: res.Rules})
	if len(res.Rules) != len(cfg.Rules) || res.DefaultAction != rules.Direct || got == nil || want == nil {
		t.Fatalf("%d rules\n%s", len(res.Rules), text)
	}
	for i, r := range res.Rules {
		o := cfg.Rules[i]
		if strings.Join(r.AllDomains(), ",") != strings.Join(o.AllDomains(), ",") || r.Action != o.Action || r.Profile != o.Profile ||
			r.Protocol != o.Protocol || (r.Enabled == nil) != (o.Enabled == nil) || len(r.AllApps()) != len(o.AllApps()) {
			t.Fatalf("rule %d: %+v vs %+v\n%s", i, r, o, text)
		}
		for j, a := range r.AllApps() {
			if a != o.AllApps()[j] {
				t.Fatalf("rule %d app: %+v vs %+v\n%s", i, a, o.AllApps()[j], text)
			}
		}
	}
}

// Rules text written for v1.2.0 (several port options on a line, "* -> …
// | порт 25") still reads, and writes back in one option.
func TestRulesTextPorts(t *testing.T) {
	text := `ssh.exe -> DE | tcp 22
game.exe -> id:nl2 | udp 27000-27200, 27015
*.example.com -> id:nl2 | порт 443 | порт 8443
DNS: * -> напрямую | udp 53
* -> блок | порт 25

[chrome.exe]
* -> DE | порт 8080

[*]
* -> vpn
`
	res := parseRulesText(text, serverTargets(textProfiles))
	if len(res.Errors) != 0 {
		t.Fatalf("%+v", res.Errors)
	}
	r := res.Rules
	if len(r) != 6 || !res.HasDefault {
		t.Fatalf("%d rules %+v", len(r), res)
	}
	if r[0].Protocol != "tcp" || strings.Join(r[0].Ports, ",") != "22" || r[0].Apps[0].Pattern != "ssh.exe" {
		t.Fatalf("%+v", r[0])
	}
	if r[1].Protocol != "udp" || strings.Join(r[1].Ports, ",") != "27000-27200,27015" {
		t.Fatalf("%+v", r[1])
	}
	if r[2].Protocol != "" || strings.Join(r[2].Ports, ",") != "443,8443" || r[2].Domains[0] != "*.example.com" {
		t.Fatalf("%+v", r[2])
	}
	if r[3].Name != "DNS" || len(r[3].Apps)+len(r[3].Domains) != 0 || strings.Join(r[3].Ports, ",") != "53" || r[3].Action != rules.Direct {
		t.Fatalf("%+v", r[3])
	}
	if r[4].Name != "" || strings.Join(r[4].Ports, ",") != "25" || r[4].Action != rules.Block {
		t.Fatalf("%+v", r[4])
	}
	if r[5].Apps[0].Pattern != "chrome.exe" || len(r[5].Domains) != 0 || strings.Join(r[5].Ports, ",") != "8080" {
		t.Fatalf("%+v", r[5])
	}

	// Back to text and again: the same rules.
	cfg := rules.Config{DefaultAction: res.DefaultAction, Rules: res.Rules}
	out := formatRulesText(cfg, serverTargets(textProfiles))
	again := parseRulesText(out, serverTargets(textProfiles))
	if len(again.Errors) != 0 || len(again.Rules) != len(r) {
		t.Fatalf("%+v\n%s", again.Errors, out)
	}
	for i := range r {
		if !slices.Equal(again.Rules[i].Ports, r[i].Ports) || again.Rules[i].Protocol != r[i].Protocol || again.Rules[i].Name != r[i].Name ||
			len(again.Rules[i].Apps) != len(r[i].Apps) || len(again.Rules[i].Domains) != len(r[i].Domains) {
			t.Fatalf("rule %d: %+v vs %+v\n%s", i, again.Rules[i], r[i], out)
		}
	}
	if !strings.Contains(out, "* -> блок | порт 25") || !strings.Contains(out, "| tcp 22") {
		t.Fatal(out)
	}

	bad := parseRulesText("a.com -> vpn | порт 70000\nb.com -> vpn | порт\nc.com -> vpn | tcp 5-1", serverTargets(textProfiles))
	if len(bad.Errors) != 3 {
		t.Fatalf("%+v", bad.Errors)
	}
}

func TestApplyRulesText(t *testing.T) {
	c, _ := newCtl(t)
	c.ImportURIs(link)
	if _, _, err := c.ApplyRulesText("youtube.com -> vpn\nbad", true, EditGuard{}); err == nil {
		t.Fatal("errors must block saving")
	}
	if len(c.Settings().Rules) != 0 {
		t.Fatal("saved despite errors")
	}
	if _, _, err := c.ApplyRulesText("youtube.com -> vpn\n* -> напрямую", true, EditGuard{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ApplyRulesText("[chrome.exe]\na.com -> блок\nb.com -> блок", false, EditGuard{}); err != nil {
		t.Fatal(err)
	}
	if st := c.Settings(); len(st.Rules) != 3 || st.DefaultAction != rules.Direct {
		t.Fatalf("%+v", st)
	}
	// Adding what the list has already (or a line twice) adds it once.
	_, res, err := c.ApplyRulesText("[chrome.exe]\nb.com -> блок\nd.com -> блок\nd.com -> блок", false, EditGuard{})
	if err != nil || res.Skipped != 2 || !strings.Contains(res.Summary, "не добавлены: 2") {
		t.Fatalf("%+v %v", res, err)
	}
	if st := c.Settings(); len(st.Rules) != 4 {
		t.Fatalf("%+v", st.Rules)
	}
	c.ApplyRulesText("d.com -> блок", false, EditGuard{}) // another rule: without chrome.exe
	if _, res, err = c.ApplyRulesText("[chrome.exe]\na.com -> блок", false, EditGuard{}); err != nil || res.Skipped != 1 || len(c.Settings().Rules) != 5 {
		t.Fatalf("nothing new: %+v %v", res, err)
	}
	// Adding rules never changes "Всё остальное": "* ->" is refused there.
	if _, _, err := c.ApplyRulesText("c.com -> блок\n* -> vpn", false, EditGuard{}); err == nil || !strings.Contains(err.Error(), "Всё остальное") {
		t.Fatalf("default changed by adding: %v", err)
	}
	if st := c.Settings(); len(st.Rules) != 5 || st.DefaultAction != rules.Direct {
		t.Fatalf("%+v", st)
	}
	// A copy that is off is switched on, not skipped.
	if _, _, err := c.ApplyRulesText("e.com -> блок | выкл", false, EditGuard{}); err != nil {
		t.Fatal(err)
	}
	if _, res, err = c.ApplyRulesText("e.com -> блок", false, EditGuard{}); err != nil || res.Enabled != 1 || res.Skipped != 0 {
		t.Fatalf("off copy: %+v %v", res, err)
	}
	if st := c.Settings(); len(st.Rules) != 6 || !st.Rules[5].On() {
		t.Fatalf("%+v", st.Rules)
	}
}

func TestRulesTextTypedItems(t *testing.T) {
	text := `YouTube: GeoSite:youtube googlevideo.com -> нидерланды
Россия: geoip:ru geosite:category-ru -> напрямую
lan: 192.168.0.0/16 10.1.2.3 2001:db8::/32 geoip:private -> напрямую
keyword:torrent regexp:^ads?\. -> блок
[chrome.exe]
geosite:instagram -> 🇩🇪
`
	res := parseRulesText(text, serverTargets(textProfiles))
	if len(res.Errors) != 0 {
		t.Fatalf("%+v", res.Errors)
	}
	r := res.Rules
	if strings.Join(r[0].Domains, " ") != "geosite:youtube .googlevideo.com" || len(r[0].Apps) != 0 {
		t.Fatalf("%+v", r[0])
	}
	if strings.Join(r[2].Domains, " ") != "192.168.0.0/16 10.1.2.3 2001:db8::/32 geoip:private" || len(r[2].Apps) != 0 {
		t.Fatalf("%+v", r[2])
	}
	if r[3].Action != rules.Block || len(r[3].Domains) != 2 {
		t.Fatalf("%+v", r[3])
	}
	if r[4].Apps[0].Pattern != "chrome.exe" || r[4].Domains[0] != "geosite:instagram" {
		t.Fatalf("%+v", r[4])
	}
	// Categories that cannot be used yet are warnings, not errors.
	if len(res.Warnings) == 0 {
		t.Fatal("no warnings for categories without a database")
	}
	back := parseRulesText(formatRulesText(rules.Config{Rules: r}, serverTargets(textProfiles)), serverTargets(textProfiles))
	if len(back.Errors) != 0 || len(back.Rules) != len(r) {
		t.Fatalf("%+v", back.Errors)
	}
	for i := range r {
		if strings.Join(back.Rules[i].Domains, " ") != strings.Join(r[i].Domains, " ") {
			t.Fatalf("round trip %d: %v vs %v", i, back.Rules[i].Domains, r[i].Domains)
		}
	}
}

func TestRulesTextFallback(t *testing.T) {
	res := parseRulesText("yt: youtube.com -> Нидерланды, vpn\n* -> vpn, Нидерланды", serverTargets(textProfiles))
	if len(res.Errors) != 0 || len(res.Rules) != 1 {
		t.Fatalf("%+v", res)
	}
	r := res.Rules[0]
	if r.Profile == "" || len(r.Fallback) != 1 || r.Fallback[0] != "" {
		t.Fatalf("rule %+v", r)
	}
	if res.DefaultProfile != "" || len(res.DefaultFallback) != 1 || res.DefaultFallback[0] != r.Profile {
		t.Fatalf("default %+v", res)
	}
	// Round trip keeps the fallbacks.
	txt := formatRulesText(rules.Config{Rules: res.Rules, DefaultAction: res.DefaultAction, DefaultFallback: res.DefaultFallback}, serverTargets(textProfiles))
	if !strings.Contains(txt, " -> vpn\n") {
		t.Fatalf("format: %s", txt)
	}
	back := parseRulesText(txt, serverTargets(textProfiles))
	if len(back.Errors) != 0 || len(back.Rules[0].Fallback) != 1 || len(back.DefaultFallback) != 1 {
		t.Fatalf("round trip: %+v\n%s", back, txt)
	}
	// Arrows chain the same way; a trailing "блок" is the end of any chain.
	for _, ok := range []string{"a.com -> Нидерланды -> vpn", "a.com -> Нидерланды → vpn -> блок", "a.com -> Нидерланды, vpn, блок"} {
		r := parseRulesText(ok, serverTargets(textProfiles))
		if len(r.Errors) != 0 || len(r.Rules) != 1 || len(r.Rules[0].Fallback) != 1 || r.Rules[0].Fallback[0] != "" {
			t.Errorf("%q: %+v", ok, r)
		}
	}
	for _, bad := range []string{"a.com -> напрямую, vpn", "a.com -> vpn -> блок -> vpn", "a.com -> vpn, марс",
		"a.com -> vpn -> напрямую", "a.com -> Нидерланды ->", "a.com -> блок -> vpn"} {
		if r := parseRulesText(bad, serverTargets(textProfiles)); len(r.Errors) == 0 {
			t.Errorf("%q accepted", bad)
		}
	}
	// A server whose name has an arrow or a comma is written as id: and
	// still found by its full name.
	odd := append(slices.Clone(textProfiles), hysteria.Profile{ID: "odd", Name: "Каскад RU -> NL, US"})
	r2 := parseRulesText("a.com -> Каскад RU -> NL, US", serverTargets(odd))
	if len(r2.Errors) != 0 || r2.Rules[0].Profile != "odd" || len(r2.Rules[0].Fallback) != 0 {
		t.Errorf("odd name: %+v", r2)
	}
	if w := targetWord(rules.Tunnel, "odd", serverTargets(odd)); w != "id:odd" {
		t.Errorf("odd name written as %q", w)
	}
}

// Rules made in the editor survive "Текстом" -> "Сохранить список" as they
// are: one-label domains, programs with and without children in one rule,
// names that look like comments, arrows or sites, regexp with "|", servers
// named like a target word.
func TestRulesTextRoundTripOdd(t *testing.T) {
	off := false
	profiles := append(slices.Clone(textProfiles),
		hysteria.Profile{ID: "d", Name: "Direct"}, hysteria.Profile{ID: "v", Name: "VPN"},
		hysteria.Profile{ID: "b", Name: "Блок"}, hysteria.Profile{ID: "m", Name: "Main"},
		hysteria.Profile{ID: "i", Name: "id:nl1"}, hysteria.Profile{ID: "sp", Name: " FI "},
		hysteria.Profile{ID: "q", Name: `NL "fast"`})
	cfg := rules.Config{DefaultAction: rules.Tunnel, DefaultProfile: "d", Rules: []rules.Rule{
		{Name: "LAN", Domains: []string{".lan", ".local", ".рф", "localhost", ".xn--p1ai", "*.home"}, Action: rules.Direct},
		{Name: "Steam", Apps: []rules.AppMatch{{Pattern: "steam.exe", InheritChildren: true}, {Pattern: "game.exe"},
			{Pattern: `C:\Program Files\X\x.exe`}}, Action: rules.Tunnel},
		{Name: "#1 YouTube", Domains: []string{"geosite:youtube"}, Action: rules.Tunnel},
		{Name: "RU -> direct", Domains: []string{".ru"}, Action: rules.Direct},
		{Name: `т.д. "сайты"`, Domains: []string{".example.com"}, Action: rules.Tunnel, Profile: "v"},
		{Name: "[x] a: b | c", Domains: []string{"a.example"}, Action: rules.Tunnel, Profile: "b"},
		{Name: "Ads", Domains: []string{`regexp:^(ads|track)\.`, "keyword:a->b"}, Action: rules.Block, Enabled: &off},
		{Name: "srv", Domains: []string{".a.com"}, Action: rules.Tunnel, Profile: "m", Fallback: []string{"i", "sp", "q"}},
		// Programs the editor allows: masks and a name with a dot but
		// without .exe, alone with sites ([...]) and in a line.
		{Name: "Chrome", Apps: []rules.AppMatch{{Pattern: "*chrome*", InheritChildren: true}}, Domains: []string{".b.com"}, Action: rules.Tunnel},
		{Name: "App", Apps: []rules.AppMatch{{Pattern: "my.app", InheritChildren: true}}, Domains: []string{".c.com"}, Action: rules.Direct},
		{Name: "Scr", Apps: []rules.AppMatch{{Pattern: "*.scr", InheritChildren: true}}, Domains: []string{".d.com"}, Action: rules.Block},
		{Name: "Masks", Apps: []rules.AppMatch{{Pattern: "*chrome*", InheritChildren: true}, {Pattern: "*fire?ox*"},
			{Pattern: "Steam.old/steam.exe", InheritChildren: true}}, Domains: []string{".e.com"}, Action: rules.Tunnel},
		// Programs a line reads as something else ("my.app" a site, "vmmem"
		// vmmem.exe) go with "app:": alone, without children, mixed.
		{Apps: []rules.AppMatch{{Pattern: "my.app", InheritChildren: true}}, Action: rules.Direct},
		{Apps: []rules.AppMatch{{Pattern: "*.scr"}}, Domains: []string{".f.com"}, Action: rules.Block},
		{Apps: []rules.AppMatch{{Pattern: "vmmem"}, {Pattern: "steam.exe", InheritChildren: true}}, Action: rules.Tunnel},
		{Apps: []rules.AppMatch{{Pattern: "vmmem", InheritChildren: true}, {Pattern: "my.app"}}, Action: rules.Direct},
		// A rule for every program is not "everything else".
		{Apps: []rules.AppMatch{{Pattern: "*", InheritChildren: true}}, Action: rules.Block},
		{Apps: []rules.AppMatch{{Pattern: "*", InheritChildren: true}}, Domains: []string{".g.com"}, Action: rules.Direct},
		// Quotes inside a quoted item.
		{Name: "Q", Domains: []string{`regexp:"q" "r"`, `keyword:a"b`}, Action: rules.Block},
		// Paths not to an .exe before another program: quoted, not read
		// as a path with spaces.
		{Apps: []rules.AppMatch{{Pattern: `C:\Tools\runner`, InheritChildren: true}, {Pattern: "discord.exe", InheritChildren: true}}, Action: rules.Tunnel},
		{Apps: []rules.AppMatch{{Pattern: `D:\Tools\run.cmd`, InheritChildren: true}, {Pattern: "Steam.old/steam.exe", InheritChildren: true}}, Action: rules.Tunnel},
		{Apps: []rules.AppMatch{{Pattern: `C:\Tools\runner`}, {Pattern: "discord.exe", InheritChildren: true}}, Action: rules.Direct},
		{Domains: []string{".setup.exe", "run.exe"}, Action: rules.Block},
	}}
	text := formatRulesText(cfg, serverTargets(profiles))
	res := parseRulesText(text, serverTargets(profiles))
	if len(res.Errors) != 0 || len(res.Rules) != len(cfg.Rules) {
		t.Fatalf("%d rules %+v\n%s", len(res.Rules), res.Errors, text)
	}
	if res.DefaultAction != rules.Tunnel || res.DefaultProfile != "d" {
		t.Fatalf("default %v %q\n%s", res.DefaultAction, res.DefaultProfile, text)
	}
	for i, r := range res.Rules {
		o := cfg.Rules[i]
		if r.Name != o.Name || r.Action != o.Action || r.Profile != o.Profile || !slices.Equal(r.Fallback, o.Fallback) ||
			(r.Enabled == nil) != (o.Enabled == nil) || !slices.Equal(r.Apps, o.Apps) {
			t.Errorf("rule %d: %+v\nwant %+v\n%s", i, r, o, text)
		}
		want := o.Domains
		if i == len(cfg.Rules)-1 {
			want = []string{"domain:setup.exe", "full:run.exe"} // the same sites
		}
		if !slices.Equal(r.Domains, want) {
			t.Errorf("rule %d: %q, want %q\n%s", i, r.Domains, want, text)
		}
	}
	// A second round gives the same text.
	if again := formatRulesText(rules.Config{DefaultAction: res.DefaultAction, DefaultProfile: res.DefaultProfile, Rules: res.Rules}, serverTargets(profiles)); again != text {
		t.Errorf("not stable:\n%s\n---\n%s", text, again)
	}
}

func TestParseRulesTextItems(t *testing.T) {
	ok := func(text string) rules.Rule {
		t.Helper()
		res := parseRulesText(text, serverTargets(textProfiles))
		if len(res.Errors) != 0 || len(res.Rules) != 1 {
			t.Fatalf("%q: %+v", text, res)
		}
		return res.Rules[0]
	}
	bad := func(text, want string) {
		t.Helper()
		res := parseRulesText(text, serverTargets(textProfiles))
		if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Text, want) {
			t.Errorf("%q: %+v, want an error with %q", text, res.Errors, want)
		}
	}
	// [discord] is discord.exe, as in a line; sites and lists are refused.
	r := ok("[discord, =game.exe]\ndiscord.com -> vpn")
	if !slices.Equal(r.Apps, []rules.AppMatch{{Pattern: "discord.exe", InheritChildren: true}, {Pattern: "game.exe"}}) {
		t.Errorf("%+v", r.Apps)
	}
	bad("[geosite:youtube]\na.com -> vpn", "не программа")
	bad("[https://discord.com/app]\na.com -> vpn", "не программа")
	bad("[.lan]\na.com -> vpn", "не программа")
	bad("[=youtube.com]\na.com -> vpn", "не программа")
	// A mask is a program; a name with a dot is one too in [ ], with a
	// warning: a line would read it as a site.
	if r = ok("[*chrome*]\na.com -> vpn"); !slices.Equal(r.Apps, []rules.AppMatch{{Pattern: "*chrome*", InheritChildren: true}}) {
		t.Errorf("%+v", r.Apps)
	}
	for _, it := range []string{"youtube.com", "*.ru"} {
		res := parseRulesText("["+it+"]\na.com -> vpn", serverTargets(textProfiles))
		if len(res.Errors) != 0 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0].Text, "а не сайт") ||
			len(res.Rules) != 1 || !slices.Equal(res.Rules[0].Apps, []rules.AppMatch{{Pattern: it, InheritChildren: true}}) {
			t.Errorf("%s: %+v", it, res)
		}
	}
	if r = ok("*chrome* =*fire?ox* a.com -> vpn"); !slices.Equal(r.Apps, []rules.AppMatch{
		{Pattern: "*chrome*", InheritChildren: true}, {Pattern: "*fire?ox*"}}) || !slices.Equal(r.Domains, []string{".a.com"}) {
		t.Errorf("%+v", r)
	}
	// "=" before a program: without children.
	if r = ok(`steam.exe =game.exe "=C:\Program Files\x.exe" -> vpn`); !slices.Equal(r.Apps, []rules.AppMatch{
		{Pattern: "steam.exe", InheritChildren: true}, {Pattern: "game.exe"}, {Pattern: `C:\Program Files\x.exe`}}) {
		t.Errorf("%+v", r.Apps)
	}
	if r = ok("=localhost =example.org -> vpn"); len(r.Apps) != 0 || !slices.Equal(r.Domains, []string{"localhost", "example.org"}) {
		t.Errorf("%+v", r)
	}
	// "* ->" has no options.
	bad("* -> блок | udp", "нет опций")
	bad("* -> vpn | мусор", "нет опций")
	if res := parseRulesText("* -> vpn |", serverTargets(textProfiles)); len(res.Errors) != 0 || !res.HasDefault {
		t.Errorf("%+v", res)
	}
	// The first arrow of any kind ends the rule; the rest is the chain.
	if r = ok("youtube.com → нидерланды -> DE"); len(r.Apps) != 0 || !slices.Equal(r.Domains, []string{".youtube.com"}) ||
		r.Profile != "nl1" || !slices.Equal(r.Fallback, []string{"de"}) {
		t.Errorf("%+v", r)
	}
	// Links give their site.
	for text, want := range map[string]string{
		"https://rutracker.org/forum/index.php?f=1 -> vpn": ".rutracker.org",
		"rutracker.org/forum -> vpn":                       ".rutracker.org",
		"HTTP://User@Example.com:8080/x -> vpn":            ".example.com",
		"http://1.2.3.4:8080/x -> vpn":                     "1.2.3.4",
		"https://[2001:db8::1]/ -> vpn":                    "2001:db8::1",
	} {
		if r = ok(text); len(r.Apps) != 0 || !slices.Equal(r.Domains, []string{want}) {
			t.Errorf("%q: %+v", text, r)
		}
	}
	bad("http:// -> vpn", "нет имени сайта")
	if r = ok(`C:/Games/*.exe \\srv\share\x.exe -> vpn`); len(r.Apps) != 2 || len(r.Domains) != 0 {
		t.Errorf("%+v", r)
	}
	// A path of dotted folders to an .exe is a program, not a link.
	if r = ok("Steam.old/steam.exe -> vpn"); !slices.Equal(r.Apps, []rules.AppMatch{{Pattern: "Steam.old/steam.exe", InheritChildren: true}}) ||
		len(r.Domains) != 0 {
		t.Errorf("%+v", r)
	}
	// "|" in an item: in quotes; without them the error says so.
	if r = ok(`Ads: "regexp:^(ads|track)\." -> блок | выкл`); r.Name != "Ads" || r.Domains[0] != `regexp:^(ads|track)\.` || *r.Enabled {
		t.Errorf("%+v", r)
	}
	bad(`regexp:^(ads|track)\. -> блок`, "кавычки")
	// Quoted names; a quoted item first is not a name.
	if r = ok(`"#1 YouTube: всё": geosite:youtube -> vpn`); r.Name != "#1 YouTube: всё" || r.Domains[0] != "geosite:youtube" {
		t.Errorf("%+v", r)
	}
	if r = ok(`"C:\Program Files\x.exe" ::1 -> vpn`); r.Name != "" || r.Apps[0].Pattern != `C:\Program Files\x.exe` || r.Domains[0] != "::1" {
		t.Errorf("%+v", r)
	}
	if r = ok(`"regexp:a: b" x.com -> vpn`); r.Name != "" || !slices.Equal(r.Domains, []string{"regexp:a: b", ".x.com"}) {
		t.Errorf("%+v", r)
	}
}

// Servers named like a target word are written as id:; a name with spaces
// around is written trimmed and found by it.
func TestTargetWordReserved(t *testing.T) {
	profiles := append(slices.Clone(textProfiles), hysteria.Profile{ID: "d", Name: "Direct"},
		hysteria.Profile{ID: "m", Name: "main"}, hysteria.Profile{ID: "b", Name: "Блок"}, hysteria.Profile{ID: "ok", Name: "Finland"},
		hysteria.Profile{ID: "sp", Name: " FI "}, hysteria.Profile{ID: "e", Name: "  "})
	for id, want := range map[string]string{"d": "id:d", "m": "id:m", "b": "id:b", "ok": "Finland", "de": "🇩🇪 DE up to 10 Gb/s",
		"sp": "FI", "e": "id:e"} {
		if w := targetWord(rules.Tunnel, id, serverTargets(profiles)); w != want {
			t.Errorf("%s: %q, want %q", id, w, want)
		}
	}
	if a, id, _, err := parseTargets("FI", serverTargets(profiles)); err != nil || a != rules.Tunnel || id != "sp" {
		t.Errorf("FI: %v %q %v", a, id, err)
	}
}

// Text that could be read two ways is read as written or refused with a
// line number, never silently turned into another rule.
func TestParseRulesTextAmbiguous(t *testing.T) {
	ok := func(text string) RulesTextResult {
		t.Helper()
		res := parseRulesText(text, serverTargets(textProfiles))
		if len(res.Errors) != 0 {
			t.Fatalf("%q: %+v", text, res.Errors)
		}
		return res
	}
	bad := func(text string, line int, want string) {
		t.Helper()
		res := parseRulesText(text, serverTargets(textProfiles))
		for _, e := range res.Errors {
			if e.Line == line && strings.Contains(e.Text, want) {
				return
			}
		}
		t.Errorf("%q: %+v, want an error at line %d with %q", text, res.Errors, line, want)
	}
	// An IPv6 address ending with "::" (and an item ending with ":") is
	// not a rule name.
	for text, want := range map[string][]string{
		"2001:db8:: 1.2.3.4 -> напрямую":        {"2001:db8::", "1.2.3.4"},
		"fe80:: 10.0.0.0/8 -> напрямую":         {"fe80::", "10.0.0.0/8"},
		":: -> блок":                            {"::"},
		"2001:db8:: -> блок":                    {"2001:db8::"},
		`regexp:^a: b.com -> блок`:              {"regexp:^a:", ".b.com"},
		"https://a.com/x: b.com -> vpn":         {".a.com", ".b.com"},
		"LAN: 2001:db8:: 1.2.3.4 -> vpn":        {"2001:db8::", "1.2.3.4"},
		"[chrome.exe]\n2001:db8:: a.com -> vpn": {"2001:db8::", ".a.com"},
	} {
		r := ok(text).Rules
		if len(r) != 1 || !slices.Equal(r[0].Domains, want) || (r[0].Name != "") != strings.HasPrefix(text, "LAN") {
			t.Errorf("%q: %+v", text, r)
		}
	}
	cfg := rules.Config{Rules: []rules.Rule{
		{Domains: []string{"2001:db8::", "1.2.3.4"}, Action: rules.Direct},
		{Apps: []rules.AppMatch{{Pattern: "chrome.exe", InheritChildren: true}}, Domains: []string{"2001:db8::", ".a.com"}, Action: rules.Tunnel},
		{Domains: []string{"regexp:a:", ".b.com"}, Action: rules.Block},
	}}
	back := ok(formatRulesText(cfg, serverTargets(textProfiles)))
	for i, r := range back.Rules {
		if r.Name != "" || !slices.Equal(r.Domains, cfg.Rules[i].Domains) {
			t.Errorf("round trip %d: %+v", i, r)
		}
	}
	// A name with . / \ * would be read as a site or a program: quotes.
	bad("Google/YouTube: youtube.com -> vpn", 1, "в кавычках")
	bad("Всё*: youtube.com -> vpn", 1, "в кавычках")
	bad("Яндекс.Музыка: music.yandex.ru -> vpn", 1, `"Яндекс.Музыка": …`)
	bad("chrome.exe discord.exe: a.com -> vpn", 1, "в кавычках")
	if r := ok(`"Google/YouTube": youtube.com -> vpn`).Rules[0]; r.Name != "Google/YouTube" || len(r.Apps) != 0 {
		t.Errorf("%+v", r)
	}
	// A name without items is a rule without items, not a program.
	bad("Discord: -> vpn", 1, "не указано")
	if r := ok("[chrome.exe]\nChrome: -> vpn").Rules[0]; r.Name != "Chrome" || !slices.Equal(r.Apps, []rules.AppMatch{{Pattern: "chrome.exe", InheritChildren: true}}) {
		t.Errorf("%+v", r)
	}
	// Under [program] a program would widen the rule, not narrow it.
	bad("[chrome.exe]\ninstagram.com -> vpn\ndiscord -> напрямую\n[*]\n* -> vpn", 3, "только сайты")
	bad("[chrome.exe]\napp:vmmem a.com -> vpn", 2, "только сайты")
	// [всё] is every program, as [все].
	if r := ok("[chrome.exe]\n[всё]\na.com -> vpn").Rules[0]; len(r.Apps) != 0 {
		t.Errorf("[всё]: %+v", r)
	}
	// Repeats that would silently override.
	bad("* -> vpn\na.com -> блок\n* -> напрямую", 3, "строке 1")
	bad("a.com -> vpn | tcp | udp", 1, "один протокол")
	if res := parseRulesText("a.com -> vpn | tcp | udp | tcp", serverTargets(textProfiles)); len(res.Errors) != 1 {
		t.Errorf("tcp|udp|tcp: %+v", res.Errors)
	}
	if r := ok("a.com -> vpn | udp | udp").Rules[0]; r.Protocol != "udp" {
		t.Errorf("%+v", r)
	}
	// A link to www.site is the site, as in the rule editor.
	for text, want := range map[string]string{
		"https://www.instagram.com/p/xyz -> vpn": ".instagram.com",
		"www.youtube.com/watch?v=1 -> vpn":       ".youtube.com",
		"https://www.com/ -> vpn":                ".www.com",
		"www.youtube.com -> vpn":                 ".www.youtube.com", // not a link: as written
	} {
		if r := ok(text).Rules[0]; !slices.Equal(r.Domains, []string{want}) {
			t.Errorf("%q: %+v", text, r.Domains)
		}
	}
	// Sites no name can be.
	for _, text := range []string{"«youtube.com» -> vpn", "(youtube.com) -> vpn", "youtube.com! -> vpn", "..example.com -> vpn",
		"example..com -> vpn", "domain:.example.com -> vpn", "full:a..b -> vpn", "=a.com, 'b.com' -> vpn", "https://www.a..com/ -> vpn"} {
		bad(text, 1, "в имени сайта")
	}
	// A refused item is the only error of its line.
	for _, text := range []string{"domain:.a.com -> vpn", "(a.com) -> vpn"} {
		if res := parseRulesText(text, serverTargets(textProfiles)); len(res.Errors) != 1 {
			t.Errorf("%q: %+v", text, res.Errors)
		}
	}
	// Characters IDNA allows by context.
	ok("col·legi.cat ab\u200ccd.com a\u30fbb.jp -> vpn")
	ok("пример.рф _dmarc.example.com *.ru .lan localhost example.com. xn--p1ai -> vpn")
	// A disabled line is checked too, without warnings.
	bad("regexp:( -> блок | выкл", 1, "регулярное")
	bad("a.com:443 -> vpn | выкл", 1, "шаблон")
	if res := ok("geosite:youtube -> vpn | выкл"); len(res.Warnings) != 0 {
		t.Errorf("%+v", res.Warnings)
	}
	// A path with spaces without quotes is cut into pieces: refused.
	bad(`C:\Program Files\Mozilla Firefox\firefox.exe -> vpn`, 1, "в кавычках")
	bad(`C:\My Games\x.exe -> vpn`, 1, "в кавычках")
	bad(`C:\Apps\v1.2 beta\x.exe -> vpn`, 1, "в кавычках")
	bad(`C:\x\My App.exe -> vpn`, 1, "в кавычках")
	bad(`[C:\Program Files\x.exe]`+"\na.com -> vpn", 1, "в кавычках")
	bad(`C:\Program Files (x86)\Steam\steam.exe -> vpn`, 1, "в кавычках")
	bad(`[C:\Program Files (x86)\Steam\steam.exe]`+"\na.com -> vpn", 1, "в кавычках")
	bad(`C:\Program Files -> vpn`, 1, "в кавычках")
	bad(`C:\Games\old.v2 My Game (2019)\x.exe -> vpn`, 1, "в кавычках")
	for _, text := range []string{`C:\a.exe b.exe -> vpn`, `C:\Games\* x.exe -> vpn`, `C:\tools\app.com x.exe -> vpn`,
		`"C:\Program Files\x.exe" y.exe -> vpn`, `\srv\share\x.exe a.com -> vpn`,
		`C:\tools\app.bin youtube.com/page 10.0.0.0/8 -> vpn`, `C:\tools\app.bin discord -> vpn`,
		// Quoted, the path is whole, whatever follows it.
		`"C:\Program Files\App\app" x.exe -> vpn`, `"C:\Tools\runner" discord.exe -> vpn`,
		`"=C:\Tools\runner" Steam.old/steam.exe -> vpn`, `C:\Tools\runner "sub\x.exe" -> vpn`} {
		ok(text)
	}
	if r := ok(`"C:\Program Files\App\app" x.exe -> vpn`).Rules[0]; !slices.Equal(r.Apps, []rules.AppMatch{
		{Pattern: `C:\Program Files\App\app`, InheritChildren: true}, {Pattern: "x.exe", InheritChildren: true}}) {
		t.Errorf("%+v", r.Apps)
	}
}

// A server name with a line break (a link's %0A) is written as id:, so the
// exported line stays one line.
func TestTargetWordLineBreak(t *testing.T) {
	for _, name := range []string{"DE\nfast", "DE\rfast", "DE\u2028fast", "DE\x00"} {
		profiles := append(slices.Clone(textProfiles), hysteria.Profile{ID: "p1", Name: name})
		if w := targetWord(rules.Tunnel, "p1", serverTargets(profiles)); w != "id:p1" {
			t.Errorf("%q written as %q", name, w)
		}
		cfg := rules.Config{DefaultAction: rules.Tunnel, DefaultFallback: []string{"p1"}, Rules: []rules.Rule{
			{Name: "Y", Domains: []string{".youtube.com"}, Action: rules.Tunnel, Profile: "p1"},
		}}
		res := parseRulesText(formatRulesText(cfg, serverTargets(profiles)), serverTargets(profiles))
		if len(res.Errors) != 0 || len(res.Rules) != 1 || res.Rules[0].Profile != "p1" || !slices.Equal(res.DefaultFallback, []string{"p1"}) {
			t.Errorf("%q: %+v", name, res)
		}
	}
}

// Groups in rules text: группа:Имя (or the bare name), id:grp-…; the
// formatter writes группа:Имя when it reads back, else id:.
func TestRulesTextGroups(t *testing.T) {
	ts := append(serverTargets(textProfiles),
		target{ID: "grp-000000000001", Name: "Авто", Group: true},
		target{ID: "grp-000000000002", Name: "vpn", Group: true},
		target{ID: "grp-000000000003", Name: "блок", Group: true},
		target{ID: "grp-000000000004", Name: "Нидерланды", Group: true})
	res := parseRulesText("Стриминг: geosite:netflix -> группа:Авто -> нидерланды напрямую\nx.com -> авто\ny.com -> id:grp-000000000002, group:Авто", ts)
	if len(res.Errors) != 0 {
		t.Fatalf("%+v", res.Errors)
	}
	if r := res.Rules[0]; r.Profile != "grp-000000000001" || !slices.Equal(r.Fallback, []string{"nl1"}) {
		t.Fatalf("%+v", r)
	}
	if res.Rules[1].Profile != "grp-000000000001" || res.Rules[2].Profile != "grp-000000000002" || res.Rules[2].Fallback[0] != "grp-000000000001" {
		t.Fatalf("%+v", res.Rules)
	}
	// A bare name that fits a server and a group alike: an error naming both
	// (an exact name wins).
	bad := parseRulesText("x.com -> нидерл", ts)
	if len(bad.Errors) != 1 || bad.Errors[0].Text != "«нидерл» подходит к нескольким: сервер «🇳🇱 Нидерланды напрямую», группа «Нидерланды» — уточните (для группы: группа:Нидерланды)" {
		t.Fatalf("%+v", bad.Errors)
	}
	if bad := parseRulesText("x.com -> группа:Марс\ny.com -> id:grp-00000000000f", ts); len(bad.Errors) != 2 ||
		bad.Errors[0].Text != "группа «Марс» не найдена" || bad.Errors[1].Text != "группы с id grp-00000000000f нет" {
		t.Fatalf("%+v", bad.Errors)
	}
	for id, want := range map[string]string{"grp-000000000001": "группа:Авто", "grp-000000000002": "id:grp-000000000002",
		"grp-000000000003": "id:grp-000000000003", "grp-000000000004": "группа:Нидерланды"} {
		if w := targetWord(rules.Tunnel, id, ts); w != want {
			t.Errorf("%s: %q, want %q", id, w, want)
		}
	}
	cfg := rules.Config{DefaultAction: rules.Tunnel, DefaultProfile: "grp-000000000002", Rules: res.Rules}
	text := formatRulesText(cfg, ts)
	if !strings.Contains(text, "# Куда: vpn (основной), имя сервера, группа:Имя, напрямую, блок.") ||
		!strings.Contains(text, "-> группа:Авто -> 🇳🇱 Нидерланды напрямую") {
		t.Fatal(text)
	}
	back := parseRulesText(text, ts)
	if len(back.Errors) != 0 || back.DefaultProfile != "grp-000000000002" || !slices.Equal(back.Rules[0].Fallback, res.Rules[0].Fallback) {
		t.Fatalf("%+v", back)
	}
}

// Port options after "|" and group targets on the other side of the arrow
// read and write together.
func TestRulesTextGroupsWithPorts(t *testing.T) {
	ts := append(serverTargets(textProfiles), target{ID: "grp-000000000001", Name: "Авто", Group: true})
	res := parseRulesText("ssh.exe -> группа:Авто, DE | tcp 22\nDNS: * -> группа:Авто | udp 53\ngame.exe -> авто | порт 27000-27200", ts)
	if len(res.Errors) != 0 || len(res.Rules) != 3 {
		t.Fatalf("%+v", res)
	}
	r := res.Rules
	if r[0].Profile != "grp-000000000001" || !slices.Equal(r[0].Fallback, []string{"de"}) || r[0].Protocol != "tcp" || strings.Join(r[0].Ports, ",") != "22" {
		t.Fatalf("%+v", r[0])
	}
	if r[1].Profile != "grp-000000000001" || strings.Join(r[1].Ports, ",") != "53" || r[1].Protocol != "udp" || len(r[1].Apps)+len(r[1].Domains) != 0 {
		t.Fatalf("%+v", r[1])
	}
	if r[2].Profile != "grp-000000000001" || strings.Join(r[2].Ports, ",") != "27000-27200" {
		t.Fatalf("%+v", r[2])
	}
	text := formatRulesText(rules.Config{Rules: r}, ts)
	if !strings.Contains(text, "ssh.exe -> группа:Авто -> ") || !strings.Contains(text, "| tcp 22") || !strings.Contains(text, "-> группа:Авто | udp 53") {
		t.Fatal(text)
	}
	back := parseRulesText(text, ts)
	if len(back.Errors) != 0 || len(back.Rules) != 3 {
		t.Fatalf("%+v\n%s", back, text)
	}
	for i := range r {
		if back.Rules[i].Profile != r[i].Profile || !slices.Equal(back.Rules[i].Fallback, r[i].Fallback) || !slices.Equal(back.Rules[i].Ports, r[i].Ports) || back.Rules[i].Protocol != r[i].Protocol {
			t.Fatalf("rule %d: %+v vs %+v\n%s", i, back.Rules[i], r[i], text)
		}
	}
}

// Repeats are the lines that can go without changing what the rules do.
func TestRulesTextRepeats(t *testing.T) {
	text := strings.Join([]string{
		"youtube.com -> напрямую",        // 1
		"YouTube: youtube.com -> direct", // 2 repeat of 1
		"chrome.exe -> блок | выкл",      // 3 off
		"chrome.exe -> блок",             // 4 the working copy of 3: kept
		"chrome.exe -> блок | выкл",      // 5 repeat (off)
		"youtube.com -> блок",            // 6 another route
		"twitch.tv -> напрямую | выкл",   // 7 off
		"twitch.tv -> напрямую | выкл",   // 8 repeat of an off one, itself off
	}, "\n")
	res := parseRulesText(text, nil)
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	if !slices.Equal(res.Repeats, []int{2, 5, 8}) {
		t.Fatalf("repeats %v", res.Repeats)
	}
	n := 0
	for _, w := range res.Warnings {
		if strings.Contains(w.Text, "повторяет правило в строке") {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("%+v", res.Warnings)
	}
	if res := parseRulesText("a.com -> напрямую\nb.com -> напрямую", nil); len(res.Repeats) != 0 {
		t.Fatalf("%v", res.Repeats)
	}
}

// A quote without its pair is an error of the line, not a program with a
// quote in its name that never matches.
func TestRulesTextUnpairedQuote(t *testing.T) {
	for _, text := range []string{
		`"C:\Program Files\App\app.exe -> vpn`,
		`"chrome.exe -> vpn`,
		"[\"C:\\Program Files\\App\\app.exe]\nexample.com -> vpn",
	} {
		res := parseRulesText(text, serverTargets(textProfiles))
		if len(res.Errors) == 0 || !strings.Contains(res.Errors[0].Text, "кавычка без пары") {
			t.Errorf("%q: %+v", text, res.Errors)
		}
	}
	if res := parseRulesText(`"C:\Program Files\App\app.exe" -> vpn`, serverTargets(textProfiles)); len(res.Errors) != 0 {
		t.Fatalf("%+v", res.Errors)
	}
}
