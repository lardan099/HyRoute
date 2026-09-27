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
	res := parseRulesText(text, textProfiles)
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
	bad := parseRulesText("youtube.com -> 🇳🇱\nfoo.com\nbar.com -> марс\nqux.com -> vpn | быстро\n[chrome.exe]\n* -> vpn", textProfiles)
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
	text := formatRulesText(cfg, textProfiles)
	if !strings.Contains(text, "[chrome.exe]") {
		t.Fatal(text)
	}
	res := parseRulesText(text, textProfiles)
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

func TestApplyRulesText(t *testing.T) {
	c, _ := newCtl(t)
	c.ImportURIs(link)
	if _, _, err := c.ApplyRulesText("youtube.com -> vpn\nbad", true); err == nil {
		t.Fatal("errors must block saving")
	}
	if len(c.Settings().Rules) != 0 {
		t.Fatal("saved despite errors")
	}
	if _, _, err := c.ApplyRulesText("youtube.com -> vpn\n* -> напрямую", true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ApplyRulesText("[chrome.exe]\na.com -> блок\nb.com -> блок", false); err != nil {
		t.Fatal(err)
	}
	if st := c.Settings(); len(st.Rules) != 3 || st.DefaultAction != rules.Direct {
		t.Fatalf("%+v", st)
	}
	// Adding rules never changes "Всё остальное": "* ->" is refused there.
	if _, _, err := c.ApplyRulesText("c.com -> блок\n* -> vpn", false); err == nil || !strings.Contains(err.Error(), "Всё остальное") {
		t.Fatalf("default changed by adding: %v", err)
	}
	if st := c.Settings(); len(st.Rules) != 3 || st.DefaultAction != rules.Direct {
		t.Fatalf("%+v", st)
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
	res := parseRulesText(text, textProfiles)
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
	back := parseRulesText(formatRulesText(rules.Config{Rules: r}, textProfiles), textProfiles)
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
	res := parseRulesText("yt: youtube.com -> Нидерланды, vpn\n* -> vpn, Нидерланды", textProfiles)
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
	txt := formatRulesText(rules.Config{Rules: res.Rules, DefaultAction: res.DefaultAction, DefaultFallback: res.DefaultFallback}, textProfiles)
	if !strings.Contains(txt, " -> vpn\n") {
		t.Fatalf("format: %s", txt)
	}
	back := parseRulesText(txt, textProfiles)
	if len(back.Errors) != 0 || len(back.Rules[0].Fallback) != 1 || len(back.DefaultFallback) != 1 {
		t.Fatalf("round trip: %+v\n%s", back, txt)
	}
	// Arrows chain the same way; a trailing "блок" is the end of any chain.
	for _, ok := range []string{"a.com -> Нидерланды -> vpn", "a.com -> Нидерланды → vpn -> блок", "a.com -> Нидерланды, vpn, блок"} {
		r := parseRulesText(ok, textProfiles)
		if len(r.Errors) != 0 || len(r.Rules) != 1 || len(r.Rules[0].Fallback) != 1 || r.Rules[0].Fallback[0] != "" {
			t.Errorf("%q: %+v", ok, r)
		}
	}
	for _, bad := range []string{"a.com -> напрямую, vpn", "a.com -> vpn -> блок -> vpn", "a.com -> vpn, марс",
		"a.com -> vpn -> напрямую", "a.com -> Нидерланды ->", "a.com -> блок -> vpn"} {
		if r := parseRulesText(bad, textProfiles); len(r.Errors) == 0 {
			t.Errorf("%q accepted", bad)
		}
	}
	// A server whose name has an arrow or a comma is written as id: and
	// still found by its full name.
	odd := append(slices.Clone(textProfiles), hysteria.Profile{ID: "odd", Name: "Каскад RU -> NL, US"})
	r2 := parseRulesText("a.com -> Каскад RU -> NL, US", odd)
	if len(r2.Errors) != 0 || r2.Rules[0].Profile != "odd" || len(r2.Rules[0].Fallback) != 0 {
		t.Errorf("odd name: %+v", r2)
	}
	if w := targetWord(rules.Tunnel, "odd", odd); w != "id:odd" {
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
		{Domains: []string{".setup.exe", "run.exe"}, Action: rules.Block},
	}}
	text := formatRulesText(cfg, profiles)
	res := parseRulesText(text, profiles)
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
	if again := formatRulesText(rules.Config{DefaultAction: res.DefaultAction, DefaultProfile: res.DefaultProfile, Rules: res.Rules}, profiles); again != text {
		t.Errorf("not stable:\n%s\n---\n%s", text, again)
	}
}

func TestParseRulesTextItems(t *testing.T) {
	ok := func(text string) rules.Rule {
		t.Helper()
		res := parseRulesText(text, textProfiles)
		if len(res.Errors) != 0 || len(res.Rules) != 1 {
			t.Fatalf("%q: %+v", text, res)
		}
		return res.Rules[0]
	}
	bad := func(text, want string) {
		t.Helper()
		res := parseRulesText(text, textProfiles)
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
		res := parseRulesText("["+it+"]\na.com -> vpn", textProfiles)
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
	if res := parseRulesText("* -> vpn |", textProfiles); len(res.Errors) != 0 || !res.HasDefault {
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
		if w := targetWord(rules.Tunnel, id, profiles); w != want {
			t.Errorf("%s: %q, want %q", id, w, want)
		}
	}
	if a, id, _, err := parseTargets("FI", profiles); err != nil || a != rules.Tunnel || id != "sp" {
		t.Errorf("FI: %v %q %v", a, id, err)
	}
}
