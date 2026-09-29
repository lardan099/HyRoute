package app

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
)

// Port rules: rules text options, «Проверить адрес», the lists page and the
// ACL converter. No test here makes a DNS query (lookupIP stubs).

func TestParsePortOptions(t *testing.T) {
	for text, want := range map[string]struct {
		proto string
		ports []string
		off   bool
	}{
		"a.com -> vpn | tcp 22":                   {"tcp", []string{"22"}, false},
		"a.com -> vpn | tcp/22":                   {"tcp", []string{"22"}, false},
		"a.com -> vpn | TCP:22":                   {"tcp", []string{"22"}, false},
		"a.com -> vpn | udp 443":                  {"udp", []string{"443"}, false},
		"a.com -> vpn | udp/27000 – 27100":        {"udp", []string{"27000-27100"}, false},
		"a.com -> vpn | порт 443":                 {"", []string{"443"}, false},
		"a.com -> vpn | порты 80, 443, 8000-8100": {"", []string{"80", "443", "8000-8100"}, false},
		"a.com -> vpn | ports 80;443":             {"", []string{"80", "443"}, false},
		"a.com -> vpn | port 0443":                {"", []string{"443"}, false},
		"a.com -> vpn | tcp 22 | выкл":            {"tcp", []string{"22"}, true},
		"a.com -> vpn | tcp | порт 22":            {"tcp", []string{"22"}, false},
		"a.com -> vpn | udp":                      {"udp", nil, false},
		// v1.2.0 wrote several port options: one list.
		"a.com -> vpn | порт 443 | порт 8443": {"", []string{"443", "8443"}, false},
		"a.com -> vpn | tcp 22 | порт 80":     {"tcp", []string{"22", "80"}, false},
		"a.com -> vpn | порт 80,443":          {"", []string{"80", "443"}, false},
	} {
		res := parseRulesText(text, serverTargets(textProfiles))
		if len(res.Errors) != 0 || len(res.Rules) != 1 {
			t.Errorf("%q: %+v", text, res.Errors)
			continue
		}
		r := res.Rules[0]
		if r.Protocol != want.proto || !slices.Equal(r.Ports, want.ports) || (r.Enabled != nil) != want.off {
			t.Errorf("%q: %+v", text, r)
		}
	}
	for text, want := range map[string]string{
		"a.com -> vpn | tcp 0":        "неверный порт «0»",
		"a.com -> vpn | порт":         "после «порт» укажите порт, например: порт 443",
		"a.com -> vpn | tcp:":         "после «tcp» укажите порт",
		"a.com -> vpn | tcp 22 | udp": "один протокол",
		// PITFALLS #10: separators only are no port, not every port.
		"a.com -> vpn | порт ,":      "не указан ни один порт",
		"ssh.exe -> блок | tcp ;":    "не указан ни один порт",
		"* -> блок | порт ,":         "не указан ни один порт",
		"a.com -> vpn | порт 100-50": "наоборот",
		"a.com -> vpn | tcp22":       "непонятная опция \"tcp22\" (есть: tcp, udp, tcp 443, порты 80, 443, выкл, без дочерних)",
		"* -> vpn | tcp":             "Правило только по порту пишется с портом: * -> напрямую | tcp 22",
		"* -> vpn | порт x":          "неверный порт «x»",
		"[chrome.exe]\n* -> vpn":     "с портом — правило для этой программы: * -> vpn | udp 443",
	} {
		res := parseRulesText(text, serverTargets(textProfiles))
		if len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Text, want) || len(res.Rules) != 0 || res.HasDefault {
			t.Errorf("%q: %+v, want %q", text, res, want)
		}
	}
}

func TestParsePortOnlyRules(t *testing.T) {
	one := func(text string) rules.Rule {
		t.Helper()
		res := parseRulesText(text, serverTargets(textProfiles))
		if len(res.Errors) != 0 || len(res.Rules) != 1 || res.HasDefault {
			t.Fatalf("%q: %+v", text, res)
		}
		return res.Rules[0]
	}
	r := one("* -> напрямую | tcp 22")
	if r.Name != "" || len(r.Apps) != 0 || len(r.Domains) != 0 || r.Protocol != "tcp" || !slices.Equal(r.Ports, []string{"22"}) || r.Action != rules.Direct {
		t.Errorf("port-only: %+v", r)
	}
	if r = one("SSH: * -> напрямую | tcp 22"); r.Name != "SSH" || len(r.Apps) != 0 || len(r.Ports) != 1 {
		t.Errorf("named: %+v", r)
	}
	if r = one(`"a.b": * -> vpn | порт 53`); r.Name != "a.b" || len(r.Apps) != 0 || !slices.Equal(r.Ports, []string{"53"}) {
		t.Errorf("quoted name: %+v", r)
	}
	if r = one("[chrome.exe]\n* -> DE | udp 443"); !slices.Equal(r.Apps, []rules.AppMatch{{Pattern: "chrome.exe", InheritChildren: true}}) ||
		r.Protocol != "udp" || r.Profile != "de" {
		t.Errorf("section: %+v", r)
	}
	// Without a port "* ->" stays everything else, "Name: * ->" a glob.
	if res := parseRulesText("* -> vpn", serverTargets(textProfiles)); !res.HasDefault || len(res.Rules) != 0 {
		t.Errorf("default: %+v", res)
	}
	if r = one("Name: * -> vpn"); !slices.Equal(r.Apps, []rules.AppMatch{{Pattern: "*", InheritChildren: true}}) {
		t.Errorf("glob: %+v", r)
	}
	// «Добавить пачкой» takes a port-only rule.
	c, _ := newCtl(t)
	if _, _, err := c.ApplyRulesText("SSH: * -> напрямую | tcp 22", false, EditGuard{}); err != nil {
		t.Fatal(err)
	}
	if st := c.Settings(); len(st.Rules) != 1 || !slices.Equal(st.Rules[0].Ports, []string{"22"}) {
		t.Fatalf("%+v", st.Rules)
	}
}

func TestRulesTextPortsRoundTrip(t *testing.T) {
	off := false
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "Discord", Apps: []rules.AppMatch{{Pattern: "discord.exe", InheritChildren: true}}, Protocol: "udp", Ports: rules.PortList{"50000-65535"}, Action: rules.Tunnel, Profile: "de"},
		{Name: "Web", Domains: []string{".a.com"}, Ports: rules.PortList{"80", "443"}, Action: rules.Tunnel},
		{Domains: []string{".b.com"}, Ports: rules.PortList{"8443"}, Action: rules.Block},
		{Name: "SSH", Protocol: "tcp", Ports: rules.PortList{"22"}, Action: rules.Direct},
		{Ports: rules.PortList{"53"}, Action: rules.Tunnel},
		{Apps: []rules.AppMatch{{Pattern: "*", InheritChildren: true}}, Ports: rules.PortList{"25"}, Action: rules.Block},
		{Name: "Glob", Apps: []rules.AppMatch{{Pattern: "*", InheritChildren: true}}, Ports: rules.PortList{"26"}, Action: rules.Block},
		{Apps: []rules.AppMatch{{Pattern: "chrome.exe", InheritChildren: true}}, Domains: []string{".x.com"}, Protocol: "udp", Ports: rules.PortList{"443"}, Action: rules.Block},
		{Name: "Off", Domains: []string{".c.com"}, Ports: rules.PortList{"1-1024"}, Action: rules.Direct, Enabled: &off},
		{Name: "Odd", Domains: []string{".d.com"}, Ports: rules.PortList{"0443", " 80"}, Action: rules.Direct},
	}}
	text := formatRulesText(cfg, serverTargets(textProfiles))
	for _, want := range []string{"Discord: discord.exe -> 🇩🇪 DE up to 10 Gb/s | udp 50000-65535", "Web: a.com -> vpn | порты 80, 443", "b.com -> блок | порт 8443",
		"SSH: * -> напрямую | tcp 22", "\n* -> vpn | порт 53", "app:* -> блок | порт 25", "Glob: app:* -> блок | порт 26", "[chrome.exe]\nx.com -> блок | udp 443",
		"Off: c.com -> напрямую | порты 1-1024 | выкл", "Odd: d.com -> напрямую | порты 443, 80",
		"Опции после |: tcp, udp, порты (tcp 443), выкл."} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	res := parseRulesText(text, serverTargets(textProfiles))
	if len(res.Errors) != 0 || len(res.Rules) != len(cfg.Rules) {
		t.Fatalf("%+v\n%s", res.Errors, text)
	}
	for i, r := range res.Rules {
		o := cfg.Rules[i]
		if r.Name != o.Name || r.Protocol != o.Protocol || !rules.SamePorts(r.Ports, o.Ports) || !slices.Equal(r.Apps, o.Apps) ||
			!slices.Equal(r.Domains, o.Domains) || (r.Enabled == nil) != (o.Enabled == nil) || r.Action != o.Action {
			t.Errorf("rule %d: %+v\nwant %+v\n%s", i, r, o, text)
		}
	}
	if !slices.Equal(res.Rules[9].Ports, []string{"443", "80"}) {
		t.Errorf("not canonical: %q", res.Rules[9].Ports)
	}
	// A rule with no items at all (disabled) keeps an empty left side:
	// re-import refuses it rather than read a glob-* rule.
	empty := formatRulesText(rules.Config{Rules: []rules.Rule{{Name: "X", Enabled: &off, Action: rules.Direct}}}, nil)
	if !strings.Contains(empty, "X:  -> напрямую | выкл") {
		t.Fatalf("%s", empty)
	}
	if res := parseRulesText(empty, nil); len(res.Errors) != 1 || len(res.Rules) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestRuleOptionText(t *testing.T) {
	for _, c := range []struct {
		proto string
		ports []string
		want  string
	}{
		{"", nil, ""},
		{"any", nil, ""},
		{"TCP", nil, "tcp"},
		{"tcp", []string{"80", "443"}, "tcp 80, 443"},
		{"udp", []string{"27000-27100"}, "udp 27000-27100"},
		{"", []string{"443"}, "порт 443"},
		{"", []string{"80", "443"}, "порты 80, 443"},
		{"", []string{"8000-8100"}, "порты 8000-8100"},
		{"", []string{"0443", "443"}, "порт 443"},
		{"", []string{"0"}, "порт 0"},
		{"tcp", []string{"80", "99999"}, "tcp 80, 99999"},
		{"", []string{"80|выкл"}, "порт 80?????"},
	} {
		if got := ruleOptionText(c.proto, c.ports); got != c.want {
			t.Errorf("%q %q: %q, want %q", c.proto, c.ports, got, c.want)
		}
	}
}

// Invalid stored ports are exported defanged, never dropped: re-import
// reports an error on that line only.
func TestRawPortItem(t *testing.T) {
	for in, want := range map[string]string{"0": "0", "99999": "99999", "": "?", "80|выкл": "80?????", "1\n* -> vpn": "1???-?????",
		"8000–8100x": "8000?8100?", "#1": "?1", `"1"`: "?1?", "1,2": "1?2", "1 2": "1?2", "1;2": "1?2", "1\r2": "1?2"} {
		got := rawPortItem(in)
		if got != want || strings.ContainsAny(got, "|#\",; \r\n") {
			t.Errorf("%q: %q", in, got)
		}
		if _, err := rules.ParsePortItem(got); err == nil {
			t.Errorf("%q: %q is valid", in, got)
		}
	}
	off := false
	bad := [][]string{{"0"}, {"99999"}, {""}, {"80|выкл"}, {"1\n* -> vpn"}, {"80", "8000–8100x"}, {"#1", "443"}, {`"1"`}, {"1,2"},
		{"1 2"}, {"-"}, {"80-"}, {"80", "-90"}, {"5", "-", "7"}}
	for _, ports := range bad {
		for _, r := range []rules.Rule{
			{Name: "X", Enabled: &off, Domains: []string{".x.com"}, Ports: ports, Action: rules.Direct},
			{Ports: ports, Action: rules.Tunnel},
			{Protocol: "udp", Ports: ports, Action: rules.Block, Enabled: &off},
		} {
			cfg := rules.Config{Rules: []rules.Rule{{Name: "A", Domains: []string{".a.com"}, Action: rules.Direct}, r,
				{Name: "B", Domains: []string{".b.com"}, Action: rules.Direct}}}
			text := formatRulesText(cfg, nil)
			res := parseRulesText(text, nil)
			if len(res.Errors) != 1 || len(res.Rules) != 2 || res.HasDefault != true || res.Rules[0].Name != "A" || res.Rules[1].Name != "B" {
				t.Errorf("%q %+v: %+v\n%s", ports, r, res, text)
			}
		}
	}
	// A port-only rule with a bad port is never read as «всё остальное».
	text := formatRulesText(rules.Config{Rules: []rules.Rule{{Ports: rules.PortList{"99999"}, Action: rules.Block}}}, nil)
	if !strings.Contains(text, "* -> блок | порт 99999") {
		t.Fatalf("%s", text)
	}
}

func TestSplitTarget(t *testing.T) {
	for in, want := range map[string]struct {
		host   string
		port   uint16
		scheme string
	}{
		"https://x.com":         {"x.com", 0, "https"},
		"HTTP://1.2.3.4:8080/p": {"1.2.3.4", 8080, "http"},
		"x.com:8443":            {"x.com", 8443, ""},
		"[2001:db8::1]:443":     {"2001:db8::1", 443, ""},
		"2001:db8::1":           {"2001:db8::1", 0, ""},
		"x.com:99999":           {"x.com", 0, ""},
		".x.com":                {"x.com", 0, ""},
		"":                      {"", 0, ""},
	} {
		h, p, s := splitTarget(in)
		if h != want.host || p != want.port || s != want.scheme {
			t.Errorf("%q: %q %d %q", in, h, p, s)
		}
	}
}

// noDNS makes the controller's lookups answer ip (or fail when invalid).
func noDNS(c *Controller, ip string) {
	c.lookupIP = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if ip == "" {
			return nil, errors.New("no DNS in tests")
		}
		return []netip.Addr{netip.MustParseAddr(ip)}, nil
	}
}

func TestExplainPort(t *testing.T) {
	c, _ := newCtl(t)
	noDNS(c, "")
	st := c.Settings()
	st.Rules = []rules.Rule{
		{Name: "web", Domains: []string{".x.com"}, Protocol: "tcp", Ports: rules.PortList{"8443"}, Action: rules.Block},
		{Name: "SSH", Protocol: "tcp", Ports: rules.PortList{"22"}, Action: rules.Block},
	}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	notes := func(ex Explanation) string { return strings.Join(ex.Notes, " ") }
	ex := c.Explain(ExplainQuery{Target: "https://x.com", Proto: "tcp", Port: 8443}, nil)
	if ex.Port != 8443 || ex.Winner.Name != "web" || !strings.Contains(notes(ex), "Порт из адреса (443) не учтён: проверен порт 8443.") {
		t.Fatalf("field over link: %+v %v", ex.Winner, ex.Notes)
	}
	if ex = c.Explain(ExplainQuery{Target: "x.com:8080", Proto: "tcp", Port: 8080}, nil); strings.Contains(notes(ex), "не учтён") || ex.Port != 8080 {
		t.Fatalf("same port: %v", ex.Notes)
	}
	if ex = c.Explain(ExplainQuery{Target: "x.com", Port: 8443}, nil); strings.Contains(notes(ex), "не учтён") || ex.Winner.Name != "web" {
		t.Fatalf("plain: %+v %v", ex.Winner, ex.Notes)
	}
	if ex = c.Explain(ExplainQuery{Target: "x.com:8443"}, nil); ex.Port != 8443 || ex.Winner.Name != "web" || !strings.Contains(notes(ex), "Порт 8443 взят из адреса.") {
		t.Fatalf("from address: %+v %v", ex.Winner, ex.Notes)
	}
	if ex = c.Explain(ExplainQuery{Target: "https://x.com/a"}, nil); ex.Port != 443 || ex.Winner.Index != -1 || !strings.Contains(notes(ex), "Порт 443 взят из ссылки.") {
		t.Fatalf("from link: %+v %v", ex.Winner, ex.Notes)
	}
	if ex = c.Explain(ExplainQuery{Target: "x.com", Port: 70000}, nil); ex.Port != 0 || !strings.Contains(notes(ex), "Порт 70000 не бывает") ||
		!strings.Contains(notes(ex), "Порт не указан, поэтому") || !ex.PortRules {
		t.Fatalf("out of range: %+v %v", ex.Winner, ex.Notes)
	}
	// «Куда пойдёт TCP 22»: no target, no program.
	if ex = c.Explain(ExplainQuery{Proto: "tcp", Port: 22}, nil); ex.Winner.Name != "SSH" || ex.Port != 22 {
		t.Fatalf("port only: %+v", ex.Winner)
	}
}

// Explain answers UDP 443 like the engine with the explained settings.
func TestExplainQUICWiring(t *testing.T) {
	c, _ := newCtl(t)
	noDNS(c, "")
	st := c.Settings()
	st.Rules = []rules.Rule{{Name: "yt", Domains: []string{".youtube.test"}, Protocol: "udp", Ports: rules.PortList{"443"}, Action: rules.Block}}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	q := ExplainQuery{Target: "https://youtube.test", Proto: "udp"}
	if ex := c.Explain(q, nil); ex.Winner.Index != rules.StepQUICBlock || ex.Port != 443 {
		t.Fatalf("defaults: %+v", ex.Winner)
	}
	no := false
	st.BlockQUIC = &no
	if ex := c.Explain(q, &st); ex.Winner.Name != "yt" {
		t.Fatalf("blockQUIC off: %+v", ex.Winner)
	}
	// Lint follows the same settings.
	if is := c.LintRules(st); len(is) != 0 {
		t.Fatalf("lint off: %+v", is)
	}
	st.BlockQUIC = nil
	if is := c.LintRules(st); len(is) != 1 || is[0].Severity != "warn" {
		t.Fatalf("lint: %+v", is)
	}
}

func TestInspectPortRule(t *testing.T) {
	c := geoCtl(t)
	noDNS(c, "192.0.2.10")
	c.ImportURIs(link)
	de := c.Profiles()[0].ID
	st := c.Settings()
	st.Rules = []rules.Rule{{Name: "YT", Domains: []string{".youtube.test"}, Protocol: "tcp", Ports: rules.PortList{"443"}, Action: rules.Tunnel, Profile: de}}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]struct {
		port int
		rule string
	}{
		"youtube.test":         {443, "YT"},
		"https://youtube.test": {443, "YT"},
		"http://youtube.test":  {80, "по умолчанию"},
		"youtube.test:8443":    {8443, "по умолчанию"},
	} {
		res, err := c.Inspect(q)
		if err != nil || res.Route == nil {
			t.Fatalf("%s: %v", q, err)
		}
		if res.Route.Port != want.port || res.Route.Winner.Name != want.rule || !res.Route.PortRules {
			t.Errorf("%s: %d %+v", q, res.Route.Port, res.Route.Winner)
		}
		if strings.Contains(strings.Join(res.Route.Notes, " "), "взят из") {
			t.Errorf("%s: %v", q, res.Route.Notes)
		}
	}
}

func TestConvertACLPorts(t *testing.T) {
	conv := func(acl string) ConvertResult {
		t.Helper()
		res := aclToRules(parseACL(acl))
		if p := parseRulesText(res.Text, nil); len(p.Errors) != 0 {
			t.Fatalf("%q: %+v\n%s", acl, p.Errors, res.Text)
		}
		return res
	}
	for acl, want := range map[string]string{
		"proxy(example.com, tcp/443)":  "ACL proxy: =example.com -> vpn | tcp 443\n",
		"direct(x.com, */80)":          "ACL direct: =x.com -> напрямую | порт 80\n",
		"proxy(x.com, tcp/0)":          "ACL proxy: =x.com -> vpn | tcp\n",
		"proxy(x.com, tcp/0-100)":      "ACL proxy: =x.com -> vpn | tcp\n",
		"proxy(x.com, */0-100)":        "ACL proxy: =x.com -> vpn\n",
		"proxy(x.com, tcp/*)":          "ACL proxy: =x.com -> vpn | tcp\n",
		"proxy(x.com, tcp/ 80-90)":     "ACL proxy: =x.com -> vpn | tcp 80-90\n",
		"direct(all, tcp/22)":          "ACL direct: * -> напрямую | tcp 22 | выкл\n",
		"direct(all, udp)":             "ACL direct: * -> напрямую | udp 1-65535 | выкл\n",
		"proxy(all, udp)":              "ACL proxy: * -> vpn | udp 1-65535\n",
		"reject(all, udp)":             "ACL reject: * -> блок | udp 1-65535 | выкл\n",
		"reject(all, tcp/25)":          "ACL reject: * -> блок | tcp 25 | выкл\n",
		"reject(geosite:ads, tcp/443)": "ACL reject: geosite:ads -> блок | tcp 443\n",
		"direct(example.com, *, )":     "ACL direct: =example.com -> напрямую\n",
	} {
		res := conv(acl)
		if !strings.HasSuffix(res.Text, want) {
			t.Errorf("%s: %q", acl, res.Text)
		}
		scope := strings.Contains(strings.Join(res.Warnings, " "), "добавлено выключенным")
		if scope != (strings.HasPrefix(acl, "reject(all") || strings.HasPrefix(acl, "direct(all")) {
			t.Errorf("%s: warnings %v", acl, res.Warnings)
		}
	}
	// Disabled when parsed back.
	if p := parseRulesText(conv("reject(all, udp)").Text, nil); len(p.Rules) != 1 || p.Rules[0].Enabled == nil || *p.Rules[0].Enabled {
		t.Fatalf("%+v", p.Rules)
	}
	// Lines Hysteria refuses, and redirects, are skipped with a warning.
	for acl, warn := range map[string]string{
		"proxy(x.com, udp/2000-1000)":     "непонятный протокол или порт",
		"proxy(x.com, tcp/5-0)":           "непонятный протокол или порт",
		"proxy(x.com, tcp/ 80)":           "непонятный протокол или порт",
		"proxy(x.com, tcp/80 - 90)":       "непонятный протокол или порт",
		"proxy(x.com, tcp/70000)":         "непонятный протокол или порт",
		"proxy(x.com, sctp/1)":            "непонятный протокол или порт",
		"proxy(x.com, tcp/x)":             "непонятный протокол или порт",
		"direct(all, udp/53, 1.1.1.1)":    "перенаправление на 1.1.1.1 в HyRoute не переносится — строка пропущена",
		"direct(example.com, *, 1.2.3.4)": "перенаправление на 1.2.3.4",
	} {
		res := conv(acl)
		if res.Count != 0 || strings.Contains(res.Text, "* ->") || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], warn) {
			t.Errorf("%s: %q %v", acl, res.Text, res.Warnings)
		}
	}
	// A redirect of all traffic on any port still ends the list, as in
	// Hysteria; a port-limited one does not.
	for acl, want := range map[string]struct {
		text  string
		count int
		stop  bool
	}{
		"direct(all, *, 1.2.3.4)\nproxy(x.com)":           {"", 0, true},
		"direct(*, */*, 1.2.3.4)\nproxy(x.com)":           {"", 0, true},
		"direct(all, tcp/0, 1.2.3.4)\nproxy(x.com)":       {"ACL proxy: =x.com -> vpn\n", 1, false},
		"direct(all, udp/53, 1.1.1.1)\nproxy(x.com, tcp)": {"ACL proxy: =x.com -> vpn | tcp\n", 1, false},
	} {
		res := conv(acl)
		w := strings.Join(res.Warnings, " ")
		if res.Count != want.count || !strings.HasSuffix(res.Text, want.text) || strings.Contains(res.Text, "* ->") ||
			!strings.Contains(w, "перенаправление на") || strings.Contains(w, "строки ниже неё (1)") != want.stop {
			t.Errorf("%s: %q %v", acl, res.Text, res.Warnings)
		}
	}
	// The QUIC block stays a warning; lines merge only with equal ports.
	res := conv("reject(all, udp/443)")
	if res.Count != 0 || !strings.Contains(res.Warnings[0], "блокировка QUIC") {
		t.Errorf("quic: %+v", res)
	}
	res = conv("proxy(a.com, tcp/443)\nproxy(b.com, tcp/443)\nproxy(c.com, tcp/80)\nproxy(d.com)")
	if res.Count != 3 || !strings.Contains(res.Text, "ACL proxy: =a.com =b.com -> vpn | tcp 443\nACL proxy: =c.com -> vpn | tcp 80\nACL proxy: =d.com -> vpn\n") {
		t.Errorf("merge: %q", res.Text)
	}
	// Domains mode: ports and redirects are not expressed, the sites are listed.
	c := geoCtl(t)
	d, err := c.ConvertACL("proxy(example.com, tcp/443)\ndirect(example.org, *, 1.2.3.4)", "domains", "", "")
	if err != nil || !strings.Contains(d.Text, "*.example.com") || !strings.Contains(d.Text, "*.example.org") ||
		!strings.Contains(strings.Join(d.Warnings, " "), "порт из \"tcp/443\" в списке доменов не учитывается") ||
		!strings.Contains(strings.Join(d.Warnings, " "), "перенаправление на 1.2.3.4 не учитывается") {
		t.Errorf("domains: %v %+v", err, d)
	}
}

// Hysteria's parseProtoPort accepts exactly what aclProtoPort accepts.
func TestACLProtoPortParity(t *testing.T) {
	for extra, want := range map[string]struct {
		proto string
		ports []string
		any   bool
		ok    bool
	}{
		"": {"", nil, true, true}, "*": {"", nil, true, true}, "*/*": {"", nil, true, true},
		"tcp": {"tcp", nil, false, true}, "udp/*": {"udp", nil, false, true}, "tcp/0": {"tcp", nil, false, true},
		"*/443": {"", []string{"443"}, false, true}, "*/0": {"", nil, true, true}, "tcp/1000-2000": {"tcp", []string{"1000-2000"}, false, true},
		"tcp/ 80-90": {"tcp", []string{"80-90"}, false, true}, "tcp/443-443": {"tcp", []string{"443"}, false, true},
		"tcp/ 80": {ok: false}, "tcp/80 - 90": {ok: false}, "tcp/5-0": {ok: false}, "sctp/1": {ok: false}, "tcp/": {ok: false},
		"tcp/70000": {ok: false}, "*/x": {ok: false}, "x": {ok: false}, "tcp/-1": {ok: false},
	} {
		p, ports, anyPort, ok := aclProtoPort(extra)
		if ok != want.ok || ok && (p != want.proto || !slices.Equal(ports, want.ports) || anyPort != want.any) {
			t.Errorf("%q: %q %q %v %v", extra, p, ports, anyPort, ok)
		}
	}
}

// Unused, the feature writes nothing: rules without ports keep the v1.0.0
// settings.json (no "ports" key), and its read paths create no file.
func TestPortsUnusedWritesNothing(t *testing.T) {
	c, _ := newCtl(t)
	st := c.Settings()
	st.Rules = []rules.Rule{{Name: "a", Domains: []string{".a.com"}, Protocol: "tcp", Action: rules.Tunnel}}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	list := func() string {
		es, _ := os.ReadDir(c.Store.Dir)
		var names []string
		for _, e := range es {
			names = append(names, e.Name())
		}
		return strings.Join(names, ",")
	}
	before := list()
	c.Explain(ExplainQuery{Target: "https://a.com", Proto: "udp", Port: 443}, nil)
	c.LintRules(c.Settings())
	c.RulesText()
	c.ParseRulesText("* -> vpn | tcp 22")
	aclToRules(parseACL("proxy(a.com, tcp/443)"))
	if after := list(); after != before {
		t.Fatalf("files: %s -> %s", before, after)
	}
	b, err := os.ReadFile(filepath.Join(c.Store.Dir, "settings.json"))
	if err != nil || strings.Contains(string(b), "ports") {
		t.Fatalf("%v %s", err, b)
	}
}

// A server warning names an unnamed port-only rule as the rest of the UI
// does («TCP 22»), an unnamed app rule by its number.
func TestPortRuleWarningLabel(t *testing.T) {
	c, _ := newCtl(t)
	c.ImportURIs(link)
	st := c.Settings()
	st.Rules = []rules.Rule{
		{Protocol: "tcp", Ports: []string{"22"}, Action: rules.Tunnel, Profile: "gone"},
		{App: &rules.AppMatch{Pattern: "a.exe"}, Action: rules.Tunnel, Profile: "gone"},
	}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if w := c.RuleWarnings(); len(w) != 2 || w[0].Rule != "TCP 22" || w[1].Rule != "правило 2" {
		t.Fatalf("%+v", w)
	}
}

// Explain carries both ports and groups: a rule with
// ports only that sends to a group names the group and the port checked.
func TestExplainGroupWithPorts(t *testing.T) {
	c, _ := newCtl(t)
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	setRules(t, c, rules.Direct, "", rules.Rule{Name: "SSH", Protocol: "tcp", Ports: rules.PortList{"22"}, Action: rules.Tunnel, Profile: g})
	ex := c.Explain(ExplainQuery{Target: "1.2.3.4", Proto: "tcp", Port: 22}, nil)
	if ex.Winner.Name != "SSH" || !ex.Group || ex.ProfileName != "Авто" || ex.Port != 22 || !ex.PortRules {
		t.Fatalf("%+v", ex)
	}
	if ex = c.Explain(ExplainQuery{Target: "1.2.3.4:23"}, nil); ex.Winner.Index != -1 || ex.Group || ex.Port != 23 {
		t.Fatalf("%+v", ex)
	}
}
