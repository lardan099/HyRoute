package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
)

// rulesJSONRig: two servers, a group, rules pointing at them and at a
// deleted server, and a default route through a deleted group.
func rulesJSONRig(t *testing.T) (*Controller, string, string, string) {
	t.Helper()
	c, _ := newCtl(t)
	res, err := c.ImportURIs(link + "\nhy2://x@h2.example:8443#NL")
	if err != nil || len(res.Added) != 2 {
		t.Fatal(res, err)
	}
	de, nl := res.Added[0].ID, res.Added[1].ID
	g, err := c.SaveGroup(groups.Group{Name: "Авто", Strategy: groups.Failover, Members: []string{de, nl}})
	if err != nil {
		t.Fatal(err)
	}
	st := c.Settings()
	st.Rules = []rules.Rule{
		{ID: "r1", Name: "YouTube", Domains: []string{".youtube.com"}, Action: rules.Tunnel, Profile: g.ID, Fallback: []string{nl}},
		{ID: "r2", Name: "Git", Domains: []string{".github.com"}, Ports: rules.PortList{"443"}, Protocol: "tcp", Action: rules.Tunnel, Profile: de},
		{ID: "r3", Name: "Old", Domains: []string{".old.example"}, Action: rules.Tunnel, Profile: "0123456789ab"},
		{ID: "r4", Name: "Off", Domains: []string{".off.example"}, Action: rules.Block, Enabled: new(bool)},
	}
	st.DefaultAction, st.DefaultProfile, st.DefaultFallback = rules.Tunnel, "grp-00000000dead", []string{nl}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	return c, de, nl, g.ID
}

func TestRulesJSONRoundTrip(t *testing.T) {
	c, de, nl, gid := rulesJSONRig(t)
	before := c.Settings().Config
	b, err := c.RulesJSON()
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(b, &env); err != nil || env["hyroute"] != "rules" || env["version"] != 1.0 {
		t.Fatalf("%s %v", b, err)
	}
	tg := env["targets"].(map[string]any)
	if tg[de].(map[string]any)["name"] != "DE one" || tg[gid].(map[string]any)["group"] != true ||
		tg["0123456789ab"].(map[string]any)["name"] != "" || tg["grp-00000000dead"].(map[string]any)["group"] != true || tg[nl] == nil {
		t.Fatalf("targets %v", tg)
	}
	if strings.Contains(string(b), "pass") || strings.Contains(string(b), "example.com:443") {
		t.Fatal("secrets or hosts in the export")
	}

	// Export → import (replace) gives the same config, dangling targets
	// kept with a warning.
	sr, res, err := c.ApplyRulesTextAs(string(b), "auto", true, EditGuard{})
	if err != nil {
		t.Fatal(err, res.Errors)
	}
	if after := c.Settings().Config; !reflect.DeepEqual(after, before) {
		t.Fatalf("round trip changed the rules:\n%+v\n%+v", after, before)
	}
	if sr.Rev == 0 || c.SettingsRev() != sr.Rev {
		t.Fatal("the import did not go through the commit", sr.Rev, c.SettingsRev())
	}
	warns := lines(res.Warnings)
	if !strings.Contains(warns, "3:«Old»: сервер не найден — соединения будут отклоняться") ||
		!strings.Contains(warns, "0:«Всё остальное»: группа не найдена") {
		t.Fatal(warns)
	}
	if !strings.HasPrefix(res.Summary, "Правил в файле: 4, «Всё остальное»:") {
		t.Fatal(res.Summary)
	}
}

func lines(ls []RuleLine) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(strings.Join([]string{itoa(l.Line), l.Text}, ":") + "\n")
	}
	return b.String()
}

func TestRulesJSONForeignIDs(t *testing.T) {
	c, de, _, gid := rulesJSONRig(t)
	file := `{"hyroute":"rules","version":1,"defaultAction":"direct","rules":[
	 {"name":"A","domains":[".a.example"],"action":"tunnel","profile":"aaaaaaaaaaaa","fallback":["grp-bbbbbbbbbbbb"]}],
	 "targets":{"aaaaaaaaaaaa":{"name":" de ONE "},"grp-bbbbbbbbbbbb":{"name":"авто","group":true}}}`
	res := c.ParseRulesTextAs(file, "auto", false)
	if len(res.Errors) != 0 || len(res.Rules) != 1 || res.Rules[0].Profile != de || res.Rules[0].Fallback[0] != gid {
		t.Fatalf("%+v", res)
	}
	// Append mode: the default route is not taken.
	if res.HasDefault || !strings.Contains(lines(res.Warnings), "«Всё остальное» из файла не применено") {
		t.Fatalf("%+v", res)
	}
	if res := c.ParseRulesTextAs(file, "json", true); !res.HasDefault || res.DefaultAction != rules.Direct {
		t.Fatalf("replace must take the default: %+v", res)
	}
	// A default route naming servers this computer lacks does not stop an
	// append: it is not used, so it is not looked up.
	foreign := `{"hyroute":"rules","version":1,"defaultAction":"tunnel","defaultProfile":"cccccccccccc","defaultFallback":["eeeeeeeeeeee"],
	 "rules":[{"name":"A","domains":[".a.example"],"action":"block"}],"targets":{"cccccccccccc":{"name":"US"}}}`
	res = c.ParseRulesTextAs(foreign, "json", false)
	if len(res.Errors) != 0 || len(res.Rules) != 1 || len(res.Warnings) != 1 || res.HasDefault ||
		!strings.HasPrefix(lines(res.Warnings), "0:«Всё остальное» из файла не применено") {
		t.Fatalf("%+v", res)
	}
	if res := c.ParseRulesTextAs(foreign, "json", true); !strings.Contains(lines(res.Errors), "0:«Всё остальное»: сервер «US» не найден") {
		t.Fatalf("%+v", res)
	}

	bad := map[string]string{
		"named, no match":  `{"hyroute":"rules","version":1,"rules":[{"name":"A","action":"tunnel","domains":[".a.b"],"profile":"cccccccccccc"}],"targets":{"cccccccccccc":{"name":"US"}}}`,
		"group no match":   `{"hyroute":"rules","version":1,"rules":[{"name":"A","action":"tunnel","domains":[".a.b"],"profile":"grp-cccccccccccc"}],"targets":{"grp-cccccccccccc":{"name":"X","group":true}}}`,
		"malformed id":     `{"hyroute":"rules","version":1,"rules":[{"name":"A","action":"tunnel","domains":[".a.b"],"profile":"a b"}],"targets":{}}`,
		"long id":          `{"hyroute":"rules","version":1,"rules":[{"name":"A","action":"tunnel","domains":[".a.b"],"profile":"` + strings.Repeat("a", 65) + `"}],"targets":{}}`,
		"unknown rule key": `{"hyroute":"rules","version":1,"rules":[{"name":"A","action":"tunnel","domains":[".a.b"],"future":1}],"targets":{}}`,
		"unknown env key":  `{"hyroute":"rules","version":1,"rules":[],"targets":{},"future":1}`,
		"not rules":        `{"hyroute":"backup","version":1}`,
		"newer":            `{"hyroute":"rules","version":2,"rules":[]}`,
		"bad regexp":       `{"hyroute":"rules","version":1,"rules":[{"name":"R","action":"block","domains":["regexp:(("]}],"targets":{}}`,
		"not json":         `{"hyroute":`,
	}
	want := map[string]string{
		"named, no match":  "1:«A»: сервер «US» не найден — добавьте его в HyRoute или поправьте файл",
		"group no match":   "1:«A»: группа «X» не найдена",
		"malformed id":     "1:«A»: неверный id сервера",
		"long id":          "1:«A»: неверный id сервера",
		"unknown rule key": "1:неизвестное поле «future» — файл из более новой версии HyRoute?",
		"unknown env key":  "0:Неизвестное поле «future»",
		"not rules":        "0:Это не файл правил HyRoute",
		"newer":            "0:Файл правил из более новой версии HyRoute (формат 2)",
		"bad regexp":       "1:«R»: ",
		"not json":         "0:Это не файл правил HyRoute: ",
	}
	for name, f := range bad {
		res := c.ParseRulesTextAs(f, "auto", true)
		if got := lines(res.Errors); !strings.Contains(got, want[name]) || len(res.Rules) != 0 {
			t.Errorf("%s: %q", name, got)
		}
	}

	// Two local servers with the name of the file's target.
	c.ImportURIs("hy2://y@h3.example:443#NL")
	amb := `{"hyroute":"rules","version":1,"rules":[{"name":"A","action":"tunnel","domains":[".a.b"],"profile":"dddddddddddd"}],"targets":{"dddddddddddd":{"name":"NL"}}}`
	if got := lines(c.ParseRulesTextAs(amb, "auto", false).Errors); !strings.Contains(got, "несколько серверов с именем «NL»") {
		t.Fatal(got)
	}
}

func TestRulesJSONIDs(t *testing.T) {
	c, _, _, _ := rulesJSONRig(t)
	file := `{"hyroute":"rules","version":1,"rules":[
	 {"id":"r1","name":"A","domains":[".a.example"],"action":"block"},
	 {"id":"x9","name":"B","domains":[".b.example"],"action":"block"},
	 {"id":"x9","name":"C","domains":[".c.example"],"action":"block"}],"targets":{}}`
	res := c.ParseRulesTextAs(file, "auto", false)
	if len(res.Errors) != 0 || res.Rules[2].ID != "" || !strings.Contains(lines(res.Warnings), "3:«C»: повторный id — выдан новый") {
		t.Fatalf("%+v", res)
	}
	odd := `{"hyroute":"rules","version":1,"rules":[{"id":"a b","name":"A","domains":[".a.example"],"action":"block"},
	 {"id":"` + strings.Repeat("z", 65) + `","name":"B","domains":[".b.example"],"action":"block"}],"targets":{}}`
	if r := c.ParseRulesTextAs(odd, "json", true); len(r.Errors) != 0 || r.Rules[0].ID != "" || r.Rules[1].ID != "" ||
		!strings.Contains(lines(r.Warnings), "1:«A»: неверный id правила — выдан новый") {
		t.Fatalf("%+v", r)
	}
	// Append: r1 is taken by a current rule, it gets a new ID (the rule
	// whose repeated ID was cleared keeps none, as a rule from text).
	if _, _, err := c.ApplyRulesTextAs(file, "auto", false, EditGuard{}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, r := range c.Settings().Rules {
		seen[r.ID]++
	}
	if len(c.Settings().Rules) != 7 || seen["r1"] != 1 || seen["x9"] != 1 || seen[""] != 1 {
		t.Fatalf("%v", seen)
	}
	// Replace keeps the file's IDs.
	if _, _, err := c.ApplyRulesTextAs(file, "json", true, EditGuard{}); err != nil {
		t.Fatal(err)
	}
	if rs := c.Settings().Rules; len(rs) != 3 || rs[0].ID != "r1" || rs[1].ID != "x9" || rs[2].ID == "x9" {
		t.Fatalf("%+v", rs)
	}
}

func TestParseRulesAutoDetect(t *testing.T) {
	c, _ := newCtl(t)
	j := " \n\t{\"hyroute\":\"rules\",\"version\":1,\"rules\":[]}"
	if res := c.ParseRulesText(j); len(res.Errors) != 0 || res.Summary != "Правил в файле: 0" {
		t.Fatalf("%+v", res)
	}
	// Forced text: a "{" line is a text error.
	if res := c.ParseRulesTextAs(j, "text", false); len(res.Errors) == 0 {
		t.Fatalf("%+v", res)
	}
	if res := c.ParseRulesTextAs("youtube.com -> напрямую", "auto", false); len(res.Errors) != 0 || len(res.Rules) != 1 {
		t.Fatalf("%+v", res)
	}
	// A pasted JSON through the unchanged ApplyRulesText.
	jd := `{"hyroute":"rules","version":1,"defaultAction":"block","rules":[{"name":"A","domains":[".a.example"],"action":"direct"}]}`
	if _, _, err := c.ApplyRulesText(jd, true, EditGuard{}); err != nil {
		t.Fatal(err)
	}
	if st := c.Settings(); len(st.Rules) != 1 || st.DefaultAction != rules.Block {
		t.Fatalf("%+v", st.Config)
	}
}
