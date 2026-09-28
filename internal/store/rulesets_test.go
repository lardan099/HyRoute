package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func twoRulesets() *Rulesets {
	return &Rulesets{Version: 1, Active: "aaaaaaaa0001", List: []Ruleset{
		{ID: "aaaaaaaa0001", Name: "Дом", Config: rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
			{ID: "r1", Name: "yt", Domains: []string{"geosite:youtube"}, Action: rules.Tunnel, Profile: "p1", Fallback: []string{"p2"}},
		}}},
		{ID: "bbbbbbbb0002", Name: "Работа", Config: rules.Config{DefaultAction: rules.Tunnel, DefaultProfile: "p2", DefaultFallback: []string{"p1"}, Rules: []rules.Rule{}}},
	}}
}

func readFile(t *testing.T, s *Store, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return b
}

func TestLoadRulesetsMissing(t *testing.T) {
	s := openStore(t)
	if r, err := s.LoadRulesets(); r != nil || err != nil {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestRulesetsRoundTrip(t *testing.T) {
	s := openStore(t)
	want := twoRulesets()
	if err := s.SaveRulesets(want); err != nil {
		t.Fatal(err)
	}
	b := readFile(t, s, "rulesets.json")
	if bytes.Contains(b, []byte("pending")) {
		t.Fatalf("pending written while nil: %s", b)
	}
	got, err := s.LoadRulesets()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	// A BOM (PowerShell 5.1) is accepted.
	if got, err := ParseRulesets(append([]byte("\xef\xbb\xbf"), b...)); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("BOM: %v", err)
	}
	// The marker round-trips too.
	h := ConfigHash(want.List[0].Config)
	want.Pending = &RulesetsPending{Was: "", To: h}
	if err := s.SaveRulesets(want); err != nil {
		t.Fatal(err)
	}
	if got, err := s.LoadRulesets(); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("pending: %+v %v", got, err)
	}
}

func TestParseRulesetsRejects(t *testing.T) {
	good := func() map[string]any {
		b, _ := json.Marshal(twoRulesets())
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	entry := func(m map[string]any, i int) map[string]any { return m["list"].([]any)[i].(map[string]any) }
	cases := map[string]struct {
		edit func(m map[string]any)
		want string
	}{
		"unknown top":      {func(m map[string]any) { m["extra"] = 1 }, "unknown field"},
		"unknown in entry": {func(m map[string]any) { entry(m, 0)["color"] = "red" }, "unknown field"},
		"no version":       {func(m map[string]any) { delete(m, "version") }, "нет версии"},
		"newer version":    {func(m map[string]any) { m["version"] = 2; m["future"] = true }, "создан более новой версией HyRoute (формат 2)"},
		"empty list":       {func(m map[string]any) { m["list"] = []any{} }, "нет ни одного"},
		"51 entries": {func(m map[string]any) {
			var l []any
			for i := range 51 {
				l = append(l, map[string]any{"id": fmt.Sprintf("%012x", i+1), "name": fmt.Sprint("n", i), "config": map[string]any{"defaultAction": "direct", "rules": []any{}}})
			}
			m["list"], m["active"] = l, "000000000001"
		}, "больше 50"},
		"bad id":         {func(m map[string]any) { entry(m, 1)["id"] = "XYZ" }, "неверный ID"},
		"short id":       {func(m map[string]any) { entry(m, 1)["id"] = "abc" }, "неверный ID"},
		"dup id":         {func(m map[string]any) { entry(m, 1)["id"] = "aaaaaaaa0001" }, "повторяется"},
		"active missing": {func(m map[string]any) { m["active"] = "cccccccc0003" }, "нет в списке"},
		"dup name case":  {func(m map[string]any) { entry(m, 1)["name"] = "дом" }, "повторяется"},
		"dup name fold": {func(m map[string]any) { // EqualFold, not ToLower
			entry(m, 0)["name"], entry(m, 1)["name"] = "ſ1", "s1"
		}, "повторяется"},
		"long name":      {func(m map[string]any) { entry(m, 1)["name"] = strings.Repeat("я", 41) }, "от 1 до 40"},
		"empty name":     {func(m map[string]any) { entry(m, 1)["name"] = " " }, "от 1 до 40"},
		"control char":   {func(m map[string]any) { entry(m, 1)["name"] = "a\nb" }, "управляющих"},
		"bidi override":  {func(m map[string]any) { entry(m, 1)["name"] = "a\u202eb" }, "управляющих"},
		"bad pending to": {func(m map[string]any) { m["pending"] = map[string]any{"was": "", "to": "sha256:xx"} }, "отметка"},
		"bad pending was": {func(m map[string]any) {
			m["pending"] = map[string]any{"was": "md5:1", "to": "sha256:" + strings.Repeat("a", 64)}
		}, "отметка"},
		"config array":  {func(m map[string]any) { entry(m, 1)["config"] = []any{} }, "объектом"},
		"config null":   {func(m map[string]any) { entry(m, 1)["config"] = nil }, "объектом"},
		"config type":   {func(m map[string]any) { entry(m, 1)["config"] = map[string]any{"defaultAction": 5} }, "профиль"},
		"bad action":    {func(m map[string]any) { entry(m, 1)["config"] = map[string]any{"defaultAction": "sideways"} }, "профиль"},
		"config string": {func(m map[string]any) { entry(m, 1)["config"] = "x" }, "объектом"},
	}
	for name, c := range cases {
		m := good()
		c.edit(m)
		b, _ := json.Marshal(m)
		if r, err := ParseRulesets(b); err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "rulesets.json: ") {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
	if _, err := ParseRulesets(bytes.Repeat([]byte(" "), maxRulesetsBytes+1)); err == nil || !strings.Contains(err.Error(), "слишком большой") {
		t.Errorf("over the cap: %v", err)
	}
}

// TestParseRulesetsNewerEntry: an entry with rule fields this version does
// not know loads as newer and keeps them through every write.
func TestParseRulesetsNewerEntry(t *testing.T) {
	src := `{"version":1,"active":"aaaaaaaa0001","list":[
	  {"id":"aaaaaaaa0001","name":"Дом","config":{"defaultAction":"direct","rules":[]}},
	  {"id":"bbbbbbbb0002","name":"Работа","config":{"defaultAction":"tunnel","defaultProfile":"p9","dnsPolicy":"x",
	    "rules":[{"name":"web","domains":["a.com"],"action":"tunnel","profile":"p7","ports":["443"]}]}},
	  {"id":"cccccccc0003","name":"Игры","config":{"defaultAction":"block","rules":[]}}]}`
	r, err := ParseRulesets([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	e := r.Find("bbbbbbbb0002")
	if !e.Newer() || r.Find("aaaaaaaa0001").Newer() {
		t.Fatal("newer flag")
	}
	if e.Config.DefaultProfile != "p9" || len(e.Config.Rules) != 1 || e.Config.Rules[0].Profile != "p7" {
		t.Fatalf("known fields not decoded: %+v", e.Config)
	}
	c := r.Clone()
	if !c.Find("bbbbbbbb0002").Newer() {
		t.Fatal("Clone dropped raw")
	}
	// Rename another entry and save: the newer config is written back as it was.
	c.Find("cccccccc0003").Name = "Игры 2"
	s := openStore(t)
	if err := s.SaveRulesets(c); err != nil {
		t.Fatal(err)
	}
	var disk struct {
		List []struct {
			ID     string          `json:"id"`
			Config json.RawMessage `json:"config"`
		} `json:"list"`
	}
	if err := json.Unmarshal(readFile(t, s, "rulesets.json"), &disk); err != nil {
		t.Fatal(err)
	}
	var orig struct {
		List []struct {
			Config json.RawMessage `json:"config"`
		} `json:"list"`
	}
	_ = json.Unmarshal([]byte(src), &orig)
	var a, b bytes.Buffer
	_ = json.Compact(&a, orig.List[1].Config)
	_ = json.Compact(&b, disk.List[1].Config)
	if a.String() != b.String() {
		t.Fatalf("newer config changed:\n%s\n%s", a.String(), b.String())
	}
	back, err := s.LoadRulesets()
	if err != nil || !back.Find("bbbbbbbb0002").Newer() || back.Find("cccccccc0003").Name != "Игры 2" {
		t.Fatalf("%+v %v", back, err)
	}
}

func TestLoadRulesetsRegularOnly(t *testing.T) {
	s := openStore(t)
	p := filepath.Join(s.Dir, "rulesets.json")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadRulesets(); err == nil || !strings.Contains(err.Error(), "не обычный файл") {
		t.Fatalf("folder: %v", err)
	}
	os.Remove(p)
	// A link to a valid file elsewhere: refused, the target never read.
	other := filepath.Join(t.TempDir(), "r.json")
	b, _ := json.Marshal(twoRulesets())
	if err := os.WriteFile(other, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, p); err != nil {
		t.Logf("symbolic link not tested: %v", err)
	} else {
		if _, err := s.LoadRulesets(); err == nil || !strings.Contains(err.Error(), "не обычный файл") {
			t.Fatalf("link: %v", err)
		}
		os.Remove(p)
	}
	// Over the cap: refused before parsing.
	if err := os.WriteFile(p, bytes.Repeat([]byte(" "), maxRulesetsBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadRulesets(); err == nil || !strings.Contains(err.Error(), "слишком большой") {
		t.Fatalf("big: %v", err)
	}
}

func TestConfigHash(t *testing.T) {
	a := rules.Config{DefaultAction: rules.Direct}
	b := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{}}
	if ConfigHash(a) != ConfigHash(b) || !hashRe.MatchString(ConfigHash(a)) {
		t.Fatal("nil and empty rules differ")
	}
	c := twoRulesets().List[0].Config
	st := settings.Settings{Config: c}
	_, parsed, _, err := ValidateSettings(&st)
	if err != nil || ConfigHash(parsed.Config) != ConfigHash(c) {
		t.Fatalf("marshal → parse changed the hash: %v", err)
	}
	d := CloneConfig(c)
	d.Rules = append(d.Rules, rules.Rule{Name: "x", Domains: []string{"x.com"}, Action: rules.Block})
	e := CloneConfig(d)
	e.Rules[0], e.Rules[1] = e.Rules[1], e.Rules[0]
	f := CloneConfig(c)
	off := false
	f.Rules[0].Enabled = &off
	for _, x := range []rules.Config{d, e, f} {
		if ConfigHash(x) == ConfigHash(c) {
			t.Fatalf("change not seen: %+v", x)
		}
	}
	if ConfigHash(d) == ConfigHash(e) {
		t.Fatal("order not seen")
	}
}

func TestCloneConfigDeep(t *testing.T) {
	src := twoRulesets().List[0].Config
	src.Rules[0].Apps = []rules.AppMatch{{Pattern: "a.exe"}}
	on := true
	src.Rules[0].Enabled = &on
	c := CloneConfig(src)
	*c.Rules[0].Enabled = false
	c.Rules[0].Apps[0].Pattern = "b.exe"
	c.Rules[0].Fallback[0] = "zz"
	if !*src.Rules[0].Enabled || src.Rules[0].Apps[0].Pattern != "a.exe" || src.Rules[0].Fallback[0] != "p2" {
		t.Fatalf("clone shares: %+v", src.Rules[0])
	}
	if CloneConfig(rules.Config{}).Rules == nil {
		t.Fatal("nil rules stay nil")
	}
	r := twoRulesets()
	cl := r.Clone()
	cl.List[0].Config.Rules[0].Name = "changed"
	cl.List[1].Config.DefaultFallback[0] = "zz"
	if r.List[0].Config.Rules[0].Name != "yt" || r.List[1].Config.DefaultFallback[0] != "p1" {
		t.Fatal("Rulesets.Clone shares")
	}
}

func TestUniqueRulesetName(t *testing.T) {
	list := []Ruleset{{Name: "Дом"}, {Name: "дом (2)"}, {Name: strings.Repeat("я", 40)}}
	for in, want := range map[string]string{
		"Работа":                "Работа",
		"ДОМ":                   "ДОМ (3)",
		strings.Repeat("я", 40): strings.Repeat("я", 36) + " (2)",
	} {
		if got := UniqueRulesetName(list, in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
		if _, err := CleanRulesetName(UniqueRulesetName(list, in)); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestCleanRulesetName(t *testing.T) {
	if n, err := CleanRulesetName("  Работа "); err != nil || n != "Работа" {
		t.Fatalf("%q %v", n, err)
	}
	for _, bad := range []string{"", "   ", strings.Repeat("x", 41), "a\tb", "a\u200bb", "a\u202eb", "\xff"} {
		if _, err := CleanRulesetName(bad); err == nil || err.Error() != "Название профиля правил: от 1 до 40 символов, без управляющих символов" {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := CleanRulesetName(strings.Repeat("я", 40)); err != nil {
		t.Fatal("40 runes refused")
	}
}

func TestRemapTargets(t *testing.T) {
	r := twoRulesets()
	r.List[0].Config.DefaultProfile = "p1"
	r.List[0].Config.DefaultFallback = []string{"p2"}
	r.List[1].Config.Rules = []rules.Rule{{Name: "g", Domains: []string{"a.com"}, Action: rules.Tunnel, Profile: "grp-000000000001", Fallback: []string{"", "p1"}}}
	var seen []string
	r.Remap(func(kind, id string) string {
		if kind != "target" {
			t.Fatalf("kind %q", kind)
		}
		seen = append(seen, id)
		if id == "" {
			return ""
		}
		return "new-" + id
	})
	c0, c1 := r.List[0].Config, r.List[1].Config
	if c0.DefaultProfile != "new-p1" || c0.DefaultFallback[0] != "new-p2" || c0.Rules[0].Profile != "new-p1" || c0.Rules[0].Fallback[0] != "new-p2" {
		t.Fatalf("%+v", c0)
	}
	if c1.DefaultProfile != "new-p2" || c1.DefaultFallback[0] != "new-p1" || c1.Rules[0].Profile != "new-grp-000000000001" || c1.Rules[0].Fallback[0] != "" || c1.Rules[0].Fallback[1] != "new-p1" {
		t.Fatalf("%+v", c1)
	}
	if len(seen) != 9 {
		t.Fatalf("visited %d targets: %v", len(seen), seen)
	}

	// A newer entry: its saved bytes change too, and nothing else of them.
	src := `{"version":1,"active":"aaaaaaaa0001","list":[
	  {"id":"aaaaaaaa0001","name":"Дом","config":{"defaultAction":"direct","rules":[]}},
	  {"id":"bbbbbbbb0002","name":"Работа","config":{"defaultAction":"tunnel","defaultProfile":"p9","defaultFallback":["p8"],"dnsPolicy":{"n":12345678901234567890},
	    "rules":[{"name":"web","domains":["a.com"],"action":"tunnel","profile":"p7","fallback":["p8",""],"ports":["443"]}]}}]}`
	nr, err := ParseRulesets([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	seen = nil
	nr.Remap(func(_, id string) string {
		seen = append(seen, id)
		if id == "" {
			return ""
		}
		return "new-" + id
	})
	e := nr.Find("bbbbbbbb0002")
	if len(seen) != 6 || !e.Newer() || e.Config.DefaultProfile != "new-p9" || e.Config.Rules[0].Fallback[0] != "new-p8" {
		t.Fatalf("%v %+v", seen, e.Config)
	}
	s := openStore(t)
	if err := s.SaveRulesets(nr); err != nil {
		t.Fatal(err)
	}
	back, err := s.LoadRulesets()
	if err != nil {
		t.Fatal(err)
	}
	b := back.Find("bbbbbbbb0002")
	var got bytes.Buffer
	_ = json.Compact(&got, b.raw)
	want := `{"defaultAction":"tunnel","defaultFallback":["new-p8"],"defaultProfile":"new-p9","dnsPolicy":{"n":12345678901234567890},` +
		`"rules":[{"action":"tunnel","domains":["a.com"],"fallback":["new-p8",""],"name":"web","ports":["443"],"profile":"new-p7"}]}`
	if !b.Newer() || got.String() != want {
		t.Fatalf("on disk:\n%s\n%s", got.String(), want)
	}
}

func TestSaveSettingsSplit(t *testing.T) {
	s := openStore(t)
	st := DefaultSettings()
	st.Rules = twoRulesets().List[0].Config.Rules
	if _, err := s.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	want, _ := json.MarshalIndent(st, "", "  ")
	b, parsed, set, err := ValidateSettings(st)
	if err != nil || set == nil || !bytes.Equal(b, want) || !bytes.Equal(readFile(t, s, "settings.json"), want) || !reflect.DeepEqual(parsed.Config, st.Config) {
		t.Fatalf("%v", err)
	}
	if !s.HasSettings() {
		t.Fatal("HasSettings")
	}
	if openStore(t).HasSettings() {
		t.Fatal("HasSettings without the file")
	}
	bad := DefaultSettings()
	bad.Rules = []rules.Rule{{Name: "x", Domains: []string{"regexp:("}, Action: rules.Block}}
	if _, _, _, err := ValidateSettings(bad); err == nil {
		t.Fatal("bad rules validated")
	}
}

func TestWriteRulesPair(t *testing.T) {
	s := openStore(t)
	rs := twoRulesets()
	st := DefaultSettings()
	st.Config = CloneConfig(rs.List[0].Config)
	b, parsed, _, err := ValidateSettings(st)
	if err != nil {
		t.Fatal(err)
	}
	h := ConfigHash(parsed.Config)
	var marks []bool
	s.TestRulesetsWrite = func(p bool) error { marks = append(marks, p); return nil }
	cleared, revErr, err := s.WriteRulesPair(b, rs, "", h)
	if err != nil || revErr != nil || !cleared || !reflect.DeepEqual(marks, []bool{true, false}) {
		t.Fatalf("%v %v %v %v", cleared, revErr, err, marks)
	}
	if rs.Pending != nil {
		t.Fatal("next changed")
	}
	if got, err := s.LoadRulesets(); err != nil || got.Pending != nil || !reflect.DeepEqual(got, rs) {
		t.Fatalf("%+v %v", got, err)
	}
	if !bytes.Equal(readFile(t, s, "settings.json"), b) {
		t.Fatal("settings.json")
	}

	// A failed clear only reports cleared = false: the marker stays.
	s.TestRulesetsWrite = func(p bool) error {
		if !p {
			return os.ErrPermission
		}
		return nil
	}
	cleared, revErr, err = s.WriteRulesPair(b, rs, h, h)
	if err != nil || revErr != nil || cleared {
		t.Fatalf("%v %v %v", cleared, revErr, err)
	}
	if got, _ := s.LoadRulesets(); got.Pending == nil || got.Pending.Was != h {
		t.Fatalf("marker: %+v", got.Pending)
	}
	s.TestRulesetsWrite = nil

	// settings.json cannot be written: rulesets.json gets its bytes back,
	// even when they do not parse.
	for _, before := range [][]byte{readFile(t, s, "rulesets.json"), []byte("{broken"), nil} {
		s := openStore(t)
		if before != nil {
			if err := os.WriteFile(filepath.Join(s.Dir, "rulesets.json"), before, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Mkdir(filepath.Join(s.Dir, "settings.json"), 0o700); err != nil {
			t.Fatal(err)
		}
		cleared, revErr, err := s.WriteRulesPair(b, rs, "", h)
		if err == nil || revErr != nil || cleared {
			t.Fatalf("%v %v %v", cleared, revErr, err)
		}
		after, statErr := os.ReadFile(filepath.Join(s.Dir, "rulesets.json"))
		if before == nil {
			if !os.IsNotExist(statErr) {
				t.Fatalf("rulesets.json left behind: %v", statErr)
			}
		} else if !bytes.Equal(after, before) {
			t.Fatalf("not restored: %s", after)
		}
	}
}
