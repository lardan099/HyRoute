package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// rsCtl is a controller with two servers: s1 (the main one) and s2.
func rsCtl(t *testing.T) (c *Controller, started *[]*fakeSession, s1, s2 string) {
	t.Helper()
	c, started = newCtl(t)
	res, err := c.ImportURIs(link + "\nhy2://x@h2.example:8443")
	if err != nil || len(res.Added) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	return c, started, res.Added[0].ID, res.Added[1].ID
}

func rsRule(name, dom string, a rules.Action, profile string) rules.Rule {
	return rules.Rule{Name: name, Domains: []string{dom}, Action: a, Profile: profile}
}

func rsSetRules(t *testing.T, c *Controller, cfg rules.Config) {
	t.Helper()
	st := c.Settings()
	st.Config = cfg
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
}

func rsCreate(t *testing.T, c *Controller, in RulesetInput) CreateResult {
	t.Helper()
	res, err := c.CreateRuleset(in, SourceUser)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func rsBytes(t *testing.T, c *Controller) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.Store.Dir, "rulesets.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

func rsDisk(t *testing.T, c *Controller) *store.Rulesets {
	t.Helper()
	r, err := c.Store.LoadRulesets()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rsSettingsDisk(t *testing.T, c *Controller) *settings.Settings {
	t.Helper()
	st, _, err := settings.Parse(settingsBytes(t, c))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// rsID is the ID of the profile named name.
func rsID(t *testing.T, c *Controller, name string) string {
	t.Helper()
	for _, v := range c.Rulesets().List {
		if v.Name == name {
			return v.ID
		}
	}
	t.Fatalf("no profile %q", name)
	return ""
}

func rsNow(c *Controller) (active string, rev uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeRulesetIDLocked(), c.rsRev
}

// rsTwo makes profiles «Дом» (the current rules, active) and «Работа»
// (cfg), not switched to.
func rsTwo(t *testing.T, c *Controller, cfg rules.Config) (home, work string) {
	t.Helper()
	res := rsCreate(t, c, RulesetInput{Name: "Работа", Config: &cfg, FirstName: "Дом"})
	return rsID(t, c, "Дом"), res.View.ID
}

func sameConfig(a, b rules.Config) bool { return sameRules(a, b) }

// TestNoRulesetsFileUntilSecondProfile: rule edits and every read of the
// feature write nothing new; the status shows the implicit profile.
func TestNoRulesetsFileUntilSecondProfile(t *testing.T) {
	c, _, s1, _ := rsCtl(t)
	rsSetRules(t, c, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rsRule("a", "a.example", rules.Tunnel, s1)}})
	before, _ := os.ReadDir(c.Store.Dir)
	v := c.Rulesets()
	if v.Saved || len(v.List) != 1 || v.List[0].Name != defaultRulesetName || v.List[0].Rules != 1 || !v.List[0].Active || v.Token != implicitToken {
		t.Fatalf("%+v", v)
	}
	c.RulesetsBrief()
	c.Status()
	c.Diagnostics(nil, false)
	c.RulesTextFor("")
	c.RulesetList()
	c.RulesetsExport()
	if _, err := c.RulesetSettings("aaaaaaaaaaaa"); !errors.Is(err, errRulesetNotFound) {
		t.Fatal(err)
	}
	if _, err := c.SwitchRuleset("aaaaaaaaaaaa", SourceUser, SwitchOptions{}); !errors.Is(err, errRulesetNotFound) {
		t.Fatal(err)
	}
	if id, err := c.ResolveRuleset("основной"); id != "" || err != nil {
		t.Fatal(id, err)
	}
	after, _ := os.ReadDir(c.Store.Dir)
	if len(after) != len(before) || len(rsBytes(t, c)) != 0 {
		t.Fatalf("files %v -> %v", before, after)
	}
	if r := c.Status().Ruleset; r.ID != "" || r.Name != defaultRulesetName || r.Count != 1 || r.Token != implicitToken {
		t.Fatalf("%+v", r)
	}
	for _, l := range strings.Split(c.Diagnostics(nil, false), "\n") {
		if strings.Contains(l, "профиль правил") {
			t.Fatalf("diagnostics line while unused: %q", l)
		}
	}
	// A new controller on the same folder reads nothing new either.
	c2, _ := newCtlAt(t, c.Store)
	if c2.Status().Ruleset.Count != 1 || len(rsBytes(t, c2)) != 0 {
		t.Fatal("reload")
	}
}

func TestCreateMaterializes(t *testing.T) {
	c, _, s1, _ := rsCtl(t)
	cur := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rsRule("a", "a.example", rules.Tunnel, s1)}}
	rsSetRules(t, c, cur)
	settingsBefore := settingsBytes(t, c)
	var changes atomic.Int32
	c.OnChange = func() { changes.Add(1) }
	_, rev0 := rsNow(c)
	res := rsCreate(t, c, RulesetInput{Name: "Работа", From: "active", FirstName: "Дом"})
	if res.Switch != nil || res.View.Name != "Работа" || res.View.Active || res.View.Rules != 1 {
		t.Fatalf("%+v", res)
	}
	disk := rsDisk(t, c)
	if disk == nil || len(disk.List) != 2 || disk.List[0].Name != "Дом" || disk.Active != disk.List[0].ID || disk.Pending != nil {
		t.Fatalf("%+v", disk)
	}
	if !sameConfig(disk.List[0].Config, cur) || !sameConfig(disk.List[1].Config, cur) {
		t.Fatal("configs")
	}
	if !bytes.Equal(settingsBytes(t, c), settingsBefore) {
		t.Fatal("settings.json rewritten by a create")
	}
	if _, rev := rsNow(c); rev <= rev0 || changes.Load() == 0 {
		t.Fatalf("rev %d→%d, changes %d", rev0, rev, changes.Load())
	}
	// A page read before still saves: "implicit" is the first profile.
	st := c.Settings()
	st.Rules = append(st.Rules, rsRule("b", "b.example", rules.Block, ""))
	if _, err := c.SaveRulesIn(EditGuard{Ruleset: implicitToken}, st.Config); err != nil {
		t.Fatal(err)
	}
	if r := c.Status().Ruleset; r.Count != 2 || r.Name != "Дом" || r.ID != disk.Active || r.Token != disk.Active {
		t.Fatalf("%+v", r)
	}
	// Names: unique ignoring case, valid, and at most 50 profiles.
	for _, n := range []string{"работа", "дом", "", strings.Repeat("я", 41), "a\u202eb"} {
		if _, err := c.CreateRuleset(RulesetInput{Name: n, From: "active"}, SourceUser); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
	for i := 3; i <= store.MaxRulesets; i++ {
		rsCreate(t, c, RulesetInput{Name: "P" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26)), From: "active"})
	}
	if _, err := c.CreateRuleset(RulesetInput{Name: "лишний", From: "active"}, SourceUser); err == nil || !strings.Contains(err.Error(), "не больше 50") {
		t.Fatal(err)
	}
}

func TestCreateAndActivate(t *testing.T) {
	c, _, s1, s2 := rsCtl(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	var manual atomic.Int32
	c.testManual = func() { manual.Add(1) }
	var writes []bool
	c.Store.TestRulesetsWrite = func(p bool) error { writes = append(writes, p); return nil }
	cfg := rules.Config{DefaultAction: rules.Tunnel, DefaultProfile: s2, Rules: []rules.Rule{rsRule("x", "x.example", rules.Tunnel, s1)}}
	res := rsCreate(t, c, RulesetInput{Name: "VPN", Config: &cfg, Activate: true})
	if res.Switch == nil || !res.Switch.Connected || res.Switch.Note == "" || res.Switch.Ruleset.Name != "VPN" || !res.View.Active {
		t.Fatalf("%+v", res)
	}
	if !reflect.DeepEqual(writes, []bool{true, false}) || manual.Load() != 1 {
		t.Fatalf("one pair write, one manual choice: %v %d", writes, manual.Load())
	}
	if got := rsSettingsDisk(t, c).Config; got.DefaultProfile != s2 || len(got.Rules) != 1 || got.Rules[0].ID == "" {
		t.Fatalf("settings.json: %+v", got)
	}
	// The implicit profile became «Основной» and holds the old rules.
	disk := rsDisk(t, c)
	if len(disk.List) != 2 || disk.List[0].Name != defaultRulesetName || disk.Active != res.View.ID || len(disk.List[0].Config.Rules) != 0 {
		t.Fatalf("%+v", disk)
	}
	// «implicit» now names an inactive profile: refused.
	if _, err := c.SaveRulesIn(EditGuard{Ruleset: implicitToken}, cfg); !errors.Is(err, errRulesetChanged) {
		t.Fatal(err)
	}
}

func TestSwitchAppliesAndKeepsEngineOptions(t *testing.T) {
	c, started, s1, s2 := rsCtl(t)
	off := false
	st := c.Settings()
	st.BlockQUIC = &off
	if _, err := c.SaveEngineOptions(st.Options()); err != nil {
		t.Fatal(err)
	}
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rsRule("w", "w.example", rules.Tunnel, s2)}})
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	f := (*started)[0]
	res, err := c.SwitchRuleset(work, SourceTray, SwitchOptions{})
	if err != nil || res.Ruleset.ID != work || !res.Connected {
		t.Fatalf("%+v %v", res, err)
	}
	disk := rsSettingsDisk(t, c)
	if disk.QUICBlocked() || len(disk.Rules) != 1 || disk.Rules[0].Profile != s2 {
		t.Fatalf("settings.json: %+v", disk)
	}
	if ids(f.profiles) != "h2.example" || len(f.set.Profiles()) != 1 {
		t.Fatalf("session: %s %v", ids(f.profiles), f.set.Profiles())
	}
	if _, src := c.rulesetActive(); src != SourceTray {
		t.Fatal(src)
	}
	if d := rsDisk(t, c); d.Pending != nil || d.Active != work {
		t.Fatalf("%+v", d)
	}
	// Back: the first profile's rules come back.
	if _, err := c.SwitchRuleset(home, SourceUser, SwitchOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(c.Settings().Rules) != 0 || rsSt(c).QUICBlocked() {
		t.Fatalf("%+v", c.Settings())
	}
	// Switching to the active one writes nothing.
	b := rsBytes(t, c)
	if res, err := c.SwitchRuleset(home, SourceUser, SwitchOptions{}); err != nil || res.Ruleset.ID != home || !bytes.Equal(rsBytes(t, c), b) {
		t.Fatal(err)
	}
	_ = s1
}

func TestSwitchKeepsEditsOfLeftProfile(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	b := rsBytes(t, c)
	addRule(t, c, "edit.example") // an S write
	if !bytes.Equal(rsBytes(t, c), b) {
		t.Fatal("a rule edit rewrote rulesets.json")
	}
	for _, id := range []string{work, home} {
		if _, err := c.SwitchRuleset(id, SourceUser, SwitchOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if r := c.Settings().Rules; len(r) != 1 || r[0].Domains[0] != "edit.example" {
		t.Fatalf("%+v", r)
	}
}

func TestSwitchSources(t *testing.T) {
	c, started, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Direct})
	var manual atomic.Int32
	c.testManual = func() {
		// Before saveMu (and no c.mu): netmodes takes its own lock there.
		if !c.saveMu.TryLock() {
			t.Error("netManual with saveMu held")
		} else {
			c.saveMu.Unlock()
		}
		manual.Add(1)
	}
	for i, src := range []Source{SourceUser, SourceTray, SourceCLI} {
		to := []string{work, home, work}[i]
		if _, err := c.SwitchRuleset(to, src, SwitchOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if manual.Load() != 3 {
		t.Fatal(manual.Load())
	}
	if err := c.ActivateRuleset(home, SourceNetwork); err != nil || manual.Load() != 3 {
		t.Fatalf("network switch: %v %d", err, manual.Load())
	}
	if _, err := c.SwitchRuleset(work, SourceNetwork, SwitchOptions{Reconnect: true}); err == nil {
		t.Fatal("network + reconnect accepted")
	}
	// Reconnect only while connected.
	res, err := c.SwitchRuleset(work, SourceCLI, SwitchOptions{Reconnect: true})
	if err != nil || res.Reconnected || len(*started) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	res, err = c.SwitchRuleset(home, SourceCLI, SwitchOptions{Reconnect: true})
	if err != nil || !res.Reconnected || len(*started) != 2 {
		t.Fatalf("%+v %v %d", res, err, len(*started))
	}
}

// TestStaleTokenRefused: a copy made for another profile is refused with
// the switch's own message, before the revision rule.
func TestStaleTokenRefused(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	v0 := c.SettingsView() // token "implicit"
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	va := c.SettingsView()
	if va.Ruleset != home {
		t.Fatal(va.Ruleset)
	}
	addRule(t, c, "moved.example") // the revision moves too
	if _, err := c.SwitchRuleset(work, SourceUser, SwitchOptions{}); err != nil {
		t.Fatal(err)
	}
	sb, rb := settingsBytes(t, c), rsBytes(t, c)
	for _, g := range []EditGuard{{Ruleset: home}, {Ruleset: home, Rev: va.Rev}, {Ruleset: implicitToken, Rev: v0.Rev}} {
		_, err := c.SaveRulesIn(g, va.Config)
		if !errors.Is(err, errRulesetChanged) || errors.Is(err, errRulesChanged) || !strings.Contains(err.Error(), "«Работа»") {
			t.Fatalf("%+v: %v", g, err)
		}
	}
	if !bytes.Equal(settingsBytes(t, c), sb) || !bytes.Equal(rsBytes(t, c), rb) {
		t.Fatal("files changed")
	}
	// A zero guard is never checked.
	if _, err := c.SaveRulesIn(EditGuard{}, va.Config); err != nil {
		t.Fatal(err)
	}
	// A refusal of the target comes before fn runs (editRulesIn).
	ran := false
	_, err := c.editRulesIn(EditGuard{Ruleset: home}, func(*rules.Config) (bool, error) { ran = true; return false, errors.New("fn") })
	if !errors.Is(err, errRulesetChanged) || ran {
		t.Fatalf("%v ran=%v", err, ran)
	}
}

func TestEditModeRevision(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	_, b := rsTwo(t, c, rules.Config{DefaultAction: rules.Block, Rules: []rules.Rule{rsRule("b", "b.example", rules.Direct, "")}})
	cfgC := rules.Config{DefaultAction: rules.Direct}
	cc := rsCreate(t, c, RulesetInput{Name: "C", Config: &cfgC}).View.ID
	v, err := c.RulesetSettings(b)
	if err != nil || v.Ruleset != editTokenPrefix+b || v.Rev != c.SettingsRev() || v.EditRev == 0 {
		t.Fatalf("%+v %v", v, err)
	}
	editB := func(g EditGuard, dom string) (SaveResult, error) {
		cfg := store.CloneConfig(v.Config)
		cfg.Rules[0].Domains = []string{dom}
		return c.SaveRulesIn(g, cfg)
	}
	old := EditGuard{Ruleset: editTokenPrefix + b, Rev: v.Rev, EditRev: v.EditRev}
	// None of these changes B's rules: a save with the old revision passes.
	steps := []struct {
		name string
		do   func()
	}{
		{"rename C", func() { must(t, c.RenameRuleset(cc, "C2")) }},
		{"move", func() { must(t, c.MoveRuleset(cc, 0)) }},
		{"create", func() { rsCreate(t, c, RulesetInput{Name: "D", Config: &cfgC}) }},
		{"delete D", func() { must(t, c.DeleteRuleset(rsID(t, c, "D"))) }},
		{"edit C", func() {
			must(t, errOf(c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + cc}, rules.Config{DefaultAction: rules.Tunnel})))
		}},
		{"switch to C and back", func() {
			home := c.Status().Ruleset.ID
			for _, id := range []string{cc, home} {
				must(t, errOf(c.SwitchRuleset(id, SourceUser, SwitchOptions{})))
			}
		}},
		{"edit active", func() { addRule(t, c, "active.example") }},
		{"engine option", func() { must(t, errOf(c.SaveEngineOptions(rsSt(c).Options()))) }},
	}
	for i, step := range steps {
		name := step.name
		step.do()
		if _, err := editB(old, fmt.Sprintf("s%d.example", i)); err != nil {
			t.Fatalf("after %s: %v", name, err)
		}
		// Undo what this save changed, still from the old copy: it is the
		// same profile edited twice, so the next one is refused…
		if _, err := editB(old, "again.example"); !errors.Is(err, errRulesChanged) {
			t.Fatalf("after %s: a second stale edit of B: %v", name, err)
		}
		// …until the page takes the revision its save returned.
		v2, _ := c.RulesetSettings(b)
		old = EditGuard{Ruleset: editTokenPrefix + b, Rev: v2.Rev, EditRev: v2.EditRev}
	}
	res, err := editB(old, "chain1.example")
	if err != nil || res.EditRev == 0 || res.Rev != c.SettingsRev() {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := editB(EditGuard{Ruleset: old.Ruleset, EditRev: res.EditRev}, "chain2.example"); err != nil {
		t.Fatalf("the chain's own revision: %v", err)
	}
	if _, err := editB(EditGuard{Ruleset: old.Ruleset}, "zero.example"); err != nil {
		t.Fatalf("EditRev 0: %v", err)
	}
	// A stale copy whose rules equal the current ones passes.
	cur, _ := c.RulesetSettings(b)
	if _, err := c.SaveRulesIn(old, cur.Config); err != nil {
		t.Fatal(err)
	}
}

// TestEditModeActivePeriod: an edit-mode copy of B read before B was
// switched to, edited while active and switched away from is refused,
// also when an R write (which refreshes the active profile's copy in
// rulesets.json) happened while B was active.
func TestEditModeActivePeriod(t *testing.T) {
	for _, r := range []struct {
		name string
		do   func(c *Controller, home string)
	}{
		{"no R write", func(*Controller, string) {}},
		{"rename", func(c *Controller, home string) { must(t, c.RenameRuleset(home, "Дом2")) }},
		{"move", func(c *Controller, home string) { must(t, c.MoveRuleset(home, 1)) }},
		{"create", func(c *Controller, _ string) {
			rsCreate(t, c, RulesetInput{Name: "C", Config: &rules.Config{DefaultAction: rules.Direct}})
		}},
		{"edit another", func(c *Controller, home string) {
			must(t, errOf(c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + home}, rules.Config{DefaultAction: rules.Tunnel})))
		}},
	} {
		c, _, _, _ := rsCtl(t)
		home, b := rsTwo(t, c, rules.Config{DefaultAction: rules.Block, Rules: []rules.Rule{rsRule("b", "b.example", rules.Direct, "")}})
		v, err := c.RulesetSettings(b)
		if err != nil {
			t.Fatal(err)
		}
		old := EditGuard{Ruleset: editTokenPrefix + b, Rev: v.Rev, EditRev: v.EditRev}
		must(t, errOf(c.SwitchRuleset(b, SourceUser, SwitchOptions{})))
		addRule(t, c, "edited-while-active.example")
		r.do(c, home)
		must(t, errOf(c.SwitchRuleset(home, SourceUser, SwitchOptions{})))
		cfg := store.CloneConfig(v.Config)
		cfg.Rules[0].Domains = []string{"stale.example"}
		if _, err := c.SaveRulesIn(old, cfg); !errors.Is(err, errRulesChanged) {
			t.Fatalf("%s: stale edit-mode save not refused: %v", r.name, err)
		}
		if cur, _ := c.RulesetSettings(b); len(cur.Config.Rules) != 2 {
			t.Fatalf("%s: the edit made while active is lost: %+v", r.name, cur.Config.Rules)
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// setCompileHook sets testCompileHook for the test (not for t.Parallel
// tests: the hook is global).
func setCompileHook(t *testing.T, fn func()) {
	testCompileHook.Store(&fn)
	t.Cleanup(func() { testCompileHook.Store(nil) })
}

// errOf is the error of a call that also returns a value.
func errOf(_ any, err error) error { return err }

// TestActiveRevisionRulesAt: the foundation's revision rule through the
// ruleset guard.
func TestActiveRevisionRulesAt(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	v := c.SettingsView()
	if v.Rev != c.SettingsRev() || v.Ruleset != home || v.EditRev != 0 {
		t.Fatalf("%+v", v)
	}
	must(t, errOf(c.SaveEngineOptions(rsSt(c).Options())))
	cfg := store.CloneConfig(v.Config)
	cfg.Rules = append(cfg.Rules, rsRule("n", "n.example", rules.Block, ""))
	res, err := c.SaveRulesIn(EditGuard{Ruleset: v.Ruleset, Rev: v.Rev}, cfg)
	if err != nil || res.Rev != c.SettingsRev() || res.EditRev != 0 {
		t.Fatalf("after an engine option save: %+v %v", res, err)
	}
	v = c.SettingsView()
	addRule(t, c, "other.example")
	cfg.Rules = append(cfg.Rules, rsRule("m", "m.example", rules.Block, ""))
	if _, err := c.SaveRulesIn(EditGuard{Ruleset: v.Ruleset, Rev: v.Rev}, cfg); !errors.Is(err, errRulesChanged) {
		t.Fatal(err)
	}
	v = c.SettingsView()
	for _, id := range []string{work, home} {
		if _, err := c.SwitchRuleset(id, SourceUser, SwitchOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	// Same token again, but the rules were replaced twice meanwhile.
	if _, err := c.SaveRulesIn(EditGuard{Ruleset: v.Ruleset, Rev: v.Rev}, cfg); !errors.Is(err, errRulesChanged) || errors.Is(err, errRulesetChanged) {
		t.Fatal(err)
	}
}

func TestDuplicateActiveUsesLiveRules(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, _ := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	b := rsBytes(t, c)
	addRule(t, c, "live.example")
	if !bytes.Equal(rsBytes(t, c), b) {
		t.Fatal("S write touched rulesets.json")
	}
	for i, from := range []string{home, "active"} {
		res := rsCreate(t, c, RulesetInput{Name: []string{"copy1", "copy2"}[i], From: from})
		cfg, _ := c.RulesetSettings(res.View.ID)
		if len(cfg.Rules) != 1 || cfg.Rules[0].Domains[0] != "live.example" || res.View.Rules != 1 {
			t.Fatalf("%s: %+v", from, cfg.Rules)
		}
	}
	exp, ok := c.RulesetsExport()
	if !ok || exp.Pending != nil || len(exp.Find(home).Config.Rules) != 1 {
		t.Fatalf("%+v", exp)
	}
	for _, v := range c.Rulesets().List {
		if v.ID == home && v.Rules != 1 {
			t.Fatalf("%+v", v)
		}
	}
}

func TestRulesetSettingsActive(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, _ := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	v, err := c.RulesetSettings(home)
	if err != nil || v.Ruleset != home || v.Rev != c.SettingsRev() || v.EditRev != 0 {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := c.RulesetSettings("ffffffffffff"); !errors.Is(err, errRulesetNotFound) {
		t.Fatal(err)
	}
}

func TestSwitchStopped(t *testing.T) {
	c, _, s1, s2 := rsCtl(t)
	rsSetRules(t, c, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		rsRule("a", "a.example", rules.Tunnel, s1), rsRule("b", "b.example", rules.Tunnel, s2)}})
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rsRule("b", "b.example", rules.Tunnel, s2)}})
	res, err := c.SwitchRuleset(work, SourceUser, SwitchOptions{})
	if err != nil || len(res.Stopped) != 0 || res.Connected || res.Note != "Он начнёт действовать при подключении." {
		t.Fatalf("disconnected: %+v %v", res, err)
	}
	must(t, errOf(c.SwitchRuleset(home, SourceUser, SwitchOptions{})))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	res, err = c.SwitchRuleset(work, SourceUser, SwitchOptions{})
	if err != nil || !slices.Equal(res.Stopped, []string{"DE one"}) || !strings.Contains(res.Note, "кроме шедших через «DE one»") ||
		!strings.Contains(res.Note, "«Переподключить»") {
		t.Fatalf("%+v %v", res, err)
	}
	// A server a local proxy uses keeps running: not stopped.
	must(t, errOf(c.SwitchRuleset(home, SourceUser, SwitchOptions{})))
	c.mu.Lock()
	c.proxies = []store.LocalProxy{{ID: "p1", Name: "p", Enabled: true, Profile: s1, Port: 1}}
	c.mu.Unlock()
	res, err = c.SwitchRuleset(work, SourceUser, SwitchOptions{})
	c.mu.Lock()
	c.proxies = nil
	c.mu.Unlock()
	if err != nil || len(res.Stopped) != 0 || !strings.Contains(res.Note, "уже открытые — по прежнему профилю.") {
		t.Fatalf("%+v %v", res, err)
	}
	if n := switchNote(SwitchResult{Connected: true, Stopped: []string{"A", "B", "C", "D", "E"}}); !strings.Contains(n, "«A», «B», «C» и ещё 2") {
		t.Fatal(n)
	}
}

func TestSwitchPrecheckNoManual(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	var manual atomic.Int32
	c.testManual = func() { manual.Add(1) }
	// A profile whose rules do not load, and one saved by a newer HyRoute.
	disk := rsDisk(t, c)
	disk.List = append(disk.List, store.Ruleset{ID: "cccccccc0003", Name: "Плохой", Config: rules.Config{Rules: []rules.Rule{{Name: "r", Domains: []string{"regexp:("}, Action: rules.Block}}}})
	must(t, c.Store.SaveRulesets(disk))
	b := rsBytes(t, c)
	b = bytes.Replace(b, []byte(`"list": [`), []byte(`"list": [{"id":"dddddddd0004","name":"Новый","config":{"defaultAction":"direct","rules":[],"future":1}},`), 1)
	must(t, os.WriteFile(filepath.Join(c.Store.Dir, "rulesets.json"), b, 0o600))
	c, _ = newCtlAt(t, c.Store)
	c.testManual = func() { manual.Add(1) }
	for _, id := range []string{"ffffffffffff", "cccccccc0003", "dddddddd0004"} {
		if _, err := c.SwitchRuleset(id, SourceUser, SwitchOptions{}); err == nil {
			t.Fatalf("%s switched", id)
		}
		if _, err := c.CreateRuleset(RulesetInput{Name: "n" + id, From: id, Activate: true}, SourceUser); err == nil && id != "cccccccc0003" {
			t.Fatalf("create from %s", id)
		}
	}
	if err := c.ActivateRuleset("cccccccc0003", SourceNetwork); err == nil || !strings.Contains(err.Error(), "не загружается") {
		t.Fatal(err)
	}
	if err := c.ActivateRuleset("dddddddd0004", SourceNetwork); err == nil || !strings.Contains(err.Error(), "более новой версией") {
		t.Fatal(err)
	}
	m := manual.Load()
	if m != 1 { // only the create from the profile that does not load passed its checks
		t.Fatalf("manual %d", m)
	}
	if _, err := c.SwitchRuleset(work, SourceUser, SwitchOptions{}); err != nil || manual.Load() != m+1 {
		t.Fatal(err)
	}
	_ = home
	// Broken rulesets.json: refused, not manual.
	must(t, os.WriteFile(filepath.Join(c.Store.Dir, "rulesets.json"), []byte("{"), 0o600))
	c, _ = newCtlAt2(t, c.Store)
	c.testManual = func() { manual.Add(1) }
	if _, err := c.SwitchRuleset(work, SourceUser, SwitchOptions{}); err == nil || !strings.Contains(err.Error(), "rulesets.json не загружен") {
		t.Fatal(err)
	}
	if manual.Load() != m+1 {
		t.Fatal("manual after a refused switch")
	}
}

// rsNewerFixture is a list whose inactive entry was saved by a newer
// HyRoute.
func rsNewerFixture(t *testing.T) *store.Rulesets {
	t.Helper()
	r, err := store.ParseRulesets([]byte(`{"version":1,"active":"aaaaaaaa0001","list":[
		{"id":"aaaaaaaa0001","name":"A","config":{"defaultAction":"direct","rules":[]}},
		{"id":"dddddddd0004","name":"D","config":{"defaultAction":"direct","rules":[],"future":1}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// rsViewsEqual compares two lists ignoring the revision (each controller
// counts its own installs).
func rsViewsEqual(a, b RulesetsView) bool {
	a.Rev, b.Rev = 0, 0
	return reflect.DeepEqual(a, b)
}

func TestNoCompileUnderMu(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	var n atomic.Int32
	setCompileHook(t, func() {
		n.Add(1)
		if !c.mu.TryLock() {
			t.Error("compiled with c.mu held")
			return
		}
		c.mu.Unlock()
	})
	_, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	must(t, errOf(c.SwitchRuleset(work, SourceUser, SwitchOptions{})))
	home := rsID(t, c, "Дом")
	must(t, errOf(c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + home}, rules.Config{DefaultAction: rules.Direct})))
	must(t, c.RenameRuleset(home, "Дом 2"))
	c.Store.TestRulesetsWrite = func(p bool) error {
		if !p {
			return errors.New("no clear")
		}
		return nil
	}
	must(t, errOf(c.SwitchRuleset(home, SourceUser, SwitchOptions{})))
	c.Store.TestRulesetsWrite = nil
	addRule(t, c, "marker.example") // a pair: the marker is on disk
	c2, _ := newCtlAt(t, c.Store)
	_ = c2
	if n.Load() < 6 {
		t.Fatalf("hook ran %d times", n.Load())
	}
}

func TestNewerEntryOps(t *testing.T) {
	c, _, s1, _ := rsCtl(t)
	rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	b := rsBytes(t, c)
	newer := `{"id":"dddddddd0004","name":"Новый","config":{"defaultAction":"tunnel","defaultProfile":"` + s1 + `","rules":[],"future":{"x":1}}}`
	b = bytes.Replace(b, []byte(`"list": [`), []byte(`"list": [`+newer+`,`), 1)
	must(t, os.WriteFile(filepath.Join(c.Store.Dir, "rulesets.json"), b, 0o600))
	c, _ = newCtlAt(t, c.Store)
	const id = "dddddddd0004"
	v := c.Rulesets()
	if !v.List[0].Newer || !strings.Contains(v.List[0].Error, "более новой версией") || c.rulesetError(id) == "" {
		t.Fatalf("%+v", v.List[0])
	}
	for name, err := range map[string]error{
		"switch":    errOf(c.SwitchRuleset(id, SourceUser, SwitchOptions{})),
		"edit":      errOf(c.RulesetSettings(id)),
		"duplicate": errOf(c.CreateRuleset(RulesetInput{Name: "dup", From: id}, SourceUser)),
		"save":      errOf(c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + id}, rules.Config{})),
		"text":      errOf(c.RulesTextFor(editTokenPrefix + id)),
	} {
		if err == nil || !strings.Contains(err.Error(), "более новой версией HyRoute") {
			t.Errorf("%s: %v", name, err)
		}
	}
	keep := func() {
		t.Helper()
		var f struct {
			List []struct {
				ID     string          `json:"id"`
				Config json.RawMessage `json:"config"`
			} `json:"list"`
		}
		must(t, json.Unmarshal(rsBytes(t, c), &f))
		for _, e := range f.List {
			if e.ID == id && !bytes.Contains(e.Config, []byte(`"future"`)) {
				t.Fatalf("newer fields lost: %s", e.Config)
			}
		}
	}
	must(t, c.RenameRuleset(id, "Новый 2"))
	keep()
	must(t, c.MoveRuleset(id, 2))
	keep()
	must(t, c.DeleteRuleset(rsID(t, c, "Работа")))
	keep()
	// A server its known fields name is pinned.
	c.mu.Lock()
	refs := c.explicitRefsLocked(s1)
	c.mu.Unlock()
	if len(refs) != 1 || !strings.Contains(refs[0], "«Новый 2»") {
		t.Fatalf("%v", refs)
	}
	must(t, c.DeleteRuleset(id))
	if c.Rulesets().List[0].ID == id {
		t.Fatal("not deleted")
	}
}

// TestEditorTokenCapturedAtOpen: a rule editor and «Правила текстом»
// opened on A save nothing into B after a switch from the tray.
func TestEditorTokenCapturedAtOpen(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block, Rules: []rules.Rule{rsRule("w", "w.example", rules.Direct, "")}})
	v := c.SettingsView()
	tv, err := c.RulesTextFor("")
	if err != nil || tv.Ruleset != home || v.Ruleset != home {
		t.Fatalf("%+v %v", tv, err)
	}
	must(t, errOf(c.SwitchRuleset(work, SourceTray, SwitchOptions{})))
	sb, rb := settingsBytes(t, c), rsBytes(t, c)
	bList := c.Settings().Config
	bList.Rules = append(bList.Rules, rsRule("x", "x.example", rules.Block, ""))
	if _, err := c.SaveSettingsIn(EditGuard{Ruleset: v.Ruleset, Rev: v.Rev}, settings.Settings{Config: bList}); !errors.Is(err, errRulesetChanged) {
		t.Fatal(err)
	}
	if _, _, err := c.ApplyRulesText(tv.Text, true, EditGuard{Ruleset: tv.Ruleset, Rev: tv.Rev}); !errors.Is(err, errRulesetChanged) {
		t.Fatal(err)
	}
	if !bytes.Equal(settingsBytes(t, c), sb) || !bytes.Equal(rsBytes(t, c), rb) {
		t.Fatal("written")
	}
	if _, err := c.RulesTextFor(home); !errors.Is(err, errRulesetChanged) || strings.Contains(err.Error(), "не сохранено") {
		t.Fatal(err) // a read: nothing was being saved
	}
}

func TestEditInactive(t *testing.T) {
	c, started, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	f := (*started)[0]
	set := f.set
	v, err := c.RulesetSettings(work)
	if err != nil || v.Ruleset != editTokenPrefix+work {
		t.Fatal(err)
	}
	sb := settingsBytes(t, c)
	on := true
	cfg := v.Config
	cfg.Rules = []rules.Rule{rsRule("", "e.example", rules.Direct, "")}
	st := v.Settings
	st.Config = cfg
	st.KillSwitch = &on // ignored: engine options are global
	res, err := c.SaveSettingsIn(EditGuard{Ruleset: v.Ruleset, EditRev: v.EditRev}, st)
	if err != nil || res.EditRev == 0 || res.NeedsReconnect {
		t.Fatalf("%+v %v", res, err)
	}
	if !bytes.Equal(settingsBytes(t, c), sb) || f.set != set || rsSt(c).KillSwitchOn() {
		t.Fatal("an inactive edit touched the running rules")
	}
	got := rsDisk(t, c).Find(work).Config
	if len(got.Rules) != 1 || got.Rules[0].ID == "" || got.DefaultAction != rules.Block {
		t.Fatalf("%+v", got)
	}
	// Rules text in edit mode edits that profile.
	tv, err := c.RulesTextFor(editTokenPrefix + work)
	if err != nil || tv.Ruleset != editTokenPrefix+work || tv.EditRev == 0 || !strings.Contains(tv.Text, "e.example") {
		t.Fatalf("%+v %v", tv, err)
	}
	if _, _, err := c.ApplyRulesText("t.example -> блок", false, EditGuard{Ruleset: tv.Ruleset}); err != nil {
		t.Fatal(err)
	}
	if n := len(rsDisk(t, c).Find(work).Config.Rules); n != 2 || !bytes.Equal(settingsBytes(t, c), sb) {
		t.Fatal(n)
	}
	// Rules that do not compile are refused.
	bad := rules.Config{Rules: []rules.Rule{{Name: "r", Domains: []string{"regexp:("}, Action: rules.Block}}}
	if _, err := c.SaveRulesIn(EditGuard{Ruleset: tv.Ruleset}, bad); err == nil || !strings.Contains(err.Error(), "не проходят проверку") {
		t.Fatal(err)
	}
	// Switched to from the tray, or deleted: the token is refused.
	must(t, errOf(c.SwitchRuleset(work, SourceTray, SwitchOptions{})))
	if _, err := c.SaveRulesIn(EditGuard{Ruleset: tv.Ruleset}, cfg); err == nil || !strings.Contains(err.Error(), "включили или удалили") {
		t.Fatal(err)
	}
	v2, _ := c.RulesetSettings(work)
	if strings.HasPrefix(v2.Ruleset, editTokenPrefix) {
		t.Fatal("the active one in edit mode")
	}
	must(t, errOf(c.SwitchRuleset(home, SourceTray, SwitchOptions{})))
	must(t, c.DeleteRuleset(work))
	if _, err := c.SaveRulesIn(EditGuard{Ruleset: tv.Ruleset}, cfg); !errors.Is(err, errRulesetChanged) {
		t.Fatal(err)
	}
}

// rsWriteSettings writes settings.json by hand (v1.0.0, an editor).
func rsWriteSettings(t *testing.T, c *Controller, cfg rules.Config) {
	t.Helper()
	st := store.DefaultSettings()
	st.Config = cfg
	b, err := json.MarshalIndent(st, "", "  ")
	must(t, err)
	must(t, os.WriteFile(filepath.Join(c.Store.Dir, "settings.json"), b, 0o600))
}

func TestLoadReconcile(t *testing.T) {
	a := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rsRule("a", "a.example", rules.Block, "")}}
	b := rules.Config{DefaultAction: rules.Block, Rules: []rules.Rule{{ID: "rb", Name: "b", Domains: []string{"b.example"}, Action: rules.Direct}}} // an ID: a create keeps it
	// setup: profiles A (active, rules a) and B (rules b).
	setup := func(t *testing.T) (*Controller, string, string) {
		c, _ := newCtl(t)
		rsSetRules(t, c, a)
		home, work := rsTwo(t, c, b)
		return c, home, work
	}
	t.Run("consistent", func(t *testing.T) {
		c, home, _ := setup(t)
		c2, _ := newCtlAt(t, c.Store)
		if !rsViewsEqual(c2.Rulesets(), c.Rulesets()) || c2.Status().Ruleset.ID != home {
			t.Fatal("reload differs")
		}
	})
	t.Run("interrupted", func(t *testing.T) {
		c, home, work := setup(t)
		// The switch to B wrote rulesets.json with the marker, then died.
		d := rsDisk(t, c)
		d.Active = work
		d.Pending = &store.RulesetsPending{Was: store.ConfigHash(a), To: store.ConfigHash(b)}
		must(t, c.Store.SaveRulesets(d))
		c2, _ := newCtlAt(t, c.Store)
		if !sameConfig(c2.Settings().Config, b) || !c2.settingsLag || !c2.rsMarker || c2.Status().Ruleset.ID != work {
			t.Fatalf("%+v", c2.Settings().Config)
		}
		// The next commit is a pair: settings.json gets B, the marker goes.
		addRule(t, c2, "next.example")
		if st := rsSettingsDisk(t, c2); len(st.Rules) != 2 || st.Rules[0].Domains[0] != "b.example" {
			t.Fatalf("%+v", st.Rules)
		}
		if rsDisk(t, c2).Pending != nil || c2.settingsLag || c2.rsMarker {
			t.Fatal("marker left")
		}
		_ = home
	})
	t.Run("marker after a completed write", func(t *testing.T) {
		c, _, work := setup(t)
		must(t, errOf(c.SwitchRuleset(work, SourceUser, SwitchOptions{})))
		d := rsDisk(t, c)
		d.Pending = &store.RulesetsPending{Was: store.ConfigHash(a), To: store.ConfigHash(b)}
		must(t, c.Store.SaveRulesets(d))
		c2, _ := newCtlAt(t, c.Store)
		if !sameConfig(c2.Settings().Config, b) || c2.settingsLag || !c2.rsMarker {
			t.Fatal("adopt")
		}
	})
	t.Run("edited outside", func(t *testing.T) {
		c, home, work := setup(t)
		x := rules.Config{DefaultAction: rules.Tunnel}
		rsWriteSettings(t, c, x)
		c2, _ := newCtlAt(t, c.Store)
		cfgHome, _ := c2.RulesetSettings(home)
		cfgWork, _ := c2.RulesetSettings(work)
		if !sameConfig(c2.Settings().Config, x) || !sameConfig(cfgHome.Config, x) || !sameConfig(cfgWork.Config, b) {
			t.Fatal("not adopted")
		}
	})
	t.Run("toggle back", func(t *testing.T) {
		c, _, _ := setup(t)
		addRule(t, c, "a2.example") // A′, an S write
		rsWriteSettings(t, c, a)    // "v1.0.0" back to A
		c2, _ := newCtlAt(t, c.Store)
		if !sameConfig(c2.Settings().Config, a) {
			t.Fatal("the edit back was not adopted")
		}
	})
	t.Run("settings.json missing", func(t *testing.T) {
		c, _, _ := setup(t)
		off := false
		st := c.Settings()
		st.BlockQUIC = &off
		must(t, errOf(c.SaveEngineOptions(st.Options())))
		must(t, os.Remove(filepath.Join(c.Store.Dir, "settings.json")))
		c2, _ := newCtlAt(t, c.Store)
		if !sameConfig(c2.Settings().Config, a) || !c2.settingsLag || !rsSt(c2).QUICBlocked() {
			t.Fatal("not restored")
		}
		addRule(t, c2, "x.example")
		if st := rsSettingsDisk(t, c2); len(st.Rules) != 2 || rsDisk(t, c2).Pending != nil {
			t.Fatal("not written")
		}
	})
	t.Run("broken rulesets.json", func(t *testing.T) {
		c, _, work := setup(t)
		ids := c.Profiles()
		_ = ids
		must(t, os.WriteFile(filepath.Join(c.Store.Dir, "rulesets.json"), []byte(`{"version":1`), 0o600))
		c2, _ := newCtlAt2(t, c.Store)
		if c2.rulesetsBroken == nil || !strings.Contains(c2.Status().LoadError, "rulesets.json") || c2.Status().Ruleset.Count != 0 {
			t.Fatalf("%+v", c2.Status())
		}
		if !sameConfig(c2.Settings().Config, a) {
			t.Fatal("settings.json rules must keep working")
		}
		if err := c2.Connect(); err != nil {
			t.Fatal(err)
		}
		c2.Disconnect()
		addRule(t, c2, "still.example") // rule edits save (settings.json only)
		if _, err := c2.SwitchRuleset(work, SourceUser, SwitchOptions{}); err == nil {
			t.Fatal("switch")
		}
		if _, err := c2.CreateRuleset(RulesetInput{Name: "n", From: "active"}, SourceUser); err == nil {
			t.Fatal("create")
		}
		if _, err := c2.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + work}, b); err == nil {
			t.Fatal("edit")
		}
		res, _ := c2.ImportURIs(link)
		if err := c2.DeleteProfile(res.Added[0].ID); err == nil || !strings.Contains(err.Error(), "rulesets.json не загружен") {
			t.Fatal(err)
		}
		c2.mu.Lock()
		used := c2.profileUsedLocked("anything")
		c2.mu.Unlock()
		if !used {
			t.Fatal("profileUsedLocked")
		}
		if string(rsBytes(t, c2)) != `{"version":1` {
			t.Fatal("broken file overwritten")
		}
		if !c2.rulesetExists("whatever") || c2.RulesetList() != nil {
			t.Fatal("netmodes' reads")
		}
		if id, _ := c2.rulesetActive(); id != "" {
			t.Fatal(id)
		}
	})
	t.Run("broken settings.json", func(t *testing.T) {
		c, _, work := setup(t)
		must(t, os.WriteFile(filepath.Join(c.Store.Dir, "settings.json"), []byte("{"), 0o600))
		c2, _ := newCtlAt2(t, c.Store)
		if _, err := c2.SwitchRuleset(work, SourceUser, SwitchOptions{}); err == nil || !strings.Contains(err.Error(), "settings.json не загружен") {
			t.Fatal(err)
		}
		if _, err := c2.RulesetSettings(work); err == nil {
			t.Fatal("edit mode")
		}
		// Kept for reference checks.
		if c2.rulesets == nil {
			t.Fatal("rulesets dropped")
		}
	})
	// settings.json missing and rulesets.json cannot supply the active
	// rules: the defaults in memory are not the user's rules, so nothing
	// connects on them and no edit writes them (a later load would adopt
	// them over the real active profile).
	for _, tc := range []struct{ name, raw, why string }{
		{"rules unknown: rulesets.json broken", `{"version":1`, "unexpected end"},
		{"rules unknown: active entry newer", `{"version":1,"active":"dddddddd0004","list":[
			{"id":"dddddddd0004","name":"D","config":{"defaultAction":"tunnel","rules":[],"future":1}}]}`, "более новой версией"},
		{"rules unknown: active entry invalid", `{"version":1,"active":"aaaaaaaa0001","list":[
			{"id":"aaaaaaaa0001","name":"A","config":{"defaultAction":"tunnel","rules":[{"name":"r","domains":["regexp:("],"action":"block"}]}}]}`, "не загружается"},
	} {
		raw := tc.raw
		t.Run(tc.name, func(t *testing.T) {
			c, _, _ := setup(t)
			must(t, os.Remove(filepath.Join(c.Store.Dir, "settings.json")))
			must(t, os.WriteFile(filepath.Join(c.Store.Dir, "rulesets.json"), []byte(raw), 0o600))
			c2, started := newCtlAt2(t, c.Store)
			if le := c2.Status().LoadError; c2.SettingsError() == nil || !strings.Contains(le, "settings.json нет") || !strings.Contains(le, tc.why) {
				t.Fatalf("%v %q", c2.SettingsError(), c2.Status().LoadError)
			}
			if err := c2.Connect(); err == nil || !strings.Contains(err.Error(), "весь трафик пошёл бы напрямую") || len(*started) != 0 {
				t.Fatal(err)
			}
			if _, err := c2.SaveRulesIn(EditGuard{}, a); err == nil || !strings.Contains(err.Error(), "settings.json не загружен") {
				t.Fatal(err)
			}
			if _, known := c2.killSwitchSetting(); known {
				t.Fatal("kill switch setting known")
			}
			if c2.Store.HasSettings() || string(rsBytes(t, c2)) != raw {
				t.Fatal("a file was written")
			}
		})
	}
	t.Run("settings.json and rulesets.json missing", func(t *testing.T) {
		c, _, _ := setup(t)
		must(t, os.Remove(filepath.Join(c.Store.Dir, "settings.json")))
		must(t, os.Remove(filepath.Join(c.Store.Dir, "rulesets.json")))
		c2, _ := newCtlAt(t, c.Store) // a first start: the defaults are the rules
		if c2.SettingsError() != nil {
			t.Fatal(c2.SettingsError())
		}
	})
	t.Run("inactive profile does not load", func(t *testing.T) {
		c, _, work := setup(t)
		d := rsDisk(t, c)
		d.Find(work).SetConfig(rules.Config{Rules: []rules.Rule{{Name: "r", Domains: []string{"regexp:("}, Action: rules.Block}}})
		must(t, c.Store.SaveRulesets(d))
		c2, _ := newCtlAt(t, c.Store)
		var view RulesetView
		for _, v := range c2.Rulesets().List {
			if v.ID == work {
				view = v
			}
		}
		if view.Error == "" || c2.rulesetError(work) == "" {
			t.Fatalf("%+v", view)
		}
		if _, err := c2.SwitchRuleset(work, SourceUser, SwitchOptions{}); err == nil || !strings.Contains(err.Error(), "не загружается") {
			t.Fatal(err)
		}
		if _, err := c2.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + work}, b); err != nil {
			t.Fatal(err)
		}
		if c2.rulesetError(work) != "" {
			t.Fatal("fixed in edit mode, error stays")
		}
		must(t, errOf(c2.SwitchRuleset(work, SourceUser, SwitchOptions{})))
	})
}

func TestMarkerForcesPair(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	_, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	c.Store.TestRulesetsWrite = func(p bool) error {
		if !p {
			return errors.New("read-only")
		}
		return nil
	}
	if _, err := c.SwitchRuleset(work, SourceUser, SwitchOptions{}); err != nil {
		t.Fatal(err)
	}
	if !c.rsMarker || rsDisk(t, c).Pending == nil {
		t.Fatal("marker")
	}
	var writes []bool
	c.Store.TestRulesetsWrite = func(p bool) error { writes = append(writes, p); return nil }
	addRule(t, c, "plain.example")
	if !reflect.DeepEqual(writes, []bool{true, false}) || c.rsMarker || rsDisk(t, c).Pending != nil {
		t.Fatalf("%v", writes)
	}
	writes = nil
	addRule(t, c, "plain2.example")
	if len(writes) != 0 {
		t.Fatal("an S write touched rulesets.json")
	}
}

func TestSettingsWriteFailureReverts(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	rb, sb := rsBytes(t, c), settingsBytes(t, c)
	p := filepath.Join(c.Store.Dir, "settings.json")
	must(t, os.RemoveAll(p))
	must(t, os.Mkdir(p, 0o700))
	cfg := c.Settings().Config
	if _, err := c.SwitchRuleset(work, SourceUser, SwitchOptions{}); err == nil || !strings.Contains(err.Error(), "не удалось сохранить") {
		t.Fatal(err)
	}
	if !bytes.Equal(rsBytes(t, c), rb) || c.Status().Ruleset.ID != home || !sameConfig(c.Settings().Config, cfg) || c.rsMarker {
		t.Fatal("not reverted")
	}
	must(t, os.Remove(p))
	if len(sb) > 0 {
		must(t, os.WriteFile(p, sb, 0o600))
	}
	c2, _ := newCtlAt(t, c.Store)
	if c2.Status().Ruleset.ID != home {
		t.Fatal("reload")
	}
}

// TestLeftoverRulesetsRemoved: the rulesets.json of a failed first pair
// whose revert failed too (rsLeftover) is removed before the next write of
// settings.json alone; a failed removal keeps the flag and the save.
func TestLeftoverRulesetsRemoved(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	p := filepath.Join(c.Store.Dir, "rulesets.json")
	leftover := func() {
		c.mu.Lock()
		c.rsLeftover = true
		c.mu.Unlock()
	}
	// A folder in its place: never removed, the save still happens.
	must(t, os.Mkdir(p, 0o700))
	leftover()
	if d := c.rulesetDiagLines(); len(d) != 1 || !strings.Contains(d[0], "не удалён rulesets.json") {
		t.Fatalf("%q", d)
	}
	addRule(t, c, "kept.example")
	if !c.rsLeftover {
		t.Fatal("flag dropped without the removal")
	}
	must(t, os.Remove(p))
	must(t, os.WriteFile(p, []byte(`{"version":1}`), 0o600))
	addRule(t, c, "removed.example")
	if c.rsLeftover || rsBytes(t, c) != nil || c.rulesetDiagLines() != nil {
		t.Fatal("leftover not removed")
	}
	// A new rulesets.json written by an R write replaces it as well.
	must(t, os.WriteFile(p, []byte(`{"version":1}`), 0o600))
	leftover()
	rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	if c.rsLeftover || len(rsDisk(t, c).List) != 2 {
		t.Fatal("create")
	}
}

// TestSwitchRefusedRecordsError: a switch refused by the full compile
// records the error for the menus at once (rsRev, OnChange).
func TestSwitchRefusedRecordsError(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	disk := rsDisk(t, c)
	disk.List = append(disk.List, store.Ruleset{ID: "cccccccc0003", Name: "Плохой", Config: rules.Config{Rules: []rules.Rule{{Name: "r", Domains: []string{"regexp:("}, Action: rules.Block}}}})
	must(t, c.Store.SaveRulesets(disk))
	c, _ = newCtlAt(t, c.Store)
	c.mu.Lock()
	c.rsErrors = map[string]string{} // as if rules.Check had passed
	c.mu.Unlock()
	var changes atomic.Int32
	c.OnChange = func() { changes.Add(1) }
	_, rev0 := rsNow(c)
	if _, err := c.SwitchRuleset("cccccccc0003", SourceUser, SwitchOptions{}); err == nil || !strings.Contains(err.Error(), "не загружается") {
		t.Fatal(err)
	}
	if _, rev := rsNow(c); rev == rev0 || c.rulesetError("cccccccc0003") == "" || changes.Load() == 0 {
		t.Fatalf("rev %d→%d, changes %d", rev0, rev, changes.Load())
	}
}

// TestRefsAcrossRulesets: a server named only by an inactive profile is
// pinned; the error says how to fix it without switching.
func TestRefsAcrossRulesets(t *testing.T) {
	c, _, s1, s2 := rsCtl(t)
	_, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rsRule("w", "w.example", rules.Tunnel, s2)}})
	err := c.DeleteProfile(s2)
	if err == nil || !strings.Contains(err.Error(), "(профиль правил «Работа»)") || !strings.Contains(err.Error(), "«Открыть без включения»") {
		t.Fatal(err)
	}
	c.mu.Lock()
	used := c.profileUsedLocked(s2)
	c.mu.Unlock()
	if !used {
		t.Fatal("a subscription update would drop it")
	}
	// Running follows the active rules only.
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, want, _ := c.routingLocked()
	c.mu.Unlock()
	for _, p := range want {
		if p.ID == s2 {
			t.Fatal("an inactive profile's server runs")
		}
	}
	c.Disconnect()
	must(t, errOf(c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + work}, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rsRule("w", "w.example", rules.Tunnel, s1)}})))
	if err := c.DeleteProfile(s2); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRenameMove(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	cfg := rules.Config{DefaultAction: rules.Direct}
	third := rsCreate(t, c, RulesetInput{Name: "Игры", Config: &cfg}).View.ID
	var changes atomic.Int32
	c.OnChange = func() { changes.Add(1) }
	step := func(name string, err error) {
		t.Helper()
		_, rev := rsNow(c)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_ = rev
	}
	if err := c.DeleteRuleset(home); err == nil || !strings.Contains(err.Error(), "Нельзя удалить активный") {
		t.Fatal(err)
	}
	if err := c.RenameRuleset(work, "игры"); err == nil || !strings.Contains(err.Error(), "таким названием") {
		t.Fatal(err)
	}
	if err := c.RenameRuleset(work, " "); err == nil {
		t.Fatal("empty name")
	}
	for _, to := range []int{-1, 3} {
		if err := c.MoveRuleset(work, to); err == nil {
			t.Fatal(to)
		}
	}
	_, rev0 := rsNow(c)
	step("rename", c.RenameRuleset(work, "Офис"))
	step("rename same", c.RenameRuleset(work, "офис"))
	step("move", c.MoveRuleset(third, 0))
	if l := c.Rulesets().List; l[0].ID != third || l[2].Name != "офис" {
		t.Fatalf("%+v", l)
	}
	step("delete", c.DeleteRuleset(third)) // «Сети» may name it: not a reason to refuse
	if _, rev := rsNow(c); rev != rev0+4 || changes.Load() != 4 {
		t.Fatalf("rev %d→%d, changes %d", rev0, rev, changes.Load())
	}
	if len(c.Rulesets().List) != 2 || rsDisk(t, c).Find(third) != nil {
		t.Fatal("not deleted")
	}
	// The file stays with one profile.
	must(t, errOf(c.SwitchRuleset(work, SourceUser, SwitchOptions{})))
	must(t, c.DeleteRuleset(home))
	if d := rsDisk(t, c); d == nil || len(d.List) != 1 {
		t.Fatal("file")
	}
	if c.Status().Ruleset.Count != 1 || c.RulesetsBrief().Saved != true {
		t.Fatal("status")
	}
}

func TestResolveRuleset(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	cfg := rules.Config{DefaultAction: rules.Direct}
	rabota2 := rsCreate(t, c, RulesetInput{Name: "Работа вечером", Config: &cfg}).View.ID
	for q, want := range map[string]string{
		"id:" + home: home, work: work, "РАБОТА": work, " дом ": home, "вечер": rabota2,
	} {
		if got, err := c.ResolveRuleset(q); err != nil || got != want {
			t.Errorf("%q: %q %v", q, got, err)
		}
	}
	if _, err := c.ResolveRuleset("раб"); err == nil || !strings.Contains(err.Error(), "подходит к нескольким") {
		t.Fatal(err)
	}
	for _, q := range []string{"нет", "id:ffffffffffff", ""} {
		if _, err := c.ResolveRuleset(q); err == nil || !strings.Contains(err.Error(), "не найден") {
			t.Errorf("%q: %v", q, err)
		}
	}
}

func TestCreateFromConfig(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	rsSetRules(t, c, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{{ID: "keep", Name: "k", Domains: []string{"k.example"}, Action: rules.Block}}})
	cfg := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{rsRule("t", "geosite:youtube", rules.Tunnel, "")}}
	tpl := rsCreate(t, c, RulesetInput{Name: "Схема", Config: &cfg}).View.ID
	copied := rsCreate(t, c, RulesetInput{Name: "Копия", From: "active"}).View.ID
	vt, _ := c.RulesetSettings(tpl)
	vc, _ := c.RulesetSettings(copied)
	if vt.Rules[0].ID == "" || vc.Rules[0].ID != "keep" {
		t.Fatalf("%+v %+v", vt.Rules, vc.Rules)
	}
	if cfg.Rules[0].ID != "" {
		t.Fatal("the caller's config changed")
	}
	bad := rules.Config{Rules: []rules.Rule{{Name: "r", Domains: []string{"regexp:("}, Action: rules.Block}}}
	if _, err := c.CreateRuleset(RulesetInput{Name: "Плохой", Config: &bad}, SourceUser); err == nil || !strings.Contains(err.Error(), "не проходят проверку") {
		t.Fatal(err)
	}
	if _, err := c.CreateRuleset(RulesetInput{Name: "Пустой"}, SourceUser); err == nil {
		t.Fatal("no config")
	}
	if _, err := c.CreateRuleset(RulesetInput{Name: "Откуда", From: "ffffffffffff"}, SourceUser); !errors.Is(err, errRulesetNotFound) {
		t.Fatal(err)
	}
}

func TestGeoDueUnion(t *testing.T) {
	c, _ := newCtl(t)
	must(t, c.SetGeoPrefs("v2fly", "", "", false, 12))
	if _, due := c.geoDue(); due {
		t.Fatal("no rule uses the databases")
	}
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rsRule("y", "geosite:youtube", rules.Block, "")}}
	rsCreate(t, c, RulesetInput{Name: "Видео", Config: &cfg})
	src, due := c.geoDue()
	if !due || src.Site == "" || src.IP != "" {
		t.Fatalf("%+v %v", src, due)
	}
}

func TestBackupHelpers(t *testing.T) {
	a := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{rsRule("a", "a.example", rules.Block, "")}}
	b := rules.Config{DefaultAction: rules.Block, Rules: []rules.Rule{}}
	cur := &store.Rulesets{Version: 1, Active: "aaaaaaaa0001", List: []store.Ruleset{{ID: "aaaaaaaa0001", Name: "A", Config: a}, {ID: "bbbbbbbb0002", Name: "B", Config: b}}}
	live := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{}}
	s := rsState{Cur: cur, Active: live, SettingsHash: store.ConfigHash(a)}

	// rulesetsForCommit
	if rulesetsForCommit(rsState{}, nil, live) != nil || rulesetsForCommit(s, nil, live) != nil {
		t.Fatal("off / consistent: settings.json alone")
	}
	if rulesetsForCommit(rsState{Cur: cur, Broken: errors.New("x"), Marker: true}, nil, live) != nil {
		t.Fatal("broken: settings.json alone")
	}
	for _, m := range []rsState{{Cur: cur, Marker: true}, {Cur: cur, Lag: true}} {
		w := rulesetsForCommit(m, nil, live)
		if w == nil || !sameConfig(w.Find("aaaaaaaa0001").Config, live) || w == cur || w.Pending != nil {
			t.Fatalf("%+v", m)
		}
	}
	next := cur.Clone()
	next.Active = "bbbbbbbb0002"
	if w := rulesetsForCommit(rsState{}, next, live); w == nil || !sameConfig(w.Find("bbbbbbbb0002").Config, live) || !sameConfig(cur.List[1].Config, b) {
		t.Fatal("next: a pair with the active entry = cfg")
	}

	// rulesetsOnlyState
	w := rulesetsOnlyState(s, cur)
	if !sameConfig(w.Find("aaaaaaaa0001").Config, live) || w.Pending != nil || !sameConfig(cur.List[0].Config, a) {
		t.Fatal("R write")
	}
	lag := s
	lag.Lag = true
	if w := rulesetsOnlyState(lag, cur); w.Pending == nil || w.Pending.Was != s.SettingsHash || w.Pending.To != store.ConfigHash(live) {
		t.Fatalf("%+v", w.Pending)
	}

	// prepRulesets
	bad := rules.Config{Rules: []rules.Rule{{Name: "r", Domains: []string{"regexp:("}, Action: rules.Block}}}
	var checks atomic.Int32
	setCompileHook(t, func() { checks.Add(1) })
	s2 := s
	s2.Errors = map[string]string{"bbbbbbbb0002": "old error"}
	n := cur.Clone()
	p := prepRulesets(s2, n)
	if checks.Load() != 0 || p.Errors["bbbbbbbb0002"] != "old error" || len(p.Changed) != 0 {
		t.Fatalf("unchanged: %+v %d", p, checks.Load())
	}
	n.List = append(n.List, store.Ruleset{ID: "cccccccc0003", Name: "C", Config: bad})
	n.Find("bbbbbbbb0002").SetConfig(a)
	p = prepRulesets(s2, n)
	if checks.Load() != 2 || p.Errors["cccccccc0003"] == "" || p.Errors["bbbbbbbb0002"] != "" || !slices.Equal(p.Changed, []string{"bbbbbbbb0002", "cccccccc0003"}) {
		t.Fatalf("%+v %d", p, checks.Load())
	}
	if p := prepRulesets(s2, n, "cccccccc0003"); p.Errors["cccccccc0003"] != "" {
		t.Fatal("compiled skipped")
	}
	// The one that was active is checked (its copy was refreshed) and
	// counts as changed (edit mode's guard); an unchanged inactive one is
	// neither.
	sw := n.Clone()
	sw.Active = "bbbbbbbb0002"
	checks.Store(0)
	sCur := s2
	sCur.Cur = n
	if p := prepRulesets(sCur, sw); checks.Load() != 1 || !slices.Equal(p.Changed, []string{"aaaaaaaa0001"}) || p.Errors["aaaaaaaa0001"] != "" {
		t.Fatalf("%+v %d", p, checks.Load())
	}
	// A newer entry gets its own error without a check.
	if p := prepRulesets(rsState{}, rsNewerFixture(t)); p.Errors["dddddddd0004"] != rsNewerText {
		t.Fatalf("%+v", p)
	}

	// installRulesetsLocked: only assigns; rsAt moves for Changed only.
	c, _ := newCtl(t)
	c.saveMu.Lock()
	c.mu.Lock()
	c.rulesetsBroken = errors.New("was broken")
	c.rsAt = map[string]uint64{"aaaaaaaa0001": 1, "bbbbbbbb0002": 1}
	c.installRulesetsLocked(n, rsPrep{Errors: map[string]string{"cccccccc0003": "x"}, Changed: []string{"bbbbbbbb0002"}}, "h", true)
	if c.rulesetsBroken != nil || c.rsErrors["cccccccc0003"] != "x" || c.rsAt["aaaaaaaa0001"] != 1 || c.rsAt["bbbbbbbb0002"] != c.rsRev ||
		!c.rsMarker || c.settingsHash != "h" {
		t.Fatalf("%+v", c.rulesetsState)
	}
	// installRulesetsLocked leaves settingsLag; a pair install clears it.
	c.settingsLag = true
	c.installRulesetsLocked(n, rsPrep{}, "h", false)
	if !c.settingsLag {
		t.Fatal("an R install cleared settingsLag")
	}
	c.installPairLocked(n, rsPrep{}, "h2", true)
	if c.settingsLag || c.rsMarker || c.settingsHash != "h2" {
		t.Fatalf("pair install: %+v", c.rulesetsState)
	}
	c.mu.Unlock()
	c.saveMu.Unlock()
	testCompileHook.Store(nil)

	// reconcileRulesets is what Load and an undo run: the same state from
	// the same raw bytes.
	c1, _ := newCtl(t)
	rsSetRules(t, c1, a)
	_, work := rsTwo(t, c1, b)
	must(t, errOf(c1.SwitchRuleset(work, SourceUser, SwitchOptions{})))
	sraw, err := c1.Store.ReadRaw("settings.json")
	must(t, err)
	rraw, err := c1.Store.ReadRaw("rulesets.json")
	must(t, err)
	c2, _ := newCtl(t)
	must(t, c2.Store.WriteRaw("settings.json", sraw))
	must(t, c2.Store.WriteRaw("rulesets.json", rraw))
	st, set, stErr := c2.Store.LoadSettings()
	l := c2.loadRulesets(st, set, stErr, true)
	c2.saveMu.Lock()
	c2.mu.Lock()
	c2.installRulesetsLoadLocked(l)
	c2.mu.Unlock()
	c2.saveMu.Unlock()
	c3, _ := newCtlAt(t, c2.Store)
	if !rsViewsEqual(c2.Rulesets(), c3.Rulesets()) || !sameConfig(c2.Settings().Config, c3.Settings().Config) || !sameConfig(c2.Settings().Config, b) {
		t.Fatal("undo-style reload differs from Load")
	}
}

// TestSettingsJSONReadableByV1: whatever profiles do, settings.json keeps
// v1.0.0's keys and parses.
func TestSettingsJSONReadableByV1(t *testing.T) {
	c, _, s1, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Tunnel, DefaultProfile: s1})
	must(t, errOf(c.SwitchRuleset(work, SourceUser, SwitchOptions{})))
	must(t, errOf(c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + home}, rules.Config{DefaultAction: rules.Block})))
	addRule(t, c, "v1.example")
	var file map[string]json.RawMessage
	must(t, json.Unmarshal(settingsBytes(t, c), &file))
	v1 := map[string]bool{"defaultAction": true, "defaultProfile": true, "defaultFallback": true, "rules": true,
		"blockQUIC": true, "blockIPv6Tunnel": true, "preferRemoteDNS": true, "exactWebDomains": true, "sniffTimeoutMs": true, "killSwitch": true}
	for k := range file {
		if !v1[k] {
			t.Errorf("settings.json key %q unknown to v1.0.0", k)
		}
	}
	if _, _, err := settings.Parse(settingsBytes(t, c)); err != nil {
		t.Fatal(err)
	}
}

// TestNetmodesReads: the reads «Сети» uses.
func TestNetmodesReads(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	if c.RulesetList() != nil || c.rulesetExists("x") || c.rulesetName("x") != "" {
		t.Fatal("not saved")
	}
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	if l := c.RulesetList(); len(l) != 2 || l[0] != (NetRuleset{ID: home, Name: "Дом"}) {
		t.Fatalf("%+v", l)
	}
	if !c.rulesetExists(work) || c.rulesetExists("ffffffffffff") || c.rulesetName(work) != "Работа" || c.rulesetError(work) != "" {
		t.Fatal("reads")
	}
	if id, src := c.rulesetActive(); id != home || src != "" {
		t.Fatal(id, src)
	}
	must(t, c.ActivateRuleset(work, SourceNetwork))
	if id, src := c.rulesetActive(); id != work || src != SourceNetwork {
		t.Fatal(id, src)
	}
	c.mu.Lock()
	name := c.activeRulesetNameLocked()
	c.mu.Unlock()
	if name != "Работа" {
		t.Fatal(name)
	}
	if b := c.RulesetsBrief(); !b.Usable || !b.Saved || b.Active != work || len(b.List) != 2 {
		t.Fatalf("%+v", b)
	}
	// Diagnostics: one line, names only: no rule of any profile.
	must(t, errOf(c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + home}, rules.Config{DefaultAction: rules.Direct,
		Rules: []rules.Rule{rsRule("private", "private-site.example", rules.Tunnel, "")}})))
	d := c.Diagnostics(nil, false)
	if !strings.Contains(d, `профиль правил: "Работа" (всего 2)`) || !strings.Contains(d, "(network)") || strings.Contains(d, "private-site") {
		t.Fatal(d)
	}
}

// TestRulesetsConcurrent: switches, rule saves, inactive edits and reads
// at once; afterwards the two files agree with each other and with memory.
func TestRulesetsConcurrent(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	home, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Block})
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(5)
		go func() {
			defer wg.Done()
			for j := range 5 {
				if _, err := c.SwitchRuleset([]string{home, work}[(i+j)%2], SourceUser, SwitchOptions{}); err != nil {
					t.Error(err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 5 {
				if _, err := addRuleErr(c, "c.example"); err != nil {
					t.Error(err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := range 5 {
				id := []string{home, work}[(i+j)%2]
				_, err := c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + id}, rules.Config{DefaultAction: rules.Direct})
				if err != nil && !errors.Is(err, errRulesetChanged) {
					t.Error(err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 10 {
				c.Status()
				c.Rulesets()
				c.RulesetsBrief()
			}
		}()
		go func() {
			defer wg.Done()
			for range 5 {
				if _, err := c.RulesTextFor(""); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	must(t, c.RenameRuleset(work, "Работа 2")) // a final R write
	d := rsDisk(t, c)
	if d.Pending != nil || !sameConfig(d.Find(d.Active).Config, rsSettingsDisk(t, c).Config) || !sameConfig(c.Settings().Config, rsSettingsDisk(t, c).Config) {
		t.Fatal("files disagree")
	}
	c2, _ := newCtlAt(t, c.Store)
	if !rsViewsEqual(c2.Rulesets(), c.Rulesets()) {
		t.Fatal("memory differs from disk")
	}
}

func rsSt(c *Controller) *settings.Settings {
	s := c.Settings()
	return &s
}

// TestDeleteGroupOnlyInInactiveRuleset (with groups): a group or a server
// that only an inactive rule profile names is pinned (not deletable, kept
// by a subscription update) and does not run.
func TestDeleteGroupOnlyInInactiveRuleset(t *testing.T) {
	c, _ := newCtl(t)
	_, de2, nl1 := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de2)
	rsSetRules(t, c, rules.Config{DefaultAction: rules.Direct})
	_, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{curlRule(g), rsRule("n", "n.example", rules.Tunnel, nl1)}})
	const inactive = " (профиль правил «Работа»)"
	if err := c.DeleteGroup(g); err == nil || !strings.Contains(err.Error(), "curl"+inactive) {
		t.Fatal(err)
	}
	if err := c.DeleteProfile(nl1); err == nil || !strings.Contains(err.Error(), "n"+inactive) || !strings.Contains(err.Error(), "«Открыть без включения»") {
		t.Fatal(err)
	}
	if err := c.DeleteProfile(de2); err == nil || !strings.Contains(err.Error(), "последний в группе «Авто»") || !strings.Contains(err.Error(), inactive) {
		t.Fatal(err)
	}
	c.mu.Lock()
	pins := c.groupPinsLocked(nil) // an update that drops every server
	usedNL := c.profileUsedLocked(nl1)
	c.mu.Unlock()
	if !pins[de2] || !usedNL {
		t.Fatalf("pins %v, %s used %v", pins, nl1, usedNL)
	}
	// What runs follows the active profile only.
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, want, used := c.routingLocked()
	c.mu.Unlock()
	c.Disconnect()
	for _, p := range want {
		if p.ID == de2 || p.ID == nl1 {
			t.Fatalf("%s of an inactive profile runs", p.Name)
		}
	}
	if slices.Contains(used, g) {
		t.Fatal("a group of an inactive profile runs")
	}
	// Fixed without switching: both can go.
	must(t, errOf(c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + work}, rules.Config{DefaultAction: rules.Direct})))
	must(t, c.DeleteGroup(g))
	must(t, c.DeleteProfile(nl1))
}

// TestInactiveRulesetBadPort (with ports): inactive profiles are checked by
// rules.Check, which checks the ports too.
func TestInactiveRulesetBadPort(t *testing.T) {
	c, _, _, _ := rsCtl(t)
	bad := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{{Name: "ssh", Protocol: "tcp", Ports: rules.PortList{"70000"}, Action: rules.Direct}}}
	if err := rules.Check(bad); err == nil || !strings.Contains(err.Error(), "70000") {
		t.Fatal(err)
	}
	if _, err := c.CreateRuleset(RulesetInput{Name: "Порты", Config: &bad}, SourceUser); err == nil || !strings.Contains(err.Error(), "70000") {
		t.Fatal(err)
	}
	_, work := rsTwo(t, c, rules.Config{DefaultAction: rules.Direct})
	if _, err := c.SaveRulesIn(EditGuard{Ruleset: editTokenPrefix + work}, bad); err == nil || !strings.Contains(err.Error(), "70000") {
		t.Fatal(err)
	}
	// Written by hand: the profile loads with its error and is not switched to.
	d := rsDisk(t, c)
	d.Find(work).SetConfig(bad)
	must(t, c.Store.SaveRulesets(d))
	c2, _ := newCtlAt(t, c.Store)
	var e *RulesetView
	for _, v := range c2.Rulesets().List {
		if v.ID == work {
			e = &v
		}
	}
	if e == nil || !strings.Contains(e.Error, "70000") {
		t.Fatalf("%+v", e)
	}
	if _, err := c2.SwitchRuleset(work, SourceUser, SwitchOptions{}); err == nil {
		t.Fatal("switched to a profile with a bad port")
	}
}
