package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
)

const staleText = "Правила изменились в другом месте (например, из «Соединений»): изменение не сохранено, список обновлён — повторите."

func settingsBytes(t *testing.T, c *Controller) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.Store.Dir, "settings.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

func rulesAt(c *Controller) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rulesAt
}

// addRule is a writer on another surface (a rule from «Соединения», the
// CLI): it edits the fresh copy.
func addRule(t *testing.T, c *Controller, dom string) SaveResult {
	t.Helper()
	res, err := addRuleErr(c, dom)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// addRuleErr is addRule for other goroutines, which may not call t.Fatal.
func addRuleErr(c *Controller, dom string) (SaveResult, error) {
	return c.editRules(func(cfg *rules.Config) (bool, error) {
		cfg.Rules = append(cfg.Rules, rules.Rule{Domains: []string{dom}, Action: rules.Block})
		return true, nil
	})
}

// TestSettingsRevAndEvent: the revision is 1 after Load and grows by one
// per commit; OnSettings is called once per commit with that revision,
// holding no lock; refusals and edits that save nothing call nothing.
func TestSettingsRevAndEvent(t *testing.T) {
	c, _ := newCtl(t)
	if c.SettingsRev() != 1 || c.Status().SettingsRev != 1 || c.SettingsView().Rev != 1 || rulesAt(c) != 1 {
		t.Fatalf("after Load: %d %d %d %d", c.SettingsRev(), c.Status().SettingsRev, c.SettingsView().Rev, rulesAt(c))
	}
	var mu sync.Mutex
	var got []uint64
	c.OnSettings = func(rev uint64) {
		// No lock of ours is held: the callback may read the settings.
		for name, m := range map[string]*sync.Mutex{"saveMu": &c.saveMu, "mu": &c.mu} {
			if !free(m) {
				t.Errorf("OnSettings called with %s held", name)
			}
		}
		if v := c.SettingsView(); v.Rev != rev {
			t.Errorf("view rev %d, event %d", v.Rev, rev)
		}
		mu.Lock()
		got = append(got, rev)
		mu.Unlock()
	}
	events := func() []uint64 {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
	on := true
	var results []uint64
	for i, save := range []func() (SaveResult, error){
		func() (SaveResult, error) { st := c.Settings(); return c.SaveSettings(st) },
		func() (SaveResult, error) {
			return c.SaveRulesIn(EditGuard{}, rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{}})
		},
		func() (SaveResult, error) { return c.SaveEngineOptions(settings.EngineOptions{BlockQUIC: &on}) },
		func() (SaveResult, error) {
			r, _, err := c.ApplyRulesText("example.com -> блок", false, EditGuard{})
			return r, err
		},
		func() (SaveResult, error) { return addRule(t, c, "b.example"), nil },
	} {
		res, err := save()
		if err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
		if res.Rev != uint64(i+2) || c.SettingsRev() != res.Rev || c.Status().SettingsRev != res.Rev {
			t.Fatalf("save %d: result %d, rev %d", i, res.Rev, c.SettingsRev())
		}
		results = append(results, res.Rev)
	}
	if e := events(); !slices.Equal(e, results) {
		t.Fatalf("events %v, results %v", e, results)
	}

	// Nothing saved: no revision, no event.
	res, err := c.editRules(func(*rules.Config) (bool, error) { return false, nil })
	if err != nil || res.Rev != 6 {
		t.Fatalf("no-op edit: %+v %v", res, err)
	}
	boom := errors.New("boom")
	if _, err := c.editRules(func(*rules.Config) (bool, error) { return true, boom }); !errors.Is(err, boom) {
		t.Fatalf("edit error: %v", err)
	}
	if _, err := c.SaveRulesIn(EditGuard{Rev: 1}, rules.Config{DefaultAction: rules.Block}); !errors.Is(err, errRulesChanged) {
		t.Fatalf("stale save: %v", err)
	}
	if c.SettingsRev() != 6 || len(events()) != 5 {
		t.Fatalf("rev %d, events %v", c.SettingsRev(), events())
	}
}

// TestSaveSettingsRevision: a copy of the rules read before another
// surface changed them is refused, unless it carries no revision or its
// rules equal the current ones; an engine option save never makes a copy
// stale.
func TestSaveSettingsRevision(t *testing.T) {
	c, _ := newCtl(t)
	v := c.SettingsView()
	r := v.Rev
	if res := addRule(t, c, "a.example"); res.Rev != r+1 || rulesAt(c) != r+1 {
		t.Fatalf("rule added elsewhere: %+v, rulesAt %d", res, rulesAt(c))
	}
	before := settingsBytes(t, c)

	stale := v.Settings
	stale.Rules = []rules.Rule{{Domains: []string{"stale.example"}, Action: rules.Direct}}
	_, err := c.SaveRulesIn(EditGuard{Rev: r}, stale.Config)
	if !errors.Is(err, errRulesChanged) || err.Error() != staleText {
		t.Fatalf("stale rules saved: %v", err)
	}
	if _, err := c.SaveSettingsIn(EditGuard{Rev: r}, stale); !errors.Is(err, errRulesChanged) {
		t.Fatalf("stale settings saved: %v", err)
	}
	if !bytes.Equal(settingsBytes(t, c), before) || c.SettingsRev() != r+1 {
		t.Fatal("a refused save wrote something")
	}

	// Stale, but the rules part equals the current one: only an option
	// changes.
	cur := c.Settings()
	off := false
	cur.BlockQUIC = &off
	res, err := c.SaveSettingsIn(EditGuard{Rev: r}, cur)
	if err != nil || res.Rev != r+2 || res.Rev != c.Status().SettingsRev {
		t.Fatalf("same rules refused: %+v %v", res, err)
	}
	if rulesAt(c) != r+1 {
		t.Fatalf("an option save moved rulesAt to %d", rulesAt(c))
	}

	// A revision read before an engine option save is still current for
	// the rules.
	v2 := c.SettingsView()
	on := true
	if _, err := c.SaveEngineOptions(settings.EngineOptions{BlockQUIC: &on}); err != nil {
		t.Fatal(err)
	}
	if c.SettingsRev() != v2.Rev+1 || rulesAt(c) != r+1 {
		t.Fatalf("option save: rev %d rulesAt %d", c.SettingsRev(), rulesAt(c))
	}
	v2.Rules = append(v2.Rules, rules.Rule{Domains: []string{"c.example"}, Action: rules.Tunnel})
	res, err = c.SaveRulesIn(EditGuard{Rev: v2.Rev}, v2.Config)
	if err != nil {
		t.Fatalf("false refusal after an option save: %v", err)
	}
	if rulesAt(c) != res.Rev {
		t.Fatalf("rulesAt %d, rev %d", rulesAt(c), res.Rev)
	}

	// No revision (internal callers, CLI): no check.
	if _, err := c.SaveRulesIn(EditGuard{}, stale.Config); err != nil {
		t.Fatal(err)
	}
	if got := c.Settings().Rules; len(got) != 1 || got[0].Domains[0] != "stale.example" {
		t.Fatalf("%+v", got)
	}
}

// TestSaveEngineOptions: engine options are saved without the rules part
// and never refused for a rules change; a rules save keeps the current
// engine options whatever the page's copy had.
func TestSaveEngineOptions(t *testing.T) {
	c, _ := newCtl(t)
	page := c.SettingsView() // «Настройки» and «Правила» read their copies
	addRule(t, c, "a.example")
	at := rulesAt(c)
	rev := c.SettingsRev()

	on := true
	o := page.Options()
	o.KillSwitch = &on
	res, err := c.SaveEngineOptions(o)
	if err != nil || res.Rev != rev+1 || rulesAt(c) != at {
		t.Fatalf("%+v %v rulesAt %d", res, err, rulesAt(c))
	}
	st, _, err := settings.Parse(settingsBytes(t, c))
	if err != nil {
		t.Fatal(err)
	}
	if !st.KillSwitchOn() || len(st.Rules) != 1 || st.Rules[0].Domains[0] != "a.example" {
		t.Fatalf("file: %+v", st)
	}

	// The rules page's copy still says kill switch off: it is not written
	// back.
	r := c.SettingsView()
	r.KillSwitch = nil
	r.Rules = append(r.Rules, rules.Rule{Domains: []string{"b.example"}, Action: rules.Direct})
	if _, err := c.SaveRulesIn(EditGuard{Rev: r.Rev}, r.Config); err != nil {
		t.Fatal(err)
	}
	st, _, _ = settings.Parse(settingsBytes(t, c))
	if cur := c.Settings(); !st.KillSwitchOn() || len(st.Rules) != 2 || !cur.KillSwitchOn() {
		t.Fatalf("kill switch reverted by a rules save: %+v", st)
	}
}

// TestApplyRulesTextGuard: «заменить всё» from a text read before the
// rules changed is refused; adding a batch needs no revision.
func TestApplyRulesTextGuard(t *testing.T) {
	c, _ := newCtl(t)
	v, err := c.RulesTextFor("")
	if err != nil || v.Rev != c.SettingsRev() || v.Ruleset != implicitToken { // rulesets: the token of the rules
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := c.RulesTextFor("other"); err == nil {
		t.Fatal("unknown token accepted")
	}
	addRule(t, c, "a.example")
	g := EditGuard{Rev: v.Rev}
	if _, _, err := c.ApplyRulesText("x.example -> напрямую", true, g); !errors.Is(err, errRulesChanged) {
		t.Fatalf("stale replace saved: %v", err)
	}
	if _, _, err := c.ApplyRulesText("x.example -> напрямую", false, g); err != nil {
		t.Fatalf("append refused: %v", err)
	}
	got := c.Settings().Rules
	if len(got) != 2 || got[0].Domains[0] != "a.example" || got[1].AllDomains()[0] != ".x.example" {
		t.Fatalf("%+v", got)
	}
	v, _ = c.RulesTextFor("")
	if _, _, err := c.ApplyRulesText("y.example -> блок", true, EditGuard{Rev: v.Rev}); err != nil {
		t.Fatal(err)
	}
	if got := c.Settings().Rules; len(got) != 1 || got[0].AllDomains()[0] != ".y.example" {
		t.Fatalf("%+v", got)
	}
	// An empty text parses to no rule list at all: equal to an empty list,
	// so a stale copy that clears the cleared rules is not refused.
	v, _ = c.RulesTextFor("")
	if _, _, err := c.ApplyRulesText("", true, EditGuard{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ApplyRulesText("", true, EditGuard{Rev: v.Rev}); err != nil {
		t.Fatalf("empty over empty refused: %v", err)
	}
	if got := c.Settings().Rules; got == nil || len(got) != 0 {
		t.Fatalf("%#v", got)
	}
	if !sameRules(rules.Config{}, rules.Config{Rules: []rules.Rule{}}) {
		t.Fatal("nil and empty rule lists differ")
	}
	if want, _ := c.RulesTextFor(""); c.RulesText() != want.Text {
		t.Fatal("RulesText and RulesTextFor differ")
	}
}

// TestEditRulesSerializes: concurrent writers of the rules and the
// options lose nothing; memory and settings.json agree afterwards.
func TestEditRulesSerializes(t *testing.T) {
	c, _ := newCtl(t)
	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			if _, err := addRuleErr(c, fmt.Sprintf("e%d.example", i)); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, _, err := c.ApplyRulesText(fmt.Sprintf("t%d.example -> напрямую", i), false, EditGuard{}); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			q := i%2 == 0
			if _, err := c.SaveEngineOptions(settings.EngineOptions{BlockQUIC: &q}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var names []string
	for _, r := range c.Settings().Rules {
		names = append(names, r.AllDomains()...)
	}
	sort.Strings(names)
	if len(names) != 2*n {
		t.Fatalf("%d rules: %v", len(names), names)
	}
	file, _, err := settings.Parse(settingsBytes(t, c))
	if err != nil {
		t.Fatal(err)
	}
	mem := c.Settings()
	if !sameRules(file.Config, mem.Config) || file.QUICBlocked() != mem.QUICBlocked() {
		t.Fatal("settings.json and memory differ")
	}
	if c.SettingsRev() != 1+3*n {
		t.Fatalf("rev %d", c.SettingsRev())
	}
}

// TestSettingsWriteFailure: a failed write changes neither the settings in
// memory nor the revision, and tells no page.
func TestSettingsWriteFailure(t *testing.T) {
	c, _ := newCtl(t)
	called := false
	c.OnSettings = func(uint64) { called = true }
	// settings.json is a folder with a file in it: the rename fails.
	if err := os.MkdirAll(filepath.Join(c.Store.Dir, "settings.json", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := c.Settings()
	if _, err := c.SaveRulesIn(EditGuard{}, rules.Config{DefaultAction: rules.Block, Rules: []rules.Rule{}}); err == nil {
		t.Fatal("no write error")
	}
	on := true
	if _, err := c.SaveEngineOptions(settings.EngineOptions{KillSwitch: &on}); err == nil {
		t.Fatal("no write error")
	}
	if c.SettingsRev() != 1 || rulesAt(c) != 1 || called || !sameRules(before.Config, c.Settings().Config) || c.settings.KillSwitchOn() {
		t.Fatalf("state changed: rev %d rulesAt %d event %v", c.SettingsRev(), rulesAt(c), called)
	}
}

// TestSettingsViewCompat: the view carries the revision to the page, but
// settings.json never gets a key v1.0.0 does not know; reading the views
// writes no file.
func TestSettingsViewCompat(t *testing.T) {
	c, _ := newCtl(t)
	list := func() []string {
		var out []string
		filepath.WalkDir(c.Store.Dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				out = append(out, p)
			}
			return nil
		})
		return out
	}
	files := list()
	v := c.SettingsView()
	c.RulesTextFor("")
	c.Status()
	if got := list(); !slices.Equal(got, files) {
		t.Fatalf("reading wrote files: %v -> %v", files, got)
	}

	b, _ := json.Marshal(v)
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"rev", "ruleset", "defaultAction", "rules"} {
		if _, ok := m[k]; !ok {
			t.Errorf("view JSON lacks %q: %s", k, b)
		}
	}
	// What the page sends back: the view with its revision.
	var back SettingsView
	if err := json.Unmarshal(b, &back); err != nil || back.Rev != v.Rev {
		t.Fatalf("%+v %v", back, err)
	}
	back.Rules = []rules.Rule{{Domains: []string{"a.example"}, Action: rules.Block}}
	if _, err := c.SaveRulesIn(EditGuard{Ruleset: back.Ruleset, Rev: back.Rev, EditRev: back.EditRev}, back.Config); err != nil {
		t.Fatal(err)
	}
	var file map[string]json.RawMessage
	if err := json.Unmarshal(settingsBytes(t, c), &file); err != nil {
		t.Fatal(err)
	}
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

// TestOnSettingsMayCallBack: the callback may read and even save the
// settings (it runs after the locks are released).
func TestOnSettingsMayCallBack(t *testing.T) {
	c, _ := newCtl(t)
	done := make(chan struct{})
	c.OnSettings = func(rev uint64) {
		if rev == 2 {
			c.Settings()
			c.Status()
			on := true
			c.SaveEngineOptions(settings.EngineOptions{BlockIPv6Tunnel: &on})
		}
	}
	go func() {
		defer close(done)
		if _, err := addRuleErr(c, "a.example"); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock")
	}
	if c.SettingsRev() != 3 {
		t.Fatalf("rev %d", c.SettingsRev())
	}
}

// TestEditRulesPrivateCopy: fn gets a deep copy, so an edit in place that
// is not saved (fn returns false or an error) leaves the live rules as
// they were.
func TestEditRulesPrivateCopy(t *testing.T) {
	c, _ := newCtl(t)
	off := false
	cfg := rules.Config{DefaultAction: rules.Tunnel, DefaultFallback: []string{""}, Rules: []rules.Rule{{
		Name: "r", Enabled: &off, Apps: []rules.AppMatch{{Pattern: "a.exe"}}, Domains: []string{"a.example"},
		Action: rules.Tunnel, Fallback: []string{""},
	}}}
	if _, err := c.SaveRulesIn(EditGuard{}, cfg); err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(c.Settings().Config)
	if err != nil {
		t.Fatal(err)
	}
	rev := c.SettingsRev()
	for _, fail := range []error{nil, errors.New("boom")} {
		_, err := c.editRules(func(cfg *rules.Config) (bool, error) {
			cfg.DefaultFallback[0] = "x"
			r := &cfg.Rules[0]
			*r.Enabled = true
			r.Apps[0].Pattern = "b.exe"
			r.Domains[0] = "b.example"
			r.Fallback[0] = "x"
			return fail != nil, fail
		})
		if err != fail {
			t.Fatalf("edit: %v", err)
		}
		after, err := json.Marshal(c.Settings().Config)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != string(before) || c.SettingsRev() != rev {
			t.Fatalf("live rules changed: %s", after)
		}
	}
}
