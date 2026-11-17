package app

import (
	"bytes"
	"errors"
	"reflect"
	"runtime"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

func TestMigrateBrowserRules(t *testing.T) {
	c, _ := newCtl(t)
	chrome := "chrome.exe"
	if runtime.GOOS == "darwin" {
		chrome = "google chrome"
	}
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{ID: "omega", Name: "Omega", Domains: []string{".ingest.example", "192.0.2.0/24"}, Action: rules.Tunnel},
		{ID: "listed", Name: "Из браузера: site.example (адреса)", Domains: []string{"site.example"}, Action: rules.Block},
		{ID: "existing", Apps: []rules.AppMatch{{Pattern: "obs64.exe"}}, Domains: []string{".ingest.example"}, Action: rules.Direct},
		{ID: "network", Domains: []string{"192.0.2.0/24"}, Action: rules.Direct},
		{ID: "managed", Name: ZapretRulePrefix + "Example", Domains: []string{".managed.example"}, Action: rules.Direct},
	}}
	if _, err := c.SaveRulesIn(EditGuard{}, cfg); err != nil {
		t.Fatal(err)
	}
	inactive := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{ID: "old", Domain: &rules.DomainMatch{Pattern: "keyword:video"}, Action: rules.Block},
	}}
	created, err := c.CreateRuleset(RulesetInput{Name: "Резерв", Config: &inactive}, SourceUser)
	if err != nil {
		t.Fatal(err)
	}
	before, _, err := c.Store.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}

	// A failed pair write leaves the originals and permits a retry.
	failure := errors.New("test failure")
	c.Store.TestRulesetsWrite = func(bool) error { return failure }
	if n, err := c.MigrateBrowserRules(); n != 0 || !errors.Is(err, failure) || c.Prefs().BrowserRulesMigrated {
		t.Fatalf("first attempt: %d, %v, %+v", n, err, c.Prefs())
	}
	if !sameRules(before.Config, c.Settings().Config) {
		t.Fatal("a failed migration changed the active rules")
	}
	backup, err := c.Store.ReadRaw(store.BrowserRulesBackup)
	if err != nil || !backup.Exists {
		t.Fatalf("backup exists: %v, %v", backup.Exists, err)
	}
	c.Store.TestRulesetsWrite = nil
	if n, err := c.MigrateBrowserRules(); n != 3 || err != nil {
		t.Fatalf("retry: %d, %v", n, err)
	}
	kept, err := c.Store.ReadRaw(store.BrowserRulesBackup)
	if err != nil || !bytes.Equal(backup.Data, kept.Data) {
		t.Fatal("retry replaced the backup")
	}

	restarted, _ := newCtlAt(t, c.Store)
	active := restarted.Settings().Rules
	if active[0].ID != "omega" || !reflect.DeepEqual(active[0].Apps, browserAppMatches(chrome)) ||
		!reflect.DeepEqual(active[0].Domains, before.Rules[0].Domains) || !browserRuleFor(active[1], chrome) ||
		!reflect.DeepEqual(active[2:], before.Rules[2:]) {
		t.Fatalf("active rules: %+v", active)
	}
	stored, err := c.Store.LoadRulesets()
	if err != nil {
		t.Fatal(err)
	}
	if r := stored.Find(created.View.ID).Config.Rules[0]; !reflect.DeepEqual(r.Apps, browserAppMatches(chrome)) ||
		!reflect.DeepEqual(r.AllDomains(), inactive.Rules[0].AllDomains()) {
		t.Fatalf("inactive rule: %+v", r)
	}
	if !restarted.Prefs().BrowserRulesMigrated {
		t.Fatal("missing completion marker after restart")
	}
	later := restarted.Settings().Config
	later.Rules = append(later.Rules, rules.Rule{Domains: []string{"new.example"}, Action: rules.Direct})
	if _, err := restarted.SaveRulesIn(EditGuard{}, later); err != nil {
		t.Fatal(err)
	}
	if n, err := restarted.MigrateBrowserRules(); n != 0 || err != nil {
		t.Fatalf("second startup: %d, %v", n, err)
	}
	if current := restarted.Settings().Rules; len(current[len(current)-1].Apps) != 0 {
		t.Fatal("a rule added after the upgrade was migrated")
	}
}
