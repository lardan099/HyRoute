package app

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// nilSlices lists nil slices reachable from v: they reach the UI as JSON
// null, and the UI reads .length on them.
func nilSlices(v reflect.Value, path string, out *[]string) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			nilSlices(v.Elem(), path, out)
		}
	case reflect.Slice:
		if v.IsNil() {
			*out = append(*out, path)
			return
		}
		for i := 0; i < v.Len() && i < 3; i++ {
			nilSlices(v.Index(i), fmt.Sprintf("%s[%d]", path, i), out)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() || f.Tag.Get("json") == "-" {
				continue
			}
			// omitempty: a nil slice is left out of the JSON, not null.
			if fv := v.Field(i); fv.Kind() == reflect.Slice && fv.IsNil() && strings.Contains(f.Tag.Get("json"), ",omitempty") {
				continue
			}
			nilSlices(v.Field(i), path+"."+f.Name, out)
		}
	}
}

// Everything the UI calls must return [] rather than null, also on a
// fresh install with nothing configured.
func TestNoNullListsForUI(t *testing.T) {
	c, _ := newCtl(t)
	st := c.Settings()
	insp, _ := c.Inspect("example.com")
	for name, v := range map[string]any{
		"Profiles":       c.Profiles(),
		"RuleWarnings":   c.RuleWarnings(),
		"LintRules":      c.LintRules(settings.Settings{Config: rules.Config{}}),
		"Subscriptions":  c.Subscriptions(),
		"Status":         c.Status(),
		"Connections":    c.Connections(100),
		"GeoInfo":        c.GeoInfo(),
		"ParseRulesText": c.ParseRulesText(""),
		"Explain":        c.Explain(ExplainQuery{Target: "example.com"}, &st),
		"Updates":        c.Updates(),
		"Logs engine":    c.Logs("engine", 1<<60),
		"Logs hysteria":  c.Logs("hysteria", 0),
		"Logs profile":   c.Logs("hysteria:nope", 0),
		"GeoCategories":  c.GeoCategories("site", "zzz-nothing", 10),
		"Inspect":        insp,
		"SiteLists":      c.SiteLists("example.com"),
		"Settings":       st,
	} {
		var bad []string
		nilSlices(reflect.ValueOf(v), name, &bad)
		for _, b := range bad {
			t.Errorf("nil slice (JSON null): %s", b)
		}
	}
}

// A hand-edited settings.json without "rules" (or with null) reaches the UI
// as an empty list: Home reads rules.filter.
func TestSettingsWithoutRulesForUI(t *testing.T) {
	for _, body := range []string{`{"defaultAction":"tunnel"}`, `{"defaultAction":"direct","rules":null}`} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		st, err := store.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := newCtlAt(t, st)
		if err := c.SettingsError(); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		var bad []string
		nilSlices(reflect.ValueOf(c.Settings()), "Settings", &bad)
		if len(bad) > 0 {
			t.Errorf("%s: nil slices (JSON null): %v", body, bad)
		}
	}
}
