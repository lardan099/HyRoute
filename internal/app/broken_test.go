package app

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// A file that did not load is never overwritten: saving would replace
// the user's rules, proxies and preferences with the defaults.
func TestBrokenFilesAreNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	want := settings.Settings{Config: rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "yt", Domains: []string{".youtube.com"}, Action: rules.Tunnel},
	}}}
	b, _ := json.Marshal(want)
	// A field this version does not know: a newer HyRoute wrote the file.
	b = append(b[:len(b)-1], `,"futureField":1}`...)
	files := map[string][]byte{
		"settings.json": b,
		"proxies.json":  []byte(`[{"id":"p1","name":"x","port":10801`),
		"prefs.json":    []byte(`{"updateCheck":"auto"`),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := New(st, nil, session.Config{}, slog.LevelInfo)
	if err := c.Load(); err == nil {
		t.Fatal("broken files loaded without an error")
	}
	if c.SettingsError() == nil {
		t.Fatal("settings.json error not kept")
	}

	s := c.Settings()
	on := true
	s.KillSwitch = &on
	if _, err := c.SaveSettings(s); err == nil || !strings.Contains(err.Error(), "settings.json не загружен") {
		t.Fatalf("settings saved over a broken file: %v", err)
	}
	if _, _, err := c.ApplyRulesText("example.com -> напрямую", true); err == nil {
		t.Fatal("rules text saved over a broken settings.json")
	}
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Port: 10802}}); err == nil || !strings.Contains(err.Error(), "proxies.json не загружен") {
		t.Fatalf("proxy saved over a broken file: %v", err)
	}
	if err := c.SavePrefs(store.Prefs{UpdateCheck: "manual"}); err == nil || !strings.Contains(err.Error(), "prefs.json не загружен") {
		t.Fatalf("prefs saved over a broken file: %v", err)
	}
	if err := c.SkipAppVersion("v9.9.9"); err == nil {
		t.Fatal("postponed version saved over a broken prefs.json")
	}
	for name, content := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != string(content) {
			t.Fatalf("%s changed: %s %v", name, got, err)
		}
	}
	if got := c.Settings(); got.KillSwitchOn() || len(c.Proxies()) != 0 || c.Prefs().UpdateCheck != "" {
		t.Fatal("a refused save changed the state in memory")
	}

	// A missing file is not broken: the defaults are saved as usual.
	fresh, _ := newCtl(t)
	if err := fresh.SettingsError(); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.SaveSettings(fresh.Settings()); err != nil {
		t.Fatal(err)
	}
}
