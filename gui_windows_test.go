package main

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
)

// With settings.json unreadable the rules in memory are the defaults
// (everything direct): connecting at start would ignore the user's rules.
func TestAutoConnectSkipsUnloadedSettings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(`{"rules":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	started := 0
	ctl := app.New(st, func(session.Config) (app.Session, error) {
		started++
		return nil, errors.New("not started in the test")
	}, session.Config{}, slog.LevelInfo)
	if err := ctl.Load(); err == nil {
		t.Fatal("broken settings.json loaded without an error")
	}
	if _, err := ctl.ImportURIs("hysteria2://pw@example.com:443#DE"); err != nil {
		t.Fatal(err)
	}
	ctl.ConnectAtStart("test")
	if started != 0 {
		t.Fatal("connected at start with the default rules")
	}

	// With the file fixed, connecting at start works again.
	if err := os.Remove(filepath.Join(dir, "settings.json")); err != nil {
		t.Fatal(err)
	}
	if err := ctl.Load(); err != nil {
		t.Fatal(err)
	}
	ctl.ConnectAtStart("test")
	if started != 1 {
		t.Fatalf("connect at start: %d attempts", started)
	}
}

// An update or a move restarts HyRoute with --reconnect unless the user
// disconnected: a session whose engine failed ("error" with stats) is
// still on, HyRoute was reconnecting it.
func TestRoutingOn(t *testing.T) {
	for _, tc := range []struct {
		st   app.Status
		want bool
	}{
		{app.Status{State: "connected"}, true},
		{app.Status{State: "tunnel-down"}, true},
		{app.Status{State: "error", Stats: &session.Stats{}}, true},
		{app.Status{State: "error"}, false}, // Connect failed
		{app.Status{State: "disconnected"}, false},
	} {
		if got := routingOn(tc.st); got != tc.want {
			t.Errorf("%q, stats %v: %v", tc.st.State, tc.st.Stats != nil, got)
		}
	}
}
