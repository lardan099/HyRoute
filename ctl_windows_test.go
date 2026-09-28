package main

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/ctl/ctlserver"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
)

func TestAllowClient(t *testing.T) {
	const owner, self, other = "S-1-5-21-1-1-1-1001", "S-1-5-21-1-1-1-500", "S-1-5-21-1-1-1-1002"
	allow := allowClient(owner, self)
	med, low := uint32(ctl.MediumRID), uint32(0x1000)
	for _, c := range []struct {
		id   ctl.Identity
		want bool
	}{
		{ctl.Identity{User: owner, IntegrityRID: med}, true},
		{ctl.Identity{User: self, IntegrityRID: 0x3000}, true},
		{ctl.Identity{User: owner, IntegrityRID: low}, false},
		{ctl.Identity{User: other, IntegrityRID: med}, false},
		{ctl.Identity{User: "S-1-5-18", System: true, IntegrityRID: 0x4000}, true},
		{ctl.Identity{User: other, Elevated: true, Admin: true, IntegrityRID: 0x3000}, true},
		{ctl.Identity{User: other, Admin: true, IntegrityRID: med}, false},
		{ctl.Identity{}, false},
	} {
		if got := allow(c.id); got != c.want {
			t.Errorf("%+v: %v", c.id, got)
		}
	}
}

func newTestGUI(t *testing.T) *GUI {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := app.New(st, func(session.Config) (app.Session, error) { return nil, errors.New("no sessions in tests") }, session.Config{}, slog.LevelInfo)
	if err := c.Load(); err != nil {
		t.Fatal(err)
	}
	return &GUI{ctl: c}
}

func TestSavePrefsKeepsCLI(t *testing.T) {
	g := newTestGUI(t)
	if err := g.SetCLIMode("full"); err != nil {
		t.Fatal(err)
	}
	// The settings page's older copy does not undo the mode.
	if err := g.SavePrefs(store.Prefs{AutoConnect: true}); err != nil {
		t.Fatal(err)
	}
	if p := g.ctl.Prefs(); p.CLI != "full" || !p.AutoConnect {
		t.Fatalf("%+v", p)
	}
	if err := g.SetCLIMode("read"); err != nil || g.ctl.Prefs().CLI != "" {
		t.Fatal("read-only is the default and is not written:", err, g.ctl.Prefs().CLI)
	}
	if err := g.SetCLIMode("all"); err == nil {
		t.Fatal("an unknown mode was saved")
	}
	if in := g.CLIInfo(); in.Mode != "read" || in.Listening {
		t.Fatalf("%+v", in)
	}
}

// ctlBackend is the command line's API.
var _ ctlserver.API = ctlBackend{}
