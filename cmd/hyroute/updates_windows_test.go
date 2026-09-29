package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
)

// testSession is a running session with no tunnels: NopSession plus a
// registry of connections.
type testSession struct{ app.NopSession }

func (testSession) Flows() *flows.Registry { return flows.NewRegistry(10) }

func testCtl(t *testing.T, start app.Starter) *app.Controller {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctl := app.New(st, start, session.Config{}, slog.LevelInfo)
	if err := ctl.Load(); err != nil {
		t.Fatal(err)
	}
	return ctl
}

// After an update with --reconnect the updater is told the new version
// works once any connect brings the filters up: when the automatic one
// failed, the user's own counts too (otherwise the updater kills the
// working version after 3 minutes and rolls it back).
func TestManualConnectReportsHealthy(t *testing.T) {
	name := fmt.Sprintf(`Local\HyRouteTest-%d`, os.Getpid())
	p, _ := windows.UTF16PtrFromString(name)
	ev, err := windows.CreateEvent(nil, 1, 0, p)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(ev)
	fail := true
	ctl := testCtl(t, func(session.Config) (app.Session, error) {
		if fail {
			return nil, errors.New("driver busy")
		}
		return testSession{}, nil
	})
	g := &GUI{ctl: ctl, updateEvent: name}
	ctl.OnChange = g.emitStatus
	g.uiUp.Store(true)

	g.reconnectAfterUpdate()
	if r, _ := windows.WaitForSingleObject(ev, 200); r == windows.WAIT_OBJECT_0 {
		t.Fatal("healthy reported after a failed connect")
	}
	fail = false
	if err := g.Connect(); err != nil {
		t.Fatal(err)
	}
	if r, _ := windows.WaitForSingleObject(ev, 10*1000); r != windows.WAIT_OBJECT_0 {
		t.Fatal("the user's connect was not reported to the updater")
	}
}

// "Позже" in the update dialog is kept when the settings page saves its
// older copy of the preferences.
func TestSavePrefsKeepsPostponedVersion(t *testing.T) {
	ctl := testCtl(t, func(session.Config) (app.Session, error) { return testSession{}, nil })
	g := &GUI{ctl: ctl}
	page := g.Prefs()
	if err := g.SkipAppVersion("v9.9.9"); err != nil {
		t.Fatal(err)
	}
	page.AutoConnect = true
	if err := g.SavePrefs(page); err != nil {
		t.Fatal(err)
	}
	if p := g.Prefs(); p.SkipVersion != "v9.9.9" || !p.AutoConnect {
		t.Fatalf("%+v", p)
	}
}
