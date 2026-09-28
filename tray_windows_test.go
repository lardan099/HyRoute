package main

import (
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

type traySession struct {
	failed bool
}

func (s *traySession) Stop()                                                {}
func (s *traySession) ResetConnections()                                    {}
func (s *traySession) SetRules(*rules.Set, []hysteria.Profile)              {}
func (s *traySession) Flows() *flows.Registry                               { return flows.NewRegistry(10) }
func (s *traySession) EngineFailed() bool                                   { return s.failed }
func (s *traySession) Tunnels() []tunnels.Status                            { return nil }
func (s *traySession) DNSSites(netip.Addr) [][]string                       { return nil }
func (s *traySession) Endpoint(string) *tunnels.Endpoint                    { return nil }
func (s *traySession) Stats() session.Stats                                 { return session.Stats{} }
func (s *traySession) Acquire(hysteria.Profile) (*tunnels.Endpoint, func()) { return nil, func() {} }

func trayGUI(t *testing.T) (*GUI, *[]*traySession) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var started []*traySession
	ctl := app.New(st, func(session.Config) (app.Session, error) {
		s := &traySession{}
		started = append(started, s)
		return s, nil
	}, session.Config{}, slog.LevelInfo)
	if err := ctl.Load(); err != nil {
		t.Fatal(err)
	}
	return &GUI{ctl: ctl}, &started
}

// drawn is what updateTray would have put in the menu for the status now.
func drawn(g *GUI) {
	_, on := trayView(g.ctl.Status())
	g.tray.on = on
}

// After the engine failed the session stays (state "error" with stats):
// the tray's "Подключить" must reconnect, Connect alone does nothing.
func TestTrayToggleReconnectsAfterEngineFailure(t *testing.T) {
	g, started := trayGUI(t)
	if err := g.ctl.Connect(); err != nil {
		t.Fatal(err)
	}
	(*started)[0].failed = true
	if st := g.ctl.Status(); st.State != "error" || st.Stats == nil {
		t.Fatalf("engine failure: state %q, stats %v", st.State, st.Stats != nil)
	}
	drawn(g)
	g.trayToggle()
	if len(*started) != 2 {
		t.Fatalf("toggle after the engine failed: %d sessions started, want a reconnect", len(*started))
	}
	if st := g.ctl.Status(); st.State == "error" || st.State == "disconnected" {
		t.Fatalf("after the reconnect the state is %q", st.State)
	}
}

// The click does what the item said when it was drawn: "Подключить"
// never disconnects, even if a connection started meanwhile.
func TestTrayToggleFollowsTheDrawnItem(t *testing.T) {
	g, started := trayGUI(t)
	drawn(g)                                // "Подключить"
	if err := g.ctl.Connect(); err != nil { // e.g. connecting at start
		t.Fatal(err)
	}
	g.trayToggle()
	if st := g.ctl.Status(); st.State == "disconnected" || len(*started) != 1 {
		t.Fatalf("\"Подключить\" left state %q after %d starts", st.State, len(*started))
	}
	drawn(g) // "Отключить"
	g.trayToggle()
	if st := g.ctl.Status(); st.State != "disconnected" {
		t.Fatalf("\"Отключить\" left state %q", st.State)
	}
}

// With the kill switch blocking, the text is the same whether routing is
// starting or off: the tray must still tell them apart.
func TestTrayViewKillSwitchBlocking(t *testing.T) {
	offText, off := trayView(app.Status{State: "disconnected", KillSwitch: "blocking"})
	onText, on := trayView(app.Status{State: "starting", KillSwitch: "blocking"})
	if offText != onText || off || !on {
		t.Fatalf("blocking: off %q/%v, starting %q/%v", offText, off, onText, on)
	}
}

// The notification area refused the icon: systray is started over until
// the icon is up, and not again while it stays up.
func TestWatchTrayRestartsUntilTheIconIsUp(t *testing.T) {
	g, _ := trayGUI(t)
	var starts atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.watchTray(time.Millisecond, func() bool {
			if starts.Add(1) == 3 {
				g.trayUp(nil, nil) // the third start brings the icon up
			}
			return true
		})
	}()
	for end := time.Now().Add(5 * time.Second); starts.Load() < 3 && time.Now().Before(end); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if n := starts.Load(); n != 3 {
		t.Fatalf("tray started over %d times, want 3", n)
	}
	g.quitting.Store(true)
	<-done
}

// Explorer takes no icon at all: the starts over stop at trayRetryMax
// (each one costs a callback Go never frees).
func TestWatchTrayGivesUp(t *testing.T) {
	g, _ := trayGUI(t)
	var starts atomic.Int32
	g.watchTray(time.Microsecond, func() bool { starts.Add(1); return true })
	if n := starts.Load(); n != trayRetryMax {
		t.Fatalf("tray started over %d times, want %d", n, trayRetryMax)
	}
}

// The icon came up after the window had taken its place: the close
// button hides to the tray again, and the new menu shows the state.
func TestLateTrayIcon(t *testing.T) {
	g, _ := trayGUI(t)
	g.checkTray()
	if !g.tray.missing.Load() {
		t.Fatal("no icon after the wait: the window should stay in the taskbar")
	}
	g.tray.state, g.tray.on = "Подключено", true // drawn in a menu that is gone
	if !g.trayUp(nil, nil) {
		t.Fatal("a late icon not reported")
	}
	if g.tray.missing.Load() || !g.tray.ready || g.tray.state != "" || g.tray.on {
		t.Fatalf("after the icon came up: missing %v, ready %v, drawn %q/%v", g.tray.missing.Load(), g.tray.ready, g.tray.state, g.tray.on)
	}
}

// A run of systray closed by restartTray before its trayReady came draws
// no menu: the next run's icon may not be up, and systray is setting it
// up meanwhile.
func TestStaleTrayReady(t *testing.T) {
	g, _ := trayGUI(t)
	g.tray.gen = 2
	g.trayReady(1) // after the next run began
	g.tray.gen = 1
	g.tray.restart.Store(true)
	g.trayReady(1) // closed, the next run not begun yet
	if g.tray.ready {
		t.Fatal("a closed run reported its icon as up")
	}
	if g.tray.restart.Store(false); !g.trayCurrent(1) {
		t.Fatal("the run going on taken for a closed one")
	}
}

// HyRoute exits before the tray started (it waits up to a minute for
// Explorer's taskbar): systray.Quit would panic then, and no run of
// systray begins afterwards.
func TestQuitTrayBeforeStart(t *testing.T) {
	g, _ := trayGUI(t)
	g.quitTray()
	if !g.tray.closed.Load() {
		t.Fatal("the tray may still start after the exit")
	}
}
