package main

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/session"
)

// The gate runs once, whichever mark comes first, however often each is
// reported.
func TestStartGate(t *testing.T) {
	for _, uiFirst := range []bool{false, true} {
		var n atomic.Int32
		g := &startGate{fn: func() { n.Add(1) }}
		if uiFirst {
			g.markUI()
		} else {
			g.markDecided()
		}
		if n.Load() != 0 {
			t.Fatal("ran on one mark")
		}
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(2)
			go func() { defer wg.Done(); g.markUI() }()
			go func() { defer wg.Done(); g.markDecided() }()
		}
		wg.Wait()
		if n.Load() != 1 {
			t.Fatalf("ran %d times", n.Load())
		}
	}
}

func TestStartNeedsWindow(t *testing.T) {
	for _, tc := range []struct {
		st   app.Status
		want bool
	}{
		{app.Status{State: "disconnected", KillSwitch: "blocking"}, true},
		{app.Status{State: "error", KillSwitch: "blocking"}, true},
		{app.Status{State: "error", KillSwitch: "blocking", Stats: &session.Stats{}}, true},
		{app.Status{State: "connected", KillSwitch: "armed"}, false},
		{app.Status{State: "disconnected"}, false},
		{app.Status{State: "starting", KillSwitch: "blocking"}, false},
	} {
		if got := startNeedsWindow(tc.st); got != tc.want {
			t.Errorf("%+v: %v", tc.st, got)
		}
	}
}

func TestPlanStart(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		updEvent, updFailed, movedFr string
		reconnect                    bool
		want                         startPlan
	}{
		{"plain start", "", "", "", false, startPlan{mode: app.NetStartDecide, connUp: true}},
		{"update --reconnect", "ev", "", "", true, startPlan{restore: "update", mode: app.NetStartRestore}},
		{"update alone", "ev", "", "", false, startPlan{mode: app.NetStartRestoreIdle, connUp: true}},
		{"rollback --reconnect", "", "v2", "", true, startPlan{restore: "rollback", mode: app.NetStartRestore, connUp: true}},
		{"rollback alone (old journal)", "", "v2", "", false, startPlan{mode: app.NetStartRestoreIdle, connUp: true}},
		{"move --reconnect", "", "", `C:\old`, true, startPlan{restore: "move", mode: app.NetStartRestore, connUp: true}},
		{"--reconnect alone", "", "", "", true, startPlan{restore: "move", mode: app.NetStartRestore, connUp: true}},
		{"move alone", "", "", `C:\old`, false, startPlan{mode: app.NetStartRestoreIdle, connUp: true}},
	} {
		if got := planStart(tc.updEvent, tc.updFailed, tc.movedFr, tc.reconnect); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	// --autostart is not a launch reason: planStart does not take it.
}
