package main

import (
	"sync"
	"sync/atomic"

	"github.com/lardan099/hyroute/internal/app"
)

// startGate runs fn once, after both the start decision (what connects at
// start: AutoConnect, the network rules, the reconnect after an update or
// a move) and the window's startup (the Wails context exists, so
// showWindow works). Either may come first; each may be reported more
// than once.
type startGate struct {
	decided, ui atomic.Bool
	once        sync.Once
	fn          func()
}

func (g *startGate) markDecided() { g.decided.Store(true); g.try() }
func (g *startGate) markUI()      { g.ui.Store(true); g.try() }
func (g *startGate) try() {
	if g.decided.Load() && g.ui.Load() {
		g.once.Do(g.fn)
	}
}

// startNeedsWindow: a kill switch block left from before stays and nothing
// connected at start, so the window has to show it (also when HyRoute
// started in the tray).
func startNeedsWindow(st app.Status) bool {
	return st.KillSwitch == "blocking" && (st.State == "disconnected" || st.State == "error")
}

// startPlan is what main does at start, from the launch reason.
type startPlan struct {
	restore string           // "update" | "rollback" | "move" | "": which restore goroutine reconnects
	mode    app.NetStartMode // Decide, Restore (restore != "") or RestoreIdle
	connUp  bool             // gui.connUp: false only while an update's own reconnect is pending
}

// planStart: an update, a rollback (also an interrupted update recovered
// without --reconnect) and a move to Program Files restore the previous
// state; --reconnect only says whether it was connected. --reconnect alone
// (no other flag) is the move, as before.
func planStart(updEvent, updFailed, movedFrom string, reconnect bool) startPlan {
	restoring := updEvent != "" || updFailed != "" || movedFrom != "" || reconnect
	switch {
	case !restoring:
		return startPlan{mode: app.NetStartDecide, connUp: true}
	case !reconnect:
		return startPlan{mode: app.NetStartRestoreIdle, connUp: true}
	case updEvent != "":
		return startPlan{restore: "update", mode: app.NetStartRestore}
	case updFailed != "":
		return startPlan{restore: "rollback", mode: app.NetStartRestore, connUp: true}
	default:
		return startPlan{restore: "move", mode: app.NetStartRestore, connUp: true}
	}
}
