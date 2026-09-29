//go:build windows

package main

import (
	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/netmode"
)

// «Сети» (network rules), see internal/app/netmodes.go.

func (g *GUI) NetModes(refresh bool) app.NetModesView { return g.ctl.NetModes(refresh) }
func (g *GUI) SaveNetModes(cfg netmode.Config) (app.NetModesView, error) {
	return g.ctl.SaveNetModes(cfg)
}
func (g *GUI) SetNetModesEnabled(on bool) (app.NetModesView, error) {
	return g.ctl.SetNetModesEnabled(on)
}
func (g *GUI) ApplyNetModes(confirmDisconnect string) (app.NetModesView, error) {
	return g.ctl.ApplyNetModes(confirmDisconnect)
}
func (g *GUI) CurrentSSID() (string, error) { return g.ctl.CurrentSSID() }

// reconnectAfterMove: the copy moved to Program Files was connected, so
// this one connects again, whatever «Подключаться при запуске» says.
func (g *GUI) reconnectAfterMove() {
	g.ctl.ConnectAtStart("connecting again: HyRoute was moved to Program Files and was connected before")
}

// startChecks runs once the start decision is made and the window exists
// (startGate): a kill switch block left from before that stays while
// nothing connected brings the window up, also when HyRoute started in the
// tray. A block a trusted network's rule released, or a connect that
// armed the kill switch again, needs no window.
func (g *GUI) startChecks() {
	if startNeedsWindow(g.ctl.Status()) {
		g.ctl.Log.Info("the kill switch block from before stays and nothing connected: showing the window")
		g.showWindow()
	}
}
