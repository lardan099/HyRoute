//go:build windows

package main

import (
	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/groups"
)

// ---- server groups ----

func (g *GUI) Groups() app.GroupsInfo { return g.ctl.Groups() }
func (g *GUI) SaveGroup(gr groups.Group) (app.GroupView, error) {
	return g.ctl.SaveGroup(gr)
}
func (g *GUI) DeleteGroup(id string) error { return g.ctl.DeleteGroup(id) }

// ProbeGroup measures every member now (up to a minute).
func (g *GUI) ProbeGroup(id string) (app.GroupView, error) { return g.ctl.ProbeGroup(id) }
func (g *GUI) SetProbe(p groups.Probe) error               { return g.ctl.SetProbe(p) }
