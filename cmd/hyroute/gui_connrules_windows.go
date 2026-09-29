//go:build windows

package main

import "github.com/lardan099/hyroute/internal/app"

// ---- rules from connections ----

// ConnRuleInfo is what the menu of a Connections row offers.
func (g *GUI) ConnRuleInfo(f app.ConnFacts) (app.ConnRuleInfo, error) { return g.ctl.ConnRuleInfo(f) }

// AddConnRule creates a rule from a Connections row.
func (g *GUI) AddConnRule(r app.ConnRuleRequest) (app.ConnRuleResult, error) {
	return g.ctl.AddConnRule(r)
}

// UndoConnRule reverts a rule created from a connection.
func (g *GUI) UndoConnRule(token string) error { return g.ctl.UndoConnRule(token) }
