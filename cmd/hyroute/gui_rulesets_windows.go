package main

import "github.com/lardan099/hyroute/internal/app"

// ---- rule profiles (see app/rulesets.go) ----

func (g *GUI) Rulesets() app.RulesetsView { return g.ctl.Rulesets() }

// RulesetSettings is edit mode's copy of an inactive profile (the active
// one gets the normal view).
func (g *GUI) RulesetSettings(id string) (app.SettingsView, error) { return g.ctl.RulesetSettings(id) }

// SwitchRuleset switches from the window; the toast offers «Переподключить».
func (g *GUI) SwitchRuleset(id string) (app.SwitchResult, error) {
	return g.ctl.SwitchRuleset(id, app.SourceUser, app.SwitchOptions{})
}

func (g *GUI) CreateRuleset(in app.RulesetInput) (app.CreateResult, error) {
	return g.ctl.CreateRuleset(in, app.SourceUser)
}

func (g *GUI) RenameRuleset(id, name string) error { return g.ctl.RenameRuleset(id, name) }
func (g *GUI) DeleteRuleset(id string) error       { return g.ctl.DeleteRuleset(id) }
func (g *GUI) MoveRuleset(id string, to int) error { return g.ctl.MoveRuleset(id, to) }
