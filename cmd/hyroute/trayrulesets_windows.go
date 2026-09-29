package main

import (
	"reflect"

	"fyne.io/systray"

	"github.com/lardan099/hyroute/internal/app"
)

// trayRulesets is the rule profile submenu's part of trayState (under
// tray.mu): the pool of items and what of it is shown (trayrulesets.go).
type trayRulesets struct {
	rs        *systray.MenuItem
	rsSlots   []*systray.MenuItem
	rsShown   bool
	slotShown []bool
	rsIDs     []string // the profile of each shown slot
	rsSig     string
}

// trayRulesetsMenu adds the parent and its pool of children, while the
// parent is visible (its submenu is attached only then), then hides them
// all: each is visible at that moment, so every Hide succeeds. trayReady
// calls it where the parent belongs in the menu; the menu is not open
// meanwhile.
func trayRulesetsMenu() (*systray.MenuItem, []*systray.MenuItem) {
	rs := systray.AddMenuItem("Профиль правил", "")
	slots := make([]*systray.MenuItem, trayRulesetsMax)
	for i := range slots {
		slots[i] = rs.AddSubMenuItemCheckbox("", "", false)
	}
	for _, s := range slots {
		s.Hide()
	}
	rs.Hide()
	return rs, slots
}

// trayRulesetsUp records a new run's submenu (everything hidden) and
// follows the clicks on it.
func (g *GUI) trayRulesetsUp(rs *systray.MenuItem, slots []*systray.MenuItem) {
	g.tray.mu.Lock()
	g.tray.rulesets = trayRulesets{rs: rs, rsSlots: slots, slotShown: make([]bool, len(slots))}
	g.tray.mu.Unlock()
	go g.trayRulesetsClicks(slots)
}

// trayRulesetsClicks switches to the profile of a clicked slot, on a
// goroutine of its own (never on the tray's thread). No channel is ever
// closed; the goroutine ends with HyRoute (one per run of systray).
func (g *GUI) trayRulesetsClicks(slots []*systray.MenuItem) {
	cases := make([]reflect.SelectCase, len(slots))
	for i, s := range slots {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(s.ClickedCh)}
	}
	for {
		k, _, ok := reflect.Select(cases)
		if !ok {
			return
		}
		g.tray.mu.Lock()
		id := ""
		r := &g.tray.rulesets
		if len(r.rsSlots) > 0 && r.rsSlots[0] == slots[0] && k < len(r.rsIDs) {
			id = r.rsIDs[k]
		}
		g.tray.mu.Unlock()
		if id != "" {
			go g.traySwitchRuleset(id)
		}
	}
}

func (g *GUI) traySwitchRuleset(id string) {
	if _, err := g.ctl.SwitchRuleset(id, app.SourceTray, app.SwitchOptions{}); err != nil {
		g.ctl.Log.Warn("tray: rule set not switched", "err", err)
		g.showWindow()
	}
}

// trayRulesetsLocked brings the submenu up to date (tray.mu held; the
// light RulesetsBrief takes only the controller's lock, as Status does).
func (g *GUI) trayRulesetsLocked() {
	r := &g.tray.rulesets
	if r.rs == nil {
		return
	}
	visible, title, items, sig := trayRulesetsView(g.ctl.RulesetsBrief())
	if sig == r.rsSig {
		return
	}
	ops := trayPlan(r.rsShown, r.slotShown, visible, title, items)
	for _, op := range ops {
		it := r.rs
		if op.Slot >= 0 {
			it = r.rsSlots[op.Slot]
		}
		switch op.Kind {
		case trayOpSetTitle:
			it.SetTitle(op.Title)
		case trayOpCheck:
			it.Check()
		case trayOpUncheck:
			it.Uncheck()
		case trayOpEnable:
			it.Enable()
		case trayOpDisable:
			it.Disable()
		case trayOpHide:
			it.Hide()
		}
	}
	r.rsShown, r.slotShown = trayApply(r.rsShown, r.slotShown, ops)
	r.rsIDs = r.rsIDs[:0]
	for _, it := range items {
		r.rsIDs = append(r.rsIDs, it.ID)
	}
	r.rsSig = sig
}
