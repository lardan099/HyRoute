package main

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/app"
)

// The tray's «Профиль правил: X ▸» submenu (rule profiles). The menu is a
// fixed pool of items made once per run of systray and never removed:
// fyne.io/systray's Remove closes an item's click channel, and a click
// racing a rebuild would then send on a closed channel. fyne.io/systray
// v1.12.2 on Windows dictates the order of the calls (see trayPlan):
//   - the first child of an item attaches its submenu inside the menu the
//     item is in at that moment: a hidden parent gets none, ever;
//   - Hide removes an item from its menu (the parent keeps its submenu), and
//     fails, logging "systray error", on an item already hidden;
//   - SetTitle, Check, Uncheck, Enable and Disable insert a hidden item (show
//     it) or update a shown one in place.
//
// So the parent is made visible with all its children, then everything is
// hidden (trayRulesetsMenu), and an update shows the parent before any
// child, calls setters only on children that must be shown and Hide only
// on children that are shown.

// trayRulesetsMax: one menu item per possible profile.
const trayRulesetsMax = 50 // store.MaxRulesets

// trayRS is one profile in the submenu.
type trayRS struct {
	ID, Title         string
	Checked, Disabled bool
}

// trayTitleMax: longer names are cut (and end with «…»).
const trayTitleMax = 40

// trayMenuText is a name as a menu shows it: cut to trayTitleMax runes,
// then '&' doubled (a single one would underline the next letter).
func trayMenuText(s string) string {
	if utf8.RuneCountInString(s) > trayTitleMax {
		s = string([]rune(s)[:trayTitleMax]) + "…"
	}
	return strings.ReplaceAll(s, "&", "&&")
}

// trayRulesetsView is what the submenu shows: only with two or more saved
// profiles and both files loaded. sig changes whenever anything shown does
// (IDs, names, order, the active one, errors).
func trayRulesetsView(v app.RulesetsBrief) (visible bool, title string, items []trayRS, sig string) {
	if !v.Usable || !v.Saved || len(v.List) < 2 {
		return false, "", nil, "hidden"
	}
	var b strings.Builder
	active := ""
	for i, e := range v.List {
		if i >= trayRulesetsMax {
			break
		}
		items = append(items, trayRS{ID: e.ID, Title: trayMenuText(e.Name), Checked: e.ID == v.Active, Disabled: e.Error})
		if e.ID == v.Active {
			active = e.Name
		}
		fmt.Fprintf(&b, "%q %q %v %v;", e.ID, e.Name, e.ID == v.Active, e.Error)
	}
	return true, "Профиль правил: " + trayMenuText(active), items, b.String()
}

type trayOpKind int

const (
	trayOpSetTitle trayOpKind = iota
	trayOpCheck
	trayOpUncheck
	trayOpEnable
	trayOpDisable
	trayOpHide
)

// trayOp is one call on the parent (Slot -1) or on a child.
type trayOp struct {
	Slot  int
	Kind  trayOpKind
	Title string // trayOpSetTitle
}

// trayPlan is the calls that turn the menu shown now (parentShown,
// slotShown) into the new view, in order: the parent first (its SetTitle
// shows it with its submenu), then the children to show, then Hide for
// the shown children no longer needed. Hidden: only the parent is hidden
// (its children stay inside the detached submenu).
func trayPlan(parentShown bool, slotShown []bool, visible bool, title string, items []trayRS) []trayOp {
	var ops []trayOp
	if !visible {
		if parentShown {
			ops = append(ops, trayOp{Slot: -1, Kind: trayOpHide})
		}
		return ops
	}
	ops = append(ops, trayOp{Slot: -1, Kind: trayOpSetTitle, Title: title})
	for i, it := range items {
		if i >= len(slotShown) {
			break
		}
		check, enable := trayOpUncheck, trayOpEnable
		if it.Checked {
			check = trayOpCheck
		}
		if it.Disabled {
			enable = trayOpDisable
		}
		ops = append(ops, trayOp{Slot: i, Kind: trayOpSetTitle, Title: it.Title}, trayOp{Slot: i, Kind: check}, trayOp{Slot: i, Kind: enable})
	}
	for i := len(items); i < len(slotShown); i++ {
		if slotShown[i] {
			ops = append(ops, trayOp{Slot: i, Kind: trayOpHide})
		}
	}
	return ops
}

// trayApply is what is shown after ops: Hide hides an item, any other call
// shows it.
func trayApply(parentShown bool, slotShown []bool, ops []trayOp) (bool, []bool) {
	shown := append([]bool(nil), slotShown...)
	for _, op := range ops {
		on := op.Kind != trayOpHide
		if op.Slot < 0 {
			parentShown = on
		} else {
			shown[op.Slot] = on
		}
	}
	return parentShown, shown
}
