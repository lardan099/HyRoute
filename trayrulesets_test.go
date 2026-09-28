package main

import (
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/store"
)

func brief(active string, names ...string) app.RulesetsBrief {
	b := app.RulesetsBrief{Usable: true, Saved: true, Active: active}
	for i, n := range names {
		b.List = append(b.List, app.RulesetBriefItem{ID: string(rune('a' + i)), Name: n})
	}
	return b
}

func TestTrayRulesetsView(t *testing.T) {
	if trayRulesetsMax != store.MaxRulesets {
		t.Fatal("one item per possible profile")
	}
	for name, v := range map[string]app.RulesetsBrief{
		"one":       brief("a", "Дом"),
		"not saved": {Usable: true, List: brief("a", "A", "B").List},
		"broken":    {Saved: true, Active: "a", List: brief("a", "A", "B").List},
	} {
		if vis, _, items, _ := trayRulesetsView(v); vis || items != nil {
			t.Errorf("%s: shown", name)
		}
	}
	long := strings.Repeat("я", 45)
	v := brief("b", "Дом & сад", long, "Игры")
	v.List[2].Error = true
	vis, title, items, sig := trayRulesetsView(v)
	if !vis || title != "Профиль правил: "+strings.Repeat("я", 40)+"…" || len(items) != 3 {
		t.Fatalf("%v %q %+v", vis, title, items)
	}
	if items[0].Title != "Дом && сад" || !items[1].Checked || items[0].Checked || !items[2].Disabled || items[0].Disabled {
		t.Fatalf("%+v", items)
	}
	// Cut first, then escaped: a cut never splits "&&".
	if got := trayMenuText(strings.Repeat("a", 39) + "&&"); got != strings.Repeat("a", 39)+"&&…" {
		t.Fatal(got)
	}
	if _, title, _, _ := trayRulesetsView(brief("a", "R&D", "B")); title != "Профиль правил: R&&D" {
		t.Fatal(title)
	}
	// sig: the same view, the same sig; any shown change, another one.
	if _, _, _, s := trayRulesetsView(brief("b", "Дом & сад", long, "Игры")); s == sig {
		t.Fatal("error change not seen")
	}
	same := brief("b", "Дом & сад", long, "Игры")
	same.List[2].Error = true
	if _, _, _, s := trayRulesetsView(same); s != sig {
		t.Fatal("identical view, new sig")
	}
	for name, edit := range map[string]func(b *app.RulesetsBrief){
		"rename":  func(b *app.RulesetsBrief) { b.List[0].Name = "Дом 2" },
		"reorder": func(b *app.RulesetsBrief) { b.List[0], b.List[1] = b.List[1], b.List[0] },
		"active":  func(b *app.RulesetsBrief) { b.Active = "a" },
		"error":   func(b *app.RulesetsBrief) { b.List[2].Error = false },
	} {
		b := brief("b", "Дом & сад", long, "Игры")
		b.List[2].Error = true
		edit(&b)
		if _, _, _, s := trayRulesetsView(b); s == sig {
			t.Errorf("%s: sig unchanged", name)
		}
	}
}

func TestTrayPlan(t *testing.T) {
	slots := make([]bool, trayRulesetsMax)
	items := func(n int) []trayRS {
		var out []trayRS
		for i := range n {
			out = append(out, trayRS{ID: string(rune('a' + i)), Title: "t", Checked: i == 0, Disabled: i == 2})
		}
		return out
	}
	// check: no setter on a slot that stays hidden, no Hide on a hidden
	// item, and the parent before any slot.
	check := func(name string, parent bool, shown []bool, n int, ops []trayOp) {
		t.Helper()
		for k, op := range ops {
			switch {
			case op.Slot >= n && op.Kind != trayOpHide:
				t.Errorf("%s: setter on slot %d", name, op.Slot)
			case op.Kind == trayOpHide && op.Slot < 0 && !parent:
				t.Errorf("%s: Hide on the hidden parent", name)
			case op.Kind == trayOpHide && op.Slot >= 0 && !shown[op.Slot]:
				t.Errorf("%s: Hide on hidden slot %d", name, op.Slot)
			case op.Slot >= 0 && op.Kind != trayOpHide && (len(ops) == 0 || ops[0].Slot != -1 || k == 0):
				t.Errorf("%s: a slot before the parent", name)
			}
		}
	}
	count := func(ops []trayOp, kind trayOpKind) int {
		n := 0
		for _, op := range ops {
			if op.Kind == kind {
				n++
			}
		}
		return n
	}

	// Hidden → 3 items: the parent's SetTitle first, setters on 0–2, no Hide.
	ops := trayPlan(false, slots, true, "P", items(3))
	check("0→3", false, slots, 3, ops)
	if ops[0] != (trayOp{Slot: -1, Kind: trayOpSetTitle, Title: "P"}) || count(ops, trayOpHide) != 0 || len(ops) != 1+3*3 {
		t.Fatalf("%+v", ops)
	}
	if ops[2].Kind != trayOpCheck || ops[5].Kind != trayOpUncheck || ops[9].Kind != trayOpDisable {
		t.Fatalf("%+v", ops)
	}
	parent, shown := trayApply(false, slots, ops)
	if !parent || !shown[0] || !shown[2] || shown[3] {
		t.Fatal("apply")
	}

	// 3 → 2: exactly one Hide (slot 2).
	ops = trayPlan(parent, shown, true, "P", items(2))
	check("3→2", parent, shown, 2, ops)
	if count(ops, trayOpHide) != 1 || ops[len(ops)-1] != (trayOp{Slot: 2, Kind: trayOpHide}) {
		t.Fatalf("%+v", ops)
	}
	parent, shown = trayApply(parent, shown, ops)

	// 2 → hidden: only the parent's Hide.
	ops = trayPlan(parent, shown, false, "", nil)
	if len(ops) != 1 || ops[0] != (trayOp{Slot: -1, Kind: trayOpHide}) {
		t.Fatalf("%+v", ops)
	}
	parent, shown = trayApply(parent, shown, ops)
	if parent || !shown[0] || !shown[1] || shown[2] {
		t.Fatal("the children keep their state in the detached submenu")
	}
	// Hidden again: nothing (Hide on a hidden item logs an error).
	if ops := trayPlan(parent, shown, false, "", nil); len(ops) != 0 {
		t.Fatalf("%+v", ops)
	}

	// Hidden → 2 again: the parent first, slots 0–1, no Hide of slot 2.
	ops = trayPlan(parent, shown, true, "P", items(2))
	check("hidden→2", parent, shown, 2, ops)
	if ops[0].Slot != -1 || count(ops, trayOpHide) != 0 {
		t.Fatalf("%+v", ops)
	}
	parent, shown = trayApply(parent, shown, ops)

	// 2 → 50 → 1.
	ops = trayPlan(parent, shown, true, "P", items(50))
	check("2→50", parent, shown, 50, ops)
	parent, shown = trayApply(parent, shown, ops)
	ops = trayPlan(parent, shown, true, "P", items(1))
	check("50→1", parent, shown, 1, ops)
	if count(ops, trayOpHide) != 49 {
		t.Fatal(count(ops, trayOpHide))
	}
	if _, shown = trayApply(parent, shown, ops); shown[1] || !shown[0] {
		t.Fatal("apply")
	}
}
