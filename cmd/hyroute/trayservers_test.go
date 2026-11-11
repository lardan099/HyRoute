package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/app"
)

func TestTrayServersView(t *testing.T) {
	// One server: nothing to choose.
	if v, _, _, sig := trayServersView(app.ServersBrief{Main: "a", List: []app.ServerBriefItem{{ID: "a", Name: "NL"}}}); v || sig != "hidden" {
		t.Fatal("shown with one server")
	}
	b := app.ServersBrief{Main: "b", List: []app.ServerBriefItem{
		{ID: "a", Name: "NL & co"}, {ID: "b", Name: "DE"}, {ID: "c", Name: "Старый", Missing: true}, {ID: "g", Name: "Быстрые", Group: true},
	}}
	v, title, items, sig := trayServersView(b)
	if !v || title != "Сервер: DE" || len(items) != 4 {
		t.Fatalf("%v %q %+v", v, title, items)
	}
	// '&' doubled for the menu; a server gone from its subscription cannot
	// be chosen; a group says it is one.
	if items[0].Title != "NL && co" || items[0].Checked || !items[1].Checked || !items[2].Disabled || items[3].Title != "Группа «Быстрые»" {
		t.Fatalf("%+v", items)
	}
	// The same view: the same signature; a new main one: another.
	if _, _, _, again := trayServersView(b); again != sig {
		t.Fatal("signature not stable")
	}
	b.Main = "g"
	if _, title, items, other := trayServersView(b); other == sig || title != "Сервер: Группа «Быстрые»" || !items[3].Checked || items[1].Checked {
		t.Fatalf("%q %+v", title, items)
	}
	// None chosen; a main one that is gone stays choosable (it is ticked).
	b.Main = ""
	if _, title, _, _ := trayServersView(b); title != "Сервер: не выбран" {
		t.Fatal(title)
	}
	b.Main = "c"
	if _, _, items, _ := trayServersView(b); items[2].Disabled || !items[2].Checked {
		t.Fatalf("%+v", items[2])
	}
	// A subscription's hundred servers: the first ones and the main one.
	var many app.ServersBrief
	for i := range 100 {
		many.List = append(many.List, app.ServerBriefItem{ID: fmt.Sprint(i), Name: fmt.Sprint("S", i)})
	}
	many.Main = "77"
	_, title, items, _ = trayServersView(many)
	if len(items) != trayServersMax || title != "Сервер: S77" || items[trayServersMax-1].ID != "77" || !items[trayServersMax-1].Checked || items[0].ID != "0" {
		t.Fatalf("%d %q %+v", len(items), title, items[len(items)-1])
	}
	many.Main = "3"
	if _, _, items, _ = trayServersView(many); len(items) != trayServersMax || !items[3].Checked || items[trayServersMax-1].ID != fmt.Sprint(trayServersMax-1) {
		t.Fatalf("%+v", items[len(items)-1])
	}
	// The pool takes the view as the profiles' one does.
	ops := trayPlan(false, make([]bool, trayServersMax), true, title, items)
	if shown, slots := trayApply(false, make([]bool, trayServersMax), ops); !shown || !slots[0] || !slots[trayServersMax-1] {
		t.Fatal("not shown")
	}
}

func TestTrayZapretView(t *testing.T) {
	if v, _, _ := trayZapretView(app.ZapretBrief{Enabled: true, Targets: []string{"YouTube"}}); v {
		t.Fatal("shown when there is nothing to switch")
	}
	v, title, on := trayZapretView(app.ZapretBrief{Shown: true, Enabled: true, Targets: []string{"YouTube", "Discord", "Свои сайты"}})
	if !v || !on || title != "Обход DPI: YouTube, Discord, Свои сайты" {
		t.Fatalf("%v %q %v", v, title, on)
	}
	if _, title, on = trayZapretView(app.ZapretBrief{Shown: true, Targets: []string{strings.Repeat("я", 60)}}); on || !strings.HasSuffix(title, "…") {
		t.Fatalf("%q %v", title, on)
	}
}
