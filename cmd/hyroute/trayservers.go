package main

import (
	"fmt"
	"strings"

	"github.com/lardan099/hyroute/internal/app"
)

// The tray's «Сервер: X ▸» submenu: the main server or group, changed
// without opening the window. A pool of items as the rule profiles' one
// (trayrulesets.go), with the same order of calls (trayPlan).

// trayServersMax: the servers the submenu lists. A subscription can bring
// a hundred: the menu keeps the first ones and the main one, the window
// has the rest.
const trayServersMax = 30

// trayServersView is what the submenu shows: only with two or more to
// choose from. The main one is always in the list. sig changes whenever
// anything shown does.
func trayServersView(b app.ServersBrief) (visible bool, title string, items []trayRS, sig string) {
	if len(b.List) < 2 {
		return false, "", nil, "hidden"
	}
	list := b.List
	if len(list) > trayServersMax {
		list = list[:trayServersMax]
		for _, e := range b.List[trayServersMax:] {
			if e.ID == b.Main {
				list = append(list[:trayServersMax-1:trayServersMax-1], e)
			}
		}
	}
	var s strings.Builder
	main := "не выбран"
	for _, e := range list {
		name := e.Name
		if e.Group {
			name = "Группа «" + name + "»"
		}
		items = append(items, trayRS{ID: e.ID, Title: trayMenuText(name), Checked: e.ID == b.Main, Disabled: e.Missing && e.ID != b.Main})
		if e.ID == b.Main {
			main = name
		}
		fmt.Fprintf(&s, "%q %q %v %v;", e.ID, name, e.ID == b.Main, e.Missing)
	}
	return true, "Сервер: " + trayMenuText(main), items, s.String()
}

// trayZapretView is the «Обход DPI» item: shown once services are chosen
// on the page, ticked while the bypass is on.
func trayZapretView(b app.ZapretBrief) (visible bool, title string, checked bool) {
	if !b.Shown {
		return false, "", false
	}
	return true, "Обход DPI: " + trayMenuText(strings.Join(b.Targets, ", ")), b.Enabled
}
