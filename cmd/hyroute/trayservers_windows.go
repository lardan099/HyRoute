package main

import (
	"reflect"

	"fyne.io/systray"
)

// trayServers is the «Сервер» submenu's and the «Обход DPI» item's part of
// trayState (under tray.mu): the pool of items and what of it is shown
// (trayservers.go), as trayRulesets.
type trayServers struct {
	srv       *systray.MenuItem
	slots     []*systray.MenuItem
	srvShown  bool
	slotShown []bool
	ids       []string // the server or group of each shown slot
	sig       string

	dpi      *systray.MenuItem
	dpiShown bool
	dpiOn    bool // as drawn: a click does the opposite
	dpiTitle string
}

// trayServersMenu adds the parent with its pool of children and the
// «Обход DPI» item, each made while visible and then hidden (see
// trayRulesetsMenu). trayReady calls it where they belong in the menu.
func trayServersMenu() (srv *systray.MenuItem, slots []*systray.MenuItem) {
	srv = systray.AddMenuItem("Сервер", "")
	slots = make([]*systray.MenuItem, trayServersMax)
	for i := range slots {
		slots[i] = srv.AddSubMenuItemCheckbox("", "", false)
	}
	for _, s := range slots {
		s.Hide()
	}
	srv.Hide()
	return srv, slots
}

func trayZapretItem() *systray.MenuItem {
	dpi := systray.AddMenuItemCheckbox("Обход DPI", "", false)
	dpi.Hide()
	return dpi
}

// trayServersUp records a new run's items (everything hidden) and follows
// the clicks on them.
func (g *GUI) trayServersUp(srv *systray.MenuItem, slots []*systray.MenuItem, dpi *systray.MenuItem) {
	g.tray.mu.Lock()
	g.tray.servers = trayServers{srv: srv, slots: slots, slotShown: make([]bool, len(slots)), dpi: dpi}
	g.tray.mu.Unlock()
	go g.trayServersClicks(slots, dpi)
}

// trayServersClicks makes the clicked server the main one, or switches
// the bypass, on a goroutine of its own (never on the tray's thread). No
// channel is ever closed; the goroutine ends with HyRoute (one per run of
// systray).
func (g *GUI) trayServersClicks(slots []*systray.MenuItem, dpi *systray.MenuItem) {
	cases := make([]reflect.SelectCase, len(slots)+1)
	for i, s := range slots {
		cases[i] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(s.ClickedCh)}
	}
	cases[len(slots)] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(dpi.ClickedCh)}
	for {
		k, _, ok := reflect.Select(cases)
		if !ok {
			return
		}
		g.tray.mu.Lock()
		s := &g.tray.servers
		current := len(s.slots) > 0 && s.slots[0] == slots[0]
		id, on := "", s.dpiOn
		if current && k < len(s.ids) {
			id = s.ids[k]
		}
		g.tray.mu.Unlock()
		switch {
		case !current:
		case k == len(slots):
			go g.trayZapretSwitch(!on)
		case id != "":
			go g.traySetMain(id)
		}
	}
}

func (g *GUI) traySetMain(id string) {
	if err := g.ctl.SetMain(id); err != nil {
		g.ctl.Log.Warn("tray: main server not set", "err", err)
		g.showWindow()
	}
}

func (g *GUI) trayZapretSwitch(on bool) {
	if err := g.ctl.SetZapretEnabled(on); err != nil {
		g.ctl.Log.Warn("tray: bypass not switched", "err", err)
		g.showWindow()
	}
}

// trayServersLocked brings the submenu and the «Обход DPI» item up to
// date (tray.mu held; the briefs are light reads, as Status).
func (g *GUI) trayServersLocked() {
	s := &g.tray.servers
	if s.srv == nil {
		return
	}
	if visible, title, items, sig := trayServersView(g.ctl.ServersBrief()); sig != s.sig {
		ops := trayPlan(s.srvShown, s.slotShown, visible, title, items)
		for _, op := range ops {
			it := s.srv
			if op.Slot >= 0 {
				it = s.slots[op.Slot]
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
		s.srvShown, s.slotShown = trayApply(s.srvShown, s.slotShown, ops)
		s.ids = s.ids[:0]
		for _, it := range items {
			s.ids = append(s.ids, it.ID)
		}
		s.sig = sig
	}
	// Hide fails on a hidden item, a setter shows one (trayrulesets.go).
	visible, title, on := trayZapretView(g.ctl.ZapretBrief())
	switch {
	case !visible:
		if s.dpiShown {
			s.dpi.Hide()
			s.dpiShown, s.dpiTitle = false, ""
		}
	case !s.dpiShown || title != s.dpiTitle || on != s.dpiOn:
		s.dpi.SetTitle(title)
		if on {
			s.dpi.Check()
		} else {
			s.dpi.Uncheck()
		}
		s.dpiShown, s.dpiTitle, s.dpiOn = true, title, on
	}
}
