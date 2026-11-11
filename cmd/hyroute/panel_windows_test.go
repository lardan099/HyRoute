//go:build windows

package main

import "testing"

// The panel stands against the taskbar, centred on the icon that was
// clicked and inside the work area, wherever the taskbar is.
func TestPanelPlace(t *testing.T) {
	full := winRect{Left: 0, Top: 0, Right: 1920, Bottom: 1080}
	for _, c := range []struct {
		name       string
		mon, work  winRect
		at         winPoint
		w, h, x, y int32
	}{
		{"an icon in the middle of the tray", full, winRect{0, 0, 1920, 1040}, winPoint{1500, 1060}, 340, 200, 1500 - 170, 1040 - 200 - panelMargin},
		{"an icon by the clock: kept inside", full, winRect{0, 0, 1920, 1040}, winPoint{1900, 1060}, 340, 200, 1920 - 340 - panelMargin, 1040 - 200 - panelMargin},
		{"taller content grows upwards", full, winRect{0, 0, 1920, 1040}, winPoint{1500, 1060}, 340, 420, 1500 - 170, 1040 - 420 - panelMargin},
		{"taskbar at the top", full, winRect{0, 40, 1920, 1080}, winPoint{1500, 10}, 340, 200, 1500 - 170, 40 + panelMargin},
		{"taskbar at the left", full, winRect{60, 0, 1920, 1080}, winPoint{20, 900}, 340, 200, 60 + panelMargin, 900 - 100},
		{"taskbar at the right", full, winRect{0, 0, 1860, 1080}, winPoint{1900, 1070}, 340, 200, 1860 - 340 - panelMargin, 1080 - 200 - panelMargin},
		{"a second screen to the left", winRect{-1920, 0, 0, 1080}, winRect{-1920, 0, 0, 1040}, winPoint{-300, 1060}, 340, 200, -300 - 170, 1040 - 200 - panelMargin},
		{"scaled 150%", winRect{0, 0, 2560, 1440}, winRect{0, 0, 2560, 1380}, winPoint{2000, 1410}, 510, 300, 2000 - 255, 1380 - 300 - panelMargin},
		{"a hidden taskbar: the nearest corner", full, full, winPoint{1800, 1070}, 340, 200, 1920 - 340 - panelMargin, 1080 - 200 - panelMargin},
		{"a hidden taskbar at the top left", full, full, winPoint{30, 5}, 340, 200, panelMargin, panelMargin},
		{"a work area smaller than the panel", winRect{0, 0, 300, 440}, winRect{0, 0, 300, 400}, winPoint{290, 420}, 340, 452, panelMargin, panelMargin},
	} {
		if x, y := panelPlace(c.mon, c.work, c.at, c.w, c.h); x != c.x || y != c.y {
			t.Errorf("%s: %d,%d, want %d,%d", c.name, x, y, c.x, c.y)
		}
	}
	if pt := parsePanelAt("-300,1060"); pt != (winPoint{-300, 1060}) {
		t.Fatalf("%+v", pt)
	}
}

// Without a panel to start (tests, a build that has none) the click on the
// tray icon does what it did before the panel, and nothing breaks at exit.
func TestShowPanelWithoutOne(t *testing.T) {
	g := newTestGUI(t)
	g.showPanel() // no hosts at all
	g.win, g.panel = &winHost{g: g}, &winHost{g: g, panel: true}
	g.showPanel()
	if g.panel.isOpen() || g.win.isOpen() {
		t.Fatal("a window process started in a test")
	}
	g.panel.notify("status")
	g.panel.close()
	// The panel's own events are never taken for the main window's: its
	// coming up is not HyRoute's start.
	if r, err := g.panel.answer("window.ready", nil); r != nil || err != nil || g.uiUp.Load() {
		t.Fatalf("%v %v", r, err)
	}
}
