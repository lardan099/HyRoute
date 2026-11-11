//go:build windows

package main

import "testing"

// The panel goes to the corner of the work area nearest the pointer: the
// tray icon is there, wherever the taskbar is.
func TestPanelCorner(t *testing.T) {
	work := winRect{Left: 0, Top: 0, Right: 1920, Bottom: 1040} // the taskbar at the bottom
	for _, c := range []struct {
		name       string
		work       winRect
		pt         winPoint
		w, h, x, y int32
	}{
		{"bottom right", work, winPoint{1800, 1060}, 340, 452, 1920 - 340 - panelMargin, 1040 - 452 - panelMargin},
		{"taskbar at the top", winRect{0, 40, 1920, 1080}, winPoint{1800, 10}, 340, 452, 1920 - 340 - panelMargin, 40 + panelMargin},
		{"taskbar at the left", winRect{60, 0, 1920, 1080}, winPoint{20, 1000}, 340, 452, 60 + panelMargin, 1080 - 452 - panelMargin},
		{"a second screen to the left", winRect{-1920, 0, 0, 1040}, winPoint{-100, 1060}, 340, 452, -340 - panelMargin, 1040 - 452 - panelMargin},
		{"scaled 150%", winRect{0, 0, 2560, 1380}, winPoint{2500, 1400}, 510, 678, 2560 - 510 - panelMargin, 1380 - 678 - panelMargin},
		{"a work area smaller than the panel", winRect{0, 0, 300, 400}, winPoint{290, 390}, 340, 452, 0, 0},
	} {
		if x, y := panelCorner(c.work, c.pt, c.w, c.h); x != c.x || y != c.y {
			t.Errorf("%s: %d,%d, want %d,%d", c.name, x, y, c.x, c.y)
		}
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
