package main

import (
	"errors"
	"testing"
)

func TestWindowGeom(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"10,20,1180,760,false", true},
		{"-1900,0,1200,800,true", true}, // a monitor to the left
		{"10,20,800,760,false", false},  // under the minimum size
		{"10,20,1180,760", false},
		{"a,20,1180,760,false", false},
		{"", false},
	} {
		if _, ok := parseGeom(c.in); ok != c.ok {
			t.Errorf("%q: %v", c.in, ok)
		}
	}
	if g, _ := parseGeom("10,20,1180,760,true"); g.String() != "10,20,1180,760,true" || !g.Max {
		t.Fatal(g)
	}
	for _, c := range []struct{ prev, closed, want string }{
		{"", "10,20,1180,760,false", "10,20,1180,760,false"},
		{"10,20,1180,760,false", "0,0,1920,1040,true", "10,20,1180,760,true"},
		{"", "0,0,1920,1040,true", "0,0,1920,1040,true"},
		{"10,20,1180,760,false", "junk", "10,20,1180,760,false"},
	} {
		if got := nextGeom(c.prev, c.closed); got != c.want {
			t.Errorf("%q then %q: %q, want %q", c.prev, c.closed, got, c.want)
		}
	}
}

// What the close button does: the window goes and HyRoute stays in the
// tray; without the icon it is only minimized (it could not be opened
// again).
func TestCloseAction(t *testing.T) {
	g, _ := trayGUI(t)
	if a := g.closeAction(); a != "close" || g.quitting.Load() {
		t.Fatalf("%q, quitting %v", a, g.quitting.Load())
	}
	g.tray.missing.Store(true)
	if a := g.closeAction(); a != "minimise" {
		t.Fatal(a)
	}
	g.quitting.Store(true) // HyRoute exits: the window just closes
	if a := g.closeAction(); a != "close" {
		t.Fatal(a)
	}
}

// Without a window the calls that need it fail plainly; a GUI of the tests
// (no exe) never starts one.
func TestNoWindow(t *testing.T) {
	g, _ := trayGUI(t)
	g.win = &winHost{g: g}
	g.win.open("normal")
	if g.win.isOpen() {
		t.Fatal("a window started without an exe")
	}
	if _, err := g.win.clipboardGet(); !errors.Is(err, errNoWindow) {
		t.Fatal(err)
	}
	if err := g.CopyText("x"); !errors.Is(err, errNoWindow) {
		t.Fatal(err)
	}
	g.win.notify("status") // dropped, no panic
	g.emitStatus()
	var nilHost *winHost
	nilHost.open("normal")
	nilHost.notify("status")
	if nilHost.isOpen() {
		t.Fatal("nil host open")
	}
}
