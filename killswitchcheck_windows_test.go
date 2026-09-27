package main

import (
	"errors"
	"testing"
)

// A start by the kill switch check goes on only to show a block left from
// before (or one it cannot rule out); any other start does not ask.
func TestSignInCheck(t *testing.T) {
	asked := 0
	probe := func(on bool, err error) func() (bool, error) {
		return func() (bool, error) { asked++; return on, err }
	}
	if !signInCheck(false, probe(false, nil)) || asked != 0 {
		t.Fatalf("a start without the flag: asked %d times", asked)
	}
	for _, tc := range []struct {
		on   bool
		err  error
		want bool
	}{
		{false, nil, false},                      // no block, or a running HyRoute looks after it
		{true, nil, true},                        // a block and no HyRoute
		{false, errors.New("BFE stopped"), true}, // unknown
	} {
		if got := signInCheck(true, probe(tc.on, tc.err)); got != tc.want {
			t.Errorf("block %v, error %v: goes on %v", tc.on, tc.err, got)
		}
	}
}

func TestPlanCheck(t *testing.T) {
	const exe = `C:\Program Files\HyRoute\HyRoute.exe`
	for _, tc := range []struct {
		what                                    string
		on, known, protected, autostart, exists bool
		current                                 string
		want                                    checkPlan
	}{
		{"kill switch on", true, true, true, false, false, "", checkCreate},
		{"already there", true, true, true, false, true, `c:\program files\hyroute\HyRoute.exe`, checkKeep},
		{"another copy's", true, true, true, false, true, `C:\Program Files (x86)\HyRoute\HyRoute.exe`, checkCreate},
		{"unreadable", true, true, true, false, true, "", checkCreate},
		{"kill switch off", false, true, true, false, true, exe, checkRemove},
		{"off, none", false, true, true, false, false, "", checkKeep},
		{"autostart starts HyRoute anyway", true, true, true, true, true, exe, checkRemove},
		{"autostart, none", true, true, true, true, false, "", checkKeep},
		{"not in Program Files", true, true, false, false, false, "", checkKeep},
		{"not in Program Files, another copy's", true, true, false, false, true, `C:\Program Files (x86)\HyRoute\HyRoute.exe`, checkKeep},
		{"folder opened to users since", true, true, false, false, true, exe, checkRemove},
		{"folder opened, settings not loaded", false, false, false, false, true, `c:\program files\hyroute\HyRoute.exe`, checkRemove},
		{"off, not in Program Files", false, true, false, false, true, exe, checkRemove},
		{"settings not loaded", false, false, true, false, true, exe, checkKeep},
		{"settings not loaded, none", false, false, true, false, false, "", checkKeep},
	} {
		if got := planCheck(tc.on, tc.known, tc.protected, tc.autostart, tc.exists, tc.current, exe); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.what, got, tc.want)
		}
	}
}
