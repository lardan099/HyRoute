//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lardan099/hyroute/internal/autostart"
)

// A kill switch block outlives HyRoute on purpose (a crash must not let
// traffic out), and a shutdown with Fast Startup keeps it: after a crash
// the next sign-in would have no internet and no HyRoute to say why.
// While the kill switch is on, a sign-in task (autostart.EnableCheck)
// starts HyRoute with --killswitch-check: it ends at once unless such a
// block is in place, and otherwise starts as usual with its window shown.
// The autostart task starts HyRoute anyway, so with it there is no check.
// Like autostart, the task needs HyRoute in Program Files.

// signInCheck decides a start: one by the kill switch check (check) goes
// on only to show a block no running HyRoute looks after, which leftover
// finds (killswitch.Leftover). An unknown answer counts as a block: better
// a window than no internet without a word. It runs before anything else
// in main, so a start that ends here changes nothing.
func signInCheck(check bool, leftover func() (bool, error)) bool {
	if !check {
		return true
	}
	on, err := leftover()
	return on || err != nil
}

type checkPlan int

const (
	checkKeep   checkPlan = iota
	checkCreate           // create it, or point it to this copy
	checkRemove
)

// planCheck decides the user's kill switch check for this copy, exe. on
// and known: the kill switch setting, and whether settings.json loaded
// (the default "off" is not the user's choice then); protected: exe is in
// Program Files and only administrators can change its folder;
// autostart: the user's autostart task exists; exists and current: the
// check exists and the program it starts ("" if unreadable).
func planCheck(on, known, protected, autostart, exists bool, current, exe string) checkPlan {
	mine := exists && current != "" && strings.EqualFold(filepath.Clean(current), filepath.Clean(exe))
	switch {
	case !protected && mine:
		// A task starts its program elevated: never one from a folder any
		// program can write to (its permissions opened since the task was
		// made), whatever the settings say.
		return checkRemove
	case !known:
		return checkKeep
	case !on || autostart:
		if exists {
			return checkRemove
		}
		return checkKeep
	case !protected:
		// Nothing to create here. The check of a copy in Program Files is
		// left to that copy.
		return checkKeep
	case mine:
		return checkKeep
	}
	return checkCreate
}

var checkMu sync.Mutex

// syncKillSwitchCheck creates or removes the kill switch check to follow
// the setting, the autostart task and the program's folder (at start and
// when one of them changes). Task Scheduler is slow to ask: callers run it
// in the background.
func (g *GUI) syncKillSwitchCheck() {
	checkMu.Lock()
	defer checkMu.Unlock()
	exe, err := os.Executable()
	if err != nil {
		return
	}
	st := g.ctl.Settings()
	on, known := st.KillSwitchOn(), g.ctl.SettingsError() == nil
	_, err = autostart.Command()
	if err != nil && !errors.Is(err, autostart.ErrNoTask) {
		g.ctl.Log.Warn("kill switch check at sign-in not updated: the autostart task is unreadable", "err", err)
		return
	}
	auto := err == nil
	current, err := autostart.CheckCommand()
	exists := !errors.Is(err, autostart.ErrNoTask)
	switch planCheck(on, known, protectedLocation(g.dllDir), auto, exists, current, exe) {
	case checkCreate:
		if err := autostart.EnableCheck(exe); err != nil {
			g.ctl.Log.Warn("kill switch check at sign-in not created: a block left after a shutdown will not show by itself", "err", err)
			return
		}
		g.ctl.Log.Info("kill switch check at sign-in: on", "exe", exe)
	case checkRemove:
		if err := autostart.DisableCheck(); err != nil {
			g.ctl.Log.Warn("kill switch check at sign-in not removed", "err", err)
			return
		}
		g.ctl.Log.Info("kill switch check at sign-in: off")
	}
}
