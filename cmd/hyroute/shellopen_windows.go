package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

// openFolder shows dir in Explorer. HyRoute runs elevated, and an
// explorer.exe started from an elevated process often hands the folder to
// the running (unelevated) Explorer and fails at it: a window flashes and
// closes. So the running Explorer is asked to open the folder itself,
// through the desktop's shell automation object
// (ShellWindows.FindWindowSW → Document.Application.ShellExecute); starting
// explorer.exe by its full path is the fallback.
func openFolder(dir string) error {
	if err := shellExecuteInExplorer(dir); err == nil {
		return nil
	}
	win, err := windows.GetWindowsDirectory()
	if err != nil {
		return err
	}
	return exec.Command(filepath.Join(win, "explorer.exe"), dir).Start()
}

func shellExecuteInExplorer(target string) error {
	return shellExecuteArgs(target, "")
}

// shellExecuteArgs runs file with args in Explorer's process: with the
// user's normal rights, not HyRoute's (a browser started elevated would
// run with another profile's rights and refuse extensions' hosts).
func shellExecuteArgs(file, args string) error {
	return shellExecuteShow(file, args, swShowNormal)
}

// ShowWindow commands for shellExecuteShow.
const (
	swShowNormal      = 1
	swShowMinNoActive = 7 // minimized, the focus stays where it is
)

// shellExecuteShow is shellExecuteArgs with the way the program's window
// shows.
func shellExecuteShow(file, args string, show int32) error {
	return inSTA(func() error { return shellExecuteSTA(file, args, show) })
}

// inSTA runs f on a thread of its own in a single-threaded COM apartment,
// which the shell's automation objects need.
func inSTA(f func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer func() {
			if r := recover(); r != nil {
				select {
				case done <- errors.New("shell automation failed"):
				default: // f had returned
				}
			}
		}()
		if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED); err != nil {
			var oe *ole.OleError
			// S_FALSE: already initialized on this thread.
			if !errors.As(err, &oe) || oe.Code() != 1 {
				done <- err
				return
			}
		}
		defer ole.CoUninitialize()
		done <- f()
	}()
	return <-done
}

func shellExecuteSTA(target, args string, show int32) error {
	unk, err := oleutil.CreateObject("Shell.Application")
	if err != nil {
		return err
	}
	defer unk.Release()
	shell, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer shell.Release()

	wv, err := oleutil.CallMethod(shell, "Windows")
	if err != nil {
		return err
	}
	sw := wv.ToIDispatch()
	defer sw.Release()

	const (
		csidlDesktop     = 0
		swcDesktop       = 8
		swfoNeedDispatch = 1
	)
	var hwnd int32
	dv, err := oleutil.CallMethod(sw, "FindWindowSW", int32(csidlDesktop), nil, int32(swcDesktop), &hwnd, int32(swfoNeedDispatch))
	if err != nil {
		return err
	}
	desktop := dv.ToIDispatch()
	if desktop == nil {
		return errors.New("no desktop window")
	}
	defer desktop.Release()

	docv, err := oleutil.GetProperty(desktop, "Document")
	if err != nil {
		return err
	}
	doc := docv.ToIDispatch()
	if doc == nil {
		return errors.New("no desktop view")
	}
	defer doc.Release()

	appv, err := oleutil.GetProperty(doc, "Application")
	if err != nil {
		return err
	}
	app := appv.ToIDispatch()
	if app == nil {
		return errors.New("no shell application")
	}
	defer app.Release()

	// ShellExecute(file, args, dir, verb, show): runs in Explorer's
	// process, with the user's normal rights.
	_, err = oleutil.CallMethod(app, "ShellExecute", target, args, "", "open", show)
	return err
}
