//go:build windows

// hyroutectl controls a running HyRoute from the command line: a console
// program running as the invoking user, talking to the elevated HyRoute
// over its control pipe (internal/ctl). All the logic is in
// internal/ctl/cli; this file wires the console, Ctrl+C and the pipe.
package main

import (
	"context"
	"io"
	"net"
	"os"
	"os/signal"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/ctl/cli"
)

// Stamped by scripts/build.ps1 (the release tag, as in HyRoute.exe).
var version = "v0.0.0-dev"

var procAllowSetForegroundWindow = windows.NewLazySystemDLL("user32.dll").NewProc("AllowSetForegroundWindow")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	sid, admin := whoami()
	d := &cli.Deps{
		Stdin:   os.Stdin,
		Stdout:  console(os.Stdout),
		Stderr:  console(os.Stderr),
		Env:     os.Getenv,
		SelfSID: sid,
		Admin:   admin,
		Version: version,
		Dial: func(name string, busy time.Duration) (net.Conn, uint32, error) {
			return ctl.Dial(name, busy, ctl.Trusted)
		},
		Probe:     func(ev string) (ctl.RunState, error) { return ctl.ProbeRunEvent(ev, ctl.Trusted) },
		FindPipes: ctl.FindPipes,
		ReadFile:  os.ReadFile,
		WriteFile: func(p string, b []byte) error { return os.WriteFile(p, b, 0o644) },
		Launch:    func(w io.Writer) error { return launch(w, sid) },
		AllowForeground: func(pid uint32) {
			procAllowSetForegroundWindow.Call(uintptr(pid))
		},
	}
	code := cli.Run(ctx, os.Args[1:], d)
	stop()
	os.Exit(code)
}

// whoami is the user's SID and whether this is an elevated administrator.
func whoami() (string, bool) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", false
	}
	admin := false
	if tok.IsElevated() {
		if ba, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err == nil {
			admin, _ = tok.IsMember(ba)
		}
	}
	return u.User.Sid.String(), admin
}

// console writes UTF-16 to a console (correct in every code page) and
// the bytes as they are (UTF-8) to a file or pipe.
func console(f *os.File) io.Writer {
	h := windows.Handle(f.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		return f
	}
	return consoleWriter{h}
}

type consoleWriter struct{ h windows.Handle }

func (c consoleWriter) Write(b []byte) (int, error) {
	u := utf16.Encode([]rune(string(b)))
	for len(u) > 0 {
		var n uint32
		if err := windows.WriteConsole(c.h, &u[0], uint32(len(u)), &n, nil); err != nil {
			return 0, err
		}
		if n == 0 {
			break
		}
		u = u[n:]
	}
	return len(b), nil
}
