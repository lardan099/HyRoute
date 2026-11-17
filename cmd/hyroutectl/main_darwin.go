//go:build darwin

// hyroutectl controls the HyRoute service from the command line (macOS):
// it runs as the invoking user and talks to the service over its socket
// (internal/ctl/pipe_darwin.go). All the logic is in internal/ctl/cli.
package main

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"slices"
	"time"

	"github.com/lardan099/hyroute/internal/ctl"
	"github.com/lardan099/hyroute/internal/ctl/cli"
	"github.com/lardan099/hyroute/internal/procinfo"
)

// Stamped by the build (the release tag, as in HyRoute).
var version = "v0.0.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	d := &cli.Deps{
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Env:     os.Getenv,
		SelfSID: ctl.MacOwner,
		Admin:   admin(),
		Version: version,
		Dial: func(name string, busy time.Duration) (net.Conn, uint32, error) {
			return ctl.Dial(name, busy, nil)
		},
		Probe:     func(ev string) (ctl.RunState, error) { return ctl.ProbeRunEvent(ev, nil) },
		FindPipes: ctl.FindPipes,
		ReadFile:  os.ReadFile,
		WriteFile: func(p string, b []byte) error { return os.WriteFile(p, b, 0o644) },
		Launch: func(w io.Writer) error {
			io.WriteString(w, "Открываю HyRoute…\n")
			return exec.Command("/usr/bin/open", "-b", "com.hyroute.app").Run()
		},
		AllowForeground: func(uint32) {},
	}
	var code int
	if cli.IsNativeHost(os.Args[1:]) {
		parent := procinfo.NewCache().Get(uint32(os.Getppid()))
		code = cli.NativeHost(ctx, os.Args[1:], os.Stdin, os.Stdout, parent.Name, d)
	} else {
		code = cli.Run(ctx, os.Args[1:], d)
	}
	stop()
	os.Exit(code)
}

// admin: root or a member of group admin (the service serves those).
func admin() bool {
	if os.Geteuid() == 0 {
		return true
	}
	u, err := user.Current()
	if err != nil {
		return false
	}
	ids, err := u.GroupIds()
	return err == nil && slices.Contains(ids, "80")
}
