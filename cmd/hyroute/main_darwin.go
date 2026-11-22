//go:build darwin

// HyRoute for macOS: the service (--daemon, root, launchd) and the window
// (HyRoute.app, the user's).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lardan099/hyroute/internal/awg"
)

// Stamped by the build: build is the git commit, version the release tag.
var (
	build      = "dev"
	version    = "v0.0.0-dev"
	updateRepo = "lardan099/HyRoute"
)

func main() {
	daemon := flag.Bool("daemon", false, "be the service (launchd starts it as root)")
	install := flag.Bool("install-service", false, "install and start the service (root)")
	uninstall := flag.Bool("uninstall-service", false, "stop and remove the service (root)")
	stub := flag.Bool("stub", false, "service: an in-process SOCKS5 stub instead of Hysteria (testing)")
	verbose := flag.Bool("v", false, "service: debug logging")
	menubar := flag.Bool("menubar", false, "be the menu bar icon (a launch agent starts it at login)")
	awgConfig := flag.String("awg", "", "set by the service: run one AmneziaWG server from this config file")
	flag.Parse()
	switch {
	case *awgConfig != "":
		// An AmneziaWG server (internal/awg) in a process of its own.
		os.Exit(awg.Main(*awgConfig))
	case *daemon:
		runDaemon(*verbose, *stub)
	case *install:
		if err := installService(); err != nil {
			fmt.Fprintln(os.Stderr, "HyRoute:", err)
			os.Exit(1)
		}
	case *menubar:
		runMenubar()
	case *uninstall:
		if err := uninstallService(); err != nil {
			fmt.Fprintln(os.Stderr, "HyRoute:", err)
			os.Exit(1)
		}
	default:
		runWindow()
	}
}
