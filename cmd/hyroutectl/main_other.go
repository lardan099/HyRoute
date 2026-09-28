//go:build !windows

// hyroutectl controls a running HyRoute from the command line (Windows).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "hyroutectl runs on Windows only")
	os.Exit(1)
}
