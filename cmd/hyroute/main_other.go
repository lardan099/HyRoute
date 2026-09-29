//go:build !windows

// HyRoute is a Windows program; this stub keeps `go build ./...` and
// `go vet ./...` working on other systems.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "HyRoute runs on Windows only")
	os.Exit(1)
}
