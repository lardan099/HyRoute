//go:build !windows

package main

import (
	"os"
	"testing"
)

// openToOthers lets everyone read path.
func openToOthers(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}
