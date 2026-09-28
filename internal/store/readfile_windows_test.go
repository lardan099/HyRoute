//go:build windows

package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestReadRegularJunction: a data file name that is a junction (which any
// user can create, no privilege needed) is refused, and so is a file
// opened while it has a second name (NumberOfLinks). Needs no
// administrator rights.
func TestReadRegularJunction(t *testing.T) {
	dir := t.TempDir()
	target := t.TempDir()
	os.WriteFile(filepath.Join(target, "x"), []byte("secret"), 0o600)
	j := filepath.Join(dir, "groups.json")
	if err := os.Mkdir(j, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setMountPoint(j, target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(j) })
	if _, err := readDataFile(j, 100); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("junction: %v", err)
	}

	f := filepath.Join(dir, "a.json")
	os.WriteFile(f, []byte("{}"), 0o600)
	if b, err := readDataFile(f, 10); err != nil || string(b) != "{}" {
		t.Fatalf("%q %v", b, err)
	}
	if err := os.Link(f, filepath.Join(target, "second")); err != nil {
		t.Fatal(err)
	}
	if _, err := readDataFile(f, 10); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("file with a second name: %v", err)
	}
}
