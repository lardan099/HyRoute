//go:build windows

package core

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// DefaultDir comes from Windows, not from the ProgramData variable the
// user can set for this elevated process.
func TestDefaultDirIgnoresEnv(t *testing.T) {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		t.Skip(err)
	}
	t.Setenv("ProgramData", t.TempDir())
	if got, want := DefaultDir("core"), filepath.Join(pd, "HyRoute", "core"); !strings.EqualFold(got, want) {
		t.Fatalf("DefaultDir = %s, want %s", got, want)
	}
}

// Without elevation (tests) the token is not split, and a folder the user
// owns is accepted; elevated over a split token what this process creates
// belongs to Administrators, which is accepted too.
func TestCheckOwnerOwnFolder(t *testing.T) {
	if err := checkOwner(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
