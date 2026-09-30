//go:build windows

package core

import (
	"os"
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

// New folders get the protected DACL as they are created; existing ones
// are protected too, a file in the way is refused.
func TestProtectDirCreates(t *testing.T) {
	root := t.TempDir()
	fresh := filepath.Join(root, "fresh", "core")
	existing := filepath.Join(root, "existing", "core")
	if err := os.MkdirAll(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	dirs := []string{fresh, filepath.Dir(fresh), existing, filepath.Dir(existing)}
	t.Cleanup(func() {
		// Without elevation the protected folders are read-only for this
		// user, who still owns them: give them back for the cleanup.
		tu, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return
		}
		sd, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;" + tu.User.Sid.String() + ")")
		if err != nil {
			return
		}
		dacl, _, _ := sd.DACL()
		for _, d := range dirs {
			windows.SetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
		}
	})
	protected := func(d string) {
		t.Helper()
		sd, err := windows.GetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		ctl, _, err := sd.Control()
		if err != nil || ctl&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("%s: DACL not protected (%v)", d, err)
		}
		if s := sd.String(); strings.Contains(s, ";ID;") || !strings.Contains(s, "0x1200a9;;;BU") {
			t.Fatalf("%s: %s", d, s)
		}
	}
	// Without elevation the protected parent does not let this user create
	// the folder in it: only the parent is checked then.
	err := ProtectDir(fresh)
	if windows.GetCurrentProcessToken().IsElevated() {
		if err != nil {
			t.Fatal(err)
		}
		protected(fresh)
	}
	protected(filepath.Dir(fresh))
	if err := ProtectDir(existing); err != nil {
		t.Fatal(err)
	}
	protected(existing)
	protected(filepath.Dir(existing))
	file := filepath.Join(root, "file")
	os.WriteFile(file, nil, 0o644)
	if err := ProtectDir(filepath.Join(file, "core")); err == nil {
		t.Fatal("a file accepted as a folder")
	}
}

// A folder that is not the administrators' is renamed out of the way,
// link or not, and the error names who owns it and what to do.
func TestMoveAsideAndOwnerError(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "HyRoute")
	if err := os.MkdirAll(filepath.Join(d, "runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	to, err := moveAside(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(to, d+".untrusted-") {
		t.Fatalf("moved to %s", to)
	}
	if _, err := os.Stat(filepath.Join(to, "runtime")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Fatalf("%s still there: %v", d, err)
	}
	msg := (&OwnerError{Path: d, Owner: `PC\Admin`}).Error()
	for _, want := range []string{d, `PC\Admin`, "rmdir /s /q", `%APPDATA%\HyRoute`} {
		if !strings.Contains(msg, want) {
			t.Fatalf("%q not in %q", want, msg)
		}
	}
}
