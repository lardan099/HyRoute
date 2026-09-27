package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

// longPath expands 8.3 names: a shortcut stores the long form of its
// target, while %TEMP% may be short (C:\Users\RUNNER~1 on CI runners).
func longPath(t *testing.T, p string) string {
	t.Helper()
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || int(n) >= len(buf) {
		t.Fatalf("long path of %s: %v", p, err)
	}
	return windows.UTF16ToString(buf[:n])
}

// readShortcut returns a shortcut's target and working folder.
func readShortcut(t *testing.T, lnk string) (target, dir string) {
	t.Helper()
	err := inSTA(func() error {
		unk, err := oleutil.CreateObject("WScript.Shell")
		if err != nil {
			return err
		}
		defer unk.Release()
		shell, err := unk.QueryInterface(ole.IID_IDispatch)
		if err != nil {
			return err
		}
		defer shell.Release()
		v, err := oleutil.CallMethod(shell, "CreateShortcut", lnk)
		if err != nil {
			return err
		}
		sc := v.ToIDispatch()
		defer sc.Release()
		tv, err := oleutil.GetProperty(sc, "TargetPath")
		if err != nil {
			return err
		}
		dv, err := oleutil.GetProperty(sc, "WorkingDirectory")
		if err != nil {
			return err
		}
		target, dir = tv.ToString(), dv.ToString()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return target, dir
}

// Paths are data, never script: quotes of any kind in them end up in the
// shortcut as they are.
func TestCreateShortcut(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "Program ‘Files’ 'x'", "HyRoute.exe")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	lnk := filepath.Join(root, "HyRoute ‘a’;$x.lnk")
	if err := createShortcut(lnk, exe); err != nil {
		t.Fatal(err)
	}
	target, dir := readShortcut(t, lnk)
	if !strings.EqualFold(longPath(t, target), longPath(t, exe)) || !strings.EqualFold(longPath(t, dir), longPath(t, filepath.Dir(exe))) {
		t.Fatalf("shortcut: target %q in %q, want %q", target, dir, exe)
	}
}

// The Program Files check follows Windows' own folders. (Common Files: a
// folder that exists, which an elevated run with a split token checks the
// permissions of.)
func TestProtectedLocation(t *testing.T) {
	pf := programFiles()
	if len(pf) == 0 {
		t.Fatal("Program Files not found")
	}
	if !protectedLocation(filepath.Join(pf[0], "Common Files")) || !strings.HasPrefix(moveTarget(), pf[0]) {
		t.Fatalf("Program Files %q: a folder there not protected, or move target %q", pf, moveTarget())
	}
	if protectedLocation(t.TempDir()) || protectedLocation(pf[0]+`X\HyRoute`) {
		t.Fatal("a folder outside Program Files counts as protected")
	}
	t.Setenv("ProgramFiles", t.TempDir())
	t.Setenv("ProgramW6432", os.Getenv("ProgramFiles"))
	if protectedLocation(os.Getenv("ProgramFiles")) {
		t.Fatal("the ProgramFiles variable decides what is protected")
	}
}

// userToken is this test's own token in the form GetLinkedToken gives an
// elevated HyRoute (an identification-level impersonation token).
func userToken(t *testing.T) windows.Token {
	var tok, dup windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()
	if err := windows.DuplicateTokenEx(tok, windows.TOKEN_QUERY, nil, windows.SecurityIdentification, windows.TokenImpersonation, &dup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dup.Close() })
	return dup
}

// A folder in Program Files that the user's own programs can write to is
// not protected: through the program folder (a DLL next to the exe), the
// exe itself, or a folder above (the program folder renamed away).
func TestUserCanReplace(t *testing.T) {
	// Access for the owner (this test) only, through OWNER RIGHTS so the
	// owner's implicit right to change the permissions is gone too. Read
	// and delete are left for the cleanup; delete alone replaces nothing.
	// owned: the same for everyone, with the owner's implicit right kept.
	const (
		modify = "D:P(A;OICI;0x1301bf;;;OW)"
		closed = "D:P(A;OICI;0x1300a9;;;OW)"
		owned  = "D:P(A;OICI;0x1300a9;;;WD)"
	)
	setDACL := func(path, sddl string) {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, _ := sd.DACL()
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	user := userToken(t)
	for _, c := range []struct {
		name           string
		root, dir, exe string
		want           bool
	}{
		{"all closed", closed, closed, closed, false},
		{"files can be added to the program folder", closed, modify, closed, true},
		{"the exe can be written", closed, closed, modify, true},
		{"folders can be added above", modify, closed, closed, true},
		{"the user owns the program folder", closed, owned, closed, true},
	} {
		// root stands for Program Files.
		root := filepath.Join(t.TempDir(), "Program Files")
		dir := filepath.Join(root, "HyRoute")
		exe := filepath.Join(dir, "HyRoute.exe")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(exe, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		// Children first: each keeps a protected DACL of its own.
		setDACL(exe, c.exe)
		setDACL(dir, c.dir)
		setDACL(root, c.root)
		if got := userCanReplace(dir, root, exe, user); got != c.want {
			t.Errorf("%s: user can replace = %v, want %v", c.name, got, c.want)
		}
	}
	if !userCanReplace(filepath.Join(t.TempDir(), "missing"), t.TempDir(), "", user) {
		t.Error("a folder whose permissions cannot be read counts as closed")
	}
}

// A file already in the target folder is replaced by a new one, which
// takes the folder's permissions: written over, it would keep its own
// (here: open to everyone, set on it alone).
func TestCopyProgramTakesFolderPermissions(t *testing.T) {
	src, target := t.TempDir(), t.TempDir()
	self := filepath.Join(src, "HyRoute (1).exe")
	for _, name := range append(programFilesList, filepath.Base(self)) {
		if name == "LICENSE.txt" || name == "HyRoute.exe" {
			continue // optional, and the running file is self
		}
		if err := os.WriteFile(filepath.Join(src, name), []byte("new "+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(target, "HyRoute.exe")
	if err := os.WriteFile(old, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(old, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := copyProgram(src, self, target); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(old); string(b) != "new HyRoute (1).exe" {
		t.Fatalf("HyRoute.exe holds %q, want the running file", b)
	}
	got, err := windows.GetNamedSecurityInfo(old, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if ctl, _, err := got.Control(); err != nil || ctl&windows.SE_DACL_PROTECTED != 0 {
		t.Fatalf("HyRoute.exe kept permissions of its own: %v (%v)", got, err)
	}
	if _, err := os.Stat(filepath.Join(target, "LICENSE.txt")); err == nil {
		t.Fatal("a file the program folder lacks appeared")
	}
}
