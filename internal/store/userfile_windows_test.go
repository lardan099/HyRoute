//go:build windows

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func ownerOf(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	o, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	return o.String()
}

func TestWriteUserFileWindows(t *testing.T) {
	dir := t.TempDir()
	user := userToken(t)
	p := filepath.Join(dir, "a.hyroute-backup")
	for _, s := range []string{"one", "two"} {
		if err := writeUserFile(p, []byte(s), user); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(p); string(b) != s {
			t.Fatal(string(b))
		}
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if got := ownerOf(t, p); got != tu.User.Sid.String() {
		t.Fatalf("owner %s, want %s", got, tu.User.Sid)
	}
	// A hard link at the target: replaced, the pointee keeps its bytes.
	pointee := filepath.Join(dir, "pointee")
	os.WriteFile(pointee, []byte("keep"), 0o600)
	hard := filepath.Join(dir, "hard.hyroute-backup")
	if err := os.Link(pointee, hard); err != nil {
		t.Fatal(err)
	}
	if err := writeUserFile(hard, []byte("new"), user); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(pointee); string(b) != "keep" {
		t.Fatal("hard link pointee written")
	}
	// A symbolic link (Developer Mode only).
	link := filepath.Join(dir, "sym.hyroute-backup")
	if os.Symlink(pointee, link) == nil {
		if err := writeUserFile(link, []byte("new"), user); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(pointee); string(b) != "keep" {
			t.Fatal("symlink pointee written")
		}
	}
	// A mount point at the target: refused as a folder (nothing renames over
	// it); nothing appears in the pointee.
	target := t.TempDir()
	mp := filepath.Join(dir, "mp.hyroute-backup")
	os.Mkdir(mp, 0o700)
	if err := setMountPoint(mp, target); err != nil {
		t.Fatal(err)
	}
	if err := writeUserFile(mp, []byte("x"), user); err == nil || !strings.Contains(err.Error(), "это папка") {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatal("wrote through the mount point")
	}
	os.Mkdir(filepath.Join(dir, "d.hyroute-backup"), 0o700)
	if err := writeUserFile(filepath.Join(dir, "d.hyroute-backup"), nil, user); err == nil || !strings.Contains(err.Error(), "это папка") {
		t.Fatal(err)
	}
	ro := filepath.Join(dir, "ro.hyroute-backup")
	os.WriteFile(ro, []byte("keep"), 0o400) // FILE_ATTRIBUTE_READONLY
	if err := writeUserFile(ro, []byte("x"), user); err == nil || !strings.Contains(err.Error(), "только для чтения") {
		t.Fatal(err)
	}
	os.Chmod(ro, 0o600)
	long := strings.Repeat("д", 240) + ".hyroute-backup" // near MAX_PATH component: the temp name still fits
	if err := writeUserFile(filepath.Join(dir, long), []byte("x"), user); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"x.hyroute-backup:s", "CON.hyroute-backup"} {
		if err := writeUserFile(filepath.Join(dir, n), nil, user); err == nil || !strings.Contains(err.Error(), "Недопустимое имя") {
			t.Fatal(n, err)
		}
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatal("temp left", e.Name())
		}
	}
}

func setDACLOf(t *testing.T, path, sddl string) {
	t.Helper()
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

func TestUserFileAccessChecks(t *testing.T) {
	user := userToken(t)
	tu, _ := windows.GetCurrentProcessToken().GetTokenUser()
	sid := tu.User.Sid.String()
	full := "D:P(A;OICI;FA;;;" + sid + ")"

	// A folder the user may only read and list.
	ro := filepath.Join(t.TempDir(), "ro")
	os.Mkdir(ro, 0o700)
	setDACLOf(t, ro, "D:P(A;OICI;0x1200a9;;;"+sid+")")
	t.Cleanup(func() { setDACLOf(t, ro, full) })
	if err := writeUserFile(filepath.Join(ro, "x.hyroute-backup"), []byte("x"), user); err == nil || !strings.Contains(err.Error(), "нельзя записать без прав администратора") {
		t.Fatal(err)
	}

	// An existing file the user may not delete, in a folder without
	// FILE_DELETE_CHILD for them: not replaced. With it: replaced.
	for _, grantChild := range []bool{false, true} {
		d := filepath.Join(t.TempDir(), "f")
		os.Mkdir(d, 0o700)
		f := filepath.Join(d, "x.hyroute-backup")
		os.WriteFile(f, []byte("old"), 0o600)
		// Modify (no delete child) or full control on the folder; the file
		// grants read/write but not DELETE.
		folder := "D:P(A;;0x1301bf;;;" + sid + ")"
		if grantChild {
			folder = "D:P(A;;FA;;;" + sid + ")"
		}
		setDACLOf(t, f, "D:P(A;;0x12019f;;;"+sid+")")
		setDACLOf(t, d, folder)
		t.Cleanup(func() { setDACLOf(t, d, full); setDACLOf(t, f, full) })
		err := writeUserFile(f, []byte("new"), user)
		if grantChild {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "нельзя перезаписать") {
			t.Fatal(err)
		}
	}

	// Reading a file the user may not read.
	d := t.TempDir()
	f := filepath.Join(d, "secret")
	os.WriteFile(f, []byte("x"), 0o600)
	setDACLOf(t, f, "D:P(A;;0x120080;;;"+sid+")(A;;FA;;;BA)(A;;FA;;;SY)") // read attributes and control only
	t.Cleanup(func() { setDACLOf(t, f, full) })
	if _, err := readUserFile(f, 10, user); err == nil || !strings.Contains(err.Error(), "Нет доступа") {
		t.Fatal(err)
	}
}

func TestReadUserFileWindows(t *testing.T) {
	user := userToken(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "a")
	os.WriteFile(p, []byte("12345"), 0o600)
	// Another program holds it open for writing: still readable.
	h, err := os.OpenFile(p, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if b, err := readUserFile(p, 5, user); err != nil || string(b) != "12345" {
		t.Fatal(err)
	}
	if _, err := readUserFile(p, 4, user); !errors.Is(err, ErrUserFileTooLarge) {
		t.Fatal(err)
	}
	if _, err := readUserFile(dir, 10, user); err == nil {
		t.Fatal("directory")
	}
}

// TestUserFileLoopbackRefused: a share of this computer is refused, and
// nothing is written through it. Client side only.
func TestUserFileLoopbackRefused(t *testing.T) {
	dir := t.TempDir()
	vol := filepath.VolumeName(dir)
	if len(vol) != 2 {
		t.Skip("not on a drive letter")
	}
	rest := dir[len(vol):]
	buf := make([]uint16, 256)
	n := uint32(len(buf))
	name := "localhost"
	if windows.GetComputerNameEx(0, &buf[0], &n) == nil {
		name = windows.UTF16ToString(buf[:n])
	}
	for _, host := range []string{"localhost", "127.0.0.1", name} {
		p := `\\` + host + `\` + vol[:1] + `$` + rest + `\x.hyroute-backup`
		err := WriteUserFile(p, []byte("x"))
		if err == nil {
			t.Fatalf("%s written", p)
		}
		if errors.Is(err, windows.ERROR_BAD_NETPATH) {
			t.Skip("Server service not running")
		}
		if _, err := ReadUserFile(p, 10); err == nil {
			t.Fatalf("%s read", p)
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatal("a file appeared")
	}
	// The volume-serial rule: a local handle taken for a remote one is
	// refused because its serial is a local volume's.
	saved := isRemote
	isRemote = func(windows.Handle) bool { return true }
	defer func() { isRemote = saved }()
	if err := WriteUserFile(filepath.Join(dir, "y.hyroute-backup"), []byte("x")); err == nil || !strings.Contains(err.Error(), "общая папка этого компьютера") {
		t.Fatal(err)
	}
}
