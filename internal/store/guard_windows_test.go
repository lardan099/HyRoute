//go:build windows

package store

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

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

func closeHandles(h handles) {
	if h.lock != 0 {
		windows.CloseHandle(h.lock)
	}
	if h.dir != 0 {
		windows.CloseHandle(h.dir)
	}
}

// TestHoldOrdinaryFolder: the user's own folder is accepted and, while
// held, cannot be renamed; files in it are saved, replaced and removed
// as usual.
func TestHoldOrdinaryFolder(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "HyRoute")
	os.Mkdir(dir, 0o700)
	h, err := hold(dir, userToken(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandles(h)
	if err := os.Rename(dir, filepath.Join(base, "other")); err == nil {
		t.Fatal("held folder renamed")
	}
	s := &Store{Dir: dir}
	for range 2 {
		if err := s.SavePrefs(Prefs{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "prefs.json")); err != nil {
		t.Fatal(err)
	}
}

// TestHoldRefusesReadOnlyFolder: a folder the user cannot write to is not
// used by an elevated HyRoute.
func TestHoldRefusesReadOnlyFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ro")
	os.Mkdir(dir, 0o700)
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := tu.User.Sid.String()
	setDACL := func(sddl string) {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, _ := sd.DACL()
		if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	setDACL("D:P(A;OICI;0x1200a9;;;" + sid + ")") // read and list only
	t.Cleanup(func() { setDACL("D:P(A;OICI;FA;;;" + sid + ")") })
	h, err := hold(dir, userToken(t))
	if err == nil {
		closeHandles(h)
		t.Fatal("read-only folder accepted")
	}
	if !strings.Contains(err.Error(), "нельзя писать") {
		t.Fatal(err)
	}
}

// TestGuardedFolderRefusesReparse: the lock file keeps an empty guarded
// folder from being turned into a mount point (which would redirect
// HyRoute's writes). The control shows the attempt succeeds on an
// unguarded empty folder, so the refusal is the lock file's doing.
func TestGuardedFolderRefusesReparse(t *testing.T) {
	target := t.TempDir()

	plain := filepath.Join(t.TempDir(), "plain")
	os.Mkdir(plain, 0o700)
	if err := setMountPoint(plain, target); err != nil {
		t.Fatalf("control: an empty unguarded folder should accept a mount point: %v", err)
	}
	os.Remove(plain) // an empty junction dir removes cleanly

	dir := filepath.Join(t.TempDir(), "guarded")
	os.Mkdir(dir, 0o700)
	h, err := hold(dir, userToken(t))
	if err != nil {
		t.Fatal(err)
	}
	defer closeHandles(h)
	// The lock file itself must stay: an emptied folder would take the
	// mount point.
	lock := filepath.Join(dir, lockName)
	if err := os.Remove(lock); err == nil {
		t.Fatal("lock file removed while held")
	}
	if err := os.Rename(lock, filepath.Join(target, "moved")); err == nil {
		t.Fatal("lock file moved while held")
	}
	err = setMountPoint(dir, target)
	if err == nil {
		t.Fatal("guarded folder turned into a mount point")
	}
	if err != windows.ERROR_DIR_NOT_EMPTY {
		t.Fatalf("want ERROR_DIR_NOT_EMPTY, got %v", err)
	}
}

// setMountPoint makes dir a mount point to target (like an attacker's
// junction). It needs no administrator rights.
func setMountPoint(dir, target string) error {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.FILE_WRITE_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	sub := utf16.Encode([]rune(`\??\` + target))
	path := append(append([]uint16{}, sub...), 0, 0) // SubstituteName\0 PrintName(empty)\0
	subLen := uint16(len(sub) * 2)
	var buf []byte
	put16 := func(v uint16) { buf = binary.LittleEndian.AppendUint16(buf, v) }
	buf = binary.LittleEndian.AppendUint32(buf, 0xA0000003) // IO_REPARSE_TAG_MOUNT_POINT
	put16(uint16(8 + len(path)*2))                          // ReparseDataLength
	put16(0)                                                // Reserved
	put16(0)                                                // SubstituteNameOffset
	put16(subLen)                                           // SubstituteNameLength
	put16(subLen + 2)                                       // PrintNameOffset
	put16(0)                                                // PrintNameLength
	for _, c := range path {
		put16(c)
	}
	const fsctlSetReparsePoint = 0x900A4
	var ret uint32
	return windows.DeviceIoControl(h, fsctlSetReparsePoint, &buf[0], uint32(len(buf)), nil, 0, &ret, nil)
}

// TestGuardNotElevated: tests are not elevated, so Guard only creates the
// folder and holds nothing (the folder can be removed afterwards).
func TestGuardNotElevated(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("elevated")
	}
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := Guard(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { release(dir) })
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
}

// TestHoldRefusesLinkedAncestor: a folder reached through a junction
// higher up (APPDATA pointed into a junction the user can retarget) is
// refused; the same folder by its real path is accepted.
func TestHoldRefusesLinkedAncestor(t *testing.T) {
	target := t.TempDir()
	real := filepath.Join(target, "HyRoute")
	os.Mkdir(real, 0o700)
	j := filepath.Join(t.TempDir(), "j")
	os.Mkdir(j, 0o700)
	if err := setMountPoint(j, target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(j) })
	if h, err := hold(filepath.Join(j, "HyRoute"), userToken(t)); err == nil {
		closeHandles(h)
		t.Fatal("folder behind a junction accepted")
	}
	h, err := hold(real, userToken(t))
	if err != nil {
		t.Fatal(err)
	}
	closeHandles(h)
}

// appDataDir resolves links and ignores the APPDATA variable.
func TestAppDataDirIgnoresEnv(t *testing.T) {
	t.Setenv("APPDATA", t.TempDir())
	d, err := appDataDir()
	if err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(d, os.Getenv("APPDATA")) {
		t.Fatalf("appDataDir = %s, the APPDATA variable", d)
	}
}
