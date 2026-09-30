//go:build windows

package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProtectDir makes dir and its parent HyRoute's own: owned by
// Administrators, with a protected DACL (SYSTEM and Administrators full
// control, Users read and execute). HyRoute runs elevated and starts
// executables from here, so a normal (non-elevated) process must not be
// able to change them; an owner keeps WRITE_DAC whatever the DACL says,
// hence the owner.
//
// One rule, so HyRoute always starts: a folder HyRoute did not make (a
// normal program made it first, or takeown gave it to the user) is never
// used: it is moved aside as <name>.untrusted-<time> (see MovedAside) and
// made anew. Moving, unlike deleting, does not walk into it, so links
// inside cannot lead the elevated process elsewhere. When Windows refuses
// Administrators as the owner, HyRoute sets it with the restore privilege,
// as icacls /setowner does.
//
// A new directory gets the DACL as it is created: set afterwards, it
// would leave a moment in which the DACL inherited from C:\ProgramData
// (Users may create subfolders and own what they create) lets a normal
// process create HyRoute\core or HyRoute\updates of its own first.
func ProtectDir(dir string) error {
	elevated := windows.GetCurrentProcessToken().IsElevated()
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	if elevated {
		// Only an elevated token may make Administrators the owner
		// (tests run without elevation and keep their own).
		sddl = "O:BA" + sddl
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var owner *windows.SID
	if elevated {
		if owner, _, err = sd.Owner(); err != nil {
			return err
		}
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	// The folders above (C:\ProgramData) are Windows' own.
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(dir)), 0o755); err != nil {
		return err
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		if err := own(d, sd, elevated); err != nil {
			return err
		}
		err := privileged(func() error {
			return windows.SetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
		})
		if err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
	}
	return nil
}

// own makes sure d is a folder HyRoute made: it creates d, and moves one
// that someone else made out of the way first.
func own(d string, sd *windows.SECURITY_DESCRIPTOR, elevated bool) error {
	created, err := mkdir(d, sd)
	if err != nil || created || !elevated || checkOwner(d) == nil {
		return err
	}
	aside, err := moveAside(d)
	if err != nil {
		return fmt.Errorf("папку %s создала другая программа, и HyRoute не может её переименовать (%w). "+
			"Удалите её в командной строке от имени администратора: rmdir /s /q \"%s\" — серверы и настройки лежат в %%APPDATA%%\\HyRoute и не пропадут", d, err, d)
	}
	movedMu.Lock()
	moved = append(moved, aside)
	movedMu.Unlock()
	if created, err = mkdir(d, sd); err == nil && !created {
		err = fmt.Errorf("%s: папку снова создала другая программа", d)
	}
	return err
}

// mkdir creates d with sd and reports whether it did; a folder already
// there is kept.
func mkdir(d string, sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	p, err := windows.UTF16PtrFromString(d)
	if err != nil {
		return false, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	err = privileged(func() error { return windows.CreateDirectory(p, sa) })
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if fi, serr := os.Stat(d); serr != nil || !fi.IsDir() {
			return false, fmt.Errorf("%s: не папка", d)
		}
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", d, err)
	}
	return true, nil
}

var (
	movedMu sync.Mutex
	moved   []string
)

// MovedAside lists the folders ProtectDir moved aside (for the log).
func MovedAside() []string {
	movedMu.Lock()
	defer movedMu.Unlock()
	return append([]string(nil), moved...)
}

// moveAside renames d to d.untrusted-<time> (a link is renamed itself,
// not what it leads to) and returns the new name.
func moveAside(d string) (string, error) {
	to := d + ".untrusted-" + time.Now().Format("20060102-150405")
	from, err := windows.UTF16PtrFromString(d)
	if err != nil {
		return "", err
	}
	top, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return "", err
	}
	if err := windows.MoveFileEx(from, top, 0); err != nil {
		return "", err
	}
	return to, nil
}

// privileged runs fn, and once more with the restore privilege when
// Windows refused the owner (ERROR_INVALID_OWNER: the elevated token does
// not mark Administrators as a group that may own objects). Administrators
// hold the privilege, disabled; it is put back as it was.
func privileged(fn func() error) error {
	err := fn()
	if !errors.Is(err, windows.ERROR_INVALID_OWNER) {
		return err
	}
	name, perr := windows.UTF16PtrFromString("SeRestorePrivilege")
	if perr != nil {
		return err
	}
	var luid windows.LUID
	if windows.LookupPrivilegeValue(nil, name, &luid) != nil {
		return err
	}
	var t windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &t) != nil {
		return err
	}
	defer t.Close()
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	var prev windows.Tokenprivileges
	var n uint32
	if windows.AdjustTokenPrivileges(t, false, &tp, uint32(unsafe.Sizeof(prev)), &prev, &n) != nil {
		return err
	}
	// prev lists the privilege only if this call enabled it.
	defer windows.AdjustTokenPrivileges(t, false, &prev, 0, nil, nil)
	return fn()
}

// CheckOwner refuses a file or folder that a process without elevation
// may have created (e.g. %ProgramData%\HyRoute before HyRoute first ran)
// and whose owner may therefore still change it.
func CheckOwner(path string) error { return checkOwner(path) }

// checkOwner accepts SYSTEM, Administrators and TrustedInstaller as the
// owner. What an elevated process creates belongs to Administrators; with
// a split UAC token the user's own SID is what the same user's
// non-elevated programs create, so it is accepted only when the token is
// not split (UAC off, the built-in Administrator, or not elevated at all,
// as in tests), where no process of the user has less rights than this one.
func checkOwner(d string) error {
	sd, err := windows.GetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	for _, t := range []windows.WELL_KNOWN_SID_TYPE{windows.WinBuiltinAdministratorsSid, windows.WinLocalSystemSid} {
		if s, err := windows.CreateWellKnownSid(t); err == nil && owner.Equals(s) {
			return nil
		}
	}
	if ti, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"); err == nil && owner.Equals(ti) {
		return nil
	}
	if !splitToken() {
		if tu, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && owner.Equals(tu.User.Sid) {
			return nil
		}
	}
	return fmt.Errorf("папка или файл %s созданы не администратором (владелец %s)", d, owner.String())
}

// splitToken reports whether this process runs elevated over a split UAC
// token (the user's other programs then run with the limited half).
func splitToken() bool {
	var typ, n uint32
	if err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenElevationType, (*byte)(unsafe.Pointer(&typ)), 4, &n); err != nil {
		return true // unknown: the strict answer
	}
	const tokenElevationTypeFull = 2
	return typ == tokenElevationTypeFull
}

// DefaultDir is %ProgramData%\HyRoute\<sub>. The folder comes from
// Windows, not from the ProgramData variable: the user's own variables
// (HKCU\Environment) reach this elevated process too.
func DefaultDir(sub string) string {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "HyRoute", sub)
}
