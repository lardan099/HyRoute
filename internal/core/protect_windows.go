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

// ProtectDir creates dir and its parent with a protected DACL: SYSTEM and
// Administrators full control, Users read and execute. HyRoute runs
// elevated and starts executables from here, so a normal (non-elevated)
// process must not be able to replace them. A directory someone other
// than administrators owns (a non-elevated process may have created it in
// advance, or takeown gave it to the user) is never used (see checkOwner):
// an elevated HyRoute moves it aside as <name>.untrusted-<time> and makes
// a new one, and refuses with an OwnerError when it cannot. An accepted
// one is given to Administrators: an owner keeps WRITE_DAC whatever the
// DACL says.
//
// A new directory gets that DACL as it is created: set afterwards, it
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
		if err := createProtected(d, sd); err != nil {
			return err
		}
		err := checkOwner(d)
		var oe *OwnerError
		if errors.As(err, &oe) && elevated {
			// Made or taken over by an account that is not an
			// administrator (a normal process, or takeown in a console):
			// HyRoute never uses what is inside. It is moved aside and
			// made anew; what it held (copies of hysteria.exe and
			// WinDivert, downloaded updates, the window's cache) is
			// downloaded or made again.
			aside, merr := moveAside(d)
			if merr != nil {
				oe.MoveErr = merr
				return oe
			}
			if err = createProtected(d, sd); err == nil {
				err = checkOwner(d)
			}
			if err == nil {
				movedMu.Lock()
				moved = append(moved, aside)
				movedMu.Unlock()
			}
		}
		if err != nil {
			return err
		}
		if err := windows.SetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil); err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
	}
	return nil
}

// createProtected creates d with sd; a folder already there is kept.
func createProtected(d string, sd *windows.SECURITY_DESCRIPTOR) error {
	p, err := windows.UTF16PtrFromString(d)
	if err != nil {
		return err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	if err := windows.CreateDirectory(p, sa); err != nil {
		if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return fmt.Errorf("%s: %w", d, err)
		}
		// Already there: it must be a directory.
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

var (
	movedMu sync.Mutex
	moved   []string
)

// MovedAside lists the folders ProtectDir found owned by someone other
// than administrators and moved aside (for the log).
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

// OwnerError: a folder or file of HyRoute's that is not owned by SYSTEM,
// Administrators or TrustedInstaller.
type OwnerError struct {
	Path  string
	Owner string // DOMAIN\name, or the SID
	// MoveErr: why ProtectDir could not move the folder aside.
	MoveErr error
}

func (e *OwnerError) Error() string {
	msg := fmt.Sprintf("Папка %s принадлежит %s, а не администраторам: её мог создать или забрать себе обычный процесс, и HyRoute не запускает программы оттуда.", e.Path, e.Owner)
	if e.MoveErr != nil {
		msg += fmt.Sprintf(" Переименовать её не удалось (%v).", e.MoveErr)
	}
	return msg + " Закройте HyRoute и удалите эту папку в командной строке от имени администратора: rmdir /s /q \"" + e.Path +
		"\". Серверы и настройки хранятся в %APPDATA%\\HyRoute и не пропадут, а папку HyRoute создаст заново."
}

func accountName(sid *windows.SID) string {
	if acc, dom, _, err := sid.LookupAccount(""); err == nil && acc != "" {
		if dom != "" {
			return dom + `\` + acc
		}
		return acc
	}
	return sid.String()
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
	return &OwnerError{Path: d, Owner: accountName(owner)}
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
