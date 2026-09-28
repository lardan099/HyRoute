//go:build windows

package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProtectDir creates dir and its parent with a protected DACL: SYSTEM and
// Administrators full control, Users read and execute. HyRoute runs
// elevated and starts executables from here, so a normal (non-elevated)
// process must not be able to replace them. A directory a non-elevated
// process may have created in advance is refused (see checkOwner), and
// an accepted one is given to Administrators: an owner keeps WRITE_DAC
// whatever the DACL says.
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
			// Already there: it must be a directory, made by the right owner.
			if err := os.MkdirAll(d, 0o755); err != nil {
				return err
			}
		}
		if err := checkOwner(d); err != nil {
			return err
		}
		if err := windows.SetNamedSecurityInfo(d, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil); err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
	}
	return nil
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
	return fmt.Errorf("папка или файл %s созданы не администратором (владелец %s): удалите и повторите", d, owner.String())
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
