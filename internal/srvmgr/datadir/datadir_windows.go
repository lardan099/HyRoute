package datadir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protect replaces the ACL with full control for SYSTEM, Administrators
// and the current user, not inherited from the parent (the directory's
// entries are inherited by what is created in it).
func protect(path string, _ fs.FileInfo, dir bool) error {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	inherit := ""
	if dir {
		inherit = "OICI"
	}
	me := tu.User.Sid.String()
	sddl := fmt.Sprintf("D:P(A;%[1]s;FA;;;SY)(A;%[1]s;FA;;;BA)(A;%[1]s;FA;;;%[2]s)", inherit, me)
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("%s: set access to SYSTEM, Administrators and the current user: %w", path, err)
	}
	return nil
}

func lock(f *os.File) error {
	err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrLocked
	}
	return err
}

// check reads the ACL of path, inherited entries included: it may allow
// only SYSTEM, Administrators and the current user. A file in the data
// directory inherits the directory's entries, which Dir narrowed.
func check(path string, _ fs.FileInfo, _ bool) error {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return fmt.Errorf("%s has no access list: everyone may open it", path)
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return err
		}
		// Entries only for what is created inside (CREATOR OWNER of a
		// parent, say) do not open the object itself.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.Equals(tu.User.Sid) {
			continue
		}
		who := sid.String()
		if account, domain, _, err := sid.LookupAccount(""); err == nil {
			who = domain + `\` + account
		}
		return fmt.Errorf("%s is open to %s: only SYSTEM, Administrators and the controller's user may reach it", path, who)
	}
	return nil
}
