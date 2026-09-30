package datadir

import (
	"fmt"
	"io/fs"

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
