//go:build windows

package ctl

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The run event tells hyroutectl that HyRoute runs before its pipe is up:
// present = running, signalled = its command line has settled (listening,
// switched off or failed), absent = not running.

// runRights: SYNCHRONIZE | READ_CONTROL for the users.
const runRights = 0x120000

// CreateRunEvent (HyRoute) creates the manual-reset, non-signalled run
// event. owner nil = BUILTIN\Administrators (production; tests pass the
// current user). An existing event is kept only when its owner is the
// expected one, else ErrNameTaken (HyRoute runs without it).
func CreateRunEvent(name string, users []*windows.SID, owner *windows.SID) (windows.Handle, error) {
	o := "BA"
	want := owner
	if owner != nil {
		o = owner.String()
	} else {
		var err error
		if want, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
			return 0, err
		}
	}
	var b strings.Builder
	b.WriteString("O:" + o + "G:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;RC;;;OW)")
	seen := map[string]bool{}
	for _, u := range users {
		if u != nil && !seen[u.String()] {
			seen[u.String()] = true
			fmt.Fprintf(&b, "(A;;0x%x;;;%s)", runRights, u.String())
		}
	}
	sd, err := windows.SecurityDescriptorFromString(b.String())
	if err != nil {
		return 0, err
	}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateEvent(sa, 1, 0, p)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return 0, ErrNameTaken
		}
		return 0, err
	}
	if err != nil { // it existed: ours only if the owner is
		if got, oerr := handleOwner(h); oerr != nil || !got.Equals(want) {
			windows.CloseHandle(h)
			return 0, ErrNameTaken
		}
	}
	return h, nil
}

// ProbeRunEvent (hyroutectl) reads the run event: absent (or one this user
// may not open: another account's), foreign (not owned by trusted),
// starting or settled.
func ProbeRunEvent(name string, trusted []string) (RunState, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return RunAbsent, err
	}
	h, err := windows.OpenEvent(windows.SYNCHRONIZE|windows.READ_CONTROL, false, p)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return RunAbsent, nil
		}
		return RunAbsent, err
	}
	defer windows.CloseHandle(h)
	if o, err := handleOwner(h); err != nil || !trustedSID(o.String(), trusted) {
		return RunForeign, nil
	}
	if ev, _ := windows.WaitForSingleObject(h, 0); ev == windows.WAIT_OBJECT_0 {
		return RunSettled, nil
	}
	return RunStarting, nil
}
