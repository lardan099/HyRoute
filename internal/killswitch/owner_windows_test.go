//go:build windows

package killswitch

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// Any program may create an object under the owner's name in Global\:
// only one an elevated process made (another HyRoute's) keeps this one
// from owning the filters; another program's must not turn the kill
// switch off.
func TestClaimOwner(t *testing.T) {
	defer func(n string) { disown(); ownerName = n }(ownerName)
	disown()
	ownerName = fmt.Sprintf(`Global\HyRoute-kill-switch-test-%d`, os.Getpid())
	n, err := windows.UTF16PtrFromString(ownerName)
	if err != nil {
		t.Fatal(err)
	}

	h, err := windows.CreateMutex(nil, false, n)
	if err != nil {
		t.Fatal(err)
	}
	// Elevated, the object is owned by Administrators, as another
	// HyRoute's; otherwise by the user, as an ordinary program's.
	if windows.GetCurrentProcessToken().IsElevated() {
		if err := claim(); !errors.Is(err, errNotOwner) {
			t.Fatalf("an elevated process's object: %v", err)
		}
	} else if err := claim(); err != nil || owner.h != 0 {
		t.Fatalf("an ordinary program's object: %v, owner %v", err, owner.h)
	}
	windows.CloseHandle(h)

	// An object of another type under the name.
	ev, err := windows.CreateEvent(nil, 0, 0, n)
	if err != nil {
		t.Fatal(err)
	}
	if err := claim(); err != nil || owner.h != 0 {
		t.Fatalf("an event under the name: %v, owner %v", err, owner.h)
	}
	windows.CloseHandle(ev)

	// Free: this process owns the filters until it gives them up. The
	// object is Administrators' whatever the default owner policy says
	// (not elevated, the default owner).
	if err := claim(); err != nil || owner.h == 0 {
		t.Fatalf("free name: %v", err)
	}
	if windows.GetCurrentProcessToken().IsElevated() && !elevated(owner.h) {
		t.Fatal("the owner's object is not Administrators'")
	}
	disown()
	if owner.h != 0 {
		t.Fatal("still the owner after disown")
	}
	if o, err := windows.OpenMutex(windows.SYNCHRONIZE, false, n); err == nil {
		windows.CloseHandle(o)
		t.Fatal("the name outlives disown")
	}
}
