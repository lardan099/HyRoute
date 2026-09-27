//go:build windows

package geodata

import (
	"os"

	"golang.org/x/sys/windows"
)

// openRead opens a database for reading. Unlike os.Open it shares delete
// access, so an update or a rollback can rename the file while a rule
// compile or the list inspector reads it (the reader keeps the old
// content) instead of failing halfway with "used by another process".
func openRead(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
