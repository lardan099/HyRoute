//go:build windows

package geodata

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// errLinked: a file in the databases folder is a link to another file.
var errLinked = errors.New("файл — ссылка на другой файл (символическая или жёсткая), не читаем")

// openRead opens a database for reading. Unlike os.Open it shares delete
// access, so an update or a rollback can rename the file while a rule
// compile or the list inspector reads it (the reader keeps the old
// content) instead of failing halfway with "used by another process".
// HyRoute runs elevated and the folder is writable by every program of
// the user, so a link is refused rather than followed: it could point to
// a file the user cannot read.
func openRead(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if fi.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || fi.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: errLinked}
	}
	return os.NewFile(uintptr(h), path), nil
}
