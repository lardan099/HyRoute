//go:build windows

package store

import (
	"os"

	"golang.org/x/sys/windows"
)

// readDataFile reads path, at most max bytes (more: ErrTooLarge). The name
// itself is opened, never what it points to, and the handle must be a
// plain file with one name: a reparse point (symbolic link, junction), a
// folder or a hard link is ErrNotRegular. The content is read from that
// same handle, so the file cannot be swapped between the check and the
// read.
func readDataFile(path string, max int64) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	// BACKUP_SEMANTICS opens a folder too, so it is refused below rather
	// than failing with "access denied".
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if fi.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || fi.NumberOfLinks != 1 {
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	return readBounded(f, path, max)
}
