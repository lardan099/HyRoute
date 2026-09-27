//go:build windows

package logx

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// errLinked: the log file name is a link to another file.
var errLinked = errors.New("файл журнала — ссылка на другой файл (символическая или жёсткая), в него не пишем")

// OpenAppend opens path for appending, creating it if needed. HyRoute runs
// elevated and its logs lie in a folder any program of the user can write
// to, so the file is opened as is, never through a link: a link under a
// log's name must not make HyRoute append to a file the user cannot write.
func OpenAppend(path string) (*os.File, error) {
	return openLog(path, windows.FILE_APPEND_DATA, windows.OPEN_ALWAYS)
}

// Truncate empties the log file at path, refusing links like OpenAppend.
func Truncate(path string) error {
	f, err := openLog(path, windows.FILE_WRITE_DATA, windows.OPEN_EXISTING)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(0)
}

func openLog(path string, access, disposition uint32) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	// Others may read the file meanwhile but not delete or rename it; the
	// log folder is kept ordinary and non-empty by store.Guard, and
	// HyRoute closes its own handle before rotating or removing a log.
	h, err := windows.CreateFile(p, access|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
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
