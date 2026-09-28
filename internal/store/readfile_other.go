//go:build !windows

package store

import (
	"errors"
	"os"
	"syscall"
)

// readDataFile reads path, at most max bytes (more: ErrTooLarge), without
// following a symbolic link; a link, a folder, a hard link or any other
// non-regular file is ErrNotRegular (the same rules as on Windows).
func readDataFile(path string, max int64) ([]byte, error) {
	// O_NONBLOCK: a FIFO in its place must not hang the open.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, &os.PathError{Op: "open", Path: path, Err: ErrNotRegular}
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || uint64(st.Nlink) != 1 {
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	return readBounded(f, path, max)
}
