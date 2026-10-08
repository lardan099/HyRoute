//go:build !windows

package datadir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

func protect(path string, st fs.FileInfo, dir bool) error {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		if uid := os.Geteuid(); int(sys.Uid) != uid {
			return fmt.Errorf("%s belongs to uid %d, but the controller runs as uid %d: give it to the controller's user (chown -R <user> %s) or run the controller as its owner", path, sys.Uid, uid, path)
		}
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		want, mode := "600", "file"
		if dir {
			want, mode = "700", "directory"
		}
		return fmt.Errorf("%s is readable by others (mode %04o): the %s holds secrets, run chmod %s %s", path, perm, mode, want, path)
	}
	return nil
}

func lock(f *os.File) error {
	err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return ErrLocked
	}
	return err
}

func check(path string, st fs.FileInfo, dir bool) error { return protect(path, st, dir) }

func create(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func replace(tmp, path string) error {
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// SyncDir makes the entries of dir (a file created or renamed in it)
// last a crash.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
