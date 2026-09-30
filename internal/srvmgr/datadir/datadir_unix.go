//go:build !windows

package datadir

import (
	"fmt"
	"io/fs"
	"os"
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
