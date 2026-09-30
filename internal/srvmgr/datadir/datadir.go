// Package datadir guards the controller's data directory, database and
// master key: only the controller's own user (and on Windows SYSTEM and
// Administrators) may reach them.
//
// On Unix an existing directory or file that others can read, or that
// another user owns, is refused with the command that fixes it: the
// controller does not guess whose files they are. On Windows the
// directory and the files get an ACL for SYSTEM, Administrators and the
// current user only.
package datadir

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// Dir checks (Unix) or protects (Windows) the data directory, which must
// exist.
func Dir(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return protect(path, st, true)
}

// File checks (Unix) or protects (Windows) a file with secrets; a missing
// file is fine (it is created owner-only).
func File(path string) error {
	st, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return protect(path, st, false)
}
