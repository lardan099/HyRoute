//go:build !linux && !windows

package datadir

import "errors"

// FreeSpace is not known on this OS.
func FreeSpace(path string) (uint64, error) {
	return 0, errors.ErrUnsupported
}
