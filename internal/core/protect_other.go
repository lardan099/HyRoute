//go:build !windows

package core

import "os"

// ProtectDir creates dir (permissions only matter on Windows).
func ProtectDir(dir string) error { return os.MkdirAll(dir, 0o755) }

// CheckOwner accepts everything (ownership only matters on Windows).
func CheckOwner(string) error { return nil }

// DefaultDir is a directory under the user config dir (tests, non-Windows).
func DefaultDir(sub string) string {
	d, _ := os.UserConfigDir()
	return d + "/HyRoute/" + sub
}
