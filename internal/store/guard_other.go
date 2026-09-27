//go:build !windows

package store

import "os"

// Guard creates dir (the checks for an elevated HyRoute are Windows-only).
func Guard(dir string) error { return os.MkdirAll(dir, 0o700) }

// appDataDir is the user config dir.
func appDataDir() (string, error) { return os.UserConfigDir() }
