//go:build !windows

package logx

import "os"

// OpenAppend opens path for appending, creating it if needed (the link
// checks are Windows-only: HyRoute runs there).
func OpenAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

// Truncate empties the log file at path.
func Truncate(path string) error { return os.Truncate(path, 0) }
