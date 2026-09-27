//go:build !windows

package geodata

import "os"

// openRead opens a database for reading (renaming an open file is always
// allowed outside Windows).
func openRead(path string) (*os.File, error) { return os.Open(path) }
