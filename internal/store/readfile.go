package store

import (
	"errors"
	"io"
	"os"
)

// The data folder is writable by every program of the user, and HyRoute
// reads it elevated: a data file that is a link (symbolic or hard), a
// junction or a folder could make it read a file the user cannot, so such
// a file is refused rather than followed. Every new loader reads through
// readRegular.
var (
	// ErrNotRegular: the name is a link, a junction or a folder.
	ErrNotRegular = errors.New("не обычный файл (ссылка или папка), не читаем")
	// ErrTooLarge: the file is larger than its loader accepts.
	ErrTooLarge = errors.New("файл слишком большой")
)

// readRegular reads the data file name in s.Dir (see readDataFile) under
// s.mu. A missing file is an error satisfying errors.Is(err,
// os.ErrNotExist).
func (s *Store) readRegular(name string, max int64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return readDataFile(s.path(name), max)
}

// readBounded reads f to the end, at most max bytes.
func readBounded(f *os.File, path string, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, &os.PathError{Op: "read", Path: path, Err: err}
	}
	if int64(len(b)) > max {
		return nil, &os.PathError{Op: "read", Path: path, Err: ErrTooLarge}
	}
	return b, nil
}
