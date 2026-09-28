package store

import (
	"errors"
	"fmt"
	"os"
)

// RawFile is a data file's bytes as they are on disk (secrets stay sealed
// in the file's own format). Exists is false when there is no such file.
type RawFile struct {
	Exists bool
	Data   []byte
}

// rawFiles are the data files ReadRaw and WriteRaw accept: fixed names,
// never user input. Features register theirs here.
var rawFiles = map[string]bool{
	"subscriptions.json": true,
	"profiles.json":      true,
	"proxies.json":       true,
	"settings.json":      true,
	"prefs.json":         true,
	"rulesets.json":      true, // rulesets
}

// maxRawBytes bounds a raw read: far above any real data file.
const maxRawBytes = 64 << 20

func rawName(name string) error {
	if !rawFiles[name] {
		return fmt.Errorf("внутренняя ошибка: %q не файл данных HyRoute", name)
	}
	return nil
}

// ReadRaw returns the bytes of the data file name as they are, even when
// they do not parse. A link, a junction or a folder at the name is an
// error (readDataFile): it is never followed.
func (s *Store) ReadRaw(name string) (RawFile, error) {
	if err := rawName(name); err != nil {
		return RawFile{}, err
	}
	b, err := s.readRegular(name, maxRawBytes)
	if errors.Is(err, os.ErrNotExist) {
		return RawFile{}, nil
	}
	if err != nil {
		return RawFile{}, err
	}
	return RawFile{Exists: true, Data: b}, nil
}

// WriteRaw puts the data file name back exactly (writeAtomic), or removes
// it when !f.Exists. The removal never follows a link: a link at the name
// is removed itself, a folder is refused.
func (s *Store) WriteRaw(name string, f RawFile) error {
	if err := rawName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.path(name)
	if f.Exists {
		return writeAtomic(p, f.Data)
	}
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return &os.PathError{Op: "remove", Path: p, Err: ErrNotRegular}
	}
	return os.Remove(p)
}
