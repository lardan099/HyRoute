package store

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// A backup's restore (internal/app/backup*.go) keeps the bytes the data
// files had before it in restore-undo.sealed, for «Вернуть как было», and a
// copy of every broken file it replaces.

const undoName = "restore-undo.sealed"

// maxUndoBytes bounds the sealed undo record: the data files it holds
// plus a statistics export.
const maxUndoBytes = 128 << 20

// SaveRestoreUndo seals b (DPAPI) and writes it as the undo record.
func (s *Store) SaveRestoreUndo(b []byte) error {
	sealed, err := seal(b)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(s.path(undoName), sealed)
}

// LoadRestoreUndo returns the unsealed undo record (os.ErrNotExist when
// there is none).
func (s *Store) LoadRestoreUndo() ([]byte, error) {
	b, err := s.readRegular(undoName, maxUndoBytes)
	if err != nil {
		return nil, err
	}
	return unseal(b)
}

// DeleteRestoreUndo removes the undo record; a missing one is fine.
func (s *Store) DeleteRestoreUndo() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(undoName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// brokenRe is the name of a copy KeepBroken writes.
var brokenRe = regexp.MustCompile(`^([a-z]+\.json)\.broken-[0-9]{8}-[0-9]{6}$`)

// KeepBroken writes a copy of a file that failed to load as
// "<name>.broken-YYYYMMDD-HHMMSS" and returns the copy's name. An existing
// copy of the same second is not replaced: the next second is tried.
func (s *Store) KeepBroken(name string, b []byte, now time.Time) (string, error) {
	if err := rawName(name); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range 10 {
		copyName := name + ".broken-" + now.Add(time.Duration(i)*time.Second).Format("20060102-150405")
		if _, err := os.Lstat(s.path(copyName)); err == nil {
			continue
		}
		return copyName, writeAtomic(s.path(copyName), b)
	}
	return "", fmt.Errorf("%s: слишком много копий повреждённого файла", name)
}

// RemoveBroken deletes such a copy (rollback of a failed restore).
func (s *Store) RemoveBroken(copyName string) error {
	m := brokenRe.FindStringSubmatch(copyName)
	if m == nil || strings.ContainsAny(copyName, `\/`) {
		return fmt.Errorf("внутренняя ошибка: %q не копия повреждённого файла", copyName)
	}
	if err := rawName(m[1]); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(copyName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
