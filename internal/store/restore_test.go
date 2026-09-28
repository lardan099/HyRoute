package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRestoreUndoRecord(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if _, err := s.LoadRestoreUndo(); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if err := s.SaveRestoreUndo([]byte(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	b, err := s.LoadRestoreUndo()
	if err != nil || string(b) != `{"x":1}` {
		t.Fatalf("%s %v", b, err)
	}
	if err := s.DeleteRestoreUndo(); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRestoreUndo(); err != nil {
		t.Fatal("missing is fine", err)
	}
}

func TestRawRoundTrip(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	data := []byte("\x00not json at all\xff")
	if err := s.WriteRaw("groups.json", RawFile{Exists: true, Data: data}); err != nil {
		t.Fatal(err)
	}
	f, err := s.ReadRaw("groups.json")
	if err != nil || !f.Exists || !bytes.Equal(f.Data, data) {
		t.Fatalf("%+v %v", f, err)
	}
	if err := s.WriteRaw("groups.json", RawFile{}); err != nil {
		t.Fatal(err)
	}
	if f, err := s.ReadRaw("groups.json"); err != nil || f.Exists {
		t.Fatalf("%+v %v", f, err)
	}
	for _, n := range []string{"hyroute.log", `..\settings.json`, "restore-undo.sealed"} {
		if _, err := s.ReadRaw(n); err == nil {
			t.Fatal(n)
		}
	}
}

func TestKeepBroken(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	now := time.Date(2026, 9, 28, 12, 30, 0, 0, time.Local)
	name, err := s.KeepBroken("settings.json", []byte("broken"), now)
	if err != nil || name != "settings.json.broken-20260928-123000" {
		t.Fatal(name, err)
	}
	if b, _ := os.ReadFile(filepath.Join(s.Dir, name)); string(b) != "broken" {
		t.Fatal(string(b))
	}
	second, err := s.KeepBroken("settings.json", []byte("again"), now)
	if err != nil || second != "settings.json.broken-20260928-123001" {
		t.Fatal(second, err)
	}
	if err := s.RemoveBroken(name); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("not removed")
	}
	if _, err := s.KeepBroken("x.json", nil, now); err == nil {
		t.Fatal("unregistered name")
	}
	for _, n := range []string{"settings.json", "x.json.broken-20260928-123000", `sub\settings.json.broken-20260928-123000`, "settings.json.broken-2026"} {
		if err := s.RemoveBroken(n); err == nil {
			t.Fatal(n)
		}
	}
}
