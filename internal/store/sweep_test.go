package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The leftovers of writes a killed run left in the data folder and subs\
// go; a fresh one, which may be being written, and other files stay.
func TestStoreSweepTemp(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	subs := filepath.Join(s.Dir, "subs")
	if err := os.MkdirAll(subs, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	write := func(p string, at time.Time) {
		t.Helper()
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(s.Dir, ".tmp-1"), old)
	write(filepath.Join(subs, ".tmp-2"), old)
	write(filepath.Join(s.Dir, ".tmp-3"), time.Now())
	write(filepath.Join(s.Dir, "settings.json"), old)
	if n := s.SweepTemp(time.Now().Add(-time.Hour)); n != 2 {
		t.Fatalf("%d removed", n)
	}
	for _, p := range []string{filepath.Join(s.Dir, ".tmp-3"), filepath.Join(s.Dir, "settings.json")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
	}
}
