package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestReadRegular: a plain file is read whole up to the limit; a missing
// one is ErrNotExist; a larger one, a folder, a hard link or a symbolic
// link to another file are refused and their target is never read.
func TestReadRegular(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	put := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(s.Dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("a.json", []byte(`{"x":1}`))
	if b, err := s.readRegular("a.json", 7); err != nil || string(b) != `{"x":1}` {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := s.readRegular("a.json", 6); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over the limit: %v", err)
	}
	big := bytes.Repeat([]byte("x"), 4<<20+1)
	put("big.json", big)
	if _, err := s.readRegular("big.json", 4<<20); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("4 MiB + 1: %v", err)
	}
	if b, err := s.readRegular("big.json", 8<<20); err != nil || len(b) != len(big) {
		t.Fatalf("%d %v", len(b), err)
	}
	put("empty.json", nil)
	if b, err := s.readRegular("empty.json", 10); err != nil || len(b) != 0 {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := s.readRegular("none.json", 10); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if err := os.Mkdir(filepath.Join(s.Dir, "dir.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.readRegular("dir.json", 10); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("folder: %v", err)
	}

	// A file elsewhere that the user cannot read, reached through a link.
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, filepath.Join(s.Dir, "hard.json")); err != nil {
		t.Fatal(err)
	}
	if b, err := s.readRegular("hard.json", 100); !errors.Is(err, ErrNotRegular) || b != nil {
		t.Fatalf("hard link: %q %v", b, err)
	}
	if err := os.Symlink(secret, filepath.Join(s.Dir, "sym.json")); err != nil {
		t.Logf("symbolic link not tested: %v", err) // Windows without the privilege
	} else if b, err := s.readRegular("sym.json", 100); !errors.Is(err, ErrNotRegular) || b != nil {
		t.Fatalf("symbolic link: %q %v", b, err)
	}
	if err := os.Symlink(filepath.Dir(secret), filepath.Join(s.Dir, "symdir.json")); err == nil {
		if _, err := s.readRegular("symdir.json", 100); !errors.Is(err, ErrNotRegular) {
			t.Fatalf("symbolic link to a folder: %v", err)
		}
	}
	if b, _ := os.ReadFile(secret); string(b) != "secret" {
		t.Fatal("target changed")
	}
}
