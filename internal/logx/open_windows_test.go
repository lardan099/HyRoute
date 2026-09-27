//go:build windows

package logx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenRefusesLinks: a log name that is a (hard) link to another file
// is neither appended to nor emptied.
func TestOpenRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	os.WriteFile(target, []byte("keep"), 0o600)
	hard := filepath.Join(dir, "hard.log")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{hard} {
		if f, err := OpenAppend(l); !errors.Is(err, errLinked) {
			if f != nil {
				f.Close()
			}
			t.Errorf("%s: append: %v", l, err)
		}
		if err := Truncate(l); !errors.Is(err, errLinked) {
			t.Errorf("%s: truncate: %v", l, err)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("target changed: %q", b)
	}
	// An ordinary file works.
	p := filepath.Join(dir, "a.log")
	f, err := OpenAppend(p)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("one\n")
	f.Close()
	f, _ = OpenAppend(p)
	f.WriteString("two\n")
	f.Close()
	if b, _ := os.ReadFile(p); string(b) != "one\ntwo\n" {
		t.Fatalf("%q", b)
	}
	if err := Truncate(p); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Size() != 0 {
		t.Fatal(fi.Size())
	}
	if err := Truncate(filepath.Join(dir, "none.log")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}
