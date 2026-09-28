//go:build !windows

package store

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteUserFileOther(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.hyroute-backup")
	for _, s := range []string{"one", "two"} {
		if err := WriteUserFile(p, []byte(s)); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(p); string(b) != s {
			t.Fatal(string(b))
		}
	}
	// A symlink at the target is replaced; its pointee stays.
	pointee := filepath.Join(dir, "pointee")
	os.WriteFile(pointee, []byte("keep"), 0o600)
	link := filepath.Join(dir, "link.hyroute-backup")
	if err := os.Symlink(pointee, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteUserFile(link, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(pointee); string(b) != "keep" {
		t.Fatal("pointee written")
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("link kept")
	}
	// A hard link: the other name keeps the old bytes.
	hard := filepath.Join(dir, "hard.hyroute-backup")
	os.Link(pointee, hard)
	if err := WriteUserFile(hard, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(pointee); string(b) != "keep" {
		t.Fatal("hard link pointee written")
	}
	os.Mkdir(filepath.Join(dir, "d.hyroute-backup"), 0o700)
	if err := WriteUserFile(filepath.Join(dir, "d.hyroute-backup"), nil); err == nil {
		t.Fatal("directory target")
	}
	if err := WriteUserFile(filepath.Join(dir, "missing", "x"), nil); err == nil {
		t.Fatal("missing folder")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatal("temp left", e.Name())
		}
	}
}

func TestReadUserFileOther(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a")
	os.WriteFile(p, []byte("12345"), 0o600)
	if b, err := ReadUserFile(p, 5); err != nil || string(b) != "12345" {
		t.Fatal(err)
	}
	if _, err := ReadUserFile(p, 4); !errors.Is(err, ErrUserFileTooLarge) {
		t.Fatal(err)
	}
	if _, err := ReadUserFile(dir, 10); err == nil {
		t.Fatal("directory")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err == nil {
		// O_NONBLOCK is not set: open a writer so the open does not block.
		go func() {
			if f, err := os.OpenFile(fifo, os.O_WRONLY, 0); err == nil {
				f.Close()
			}
		}()
		if _, err := ReadUserFile(fifo, 10); err == nil {
			t.Fatal("fifo")
		}
	}
}
