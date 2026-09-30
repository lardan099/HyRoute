//go:build !windows

package datadir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	os.Mkdir(dir, 0o700)
	if err := Dir(dir); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0o755)
	if err := Dir(dir); err == nil || !strings.Contains(err.Error(), "chmod 700 "+dir) {
		t.Fatalf("0755 directory: %v", err)
	}
	os.Chmod(dir, 0o700)

	key := filepath.Join(dir, "master.key")
	if err := File(key); err != nil {
		t.Fatalf("missing file: %v", err)
	}
	os.WriteFile(key, []byte("fake"), 0o600)
	if err := File(key); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660} {
		os.Chmod(key, mode)
		if err := File(key); err == nil || !strings.Contains(err.Error(), "chmod 600 "+key) {
			t.Fatalf("%04o: %v", mode, err)
		}
	}
	if err := File(dir); err == nil {
		t.Fatal("a directory taken for a file")
	}
	if err := Dir(key); err == nil {
		t.Fatal("a file taken for a directory")
	}
}

func TestUnixOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give a file away")
	}
	key := filepath.Join(t.TempDir(), "master.key")
	os.WriteFile(key, []byte("fake"), 0o600)
	os.Chown(key, 65534, 65534)
	if err := File(key); err == nil || !strings.Contains(err.Error(), "chown") {
		t.Fatalf("someone else's key: %v", err)
	}
}
