package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestRawFiles: ReadRaw and WriteRaw round-trip bytes exactly, remove a
// file, accept only data files, and never follow a link.
func TestRawFiles(t *testing.T) {
	s := openStore(t)
	for _, name := range []string{"settings.json", "rulesets.json"} {
		if f, err := s.ReadRaw(name); err != nil || f.Exists {
			t.Fatalf("%s missing: %+v %v", name, f, err)
		}
		data := []byte("{not json at all\x00")
		if err := s.WriteRaw(name, RawFile{Exists: true, Data: data}); err != nil {
			t.Fatal(err)
		}
		if f, err := s.ReadRaw(name); err != nil || !f.Exists || !bytes.Equal(f.Data, data) {
			t.Fatalf("%s: %+v %v", name, f, err)
		}
		if err := s.WriteRaw(name, RawFile{}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(s.Dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s not removed: %v", name, err)
		}
		if err := s.WriteRaw(name, RawFile{}); err != nil {
			t.Fatalf("removing a missing file: %v", err)
		}
	}
	for _, name := range []string{"geo/geosite.dat", "../x.json", "other.json", ""} {
		if _, err := s.ReadRaw(name); err == nil {
			t.Errorf("ReadRaw %q accepted", name)
		}
		if err := s.WriteRaw(name, RawFile{Exists: true}); err == nil {
			t.Errorf("WriteRaw %q accepted", name)
		}
	}

	// A folder at the name: not read, not removed.
	dir := filepath.Join(s.Dir, "prefs.json")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRaw("prefs.json"); err == nil {
		t.Fatal("folder read")
	}
	if err := s.WriteRaw("prefs.json", RawFile{}); err == nil {
		t.Fatal("folder removed")
	}
	os.Remove(dir)

	// A link to a file elsewhere: not read; removing removes the link only.
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(s.Dir, "rulesets.json")
	if err := os.Symlink(secret, link); err != nil {
		t.Logf("symbolic link not tested: %v", err)
		return
	}
	if f, err := s.ReadRaw("rulesets.json"); err == nil || f.Data != nil {
		t.Fatalf("link followed: %+v %v", f, err)
	}
	if err := s.WriteRaw("rulesets.json", RawFile{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatal("link not removed")
	}
	if b, err := os.ReadFile(secret); err != nil || string(b) != "secret" {
		t.Fatal("target touched")
	}
}
