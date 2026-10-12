package browser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lardan099/hyroute/internal/ctl"
)

func TestWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), DirName)
	// An older version's leftovers go; the files are written anew.
	os.MkdirAll(filepath.Join(dir, "old"), 0o755)
	os.WriteFile(filepath.Join(dir, "old", "x.js"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "stale.js"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "popup.js"), []byte("old"), 0o644)
	if err := Write(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"manifest.json", "background.js", "popup.html", "popup.js", "popup.css", "icons/icon128.png"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Error(err)
		}
	}
	for _, f := range []string{"old", "stale.js"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Errorf("%s kept", f)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "popup.js")); string(b) == "old" {
		t.Fatal("not rewritten")
	}
	if v := DiskVersion(dir); v == "" || v != Version() {
		t.Fatalf("%q %q", v, Version())
	}
	if DiskVersion(t.TempDir()) != "" {
		t.Fatal("version of nothing")
	}
}

// The extension's ID comes from its key: the host lets in that ID only.
func TestManifests(t *testing.T) {
	b, err := files.ReadFile("extension/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Key         string   `json:"key"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.Key == "" {
		t.Fatalf("%v %+v", err, m)
	}
	if got := "chrome-extension://" + ExtensionID(m.Key) + "/"; len(ctl.BrowserOrigins) != 1 || ctl.BrowserOrigins[0] != got {
		t.Fatalf("%s, origins %v", got, ctl.BrowserOrigins)
	}
	p := filepath.Join(t.TempDir(), HostFile)
	if err := WriteHostManifest(p, `C:\HyRoute\hyroutectl.exe`); err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	raw, _ := os.ReadFile(p)
	if err := json.Unmarshal(raw, &h); err != nil || h["name"] != ctl.BrowserHost || h["path"] != `C:\HyRoute\hyroutectl.exe` || h["type"] != "stdio" {
		t.Fatalf("%v %v", err, h)
	}
	if err := Remove(filepath.Join(t.TempDir(), "none"), p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("manifest kept")
	}
}
