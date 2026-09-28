package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrefsCLIMode(t *testing.T) {
	for in, want := range map[string]string{"": "read", "read": "read", "full": "full", "off": "off", "all": "off", "FULL": "off"} {
		if got := (Prefs{CLI: in}).CLIMode(); got != want {
			t.Errorf("CLIMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPrefsCLIOmitted(t *testing.T) {
	s, _ := Open(t.TempDir())
	if err := s.SavePrefs(Prefs{AutoConnect: true}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, "prefs.json"))
	if strings.Contains(string(b), "cli") {
		t.Fatalf("the default mode is written: %s", b)
	}
	// A file with the key loads (plain Unmarshal, as v1.0.0 reads it too).
	os.WriteFile(filepath.Join(s.Dir, "prefs.json"), []byte(`{"autoConnect":true,"cli":"full"}`), 0o600)
	p, err := s.LoadPrefs()
	if err != nil || p.CLI != "full" || p.CLIMode() != "full" || !p.AutoConnect {
		t.Fatal(p, err)
	}
}
