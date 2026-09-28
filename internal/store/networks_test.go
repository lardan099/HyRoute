package store

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/netmode"
)

func netModesStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// dirFiles lists the regular files of dir (not the lock files).
func dirFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".hyroute") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func TestNetModesMissingIsDefault(t *testing.T) {
	s := netModesStore(t)
	before := dirFiles(t, s.Dir)
	cfg, err := s.LoadNetModes()
	if err != nil || cfg.Enabled || len(cfg.Rules) != 0 || cfg.Unknown.Connect != netmode.Connect {
		t.Fatalf("%+v %v", cfg, err)
	}
	if after := dirFiles(t, s.Dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("reading created files: %v", after)
	}
}

func TestNetModesRoundTrip(t *testing.T) {
	s := netModesStore(t)
	cfg := netmode.Default()
	cfg.Enabled = true
	cfg.Rules = []netmode.Rule{{ID: "a1b2c3d4e5f6", Name: "Дом",
		Match:  netmode.Match{Networks: []netmode.Known{{ID: "{5E1B9C0A-3C7D-4F0E-9A51-0D2B6B1C7E11}", Name: "HomeWiFi"}}},
		Action: netmode.Action{Connect: netmode.Disconnect}}}
	if err := s.SaveNetModes(cfg); err != nil {
		t.Fatal(err)
	}
	if files := dirFiles(t, s.Dir); strings.Join(files, ",") != "networks.json" {
		t.Fatalf("files %v", files)
	}
	back, err := s.LoadNetModes()
	if err != nil || !back.Enabled || len(back.Rules) != 1 || back.Rules[0].Connect != netmode.Disconnect || back.Unknown.Connect != netmode.Connect || back.Version != 1 {
		t.Fatalf("%+v %v", back, err)
	}
}

func TestNetModesBrokenAndLimits(t *testing.T) {
	s := netModesStore(t)
	p := filepath.Join(s.Dir, "networks.json")
	if err := os.WriteFile(p, []byte(`{"rules":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadNetModes(); err == nil || !strings.HasPrefix(err.Error(), "networks.json:") {
		t.Fatal(err)
	}
	// An invalid config is not written; the file stays as it was.
	bad := netmode.Default()
	bad.Rules = []netmode.Rule{{Name: "x"}}
	if err := s.SaveNetModes(bad); err == nil {
		t.Fatal("invalid config saved")
	}
	if b, _ := os.ReadFile(p); string(b) != `{"rules":[` {
		t.Fatalf("file changed: %s", b)
	}
	// Over the cap: refused without reading it whole.
	if err := os.WriteFile(p, bytes.Repeat([]byte(" "), netmode.MaxFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadNetModes(); err == nil || !strings.Contains(err.Error(), "больше 1 МБ") {
		t.Fatal(err)
	}
	os.Remove(p)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadNetModes(); err == nil || !strings.Contains(err.Error(), "не обычный файл") {
		t.Fatal(err)
	}
	os.Remove(p)
	// A link to a large file elsewhere: refused as a link, never followed.
	other := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(other, bytes.Repeat([]byte(" "), 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, p); err != nil {
		t.Logf("symbolic link not tested: %v", err)
	} else if _, err := s.LoadNetModes(); err == nil || !strings.Contains(err.Error(), "не обычный файл") {
		t.Fatalf("link: %v", err)
	}
}

// A save writes networks.json only.
func TestNetModesSaveTouchesNothingElse(t *testing.T) {
	s := netModesStore(t)
	if err := os.WriteFile(filepath.Join(s.Dir, "settings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveNetModes(netmode.Default()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(s.Dir, "settings.json")); string(b) != "{}" {
		t.Fatal("settings.json changed")
	}
	if files := dirFiles(t, s.Dir); strings.Join(files, ",") != "networks.json,settings.json" {
		t.Fatalf("files %v", files)
	}
}
