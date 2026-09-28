package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/groups"
)

func TestGroupsMissingAndRoundTrip(t *testing.T) {
	s, _ := Open(t.TempDir())
	f, err := s.LoadGroups()
	if err != nil || f.Version != 1 || f.Groups == nil || len(f.Groups) != 0 || f.Main != "" {
		t.Fatal(f, err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "groups.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("LoadGroups created the file")
	}
	f.Main = "grp-000000000001"
	f.Groups = []groups.Group{
		{ID: "grp-000000000001", Name: "Авто", Strategy: groups.Latency, Members: []string{"a1b2c3d4e5f6"}},
		{ID: "grp-000000000002", Name: "Пусто", Strategy: groups.Failover},
	}
	f.Probe = &groups.Probe{IntervalSec: 120}
	if err := s.SaveGroups(f); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(s.Dir, "groups.json"))
	if !strings.Contains(string(raw), `"members": []`) || !strings.Contains(string(raw), "\n  \"groups\"") {
		t.Fatalf("members null or not indented:\n%s", raw)
	}
	got, err := s.LoadGroups()
	if err != nil || got.Main != f.Main || len(got.Groups) != 2 || got.Probe.IntervalSec != 120 || got.Groups[0].Members[0] != "a1b2c3d4e5f6" {
		t.Fatal(got, err)
	}
	// The load rules hold for every write.
	bad := got.Clone()
	bad.Groups[1].Name = "авто"
	if err := s.SaveGroups(bad); err == nil {
		t.Fatal("duplicate name saved")
	}
}

func TestGroupsBroken(t *testing.T) {
	s, _ := Open(t.TempDir())
	path := filepath.Join(s.Dir, "groups.json")
	os.WriteFile(path, []byte(`{"version":1,"main":"grp-000000000001","groups":[{"id":"grp-000000000001","name":"a","strategy":"best","members":[]}]}`), 0o600)
	f, err := s.LoadGroups()
	if err == nil || !strings.HasPrefix(err.Error(), "groups.json: ") || f == nil || f.Main != "grp-000000000001" || len(f.Groups) != 0 {
		t.Fatal(f, err)
	}
	os.WriteFile(path, []byte(`{"version":7,"groups":[]}`), 0o600)
	if _, err := s.LoadGroups(); err == nil || strings.HasPrefix(err.Error(), "groups.json: groups.json") || !strings.Contains(err.Error(), "формат 7") {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte(`{"version":1,"groups":[], "pad":"`+strings.Repeat("x", groups.MaxFileSize)+`"}`), 0o600)
	f, err = s.LoadGroups()
	if !errors.Is(err, ErrTooLarge) || f == nil {
		t.Fatal(f, err)
	}
}
