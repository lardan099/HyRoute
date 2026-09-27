package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
)

func TestProfilesRoundTripKeepsSecretsOutOfPlainFields(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &Profiles{Active: "a", List: []hysteria.Profile{{ID: "a", Name: "one", Host: "example.com", Ports: "443", Auth: "pw-auth", Obfs: hysteria.Obfs{Type: "salamander", Password: "pw-obfs"}}}}
	if err := s.SaveProfiles(p); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(s.Dir, "profiles.json"))
	if strings.Contains(string(raw), `"auth": "pw-auth"`) || strings.Contains(string(raw), `"password": "pw-obfs"`) {
		t.Fatalf("plain secrets on disk: %s", raw)
	}
	got, err := s.LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if got.Active != "a" || len(got.List) != 1 || got.List[0].Auth != "pw-auth" || got.List[0].Obfs.Password != "pw-obfs" {
		t.Fatalf("%+v", got)
	}
}

func TestMissingFilesGiveDefaults(t *testing.T) {
	s, _ := Open(t.TempDir())
	p, err := s.LoadProfiles()
	if err != nil || len(p.List) != 0 {
		t.Fatal(p, err)
	}
	st, set, err := s.LoadSettings()
	if err != nil || st.DefaultAction != rules.Direct || set == nil || !set.ExactWeb {
		t.Fatal(st, err)
	}
}

func TestSaveSettingsValidates(t *testing.T) {
	s, _ := Open(t.TempDir())
	st := DefaultSettings()
	st.Rules = append(st.Rules, rules.Rule{Name: "bad", Domain: &rules.DomainMatch{Pattern: "a b"}, Action: rules.Tunnel})
	if _, err := s.SaveSettings(st); err == nil {
		t.Fatal("invalid rule saved")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "settings.json")); !os.IsNotExist(err) {
		t.Fatal("file written despite error")
	}
	st.Rules[0].Domain.Pattern = ".example.com"
	if _, err := s.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.LoadSettings()
	if err != nil || len(got.Rules) != 1 || got.Rules[0].Domain.Pattern != ".example.com" {
		t.Fatal(got, err)
	}
}
