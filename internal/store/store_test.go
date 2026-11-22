package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/awg"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/vless"
)

func TestProfilesRoundTripKeepsSecretsOutOfPlainFields(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &Profiles{Active: "a", List: []hysteria.Profile{
		{ID: "a", Name: "one", Host: "example.com", Ports: "443", Auth: "pw-auth", Obfs: hysteria.Obfs{Type: "salamander", Password: "pw-obfs"}},
		{ID: "b", Name: "two", Host: "example.org", Ports: "443", Protocol: hysteria.ProtoVLESS,
			VLESS: vless.Settings{ID: "5f0b7c1e-1234-4abc-9def-0123456789ab", Security: "tls", Network: "ws"}},
	}}
	if err := s.SaveProfiles(p); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(s.Dir, "profiles.json"))
	if strings.Contains(string(raw), `"auth": "pw-auth"`) || strings.Contains(string(raw), `"password": "pw-obfs"`) ||
		strings.Contains(string(raw), "5f0b7c1e-1234") || strings.Count(string(raw), `"vless": {`) != 1 {
		t.Fatalf("plain secrets on disk: %s", raw)
	}
	got, err := s.LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if got.Active != "a" || len(got.List) != 2 || got.List[0].Auth != "pw-auth" || got.List[0].Obfs.Password != "pw-obfs" ||
		got.List[1].VLESS != p.List[1].VLESS || got.List[0].VLESS != (vless.Settings{}) {
		t.Fatalf("%+v", got)
	}
}

func TestProfilesSealAmneziaWGKeys(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Test keys, not real ones.
	priv, psk, hpk := strings.Repeat("A", 43)+"=", strings.Repeat("B", 43)+"=", strings.Repeat("C", 43)+"="
	p := &Profiles{Active: "a", List: []hysteria.Profile{{ID: "a", Name: "awg", Host: "203.0.113.5", Ports: "51820",
		Protocol: hysteria.ProtoAWG, AWG: awg.Settings{PrivateKey: priv, PublicKey: strings.Repeat("D", 43) + "=",
			PresharedKey: psk, HeaderProtectionKey: hpk, Address: "10.8.1.2/32", Jc: 4, S1: 16, S2: 16, S3: 16, S4: 16}}}}
	if err := s.SaveProfiles(p); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(s.Dir, "profiles.json"))
	for _, k := range []string{priv, psk, hpk} {
		if strings.Contains(string(raw), k) {
			t.Fatalf("a plain key on disk: %s", raw)
		}
	}
	if !strings.Contains(string(raw), strings.Repeat("D", 43)) {
		t.Error("the server's public key is not secret, yet it is not in the plain fields")
	}
	got, err := s.LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if got.List[0].AWG != p.List[0].AWG {
		t.Fatalf("%+v", got.List[0].AWG)
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
