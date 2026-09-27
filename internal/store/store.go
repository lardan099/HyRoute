// Package store keeps HyRoute's state in %APPDATA%\HyRoute:
//
//	profiles.json   Hysteria profiles; auth and obfs password are sealed
//	                with DPAPI (current user) on Windows
//	settings.json   rules and routing options (internal/settings format)
//
// Files are replaced atomically (write to a temp file, then rename).
package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
)

// DefaultDir is %APPDATA%\HyRoute (or the user config dir elsewhere).
func DefaultDir() (string, error) {
	d, err := appDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "HyRoute"), nil
}

type Store struct {
	Dir string
	mu  sync.Mutex
}

// Open prepares dir and the folders in it where an elevated HyRoute
// writes, renames and deletes files by name (see Guard): subs (here), geo
// (geodata) and run (Hysteria configs). logs is guarded by the log setup.
// WebView2's data are not kept here (see webviewDataDir in main).
func Open(dir string) (*Store, error) {
	for _, d := range []string{dir, filepath.Join(dir, "subs"), filepath.Join(dir, "geo"), filepath.Join(dir, "run")} {
		if err := Guard(d); err != nil {
			return nil, err
		}
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.Dir, name) }

// Profiles is the saved profile list.
type Profiles struct {
	Active string             `json:"active"`
	List   []hysteria.Profile `json:"list"`
}

// Find returns the profile with id, or nil.
func (p *Profiles) Find(id string) *hysteria.Profile {
	for i := range p.List {
		if p.List[i].ID == id {
			return &p.List[i]
		}
	}
	return nil
}

type storedProfile struct {
	hysteria.Profile
	// Sealed holds the secrets (auth, obfs password); the plain fields are
	// emptied on disk.
	Sealed string `json:"sealed,omitempty"`
}

type secrets struct {
	Auth string `json:"auth,omitempty"`
	Obfs string `json:"obfs,omitempty"`
}

type storedProfiles struct {
	Active string          `json:"active"`
	List   []storedProfile `json:"list"`
}

func (s *Store) LoadProfiles() (*Profiles, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path("profiles.json"))
	if errors.Is(err, os.ErrNotExist) {
		return &Profiles{}, nil
	}
	if err != nil {
		return nil, err
	}
	var sp storedProfiles
	if err := json.Unmarshal(b, &sp); err != nil {
		return nil, fmt.Errorf("profiles.json: %w", err)
	}
	out := &Profiles{Active: sp.Active}
	for _, p := range sp.List {
		if p.Sealed != "" {
			raw, err := base64.StdEncoding.DecodeString(p.Sealed)
			if err == nil {
				raw, err = unseal(raw)
			}
			var sec secrets
			if err == nil {
				err = json.Unmarshal(raw, &sec)
			}
			if err != nil {
				return nil, fmt.Errorf("profile %q: secrets cannot be decrypted (profiles.json from another user or machine?): %w", p.Name, err)
			}
			p.Auth, p.Obfs.Password = sec.Auth, sec.Obfs
		}
		out.List = append(out.List, p.Profile)
	}
	return out, nil
}

func (s *Store) SaveProfiles(p *Profiles) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sp := storedProfiles{Active: p.Active, List: []storedProfile{}}
	for _, pr := range p.List {
		raw, _ := json.Marshal(secrets{Auth: pr.Auth, Obfs: pr.Obfs.Password})
		sealed, err := seal(raw)
		if err != nil {
			return fmt.Errorf("seal secrets: %w", err)
		}
		pr.Auth, pr.Obfs.Password = "", ""
		sp.List = append(sp.List, storedProfile{Profile: pr, Sealed: base64.StdEncoding.EncodeToString(sealed)})
	}
	b, err := json.MarshalIndent(sp, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path("profiles.json"), b)
}

// DefaultSettings is used when settings.json does not exist yet.
func DefaultSettings() *settings.Settings {
	st := &settings.Settings{}
	st.DefaultAction = rules.Direct
	st.Rules = []rules.Rule{}
	return st
}

// LoadSettings returns the settings and the compiled rule set.
func (s *Store) LoadSettings() (*settings.Settings, *rules.Set, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.path("settings.json"))
	if errors.Is(err, os.ErrNotExist) {
		st := DefaultSettings()
		set, err := rules.Compile(st.Config)
		if err == nil {
			set.ExactWeb = st.ExactWeb()
		}
		return st, set, err
	}
	if err != nil {
		return nil, nil, err
	}
	st, set, err := settings.Parse(b)
	if err != nil {
		return nil, nil, fmt.Errorf("settings.json: %w", err)
	}
	return st, set, nil
}

// SaveSettings validates, then writes.
func (s *Store) SaveSettings(st *settings.Settings) (*rules.Set, error) {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, err
	}
	_, set, err := settings.Parse(b)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return set, writeAtomic(s.path("settings.json"), b)
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
