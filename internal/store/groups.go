package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lardan099/hyroute/internal/groups"
)

// groups.json holds the server groups, the probe settings and a group main
// target. It is written only when the user uses groups: a user who never
// did has no such file.
const groupsFile = "groups.json"

// LoadGroups reads groups.json. A missing file is no groups. On any other
// error the returned file is not nil: it holds only the main target a
// lenient read found (groups.MainOf), so a broken file whose main was a
// group still fails closed.
func (s *Store) LoadGroups() (*groups.File, error) {
	empty := &groups.File{Version: groups.FormatVersion, Groups: []groups.Group{}}
	b, err := s.readRegular(groupsFile, groups.MaxFileSize)
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, fmt.Errorf("groups.json: %w", err)
	}
	f, err := groups.Parse(b)
	if err != nil {
		empty.Main = groups.MainOf(b)
		if !strings.HasPrefix(err.Error(), "groups.json") {
			err = fmt.Errorf("groups.json: %w", err)
		}
		return empty, err
	}
	return f, nil
}

// SaveGroups validates f with the load rules and writes it.
func (s *Store) SaveGroups(f *groups.File) error {
	f.Version = groups.FormatVersion
	if f.Groups == nil {
		f.Groups = []groups.Group{}
	}
	for i := range f.Groups {
		if f.Groups[i].Members == nil {
			f.Groups[i].Members = []string{}
		}
	}
	if err := f.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(s.path(groupsFile), b)
}
