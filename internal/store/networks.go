package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lardan099/hyroute/internal/netmode"
)

// networks.json holds the network rules («Сети»). It is written only when
// the user saves or toggles them on that page: a user who never did has no
// such file, and the feature is off.
const netModesFile = "networks.json"

// LoadNetModes reads networks.json (absent = netmode.Default()). The read
// goes through readRegular: a link or a folder is refused, and so is a file
// over the size cap.
func (s *Store) LoadNetModes() (netmode.Config, error) {
	b, err := s.readRegular(netModesFile, netmode.MaxFileSize)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return netmode.Default(), nil
	case errors.Is(err, ErrNotRegular):
		return netmode.Default(), errors.New("networks.json: не обычный файл — HyRoute его не читает")
	case errors.Is(err, ErrTooLarge):
		return netmode.Default(), errors.New("networks.json больше 1 МБ")
	case err != nil:
		return netmode.Default(), fmt.Errorf("networks.json: %w", err)
	}
	cfg, err := netmode.Parse(b)
	if err != nil {
		if !strings.HasPrefix(err.Error(), "networks.json") {
			err = fmt.Errorf("networks.json: %w", err)
		}
		return netmode.Default(), err
	}
	return cfg, nil
}

// SaveNetModes normalizes and validates cfg and writes it atomically
// (version 1).
func (s *Store) SaveNetModes(cfg netmode.Config) error {
	netmode.Normalize(&cfg)
	cfg.Version = netmode.Version
	if err := netmode.Validate(cfg); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(s.path(netModesFile), b)
}
