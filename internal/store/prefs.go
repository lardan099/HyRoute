package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Prefs are application preferences (not routing): logs and updates.
type Prefs struct {
	// LogsToDisk: write logs\hyroute.log and one file per Hysteria
	// profile. Off = only the in-memory buffers.
	LogsToDisk *bool `json:"logsToDisk,omitempty"`
	LogMaxMB   int   `json:"logMaxMB,omitempty"`
	LogKeep    int   `json:"logKeep,omitempty"`
	// UpdateCheck: "auto" checks HyRoute and Hysteria releases at start
	// and every 12 h; "manual" only on the button.
	UpdateCheck string `json:"updateCheck,omitempty"`
	// UpdateChannel: "stable" (a "beta" channel may come later).
	UpdateChannel string `json:"updateChannel,omitempty"`
	// SkipVersion: the HyRoute version the user postponed ("Позже").
	SkipVersion string `json:"skipVersion,omitempty"`

	// Rule databases (geosite.dat/geoip.dat): a preset ID or "custom"
	// with GeoSiteURL/GeoIPURL. Empty = the default preset.
	GeoSource  string `json:"geoSource,omitempty"`
	GeoSiteURL string `json:"geoSiteURL,omitempty"`
	GeoIPURL   string `json:"geoIPURL,omitempty"`
	// GeoAutoOff disables background updates (a missing database a rule
	// needs is still downloaded).
	GeoAutoOff       *bool `json:"geoAutoOff,omitempty"`
	GeoIntervalHours int   `json:"geoIntervalHours,omitempty"`

	// AutoConnect: turn routing on as soon as HyRoute starts (with the
	// sign-in task this restores the connection after a reboot).
	AutoConnect bool `json:"autoConnect,omitempty"`
	// CloseToTray: the close button hides the window to the tray (on
	// when omitted); "Выход" in the tray menu quits.
	CloseToTray *bool `json:"closeToTray,omitempty"`

	// cli
	// CLI: access of hyroutectl.exe over the control pipe: "" = read-only
	// (the default), "full" = every command, "off" = no pipe. "read" is
	// accepted for read-only too (CLIMode).
	CLI string `json:"cli,omitempty"`
}

// CLIMode is the hyroutectl access CLI stands for: "full", "read" or
// "off". Unset is read-only; a value written by a newer version reads as
// "off", so it is never widened.
func (p Prefs) CLIMode() string {
	switch p.CLI {
	case "", "read":
		return "read"
	case "full", "off":
		return p.CLI
	}
	return "off"
}

func (p Prefs) CloseToTrayOn() bool { return p.CloseToTray == nil || *p.CloseToTray }

func (p Prefs) GeoAutoUpdate() bool { return p.GeoAutoOff == nil || !*p.GeoAutoOff }

// GeoHours is the database update interval (default 12 h).
func (p Prefs) GeoHours() int {
	if p.GeoIntervalHours <= 0 {
		return 12
	}
	return p.GeoIntervalHours
}

func (p Prefs) ToDisk() bool {
	return p.LogsToDisk == nil || *p.LogsToDisk
}

func (p Prefs) MaxBytes() int64 {
	mb := p.LogMaxMB
	if mb <= 0 {
		mb = 5
	}
	return int64(min(mb, 200)) << 20
}

func (p Prefs) Keep() int {
	if p.LogKeep <= 0 {
		return 3
	}
	return min(p.LogKeep, 20)
}

func (s *Store) LoadPrefs() (Prefs, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var p Prefs
	b, err := os.ReadFile(s.path("prefs.json"))
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return Prefs{}, fmt.Errorf("prefs.json: %w", err)
	}
	return p, nil
}

func (s *Store) SavePrefs(p Prefs) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(s.path("prefs.json"), b)
}
