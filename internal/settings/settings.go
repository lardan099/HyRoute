// Package settings loads the routing settings file (rules plus engine
// options) and watches it for changes. Rule changes apply to new flows
// only; Hysteria is not restarted.
package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/lardan099/hyroute/internal/rules"
)

type Settings struct {
	rules.Config
	// Options default to true when omitted.
	BlockQUIC       *bool `json:"blockQUIC,omitempty"`
	BlockIPv6Tunnel *bool `json:"blockIPv6Tunnel,omitempty"`
	PreferRemoteDNS *bool `json:"preferRemoteDNS,omitempty"`
	// ExactWebDomains: decide web connections by SNI/Host only, the DNS
	// cache is a fallback (see rules.Set.ExactWeb). Applied on reload.
	ExactWebDomains *bool `json:"exactWebDomains,omitempty"`
	SniffTimeoutMs  int   `json:"sniffTimeoutMs,omitempty"`
	// KillSwitch: keep the internet closed when routing stops without a
	// Disconnect (crash, engine failure). Off when omitted.
	KillSwitch *bool `json:"killSwitch,omitempty"`
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func (s *Settings) QUICBlocked() bool       { return boolOr(s.BlockQUIC, true) }
func (s *Settings) IPv6TunnelBlocked() bool { return boolOr(s.BlockIPv6Tunnel, true) }
func (s *Settings) RemoteDNS() bool         { return boolOr(s.PreferRemoteDNS, true) }
func (s *Settings) ExactWeb() bool          { return boolOr(s.ExactWebDomains, true) }
func (s *Settings) KillSwitchOn() bool      { return boolOr(s.KillSwitch, false) }

func (s *Settings) SniffTimeout() time.Duration {
	if s.SniffTimeoutMs <= 0 {
		return 800 * time.Millisecond
	}
	return time.Duration(s.SniffTimeoutMs) * time.Millisecond
}

// Parse decodes and compiles settings.
func Parse(b []byte) (*Settings, *rules.Set, error) {
	var s Settings
	// Windows PowerShell 5.1 writes UTF-8 with a BOM.
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, nil, err
	}
	// A hand-edited file without "rules" (or "rules": null) has no rules:
	// the UI gets [] rather than null.
	if s.Rules == nil {
		s.Rules = []rules.Rule{}
	}
	set, err := rules.Compile(s.Config)
	if err != nil {
		return nil, nil, err
	}
	set.ExactWeb = s.ExactWeb()
	return &s, set, nil
}

// Load reads and parses a file.
func Load(path string) (*Settings, *rules.Set, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Parse(b)
}

// Watch polls path and calls onChange with every valid new version, and
// onError when an edited file does not parse (the previous rules stay).
func Watch(path string, every time.Duration, stop <-chan struct{}, onChange func(*Settings, *rules.Set), onError func(error)) {
	var last time.Time
	if fi, err := os.Stat(path); err == nil {
		last = fi.ModTime()
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		fi, err := os.Stat(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				onError(err)
			}
			continue
		}
		if !fi.ModTime().After(last) {
			continue
		}
		last = fi.ModTime()
		s, set, err := Load(path)
		if err != nil {
			onError(err)
			continue
		}
		onChange(s, set)
	}
}
