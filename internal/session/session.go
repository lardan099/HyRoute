// Package session runs one connection lifetime: relay, WinDivert engine
// and the Hysteria supervisor (or a SOCKS5 stub), wired together. The
// console PoC and the GUI both use it.
package session

import (
	"log/slog"
	"path/filepath"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// HysteriaPath is the hysteria.exe a profile starts with.
func (cfg *Config) HysteriaPath() string {
	if cfg.Hysteria != nil {
		if p := cfg.Hysteria(); p != "" {
			return p
		}
	}
	return filepath.Join(cfg.Dir, "hysteria.exe")
}

// RunnerFactory starts a hysteria.Supervisor per profile. The profile
// check uses it outside a session too.
func RunnerFactory(cfg Config) tunnels.Factory {
	return func(p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
		return &hysteria.Supervisor{
			Exe:          cfg.HysteriaPath(),
			RunDir:       cfg.RunDir,
			Profile:      p,
			Redactor:     cfg.Redactor,
			RedactGroup:  h.RedactGroup,
			LogLine:      h.LogLine,
			OnStatus:     h.OnStatus,
			SetServerIPs: h.SetServerIPs,
		}
	}
}

type Config struct {
	// Dir holds WinDivert.dll, WinDivert64.sys and hysteria.exe.
	Dir string
	// Exe is the program the relay firewall rule allows.
	Exe string
	// Hysteria returns the hysteria.exe to launch (read at every profile
	// start). Nil = Dir\hysteria.exe.
	Hysteria func() string
	RunDir   string
	// Profiles are the profiles the rules use; each gets its own Hysteria.
	Profiles []hysteria.Profile
	// Stub replaces Hysteria with an in-process SOCKS5 server shared by
	// every profile.
	Stub bool

	Settings *settings.Settings
	Rules    *rules.Set
	TCPOnly  bool
	// ResetUnknownDomain: see engine.Options.
	ResetUnknownDomain bool

	Log      *slog.Logger
	Redactor *logx.Redactor

	HysteriaLog func(profile string, l hysteria.LogLine)
	OnStatus    func(profile string, st hysteria.Status)
	OnDecision  func(flows.View)
	OnClose     func(flows.View)
	// OnEngineFail: the packet engine removed its filters after an error.
	OnEngineFail func()
}

// Stats are the counters shown next to the status.
type Stats struct {
	Reflected   int64 `json:"reflected"`
	Passed      int64 `json:"passed"`
	Blocked     int64 `json:"blocked"`
	Rejected    int64 `json:"rejected"` // Tunnel refused while the tunnel was down
	Unknown     int64 `json:"unknownOwner"`
	RelayTunnel int64 `json:"relayTunnel"`
	RelayDirect int64 `json:"relayDirect"`
	UDPTunneled int64 `json:"udpTunneled"`
	UDPDropped  int64 `json:"udpDropped"`
	SYNRetries  int64 `json:"synRetries"`
	// FragDropped: IP fragments dropped (their datagram was not direct);
	// Malformed: outbound packets that did not parse, dropped; Panics:
	// packets whose handling panicked, dropped.
	FragDropped int64  `json:"fragDropped"`
	Malformed   int64  `json:"malformed"`
	Panics      int64  `json:"panics"`
	DNSPairs    int    `json:"dnsPairs"`
	NATEntries  int    `json:"natEntries"`
	RelayPort   int    `json:"relayPort"`
	Driver      string `json:"driverVersion"`
}
