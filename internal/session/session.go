// Package session runs one connection lifetime: relay, WinDivert engine
// and the Hysteria supervisor (or a SOCKS5 stub), wired together. The
// console PoC and the GUI both use it.
package session

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"

	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/socks5"
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

// XrayPath is the xray.exe a VLESS profile starts with.
func (cfg *Config) XrayPath() string {
	if cfg.Xray != nil {
		if p := cfg.Xray(); p != "" {
			return p
		}
	}
	return filepath.Join(cfg.Dir, "xray.exe")
}

// RunnerFactory starts a hysteria.Supervisor per profile: hysteria.exe, or
// xray.exe for VLESS. The profile check uses it outside a session too.
func RunnerFactory(cfg Config) tunnels.Factory {
	return func(p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
		exe, path := cfg.HysteriaPath(), cfg.HysteriaPath
		if p.IsVLESS() {
			exe, path = cfg.XrayPath(), cfg.XrayPath
		}
		return &hysteria.Supervisor{
			Exe:          exe,
			ExePath:      path,
			RunDir:       cfg.RunDir,
			Profile:      p,
			Redactor:     cfg.Redactor,
			RedactGroup:  h.RedactGroup,
			LogLine:      h.LogLine,
			OnStatus:     h.OnStatus,
			SetServerIPs: h.SetServerIPs,
			Via:          h.Via,
			Received:     h.Received,
		}
	}
}

type Config struct {
	// Dir holds WinDivert.dll, WinDivert64.sys, hysteria.exe and xray.exe.
	Dir string
	// Exe is the program the relay firewall rule allows.
	Exe string
	// Hysteria returns the hysteria.exe to launch (read at every profile
	// start). Nil = Dir\hysteria.exe.
	Hysteria func() string
	// Xray is the same for xray.exe (an updated core). Nil = Dir\xray.exe.
	Xray   func() string
	RunDir string
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
	// groups
	// Groups resolves server group targets. OnDial and OnHealth report the
	// dials and the status of routing endpoints only (tunnels.Manager).
	Groups *groups.Runtime
	// Extra: routes served in-process (TCP only) by a profile ID of their
	// own, as a server would be: «Telegram без VPN» (tgws.ProfileID).
	Extra    map[string]ExtraTunnel
	OnDial   func(profile, dst string, err error)
	OnHealth func(profile string, st hysteria.Status)
	// dns
	// DNS is the DNS policy (nil = off). ProfileName names a profile in the
	// DNS resolver's log lines (nil: its ID). OwnName reports one of
	// HyRoute's own hosts, whose lookups the policy passes on
	// (dnspolicy.OwnNames.Has of the controller; nil = none).
	DNS         *dnspolicy.Policy
	ProfileName func(id string) string
	OwnName     func(name string) bool
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
	FragDropped int64 `json:"fragDropped"`
	Malformed   int64 `json:"malformed"`
	Panics      int64 `json:"panics"`
	// PendingFull: packets the pending queue had no room for (a flow
	// decided without waiting for its owner, or a packet of a waiting flow
	// past its 8, dropped).
	PendingFull int64  `json:"pendingFull"`
	DNSPairs    int    `json:"dnsPairs"`
	NATEntries  int    `json:"natEntries"`
	RelayPort   int    `json:"relayPort"`
	Driver      string `json:"driverVersion"`
	// bigudp
	// FragReassembled: UDP datagrams reassembled from IP fragments and
	// routed whole; FragIncomplete: datagrams not reassembled (incomplete,
	// invalid, overlapping, over budget), dropped; FragOrphan: fragments
	// whose first fragment never came; FragLegacy: datagrams dropped at
	// their first fragment on the legacy path (TCP, IPv6 extension headers;
	// route not Direct); UDPTooBig: tunnel datagrams larger than Hysteria
	// carries, dropped (also in UDPDropped).
	FragReassembled int64 `json:"fragReassembled"`
	FragIncomplete  int64 `json:"fragIncomplete"`
	FragOrphan      int64 `json:"fragOrphan"`
	FragLegacy      int64 `json:"fragLegacy"`
	UDPTooBig       int64 `json:"udpTooBig"`
	// dns: queries HyRoute resolved through a tunnel or directly, passed on
	// as before, answered NXDOMAIN by a block rule, answered or blocked for
	// browser DoH, answered SERVFAIL, answered truncated, passed during the
	// captive-portal pause; SystemDoH: the Windows DNS client's encrypted
	// DNS connections seen (DNS policies cannot see those queries).
	DNSTunnel       int64 `json:"dnsTunnel"`
	DNSDirect       int64 `json:"dnsDirect"`
	DNSPassed       int64 `json:"dnsPassed"`
	DNSBlocked      int64 `json:"dnsBlocked"`
	DNSDoH          int64 `json:"dnsDoH"`
	DNSFailed       int64 `json:"dnsFailed"`
	DNSTruncated    int64 `json:"dnsTruncated"`
	DNSPortalPassed int64 `json:"dnsPortalPassed"`
	SystemDoH       int64 `json:"systemDoH"`
}

// ExtraTunnel is an in-process route (Config.Extra): TCP through the
// relay, no UDP.
type ExtraTunnel interface {
	Available() bool
	Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error)
}
