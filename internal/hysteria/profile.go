// Package hysteria manages HyRoute's server profiles (URI import/export,
// config generation) and supervises the process that runs one: hysteria.exe
// for Hysteria 2, xray.exe for VLESS (internal/vless), HyRoute itself for
// AmneziaWG (internal/awg).
//
// Field names follow https://v2.hysteria.network/docs/advanced/Full-Client-Config/
// (checked against apernet/hysteria app/v2.12.3).
package hysteria

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/awg"
	"github.com/lardan099/hyroute/internal/hy2uri"
	"github.com/lardan099/hyroute/internal/vless"
)

// Protocols of a profile.
const (
	ProtoHysteria2 = "" // the default: profiles saved before VLESS have none
	ProtoVLESS     = "vless"
	ProtoAWG       = "awg"
)

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Protocol is "" (Hysteria 2) or "vless" (run by Xray). A VLESS
	// profile uses Host, Ports (one port), PinServerIP and VLESS; the
	// Hysteria fields stay empty.
	Protocol string         `json:"protocol,omitempty"`
	VLESS    vless.Settings `json:"vless,omitzero"`
	Balance  *vless.Balance `json:"balance,omitempty"`
	// AWG is an AmneziaWG (or plain WireGuard) server's settings; it uses
	// Host and Ports (one port) for the endpoint.
	AWG awg.Settings `json:"awg,omitzero"`
	// Host is a domain or IP literal (no brackets).
	Host string `json:"host"`
	// Ports is "443", "20000-50000" or "443,20000-50000" (port hopping).
	Ports string `json:"ports"`
	Auth  string `json:"auth"`

	TLS        TLS        `json:"tls"`
	Obfs       Obfs       `json:"obfs"`
	Hop        Hop        `json:"hop"`
	Bandwidth  Bandwidth  `json:"bandwidth"`
	Congestion Congestion `json:"congestion"`
	QUIC       QUIC       `json:"quic"`
	FastOpen   bool       `json:"fastOpen,omitempty"`

	// PinServerIP makes HyRoute resolve Host itself and hand Hysteria the IP,
	// so the excluded IP is exactly the one Hysteria connects to.
	PinServerIP bool `json:"pinServerIP"`
	// Via is the ID of the profile that carries this server's connection.
	Via string `json:"via,omitempty"`

	// Source is "" for profiles added by hand, "sub:<id>" for profiles
	// that a subscription manages.
	Source string `json:"source,omitempty"`
	// Missing: the subscription no longer lists this profile; it is kept
	// because a rule uses it.
	Missing bool `json:"missing,omitempty"`
}

// SameConnection reports whether two profiles produce the same Hysteria
// config (name, ID and bookkeeping fields do not matter).
func SameConnection(a, b Profile) bool {
	strip := func(p Profile) Profile {
		p.ID, p.Name, p.Source, p.Missing = "", "", "", false
		return p
	}
	return reflect.DeepEqual(strip(a), strip(b))
}

// SameConnectionNoSecrets is SameConnection with the secrets (ClearSecrets)
// ignored: the same server, whatever the credentials. Only a server equal
// in every other connection field may inherit secrets (backup).
func SameConnectionNoSecrets(a, b Profile) bool {
	a.ClearSecrets()
	b.ClearSecrets()
	return SameConnection(a, b)
}

// IsVLESS: the profile runs through Xray.
func (p *Profile) IsVLESS() bool { return p.Protocol == ProtoVLESS }

// IsAWG: the profile is an AmneziaWG (or WireGuard) server.
func (p *Profile) IsAWG() bool { return p.Protocol == ProtoAWG }

// Probed: the server is up once a request went through it (Xray and
// AmneziaWG report no connection of their own, see xray.go).
func (p *Profile) Probed() bool { return p.IsVLESS() || p.IsAWG() }

// ProtocolName names the protocol for the user.
func (p *Profile) ProtocolName() string {
	switch {
	case p.IsVLESS():
		return "VLESS"
	case p.IsAWG():
		return "AmneziaWG"
	}
	return "Hysteria 2"
}

// CoreName names the program that runs the profile.
func (p *Profile) CoreName() string {
	switch {
	case p.IsVLESS():
		return "Xray"
	case p.IsAWG():
		return "AmneziaWG"
	}
	return "Hysteria"
}

// Normalize clears the fields of the other protocols (an editor may send
// them all) and puts VLESS's transport name in HyRoute's form.
func (p *Profile) Normalize() {
	if p.Protocol != ProtoHysteria2 {
		p.Auth, p.TLS, p.Obfs, p.Hop, p.Bandwidth, p.Congestion, p.QUIC, p.FastOpen = "", TLS{}, Obfs{}, Hop{}, Bandwidth{}, Congestion{}, QUIC{}, false
	}
	if !p.IsAWG() {
		p.AWG = awg.Settings{}
	}
	if p.IsAWG() {
		p.VLESS = vless.Settings{}
		// HyRoute resolves the endpoint itself: amneziawg-go takes an IP.
		p.PinServerIP = false
		p.AWG.Trim()
		return
	}
	if p.IsVLESS() {
		p.VLESS.Network = vless.NormalizeNetwork(p.VLESS.Network)
		if p.VLESS.Encryption == "none" {
			p.VLESS.Encryption = ""
		}
		return
	}
	p.VLESS = vless.Settings{}
}

// Transport describes the connection for the list: "REALITY",
// "WS · TLS", "XHTTP · REALITY" (VLESS); "WireGuard" for an AmneziaWG
// server without obfuscation.
func (p *Profile) Transport() string {
	if p.IsAWG() && !p.AWG.Obfuscated() {
		return "WireGuard"
	}
	if !p.IsVLESS() {
		return ""
	}
	sec := map[string]string{"": "", "tls": "TLS", "reality": "REALITY"}[p.VLESS.Security]
	net := map[string]string{"": "", "ws": "WS", "grpc": "gRPC", "httpupgrade": "HTTPUpgrade", "xhttp": "XHTTP", "kcp": "mKCP"}[p.VLESS.Network]
	switch {
	case net == "" && sec == "":
		return "TCP"
	case net == "":
		return sec
	case sec == "":
		return net
	}
	return net + " · " + sec
}

// Secrets are the values no log may show: the auth and obfuscation
// passwords of Hysteria, the user ID of VLESS, the keys of AmneziaWG.
func (p *Profile) Secrets() []string {
	return slices.Concat([]string{p.Auth, p.Obfs.Password, p.VLESS.ID}, p.BalanceIDs(), p.AWG.Secrets())
}

// ClearSecrets empties the secrets (a backup without them).
func (p *Profile) ClearSecrets() {
	p.Auth, p.Obfs.Password, p.VLESS.ID = "", "", ""
	p.SetBalanceIDs(nil)
	p.AWG.ClearSecrets()
}

// HasSecrets: any secret is set.
func (p *Profile) HasSecrets() bool {
	return slices.ContainsFunc(p.Secrets(), func(secret string) bool { return secret != "" })
}

// CopySecrets takes the secrets of from.
func (p *Profile) CopySecrets(from Profile) {
	p.Auth, p.Obfs.Password, p.VLESS.ID = from.Auth, from.Obfs.Password, from.VLESS.ID
	p.SetBalanceIDs(from.BalanceIDs())
	p.AWG.CopySecrets(from.AWG)
}

func (p *Profile) BalanceIDs() []string {
	if p.Balance == nil {
		return nil
	}
	ids := make([]string, len(p.Balance.Nodes))
	for i, n := range p.Balance.Nodes {
		ids[i] = n.Settings.ID
	}
	return ids
}

// SetBalanceIDs copies the nodes before changing their IDs because profiles
// are commonly copied by value, including for secret-free backups.
func (p *Profile) SetBalanceIDs(ids []string) {
	if p.Balance == nil {
		return
	}
	b := *p.Balance
	b.Nodes = slices.Clone(b.Nodes)
	for i := range b.Nodes {
		b.Nodes[i].Settings.ID = ""
		if i < len(ids) {
			b.Nodes[i].Settings.ID = ids[i]
		}
	}
	p.Balance = &b
}

type TLS struct {
	SNI       string `json:"sni,omitempty"`
	Insecure  bool   `json:"insecure,omitempty"`
	PinSHA256 string `json:"pinSHA256,omitempty"`
	CA        string `json:"ca,omitempty"`
	ECH       string `json:"ech,omitempty"`
}

type Obfs struct {
	Type          string `json:"type,omitempty"` // "", "salamander", "gecko"
	Password      string `json:"password,omitempty"`
	MinPacketSize int    `json:"minPacketSize,omitempty"` // gecko
	MaxPacketSize int    `json:"maxPacketSize,omitempty"` // gecko
}

// Hop configures port hopping intervals (durations like "30s").
type Hop struct {
	Interval    string `json:"interval,omitempty"`
	MinInterval string `json:"minInterval,omitempty"`
	MaxInterval string `json:"maxInterval,omitempty"`
}

type Bandwidth struct {
	Up   string `json:"up,omitempty"`
	Down string `json:"down,omitempty"`
}

type Congestion struct {
	Type       string `json:"type,omitempty"` // "bbr", "reno"
	BBRProfile string `json:"bbrProfile,omitempty"`
}

type QUIC struct {
	InitStreamReceiveWindow uint64 `json:"initStreamReceiveWindow,omitempty"`
	MaxStreamReceiveWindow  uint64 `json:"maxStreamReceiveWindow,omitempty"`
	InitConnReceiveWindow   uint64 `json:"initConnReceiveWindow,omitempty"`
	MaxConnReceiveWindow    uint64 `json:"maxConnReceiveWindow,omitempty"`
	MaxIdleTimeout          string `json:"maxIdleTimeout,omitempty"`
	KeepAlivePeriod         string `json:"keepAlivePeriod,omitempty"`
	DisablePathMTUDiscovery bool   `json:"disablePathMTUDiscovery,omitempty"`
	DisableChromeParrot     bool   `json:"disableChromeParrot,omitempty"`
}

// Validate checks the fields HyRoute relies on.
func (p *Profile) Validate() error {
	if p.Via != "" && p.ID == p.Via {
		return errors.New("профиль не может подключаться через себя")
	}
	if p.Balance != nil {
		q := *p
		q.ID, q.Name, q.Source, q.Protocol, q.Missing, q.Balance, q.Via = "", "", "", "", false, nil, ""
		if !p.IsVLESS() || !reflect.DeepEqual(q, Profile{}) {
			return errors.New("балансировщик Xray хранит адреса и параметры только в узлах")
		}
		if p.Via != "" {
			if err := p.Balance.ValidateChain(); err != nil {
				return err
			}
		}
		return p.Balance.Validate()
	}
	if p.Host == "" {
		return errors.New("server host is empty")
	}
	switch p.Protocol {
	case ProtoHysteria2:
	case ProtoVLESS:
		return p.validateVLESS()
	case ProtoAWG:
		return p.validateAWG()
	default:
		return fmt.Errorf("протокол %q не поддерживается", p.Protocol)
	}
	if _, err := ParsePorts(p.Ports); err != nil {
		return err
	}
	if p.Via != "" {
		if _, err := VLESSPort(p.Ports); err != nil {
			return errors.New("для Hysteria 2 через другой VPN нужен один порт")
		}
	}
	switch strings.ToLower(p.Obfs.Type) {
	case "":
	case "salamander", "gecko":
		if p.Obfs.Password == "" {
			return errors.New("obfs password is empty")
		}
	default:
		return fmt.Errorf("unsupported obfs type %q", p.Obfs.Type)
	}
	for _, d := range []string{p.Hop.Interval, p.Hop.MinInterval, p.Hop.MaxInterval, p.QUIC.MaxIdleTimeout, p.QUIC.KeepAlivePeriod} {
		if d == "" {
			continue
		}
		if _, err := time.ParseDuration(d); err != nil {
			return fmt.Errorf("bad duration %q", d)
		}
	}
	// Hysteria reads a non-inline ECH value as a file (see ECHInline):
	// only a full path on a drive letter, never a network or device path.
	if e := p.TLS.ECH; e != "" && !ECHInline(e) && !localDrivePath(e) {
		return errors.New("ECH: нужен список ECHConfigList в base64 или полный путь к файлу на локальном диске")
	}
	// The CA file too is read by Hysteria with HyRoute's rights: a local
	// file only. It is plain text in profiles.json.
	if ca := p.TLS.CA; ca != "" && !localFilePath(ca) {
		return errors.New("CA: нужен полный путь к файлу на локальном диске")
	}
	// Hysteria refuses to start with a shorter one (0 is its default).
	for _, d := range []string{p.Hop.Interval, p.Hop.MinInterval, p.Hop.MaxInterval} {
		if v, _ := time.ParseDuration(d); v != 0 && v < hy2uri.MinHopInterval {
			return fmt.Errorf("интервал port hopping %s: Hysteria принимает не меньше %s", d, hy2uri.MinHopInterval)
		}
	}
	return nil
}

// validateVLESS: one port, no Hysteria settings, and VLESS settings Xray
// takes for this host.
func (p *Profile) validateVLESS() error {
	if _, err := VLESSPort(p.Ports); err != nil {
		return err
	}
	q := *p
	q.ID, q.Name, q.Source, q.Missing, q.Host, q.Ports, q.Protocol, q.VLESS, q.PinServerIP = "", "", "", false, "", "", "", vless.Settings{}, false
	q.Via = ""
	if !reflect.DeepEqual(q, Profile{}) {
		return errors.New("у сервера VLESS не бывает настроек Hysteria (auth, obfs, port hopping, скорость, QUIC)")
	}
	if p.Via != "" {
		if err := p.VLESS.ValidateChain(); err != nil {
			return err
		}
	}
	return p.VLESS.ValidateFor(p.Host)
}

// validateAWG: one port, no settings of the other protocols, and settings
// amneziawg-go takes.
func (p *Profile) validateAWG() error {
	rs, err := ParsePorts(p.Ports)
	if err != nil {
		return err
	}
	if len(rs) != 1 || rs[0].From != rs[0].To {
		return errors.New("у сервера AmneziaWG один порт, без диапазонов")
	}
	q := *p
	q.ID, q.Name, q.Source, q.Missing, q.Host, q.Ports, q.Protocol, q.AWG, q.PinServerIP, q.Via = "", "", "", false, "", "", "", awg.Settings{}, false, ""
	if !reflect.DeepEqual(q, Profile{}) {
		return errors.New("у сервера AmneziaWG не бывает настроек Hysteria и VLESS")
	}
	return p.AWG.Validate()
}

// VLESSPort is the one port of a VLESS server.
func VLESSPort(ports string) (int, error) {
	rs, err := ParsePorts(ports)
	if err != nil {
		return 0, err
	}
	if len(rs) != 1 || rs[0].From != rs[0].To {
		return 0, errors.New("у сервера VLESS один порт, без диапазонов")
	}
	return int(rs[0].From), nil
}

// localDrivePath: "X:\..." with no second colon and no forward slashes;
// UNC (\\host\share), device (\\?\, \\.\) and relative paths fail.
func localDrivePath(s string) bool {
	if len(s) < 4 || s != strings.TrimSpace(s) || strings.ContainsAny(s, "/") {
		return false
	}
	c := s[0] | 0x20
	return c >= 'a' && c <= 'z' && s[1] == ':' && s[2] == '\\' && !strings.Contains(s[2:], ":")
}

// localFilePath: a full path to a local file: localDrivePath (on any
// system: profiles and backups made on Windows are read elsewhere too),
// or an absolute path outside Windows.
func localFilePath(s string) bool {
	if localDrivePath(s) {
		return true
	}
	return runtime.GOOS != "windows" && s == strings.TrimSpace(s) && filepath.IsAbs(s)
}

// ValidPin accepts the formats Hysteria normalizes: hex with optional ':'
// or '-' separators, any case.
func ValidPin(s string) bool { return hy2uri.ValidPin(s) }

// HostIsIP reports whether Host is an IP literal.
func (p *Profile) HostIsIP() bool {
	_, err := netip.ParseAddr(p.Host)
	return err == nil
}

// PortRange is an inclusive range.
type PortRange struct{ From, To uint16 }

// ParsePorts parses "443", "20000-50000", "443,20000-50000".
func ParsePorts(s string) ([]PortRange, error) {
	rs, err := hy2uri.ParsePorts(s)
	if err != nil {
		return nil, err
	}
	out := make([]PortRange, len(rs))
	for i, r := range rs {
		out[i] = PortRange(r)
	}
	return out, nil
}

// NormalizePorts is the port set of a spec in one form, for telling
// whether two profiles name the same server (see hy2uri.NormalizePorts).
func NormalizePorts(s string) string { return hy2uri.NormalizePorts(s) }

// ServerString formats host (or an override IP) with the ports spec the way
// Hysteria's "server" field expects it (see hy2uri.ServerString).
func ServerString(host, ports string) string { return hy2uri.ServerString(host, ports) }
