// Package hysteria manages Hysteria 2 client profiles (URI import/export,
// YAML generation) and supervises the hysteria.exe child process.
//
// Field names follow https://v2.hysteria.network/docs/advanced/Full-Client-Config/
// (checked against apernet/hysteria app/v2.12.3).
package hysteria

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hy2uri"
)

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
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

// SameConnectionNoSecrets is SameConnection with Auth and the obfuscation
// password ignored: the same server, whatever the credentials. Only a
// server equal in every other connection field may inherit secrets
// (backup).
func SameConnectionNoSecrets(a, b Profile) bool {
	a.Auth, a.Obfs.Password, b.Auth, b.Obfs.Password = "", "", "", ""
	return SameConnection(a, b)
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
	if p.Host == "" {
		return errors.New("server host is empty")
	}
	if _, err := ParsePorts(p.Ports); err != nil {
		return err
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
	return nil
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
