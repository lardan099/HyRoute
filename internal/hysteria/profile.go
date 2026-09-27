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
	"strconv"
	"strings"
	"time"
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
func ValidPin(s string) bool {
	s = strings.NewReplacer(":", "", "-", "").Replace(strings.TrimSpace(s))
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// HostIsIP reports whether Host is an IP literal.
func (p *Profile) HostIsIP() bool {
	_, err := netip.ParseAddr(p.Host)
	return err == nil
}

// PortRange is an inclusive range.
type PortRange struct{ From, To uint16 }

// ParsePorts parses "443", "20000-50000", "443,20000-50000".
func ParsePorts(s string) ([]PortRange, error) {
	if s == "" {
		return nil, errors.New("server port is empty")
	}
	var out []PortRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = parsePort(hi); err != nil {
				return nil, err
			}
			if b < a {
				return nil, fmt.Errorf("bad port range %q", part)
			}
		}
		out = append(out, PortRange{a, b})
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}

// ServerString formats host (or an override IP) with the ports spec the way
// Hysteria's "server" field expects it: every IPv6 literal (IPv4-mapped
// too) in brackets, the ports without the spaces ParsePorts tolerates
// (Hysteria rejects "443, 20000-50000").
func ServerString(host, ports string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strings.Join(strings.Fields(ports), "")
}
