// Package cascade makes what a cascade link puts on its servers (P3-02):
// the link's credentials on the exit, the config and systemd unit of the
// Hysteria client on the entry, and the entry's outbound "cascade" to that
// client's SOCKS5 on loopback. Everything here is pure; the link job
// (P3-02b) writes it to the servers.
package cascade

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/profile"
)

// OutboundName is the entry's outbound to the link client. It goes first:
// the first outbound is the default, with or without ACL, so everything
// leaves through the exit but what ACL sends elsewhere.
const OutboundName = "cascade"

// Params are the settings of a link as stored (chain_links.params): no
// secrets.
type Params struct {
	// LocalPort is the port of the link client's SOCKS5 on the entry's
	// loopback, picked when the link is first deployed (0: not yet).
	LocalPort int `json:"localPort,omitempty"`
	// Up and Down are the link client's bandwidth ("100 mbps"; empty:
	// BBR).
	Up   string `json:"up,omitempty"`
	Down string `json:"down,omitempty"`
	// NoUDP: UDP does not go through the link (the client's SOCKS5
	// refuses UDP ASSOCIATE).
	NoUDP bool `json:"noUdp,omitempty"`
	// CheckTarget is what the link checks open through the exit (P3-03),
	// host:port; empty: the exit's address and SSH port.
	CheckTarget string `json:"checkTarget,omitempty"`
}

// Validate checks the params as the admin entered them.
func (p Params) Validate() error {
	if p.LocalPort != 0 && (p.LocalPort < 1024 || p.LocalPort > 65535) {
		return &model.FieldError{Field: "localPort", Msg: "Локальный порт связи: от 1024 до 65535."}
	}
	for _, b := range []struct{ field, v string }{{"up", p.Up}, {"down", p.Down}} {
		if b.v == "" {
			continue
		}
		if _, err := hyconfig.ParseBandwidth(b.v); err != nil {
			return &model.FieldError{Field: b.field, Msg: "Скорость связи: число с единицей, например 100 mbps."}
		}
	}
	if (p.Up == "") != (p.Down == "") {
		return &model.FieldError{Field: "up", Msg: "Укажите обе скорости связи (вверх и вниз) или ни одной."}
	}
	if p.CheckTarget != "" {
		if _, err := CheckAddr(p.CheckTarget); err != nil {
			return &model.FieldError{Field: "checkTarget", Msg: "Адрес проверки связи: хост:порт, например 1.1.1.1:443."}
		}
	}
	return nil
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// CheckAddr checks a host:port the link check opens through the exit and
// returns it as host:port again. Only names, IPv4 and IPv6 addresses: the
// value ends up on a command line (`hysteria ping`) and in a SOCKS5
// request.
func CheckAddr(s string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("bad port")
	}
	if net.ParseIP(host) == nil && (!hostRe.MatchString(host) || strings.HasPrefix(host, "-") || len(host) > 253) {
		return "", errors.New("bad host")
	}
	return net.JoinHostPort(host, port), nil
}

// Secrets of a link, sealed with model.LinkSecretContext.
type Secrets struct {
	// ExitPassword is the password of the link's own user on a userpass
	// exit. With password auth the link uses the exit's password, read
	// from its config whenever the link is made.
	ExitPassword string `json:"exitPassword,omitempty"`
	// SOCKSUser and SOCKSPassword guard the link client's SOCKS5: the
	// entry's own clients reach its 127.0.0.1 through direct.
	SOCKSUser     string `json:"socksUser"`
	SOCKSPassword string `json:"socksPassword"`
}

// NewSecrets makes the secrets of a new link.
func NewSecrets() (Secrets, error) {
	var s Secrets
	var err error
	if s.ExitPassword, err = random(); err != nil {
		return s, err
	}
	if s.SOCKSPassword, err = random(); err != nil {
		return s, err
	}
	s.SOCKSUser = "hyroute"
	return s, nil
}

// random is 24 random bytes, URL-safe base64: safe in YAML and URIs.
func random() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ID names a link on its servers: <chain>-<idx>.
func ID(chainID int64, idx int) string {
	return strconv.FormatInt(chainID, 10) + "-" + strconv.Itoa(idx)
}

// User is the link's own user on a userpass exit.
func User(chainID int64, idx int) string { return "link-" + ID(chainID, idx) }

// UnitName is the systemd unit of the link client on the entry.
func UnitName(chainID int64, idx int) string { return "hyroute-link-" + ID(chainID, idx) + ".service" }

// UnitPath is where the unit is written.
func UnitPath(chainID int64, idx int) string { return "/etc/systemd/system/" + UnitName(chainID, idx) }

// ConfigPath is the link client's config on the entry: next to the
// entry's own config (an imported server may keep it elsewhere than
// /etc/hysteria).
func ConfigPath(entry model.Installation, chainID int64, idx int) string {
	dir := "/etc/hysteria"
	if strings.HasPrefix(entry.Config, "/") {
		dir = path.Dir(entry.Config)
	}
	return path.Join(dir, "link-"+ID(chainID, idx)+".yaml")
}

// ErrAuth: the exit's clients log in with http or command auth, where
// HyRoute cannot make credentials for the link.
var ErrAuth = errors.New("cascade: the exit's auth is neither password nor userpass")

// ExitWith gives exit config c the link's credentials, in place, and
// reports whether it changed: a userpass exit gets the link's own user
// (or its password again); a password exit is left as it is.
func ExitWith(c *hyconfig.Server, user, password string) (bool, error) {
	switch strings.ToLower(c.Auth.Type) {
	case "password":
		return false, nil
	case "userpass":
		for u, p := range c.Auth.UserPass {
			if strings.EqualFold(u, user) {
				if u == user && p == password {
					return false, nil
				}
				delete(c.Auth.UserPass, u)
			}
		}
		if c.Auth.UserPass == nil {
			c.Auth.UserPass = map[string]string{}
		}
		c.Auth.UserPass[user] = password
		return true, nil
	}
	return false, ErrAuth
}

// HasUser reports whether exit config c has a userpass user named user
// (case-insensitively): before a link is first deployed, one there was
// made by someone else and must not get the link's password.
func HasUser(c *hyconfig.Server, user string) bool {
	for u := range c.Auth.UserPass {
		if strings.EqualFold(u, user) {
			return true
		}
	}
	return false
}

// ExitWithout removes the link's user from exit config c, in place.
func ExitWithout(c *hyconfig.Server, user string) bool {
	changed := false
	for u := range c.Auth.UserPass {
		if strings.EqualFold(u, user) {
			delete(c.Auth.UserPass, u)
			changed = true
		}
	}
	return changed
}

// ClientConfig is the link client's config on the entry: a client of the
// exit as its share links are (address, ports, hop interval, certificate
// check, obfs), logging in with the link's credentials, with SOCKS5 on the
// entry's loopback guarded by a password and no HTTP proxy. lazy is off:
// the client connects at start, so a broken link shows at once.
func ClientConfig(exit model.Server, exitCfg *hyconfig.Server, meta model.ConfigMeta, chainID int64, idx int, p Params, s Secrets) (*hyconfig.Client, error) {
	if p.LocalPort == 0 {
		return nil, errors.New("cascade: no local port")
	}
	o := profile.ClientOptions(exit, exitCfg, meta, "")
	switch strings.ToLower(exitCfg.Auth.Type) {
	case "password":
		o.Auth = exitCfg.Auth.Password
	case "userpass":
		o.Auth = User(chainID, idx) + ":" + s.ExitPassword
	default:
		return nil, ErrAuth
	}
	o.Bandwidth = hyconfig.Bandwidth{Up: p.Up, Down: p.Down}
	o.SOCKS5Listen = net.JoinHostPort("127.0.0.1", strconv.Itoa(p.LocalPort))
	c, err := hyconfig.ClientFor(exitCfg, o)
	if err != nil {
		return nil, err
	}
	c.HTTP = nil
	c.SOCKS5.Username, c.SOCKS5.Password, c.SOCKS5.DisableUDP = s.SOCKSUser, s.SOCKSPassword, p.NoUDP
	c.Lazy = false
	return c, nil
}

// Outbound is the entry's outbound to the link client.
func Outbound(port int, s Secrets) hyconfig.Outbound {
	return hyconfig.Outbound{Name: OutboundName, Type: "socks5", SOCKS5: hyconfig.OutboundSOCKS5{
		Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Username: s.SOCKSUser, Password: s.SOCKSPassword,
	}}
}

// HasOutbound reports whether entry config c has an outbound named
// "cascade" (Hysteria compares outbound names case-insensitively).
func HasOutbound(c *hyconfig.Server) bool {
	for _, o := range c.Outbounds {
		if strings.EqualFold(o.Name, OutboundName) {
			return true
		}
	}
	return false
}

// EntryWith puts the link's outbound first in entry config c, in place,
// replacing any outbound named "cascade", and reports whether it changed.
func EntryWith(c *hyconfig.Server, port int, s Secrets) bool {
	want := Outbound(port, s)
	if len(c.Outbounds) > 0 && same(c.Outbounds[0], want) {
		rest := false
		for _, o := range c.Outbounds[1:] {
			rest = rest || strings.EqualFold(o.Name, OutboundName)
		}
		if !rest {
			return false
		}
	}
	obs := []hyconfig.Outbound{want}
	for _, o := range c.Outbounds {
		if !strings.EqualFold(o.Name, OutboundName) {
			obs = append(obs, o)
		}
	}
	c.Outbounds = obs
	return true
}

// EntryWithout removes the outbound "cascade" from entry config c, in
// place, and reports whether it changed. Without outbounds left Hysteria
// goes direct, as before the link.
func EntryWithout(c *hyconfig.Server) bool {
	var obs []hyconfig.Outbound
	for _, o := range c.Outbounds {
		if !strings.EqualFold(o.Name, OutboundName) {
			obs = append(obs, o)
		}
	}
	changed := len(obs) != len(c.Outbounds)
	c.Outbounds = obs
	return changed
}

func same(a, b hyconfig.Outbound) bool {
	return a.Name == b.Name && strings.EqualFold(a.Type, b.Type) && a.SOCKS5.Addr == b.SOCKS5.Addr &&
		a.SOCKS5.Username == b.SOCKS5.Username && a.SOCKS5.Password == b.SOCKS5.Password && len(a.Unknown) == 0 && len(a.SOCKS5.Unknown) == 0
}

var userRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// UnitText is the systemd unit of the link client: the entry's Hysteria
// binary as the entry service's user, no update checks (they would go
// through the link to api.hy2.io), restarted whenever it stops.
func UnitText(entry model.Installation, chainID int64, idx int) (string, error) {
	bin := entry.Binary
	if !strings.HasPrefix(bin, "/") || strings.ContainsAny(bin, " \t\n\\\"'%$;") {
		return "", fmt.Errorf("cascade: unusable binary path %q", bin)
	}
	cfg := ConfigPath(entry, chainID, idx)
	if strings.ContainsAny(cfg, " \t\n\\\"'%$;") {
		return "", fmt.Errorf("cascade: unusable config path %q", cfg)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Unit]\nDescription=HyRoute cascade link %s (Hysteria client)\nAfter=network-online.target\nWants=network-online.target\n\n", ID(chainID, idx))
	fmt.Fprintf(&b, "[Service]\nType=simple\nExecStart=%s client --config %s --disable-update-check\nWorkingDirectory=~\n", bin, cfg)
	if u := entry.User; u != "" && u != "root" {
		if !userRe.MatchString(u) {
			return "", fmt.Errorf("cascade: unusable service user %q", u)
		}
		fmt.Fprintf(&b, "User=%s\nGroup=%s\n", u, u)
	}
	b.WriteString("Environment=HYSTERIA_LOG_LEVEL=info\nNoNewPrivileges=true\nRestart=always\nRestartSec=5s\n\n[Install]\nWantedBy=multi-user.target\n")
	return b.String(), nil
}
