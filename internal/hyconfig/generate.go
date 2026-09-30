package hyconfig

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Listen is a parsed server listen address.
type Listen struct {
	Host    string // "" for all interfaces
	Ports   string // as written: "443", "20000-50000", "443,8443"
	First   int    // the port the server actually binds
	Hopping bool   // a port union: the server redirects the rest to First
}

// DefaultListen is the listen address when the field is empty.
const DefaultListen = ":443"

// ParseListen parses a listen address ("" means :443). Realms URIs are
// not addresses and fail.
func ParseListen(s string) (Listen, error) {
	if s == "" {
		s = DefaultListen
	}
	if strings.Contains(s, "://") {
		return Listen{}, errors.New("адрес Realms, а не host:port")
	}
	host, ports, err := net.SplitHostPort(s)
	if err != nil {
		return Listen{}, fmt.Errorf("неверный адрес %q (пример: :443 или :20000-50000)", s)
	}
	l := Listen{Host: host, Ports: ports, Hopping: strings.ContainsAny(ports, "-,")}
	if !l.Hopping {
		p, err := strconv.Atoi(ports)
		if err != nil || p < 1 || p > 65535 {
			return Listen{}, fmt.Errorf("неверный порт %q", ports)
		}
		l.First = p
		return l, nil
	}
	first, ok := portUnionFirst(ports)
	if !ok {
		return Listen{}, fmt.Errorf("неверный диапазон портов %q", ports)
	}
	l.First = first
	return l, nil
}

// portUnionFirst checks "443,20000-50000" (ports 1–65535) and returns the
// lowest port, which is the one Hysteria binds.
func portUnionFirst(s string) (int, bool) {
	first := 0
	for _, part := range strings.Split(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			return 0, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < 1 || b > 65535 {
				return 0, false
			}
		}
		if b < a {
			a = b
		}
		if first == 0 || a < first {
			first = a
		}
	}
	return first, first != 0
}

// validPortUnion checks a port list; all allows the "all" and "*"
// wildcards (sniff ports).
func validPortUnion(s string, all bool) bool {
	if all && (s == "all" || s == "*") {
		return true
	}
	_, ok := portUnionFirst(s)
	return ok
}

// SplitServer splits a client server field ("host:443",
// "[2001:db8::1]:20000-50000") into host and ports.
func SplitServer(s string) (host, ports string, err error) {
	host, ports, err = net.SplitHostPort(s)
	if err != nil || host == "" {
		return "", "", fmt.Errorf("неверный адрес сервера %q (нужно host:порт)", s)
	}
	if !validPortUnion(ports, false) {
		return "", "", fmt.Errorf("неверные порты %q", ports)
	}
	return host, ports, nil
}

// ClientOptions is what the controller knows beyond the server config.
type ClientOptions struct {
	Host string // public name or IP of the server
	// Ports overrides the ports from listen (a NAT or a different public
	// range).
	Ports string
	// SNI overrides the TLS server name. By default the first ACME domain
	// is used when Host is not one of the domains.
	SNI string
	// PinSHA256 is the pin of a self-signed certificate: the client then
	// skips the chain check and verifies the pin instead.
	PinSHA256 string
	// User picks the userpass user (may be omitted when there is one).
	User string
	// Auth overrides the auth string; required for http and command
	// authentication, whose passwords the controller does not know.
	Auth        string
	HopInterval Duration // port hopping interval, when the ports are a union
	Bandwidth   Bandwidth
	// Local inbounds; empty means 127.0.0.1:1080 and 127.0.0.1:8080.
	SOCKS5Listen string
	HTTPListen   string
}

// ClientFor builds the client config for a server config. It does not
// cover ECH (the client needs the config list the server logs at start).
func ClientFor(s *Server, o ClientOptions) (*Client, error) {
	host := strings.Trim(o.Host, "[]")
	if host == "" || strings.ContainsAny(host, " /@?#") {
		return nil, errors.New("не указан адрес сервера")
	}
	ports := o.Ports
	if ports == "" {
		l, err := ParseListen(s.Listen)
		if err != nil {
			return nil, err
		}
		ports = l.Ports
	}
	c := &Client{Server: net.JoinHostPort(host, ports), Mimic: Mimic{Enabled: s.Mimic.Enabled}}

	auth, err := clientAuth(&s.Auth, o)
	if err != nil {
		return nil, err
	}
	c.Auth = auth

	c.TLS.SNI = o.SNI
	if s.ACME != nil && len(s.ACME.Domains) > 0 && c.TLS.SNI == "" && !containsFold(s.ACME.Domains, host) {
		c.TLS.SNI = s.ACME.Domains[0]
	}
	if o.PinSHA256 != "" {
		// Hysteria checks the pin in addition to the chain, so a
		// self-signed certificate needs insecure to get to the pin.
		c.TLS.Insecure = true
		c.TLS.PinSHA256 = o.PinSHA256
	}

	switch strings.ToLower(s.Obfs.Type) {
	case "salamander":
		c.Obfs = Obfs{Type: "salamander", Salamander: Salamander{Password: s.Obfs.Salamander.Password}}
	case "gecko":
		c.Obfs = Obfs{Type: "gecko", Gecko: Gecko{Password: s.Obfs.Gecko.Password}}
	}
	if o.HopInterval != "" && strings.ContainsAny(ports, "-,") {
		c.Transport.UDP.HopInterval = o.HopInterval
	}
	c.Bandwidth = Bandwidth{Up: o.Bandwidth.Up, Down: o.Bandwidth.Down}
	c.SOCKS5 = &SOCKS5{Listen: or(o.SOCKS5Listen, "127.0.0.1:1080")}
	c.HTTP = &HTTPProxy{Listen: or(o.HTTPListen, "127.0.0.1:8080")}

	for _, p := range c.Validate() {
		if !p.Warning {
			return nil, fmt.Errorf("%s: %s", p.Field, p.Message)
		}
	}
	return c, nil
}

func clientAuth(a *Auth, o ClientOptions) (string, error) {
	if o.Auth != "" {
		return o.Auth, nil
	}
	switch strings.ToLower(a.Type) {
	case "password":
		return a.Password, nil
	case "userpass":
		user := o.User
		if user == "" {
			if len(a.UserPass) != 1 {
				return "", errors.New("выберите пользователя")
			}
			for u := range a.UserPass {
				user = u
			}
		}
		for u, p := range a.UserPass {
			if strings.EqualFold(u, user) {
				return u + ":" + p, nil
			}
		}
		return "", fmt.Errorf("нет пользователя %q", user)
	}
	return "", errors.New("пароль клиента проверяет внешний сервис: укажите его вручную")
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func or(v, def string) string {
	if v != "" {
		return v
	}
	return def
}
