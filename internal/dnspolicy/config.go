// Package dnspolicy decides what happens to a DNS query HyRoute
// intercepts: passed on as before, answered at once (NXDOMAIN, NODATA,
// SERVFAIL) or resolved upstream through a rule's tunnel or directly over
// DoH/DoT. It holds the settings of «Настройки» → «DNS» (dns.json), the
// curated lists (browser DoH servers, local names) and the classifier. It
// does no I/O.
package dnspolicy

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/lardan099/hyroute/internal/rules"
)

// Config is the DNS policy the user chose (dns.json, in memory). Every
// option is off by default.
type Config struct {
	BlockBrowserDoH bool `json:"blockBrowserDoH"`
	// StripECH is effective only with BlockBrowserDoH.
	StripECH bool `json:"stripECH"`
	ByRules  bool `json:"byRules"`
	// IgnoreAddrRules: address rules do not count for names (the option
	// «Сверяться с правилами по IP и geoip» turned off); false = the
	// default, on.
	IgnoreAddrRules bool     `json:"ignoreAddrRules"`
	Tunnel          Upstream `json:"tunnel"`
	Direct          Upstream `json:"direct"`
}

// Upstream is a preset ID ("" = the default: "cloudflare" for Tunnel, off
// for Direct) or "custom" with URL.
type Upstream struct {
	Preset string `json:"preset"`
	URL    string `json:"url,omitempty"` // custom only; a secret (may carry an account ID)
}

// Custom is the preset ID of a user's own server.
const Custom = "custom"

// CustomName is how a custom server is named in the UI, logs and
// diagnostics: its URL never is.
const CustomName = "свой сервер"

// Preset is a well-known resolver. Bootstrap addresses are dialled instead
// of resolving the host (no chicken-and-egg, no system resolver); TLS
// checks the certificate against the host.
type Preset struct {
	ID, Name, URL  string
	Bootstrap      []netip.Addr
	Tunnel, Direct bool // may be chosen for «DNS-сервер для VPN» / for direct names
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// Presets in the order the UI lists them.
var Presets = []Preset{
	{ID: "cloudflare", Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query",
		Bootstrap: addrs("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"), Tunnel: true, Direct: true},
	{ID: "google", Name: "Google", URL: "https://dns.google/dns-query",
		Bootstrap: addrs("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"), Tunnel: true, Direct: true},
	{ID: "quad9", Name: "Quad9", URL: "https://dns.quad9.net/dns-query",
		Bootstrap: addrs("9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"), Tunnel: true, Direct: true},
	{ID: "adguard", Name: "AdGuard (без рекламы)", URL: "https://dns.adguard-dns.com/dns-query",
		Bootstrap: addrs("94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"), Tunnel: true, Direct: true},
	{ID: "yandex", Name: "Яндекс", URL: "https://common.dot.dns.yandex.net/dns-query",
		Bootstrap: addrs("77.88.8.8", "77.88.8.1", "2a02:6b8::feed:0ff", "2a02:6b8:0:1::feed:0ff"), Tunnel: false, Direct: true},
}

// DefaultTunnel is the preset of «DNS-сервер для VPN» when none is chosen.
const DefaultTunnel = "cloudflare"

// FindPreset returns the preset with id, or nil.
func FindPreset(id string) *Preset {
	for i := range Presets {
		if Presets[i].ID == id {
			return &Presets[i]
		}
	}
	return nil
}

// Spec is a parsed upstream.
type Spec struct {
	Scheme    string       // "https" | "tls" | "tcp"
	Host      string       // normalized name or IP literal (no brackets)
	Port      uint16       // default 443 / 853 / 53
	Path      string       // https only; default "/dns-query"; query kept
	Bootstrap []netip.Addr // presets only
	Name      string       // UI: preset name or CustomName
}

// IP is Host as an address, when it is one.
func (s Spec) IP() (netip.Addr, bool) {
	a, err := netip.ParseAddr(s.Host)
	return a, err == nil
}

// The validation messages of «Свой…» (the card shows them as they are).
var (
	errEmpty     = InputError("Укажите адрес DNS-сервера: https://…/dns-query или tls://…")
	errURL       = InputError("Неверный адрес DNS-сервера: нужен https://…, tls://… или tcp://…")
	errUserinfo  = InputError("Адрес DNS-сервера не должен содержать логин, пароль, # и пробелы")
	errPort      = InputError("Неверный порт DNS-сервера")
	errTooLong   = InputError("Слишком длинный адрес DNS-сервера")
	errLocal     = InputError("Этот адрес находится в вашей локальной сети и через VPN недоступен")
	errPlainTCP  = InputError("Для прямых запросов нужен зашифрованный сервер: https://… или tls://…")
	maxURLLength = 2048
)

func errHost(h string) error {
	return HostError{InputError(fmt.Sprintf("Неверное имя или IP DNS-сервера «%s»", h))}
}

// HostError: a custom server's host is not a valid name or IP. Its text
// quotes the host, which can carry an account ID (a load error of dns.json
// shows only its class).
type HostError struct{ InputError }

// InputError is a message for the card, shown as it is.
type InputError string

func (e InputError) Error() string { return string(e) }

// ParseUpstream parses a custom server address: https://host[:port]/path,
// tls://host[:port] or tcp://host[:port]. tunnel: the server is reached
// through a tunnel (plain tcp:// is allowed, a local address is not); else
// directly (only encrypted transports).
func ParseUpstream(raw string, tunnel bool) (Spec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Spec{}, errEmpty
	}
	if len(raw) > maxURLLength {
		return Spec{}, errTooLong
	}
	if strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r == '#' }) {
		return Spec{}, errUserinfo
	}
	u, err := url.Parse(raw)
	if err != nil {
		if strings.Contains(err.Error(), "port") {
			return Spec{}, errPort
		}
		return Spec{}, errURL
	}
	s := Spec{Scheme: strings.ToLower(u.Scheme), Name: CustomName}
	switch s.Scheme {
	case "https":
		s.Port = 443
	case "tls":
		s.Port = 853
	case "tcp":
		s.Port = 53
	default:
		return Spec{}, errURL
	}
	if u.User != nil {
		return Spec{}, errUserinfo
	}
	if u.Opaque != "" || u.Host == "" {
		return Spec{}, errURL
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Spec{}, errPort
		}
		s.Port = uint16(n)
	} else if strings.HasSuffix(u.Host, ":") {
		return Spec{}, errPort
	}
	host := u.Hostname()
	if h, ok := cleanHost(host); ok {
		s.Host = h
	} else {
		return Spec{}, errHost(host)
	}
	if s.Scheme == "https" {
		s.Path = u.EscapedPath()
		if s.Path == "" || s.Path == "/" {
			s.Path = "/dns-query"
		}
		if u.RawQuery != "" {
			s.Path += "?" + u.RawQuery
		}
	} else if p := u.EscapedPath(); p != "" && p != "/" || u.RawQuery != "" {
		return Spec{}, errURL
	}
	if a, ok := s.IP(); ok && tunnel && (a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified()) {
		return Spec{}, errLocal
	}
	if !tunnel && s.Scheme == "tcp" {
		return Spec{}, errPlainTCP
	}
	return s, nil
}

// cleanHost normalizes a server host: an IP literal (brackets trimmed, no
// zone) or a DNS name (IDN to punycode, labels of [a-z0-9-], 63 bytes each,
// 253 in all).
func cleanHost(h string) (string, bool) {
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if h == "" {
		return "", false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Zone() != "" {
			return "", false
		}
		return a.Unmap().String(), true
	}
	if strings.Contains(h, ":") {
		return "", false
	}
	n := rules.NormalizeDomain(h)
	if n == "" || len(n) > 253 {
		return "", false
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return n, true
}

// Spec resolves u: a preset (its URL and bootstrap addresses) or the
// custom URL. tunnel selects the defaults and rules of «DNS-сервер для
// VPN» ("" = DefaultTunnel); for direct names "" means off and has no Spec.
func (u Upstream) Spec(tunnel bool) (Spec, error) {
	id := u.Preset
	if id == "" && tunnel {
		id = DefaultTunnel
	}
	if id == Custom {
		return ParseUpstream(u.URL, tunnel)
	}
	p := FindPreset(id)
	if p == nil {
		return Spec{}, fmt.Errorf("неизвестный DNS-сервер %q", u.Preset)
	}
	if tunnel && !p.Tunnel || !tunnel && !p.Direct {
		return Spec{}, InputError(fmt.Sprintf("DNS-сервер «%s» здесь выбрать нельзя", p.Name))
	}
	s, err := ParseUpstream(p.URL, tunnel)
	if err != nil {
		return Spec{}, err
	}
	s.Bootstrap, s.Name = p.Bootstrap, p.Name
	return s, nil
}

// Normalize drops what a config does not use: the URL of a preset that is
// not custom.
func (c *Config) Normalize() {
	for _, u := range []*Upstream{&c.Tunnel, &c.Direct} {
		u.Preset = strings.TrimSpace(u.Preset)
		if u.Preset != Custom {
			u.URL = ""
		}
	}
}

// Validate checks the presets and custom URLs, also of an option that is
// off (a later «on» must not meet a broken address). A URL on a preset
// that is not custom is ignored (Normalize drops it).
func (c Config) Validate() error {
	if _, err := c.Tunnel.Spec(true); err != nil {
		return err
	}
	if c.Direct.Preset != "" {
		if _, err := c.Direct.Spec(false); err != nil {
			return err
		}
	}
	return nil
}

// Active reports whether any option is on: the engine then intercepts DNS.
func (c Config) Active() bool { return c.BlockBrowserDoH || c.ByRules || c.Direct.Preset != "" }

// UpstreamName is the preset name of u, or CustomName (never the URL).
func (u Upstream) UpstreamName(tunnel bool) string {
	id := u.Preset
	if id == "" && tunnel {
		id = DefaultTunnel
	}
	if p := FindPreset(id); p != nil {
		return p.Name
	}
	if id == Custom {
		return CustomName
	}
	return id
}

// LogName is u for logs: the preset ID, "custom", or "off".
func (u Upstream) LogName(tunnel bool) string {
	switch {
	case u.Preset == "" && tunnel:
		return DefaultTunnel
	case u.Preset == "":
		return "off"
	case FindPreset(u.Preset) != nil || u.Preset == Custom:
		return u.Preset
	}
	return "unknown"
}
