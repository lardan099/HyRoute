// Package awg runs AmneziaWG servers: WireGuard with the obfuscation
// that hides it from DPI (junk packets, paddings, custom headers and
// signature packets). It holds a profile's settings, reads the .conf
// files of amneziawg-tools and the Amnezia app's vpn:// keys (conf.go,
// vpnkey.go), and is the child process HyRoute starts for each server
// (run.go): amneziawg-go over a userspace network stack, served as SOCKS5
// on the loopback like hysteria.exe and xray.exe. Plain WireGuard is
// AmneziaWG with no obfuscation set.
//
// Parameters follow amneziawg-go v3.1 (README "Configuration") and the
// configuration keys of amneziawg-tools (src/config.c).
package awg

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Settings are one client: the [Interface] and [Peer] of a .conf without
// the endpoint, which is the profile's Host and Ports. Keys are base64 as
// in .conf files. A zero value is amneziawg-go's default.
type Settings struct {
	PrivateKey   string `json:"privateKey"`
	PublicKey    string `json:"publicKey"` // the server's
	PresharedKey string `json:"presharedKey,omitempty"`
	// Address is this client's addresses in the tunnel
	// ("10.8.1.2/32, fd00::2/128"); DNS the servers asked through the
	// tunnel ("1.1.1.1, 1.0.0.1"; none: Cloudflare's).
	Address string `json:"address"`
	DNS     string `json:"dns,omitempty"`
	MTU     int    `json:"mtu,omitempty"`
	// Keepalive is PersistentKeepalive in seconds: "25" or a range
	// "22-30".
	Keepalive string `json:"keepalive,omitempty"`

	// Junk packets sent before every handshake.
	Jc   int `json:"jc,omitempty"`
	Jmin int `json:"jmin,omitempty"`
	Jmax int `json:"jmax,omitempty"`
	// Paddings of the handshake initiation, response, cookie and
	// transport messages.
	S1 int `json:"s1,omitempty"`
	S2 int `json:"s2,omitempty"`
	S3 int `json:"s3,omitempty"`
	S4 int `json:"s4,omitempty"`
	// Message headers: a number or a range "a-b".
	H1 string `json:"h1,omitempty"`
	H2 string `json:"h2,omitempty"`
	H3 string `json:"h3,omitempty"`
	H4 string `json:"h4,omitempty"`
	// Signature packets sent before every handshake: tags such as
	// <b 0x…><r 16><t>.
	I1 string `json:"i1,omitempty"`
	I2 string `json:"i2,omitempty"`
	I3 string `json:"i3,omitempty"`
	I4 string `json:"i4,omitempty"`
	I5 string `json:"i5,omitempty"`

	// AmneziaWG 3: header protection, content padding, random trailers,
	// cookies and WireGuard's timings (seconds, a number or a range).
	HeaderProtectionKey  string `json:"headerProtectionKey,omitempty"`
	ContentPadding       string `json:"contentPadding,omitempty"`
	RandomTrailers       bool   `json:"randomTrailers,omitempty"`
	DisableCookies       bool   `json:"disableCookies,omitempty"`
	RekeyAfterTime       string `json:"rekeyAfterTime,omitempty"`
	RekeyTimeout         string `json:"rekeyTimeout,omitempty"`
	RejectAfterTime      string `json:"rejectAfterTime,omitempty"`
	KeepaliveTimeout     string `json:"keepaliveTimeout,omitempty"`
	MaxHandshakeAttempts string `json:"maxHandshakeAttempts,omitempty"`
}

// DefaultMTU is amneziawg-go's MTU, used when the settings have none.
const DefaultMTU = 1420

// DefaultDNS are asked through the tunnel when the settings name no DNS.
var DefaultDNS = []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}

// Obfuscated: any AmneziaWG parameter is set (else it is plain
// WireGuard, which any WireGuard server accepts).
func (s *Settings) Obfuscated() bool {
	t := *s
	t.PrivateKey, t.PublicKey, t.PresharedKey, t.Address, t.DNS, t.MTU, t.Keepalive = "", "", "", "", "", 0, ""
	t.RekeyAfterTime, t.RekeyTimeout, t.RejectAfterTime, t.KeepaliveTimeout, t.MaxHandshakeAttempts = "", "", "", "", ""
	t.DisableCookies = false
	return t != Settings{}
}

// Secrets are the values no log may show, as stored (base64).
func (s *Settings) Secrets() []string {
	return []string{s.PrivateKey, s.PresharedKey, s.HeaderProtectionKey}
}

// HexSecrets are the secrets as amneziawg-go's configuration has them.
func (s *Settings) HexSecrets() []string {
	var out []string
	for _, k := range s.Secrets() {
		if h, err := hexKey(k); err == nil && h != "" {
			out = append(out, h)
		}
	}
	return out
}

// ClearSecrets empties the secrets (a backup without them).
func (s *Settings) ClearSecrets() { s.PrivateKey, s.PresharedKey, s.HeaderProtectionKey = "", "", "" }

// CopySecrets takes the secrets of from.
func (s *Settings) CopySecrets(from Settings) {
	s.PrivateKey, s.PresharedKey, s.HeaderProtectionKey = from.PrivateKey, from.PresharedKey, from.HeaderProtectionKey
}

// Trim removes the spaces a pasted value brings.
func (s *Settings) Trim() {
	for _, f := range s.strings() {
		*f.v = strings.TrimSpace(*f.v)
	}
}

type field struct {
	name string
	v    *string
}

func (s *Settings) strings() []field {
	return []field{
		{"PrivateKey", &s.PrivateKey}, {"PublicKey", &s.PublicKey}, {"PresharedKey", &s.PresharedKey},
		{"Address", &s.Address}, {"DNS", &s.DNS}, {"PersistentKeepalive", &s.Keepalive},
		{"H1", &s.H1}, {"H2", &s.H2}, {"H3", &s.H3}, {"H4", &s.H4},
		{"I1", &s.I1}, {"I2", &s.I2}, {"I3", &s.I3}, {"I4", &s.I4}, {"I5", &s.I5},
		{"HeaderProtectionKey", &s.HeaderProtectionKey}, {"ContentPaddingAddition", &s.ContentPadding},
		{"RekeyAfterTime", &s.RekeyAfterTime}, {"RekeyTimeout", &s.RekeyTimeout},
		{"RejectAfterTime", &s.RejectAfterTime}, {"KeepaliveTimeout", &s.KeepaliveTimeout},
		{"MaxHandshakeAttempts", &s.MaxHandshakeAttempts},
	}
}

// Validate checks what amneziawg-go would refuse, and keeps line breaks
// out of its configuration (one key per line).
func (s *Settings) Validate() error {
	for _, f := range s.strings() {
		if strings.ContainsFunc(*f.v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("AmneziaWG: в %s не бывает переносов строк и управляющих символов", f.name)
		}
	}
	if s.PrivateKey == "" {
		return errors.New("AmneziaWG: нужен приватный ключ (PrivateKey)")
	}
	if s.PublicKey == "" {
		return errors.New("AmneziaWG: нужен публичный ключ сервера (PublicKey)")
	}
	for _, k := range []field{{"PrivateKey", &s.PrivateKey}, {"PublicKey", &s.PublicKey}, {"PresharedKey", &s.PresharedKey}, {"HeaderProtectionKey", &s.HeaderProtectionKey}} {
		if _, err := hexKey(*k.v); err != nil {
			return fmt.Errorf("AmneziaWG: %s — ключ из 32 байт в base64 (44 символа), как его выдаёт awg genkey", k.name)
		}
	}
	if _, err := s.Addrs(); err != nil {
		return err
	}
	if _, err := s.DNSServers(); err != nil {
		return err
	}
	if s.MTU != 0 && (s.MTU < 576 || s.MTU > 65535) {
		return errors.New("AmneziaWG: MTU — от 576 до 65535")
	}
	if s.Jc < 0 || s.Jc > 128 {
		return errors.New("AmneziaWG: Jc — от 0 до 128 мусорных пакетов")
	}
	if s.Jmin < 0 || s.Jmax < 0 || s.Jmax > 65535 || s.Jmin > s.Jmax {
		return errors.New("AmneziaWG: Jmin и Jmax — размеры от 0 до 65535, Jmin не больше Jmax")
	}
	for i, v := range []int{s.S1, s.S2, s.S3, s.S4} {
		if v < 0 || v > 65535 {
			return fmt.Errorf("AmneziaWG: S%d — от 0 до 65535", i+1)
		}
	}
	// Unset headers are WireGuard's message types 1 to 4.
	var hs [4][2]uint64
	for i, h := range []string{s.H1, s.H2, s.H3, s.H4} {
		if err := checkRange(h, 1<<32-1); err != nil {
			return fmt.Errorf("AmneziaWG: H%d — число или диапазон «от-до»: %v", i+1, err)
		}
		hs[i] = [2]uint64{uint64(i + 1), uint64(i + 1)}
		if h != "" {
			hs[i][0], hs[i][1] = parseRange(h)
		}
	}
	for i := range hs {
		for j := i + 1; j < len(hs); j++ {
			if hs[i][0] <= hs[j][1] && hs[j][0] <= hs[i][1] {
				return fmt.Errorf("AmneziaWG: H%d и H%d пересекаются, а у разных сообщений заголовки должны различаться", i+1, j+1)
			}
		}
	}
	if s.HeaderProtectionKey != "" {
		for i, v := range []int{s.S1, s.S2, s.S3, s.S4} {
			if v < 12 {
				return fmt.Errorf("AmneziaWG: с HeaderProtectionKey S%d должен быть не меньше 12", i+1)
			}
		}
	}
	for _, f := range []field{
		{"PersistentKeepalive", &s.Keepalive}, {"ContentPaddingAddition", &s.ContentPadding},
		{"RekeyAfterTime", &s.RekeyAfterTime}, {"RekeyTimeout", &s.RekeyTimeout}, {"RejectAfterTime", &s.RejectAfterTime},
		{"KeepaliveTimeout", &s.KeepaliveTimeout}, {"MaxHandshakeAttempts", &s.MaxHandshakeAttempts},
	} {
		if err := checkRange(*f.v, 65535); err != nil {
			return fmt.Errorf("AmneziaWG: %s — число или диапазон «от-до» до 65535: %v", f.name, err)
		}
	}
	for i, v := range []string{s.I1, s.I2, s.I3, s.I4, s.I5} {
		if err := checkTags(v); err != nil {
			return fmt.Errorf("AmneziaWG: I%d: %v", i+1, err)
		}
	}
	return nil
}

// Addrs are the client's addresses in the tunnel (Address without the
// prefix lengths).
func (s *Settings) Addrs() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, f := range splitList(s.Address) {
		a, err := netip.ParseAddr(f)
		if p, perr := netip.ParsePrefix(f); perr == nil {
			a, err = p.Addr(), nil
		}
		if err != nil {
			return nil, fmt.Errorf("AmneziaWG: Address %q — нужен IP-адрес, например 10.8.1.2/32", f)
		}
		out = append(out, a.Unmap())
	}
	if len(out) == 0 {
		return nil, errors.New("AmneziaWG: нужен адрес клиента в VPN (Address), например 10.8.1.2/32")
	}
	return out, nil
}

// DNSServers are the IPs of DNS (nil when it names none).
func (s *Settings) DNSServers() ([]netip.Addr, error) {
	var out []netip.Addr
	for _, f := range splitList(s.DNS) {
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("AmneziaWG: DNS %q — нужен IP-адрес DNS-сервера", f)
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

// splitList splits "a, b c" into its items.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}

// hexKey turns a base64 key into the hex amneziawg-go reads ("" stays
// ""). A key is 32 bytes.
func hexKey(b64 string) (string, error) {
	if b64 == "" {
		return "", nil
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != 32 {
		return "", errors.New("bad key")
	}
	return hex.EncodeToString(b), nil
}

// checkRange accepts "", "n" and "a-b" with a <= b <= max.
func checkRange(s string, max uint64) error {
	if s == "" {
		return nil
	}
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 64)
	if err != nil {
		return fmt.Errorf("%q не число", lo)
	}
	b := a
	if isRange {
		if b, err = strconv.ParseUint(strings.TrimSpace(hi), 10, 64); err != nil {
			return fmt.Errorf("%q не число", hi)
		}
	}
	if a > b || b > max {
		return fmt.Errorf("%q вне пределов", s)
	}
	return nil
}

// parseRange reads a range checkRange accepted.
func parseRange(s string) (lo, hi uint64) {
	a, b, isRange := strings.Cut(s, "-")
	lo, _ = strconv.ParseUint(strings.TrimSpace(a), 10, 64)
	hi = lo
	if isRange {
		hi, _ = strconv.ParseUint(strings.TrimSpace(b), 10, 64)
	}
	return lo, hi
}

// tagArgs are the tags of signature packets and their arguments:
// amneziawg-go device/obf.go.
var tagArgs = map[string]string{
	"b": "hex", "t": "", "r": "len", "rc": "len", "rd": "len", "d": "", "ds": "", "dz": "len",
}

// checkTags checks a signature packet as amneziawg-go parses it: a
// sequence of <tag arg> items.
func checkTags(s string) error {
	rest := strings.TrimSpace(s)
	for rest != "" {
		if rest[0] != '<' {
			return errors.New("ожидались теги вида <b 0x…>, <r 16>, <rc 8>, <rd 8>, <t>")
		}
		end := strings.IndexByte(rest, '>')
		if end < 0 {
			return errors.New("тег не закрыт «>»")
		}
		parts := strings.Fields(rest[1:end])
		rest = strings.TrimSpace(rest[end+1:])
		if len(parts) == 0 {
			return errors.New("пустой тег <>")
		}
		kind, ok := tagArgs[parts[0]]
		if !ok {
			return fmt.Errorf("неизвестный тег <%s>", parts[0])
		}
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}
		switch kind {
		case "hex":
			h, ok := strings.CutPrefix(arg, "0x")
			if _, err := hex.DecodeString(h); !ok || err != nil || h == "" {
				return fmt.Errorf("<b %s>: нужны байты в hex с 0x, чётное число цифр", arg)
			}
		case "len":
			if n, err := strconv.Atoi(arg); err != nil || n < 0 {
				return fmt.Errorf("<%s %s>: нужна длина — неотрицательное число", parts[0], arg)
			}
		}
	}
	return nil
}

// UAPI is amneziawg-go's configuration of the device with one peer at
// endpoint that takes all traffic (HyRoute's rules choose what goes in).
func (s *Settings) UAPI(endpoint netip.AddrPort) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	set := func(k, v string) {
		if v != "" {
			b.WriteString(k + "=" + v + "\n")
		}
	}
	num := func(k string, v int) {
		if v != 0 {
			set(k, strconv.Itoa(v))
		}
	}
	key := func(k, v string) {
		h, _ := hexKey(v)
		set(k, h)
	}
	key("private_key", s.PrivateKey)
	num("jc", s.Jc)
	num("jmin", s.Jmin)
	num("jmax", s.Jmax)
	num("s1", s.S1)
	num("s2", s.S2)
	num("s3", s.S3)
	num("s4", s.S4)
	set("h1", s.H1)
	set("h2", s.H2)
	set("h3", s.H3)
	set("h4", s.H4)
	set("i1", s.I1)
	set("i2", s.I2)
	set("i3", s.I3)
	set("i4", s.I4)
	set("i5", s.I5)
	key("header_protection_key", s.HeaderProtectionKey)
	set("content_padding_addition", s.ContentPadding)
	set("rekey_after_time", s.RekeyAfterTime)
	set("rekey_timeout", s.RekeyTimeout)
	set("reject_after_time", s.RejectAfterTime)
	set("keepalive_timeout", s.KeepaliveTimeout)
	set("max_handshake_attempts", s.MaxHandshakeAttempts)
	if s.RandomTrailers {
		set("random_trailers", "true")
	}
	if s.DisableCookies {
		set("disable_cookies", "true")
	}
	set("replace_peers", "true")
	key("public_key", s.PublicKey)
	key("preshared_key", s.PresharedKey)
	set("endpoint", endpoint.String())
	set("persistent_keepalive_interval", s.Keepalive)
	set("replace_allowed_ips", "true")
	set("allowed_ip", "0.0.0.0/0")
	set("allowed_ip", "::/0")
	return b.String(), nil
}
