// Package vless holds HyRoute's VLESS servers: the settings a server
// needs, vless:// share links (the Xray share link standard, XTLS/Xray-core
// discussion #716, with the later pcs, vcn, pqv, ech and extra parameters)
// and the config of the xray.exe that runs one server as a local SOCKS5
// proxy, as hysteria.exe does for Hysteria 2.
//
// Field names follow Xray-core v26.10.31 (infra/conf: vless.go,
// transport_internet.go, transport_method.go, transport_security.go).
package vless

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// Settings are the VLESS part of a server; its address and port are the
// profile's Host and Ports.
type Settings struct {
	// ID is the user's UUID (or a string of 1 to 30 bytes, which Xray
	// maps to one): the server's password.
	ID string `json:"id"`
	// Flow is "" or xtls-rprx-vision (also -udp443).
	Flow string `json:"flow,omitempty"`
	// Encryption is VLESS encryption: "" for "none", or the client's
	// mlkem768x25519plus.… string from the server.
	Encryption string `json:"encryption,omitempty"`

	// Network is the transport: "" (raw TCP), ws, grpc, httpupgrade,
	// xhttp or kcp.
	Network string `json:"network,omitempty"`
	// Security is "" (none), tls or reality.
	Security string `json:"security,omitempty"`

	SNI         string `json:"sni,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	ALPN        string `json:"alpn,omitempty"` // comma-separated
	// ECH is an ECHConfigList (base64) or a DNS query form Xray accepts.
	ECH string `json:"ech,omitempty"`
	// PinSHA256 are certificate SHA-256 pins, comma-separated (pcs).
	PinSHA256 string `json:"pinSHA256,omitempty"`
	// VerifyName are names the certificate may carry instead of the SNI
	// (vcn).
	VerifyName string `json:"verifyName,omitempty"`

	// REALITY
	PublicKey     string `json:"publicKey,omitempty"`
	ShortID       string `json:"shortId,omitempty"`
	SpiderX       string `json:"spiderX,omitempty"`
	MLDSA65Verify string `json:"mldsa65Verify,omitempty"`

	// Transport parameters. HeaderType: raw "http" (or "none"), the mKCP
	// header. Host and Path: ws, httpupgrade, xhttp, the raw HTTP header.
	// Mode: grpc "gun" or "multi", xhttp "auto", "packet-up", "stream-up"
	// or "stream-one". Extra: xhttp's extra settings (a JSON object).
	HeaderType  string      `json:"headerType,omitempty"`
	Host        string      `json:"host,omitempty"`
	Path        string      `json:"path,omitempty"`
	ServiceName string      `json:"serviceName,omitempty"`
	Authority   string      `json:"authority,omitempty"`
	Mode        string      `json:"mode,omitempty"`
	Extra       string      `json:"extra,omitempty"`
	Seed        string      `json:"seed,omitempty"` // mKCP
	TCPFragment TCPFragment `json:"tcpFragment,omitzero"`
}

// Transports and securities HyRoute runs.
var (
	Networks   = []string{"", "ws", "grpc", "httpupgrade", "xhttp", "kcp"}
	Securities = []string{"", "tls", "reality"}
)

const (
	FlowVision       = "xtls-rprx-vision"
	FlowVisionUDP443 = "xtls-rprx-vision-udp443"
)

// NormalizeNetwork maps the names Xray and other clients accept to
// HyRoute's: raw and tcp are "", websocket is ws, splithttp is xhttp,
// mkcp is kcp. Removed transports (h2, http, quic) stay as they are and
// fail Validate.
func NormalizeNetwork(n string) string {
	switch n = strings.ToLower(strings.TrimSpace(n)); n {
	case "", "tcp", "raw":
		return ""
	case "websocket":
		return "ws"
	case "splithttp":
		return "xhttp"
	case "mkcp":
		return "kcp"
	}
	return n
}

// Validate checks what Xray would refuse at start, with messages for the
// user.
func (s *Settings) Validate() error {
	if err := ValidID(s.ID); err != nil {
		return err
	}
	if err := s.TCPFragment.Validate(); err != nil {
		return err
	}
	if s.Network == "kcp" && s.TCPFragment != (TCPFragment{}) {
		return errors.New("TCP fragment требует транспорт на TCP")
	}
	switch s.Flow {
	case "", FlowVision, FlowVisionUDP443:
	default:
		return fmt.Errorf("flow %q: Xray знает только %s", s.Flow, FlowVision)
	}
	if s.Flow != "" && s.Security == "" {
		return errors.New("flow xtls-rprx-vision работает только с security tls или reality")
	}
	if s.Flow != "" && s.Network != "" {
		return fmt.Errorf("flow xtls-rprx-vision работает только с транспортом raw (tcp), а не %s", s.Network)
	}
	if e := s.Encryption; e != "" && e != "none" && !strings.HasPrefix(e, "mlkem768x25519plus.") {
		return fmt.Errorf("encryption %q: Xray знает только none и mlkem768x25519plus", e)
	}
	switch s.Network {
	case "", "ws", "grpc", "httpupgrade", "xhttp", "kcp":
	case "h2", "h3", "http":
		return errors.New("транспорт HTTP/2 (type=http) убран из Xray: сервер нужно перевести на xhttp")
	case "quic":
		return errors.New("транспорт QUIC убран из Xray: сервер нужно перевести на xhttp")
	default:
		return fmt.Errorf("транспорт %q не поддерживается", s.Network)
	}
	switch s.Security {
	case "", "tls":
	case "reality":
		if s.Network != "" && s.Network != "xhttp" && s.Network != "grpc" {
			return errors.New("REALITY работает только с транспортами raw (tcp), xhttp и grpc")
		}
		if s.PublicKey == "" {
			return errors.New("REALITY: нет публичного ключа сервера (pbk)")
		}
		if s.SNI == "" {
			return errors.New("REALITY: нет имени сайта для маскировки (sni)")
		}
	case "xtls":
		return errors.New("security xtls убран из Xray: на сервере нужен flow xtls-rprx-vision с tls или reality")
	default:
		return fmt.Errorf("security %q не поддерживается", s.Security)
	}
	if !fingerprintOK(s.Fingerprint) {
		return fmt.Errorf("fingerprint %q: недопустимые символы", s.Fingerprint)
	}
	for v := range strings.SplitSeq(s.PinSHA256, ",") {
		v = strings.ReplaceAll(strings.TrimSpace(v), ":", "")
		if v == "" {
			continue
		}
		if b, err := hex.DecodeString(v); err != nil || len(b) != 32 {
			return fmt.Errorf("pinnedPeerCertSha256 %q: нужен SHA-256 сертификата в hex", v)
		}
	}
	if s.ShortID != "" {
		if b, err := hex.DecodeString(s.ShortID); err != nil || len(b) > 8 {
			return fmt.Errorf("REALITY shortId %q: до 16 шестнадцатеричных символов", s.ShortID)
		}
	}
	if s.Extra != "" {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s.Extra), &m); err != nil {
			return errors.New("xhttp extra: нужен JSON-объект")
		}
	}
	if s.Network == "grpc" {
		switch s.Mode {
		case "", "gun", "multi":
		default:
			return fmt.Errorf("grpc mode %q: бывает gun или multi", s.Mode)
		}
	}
	if s.Network == "xhttp" {
		switch s.Mode {
		case "", "auto", "packet-up", "stream-up", "stream-one":
		default:
			return fmt.Errorf("xhttp mode %q: бывает auto, packet-up, stream-up или stream-one", s.Mode)
		}
	}
	if s.Network == "kcp" && s.Seed != "" && s.HeaderType != "" && s.HeaderType != "none" {
		return errors.New("mKCP: seed и headerType вместе Xray больше не поддерживает")
	}
	if s.Network == "" {
		switch s.HeaderType {
		case "", "none", "http":
		default:
			return fmt.Errorf("headerType %q для raw: бывает none или http", s.HeaderType)
		}
	}
	for _, f := range []string{s.SNI, s.Host, s.Path, s.ServiceName, s.Authority, s.SpiderX, s.ALPN, s.VerifyName} {
		if strings.ContainsAny(f, "\r\n\x00") {
			return errors.New("в параметрах сервера не может быть переводов строки")
		}
	}
	return nil
}

// ValidateFor is Validate for a server at host: Xray refuses VLESS with
// neither TLS, REALITY nor VLESS encryption to a public address
// (infra/conf/xray.go, requiresTransportSecurity).
func (s *Settings) ValidateFor(host string) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.Security == "" && (s.Encryption == "" || s.Encryption == "none") && !PlainAllowed(host) {
		return errors.New("VLESS без tls, reality и encryption Xray запускает только к адресам локальной сети")
	}
	return nil
}

// PlainAllowed: a private, loopback or link-local IP, or a local name.
func PlainAllowed(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "localhost" {
		return true
	}
	for _, suf := range []string{".localhost", ".local", ".lan", ".internal", ".home.arpa", ".localdomain"} {
		if strings.HasSuffix(h, suf) {
			return true
		}
	}
	return false
}

// ValidID accepts a UUID (with or without dashes) or a string of 1 to 30
// bytes, as Xray does (common/uuid.ParseString).
func ValidID(id string) error {
	switch n := len(id); {
	case n == 0:
		return errors.New("нет UUID пользователя (id)")
	case n <= 30:
		if strings.ContainsAny(id, " \t\r\n") {
			return errors.New("id: пробелы недопустимы")
		}
		return nil
	case n < 32 || n > 36:
		return errors.New("id: нужен UUID")
	}
	hexs := strings.ReplaceAll(id, "-", "")
	if b, err := hex.DecodeString(hexs); err != nil || len(b) != 16 {
		return errors.New("id: нужен UUID")
	}
	return nil
}

// fingerprintOK: a name of Xray's uTLS fingerprints (chrome, firefox,
// randomized, hellochrome_131 …); Xray checks the name itself.
func fingerprintOK(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return len(s) <= 40
}

// Secrets are the values that must never reach a log: the user ID.
func (s *Settings) Secrets() []string { return []string{s.ID} }
