// Package hy2uri is the Hysteria 2 share link (hysteria2://, hy2://): a
// typed model, a tolerant parser and two serializers. The HyRoute client
// and the server manager share it.
//
// Format: https://v2.hysteria.network/docs/developers/URI-Scheme/
package hy2uri

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Link is a share link.
type Link struct {
	Name string
	// Auth is the password, or "user:pass" for userpass authentication.
	Auth string
	// Host is a domain or IP literal (no brackets).
	Host string
	// Ports is "443", "20000-50000" or "443,20000-50000" (port hopping).
	Ports string

	ObfsType     string // "", "salamander", "gecko"
	ObfsPassword string

	SNI       string
	Insecure  bool
	PinSHA256 string
	ECH       string

	// Not in the official scheme; some clients put them in links.
	HopInterval string // "30s" (mportHopInt, seconds)
	UpMbps      int    // up (Mbps)
	DownMbps    int    // down (Mbps)
}

// Parse parses hysteria2:// and hy2:// share links.
//
// Besides the official parameters (obfs, obfs-password, sni, insecure,
// pinSHA256, ech) it accepts variants found in links produced by panels and
// third-party clients (Xray, v2rayN, Throne, Incy): allowInsecure, peer (as
// SNI), mport or ports (hopping ports), mportHopInt (hop interval in
// seconds), up and down (Mbps), pcs (pinned certificate SHA-256), fm (Xray
// "finalmask" JSON carrying the salamander obfs) and obfs-password without
// obfs (salamander is assumed). Guesses and unknown parameters are reported
// in warnings; cosmetic client parameters are ignored silently.
//
// The authority is parsed by hand: net/url rejects multi-port hosts like
// "host:443,20000-50000".
func Parse(s string) (l Link, warnings []string, err error) {
	s = strings.TrimSpace(s)
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return l, nil, errors.New("not a URI")
	}
	switch strings.ToLower(scheme) {
	case "hysteria2", "hy2":
	default:
		return l, nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
	rest, frag, _ := strings.Cut(rest, "#")
	rest, rawQuery, _ := strings.Cut(rest, "?")
	authority, _, _ := strings.Cut(rest, "/")

	if frag != "" {
		if l.Name, err = url.PathUnescape(frag); err != nil {
			l.Name = frag
		}
	}

	hostport := authority
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		userinfo := authority[:i]
		hostport = authority[i+1:]
		user, pass, hasPass := strings.Cut(userinfo, ":")
		if user, err = url.PathUnescape(user); err != nil {
			return l, nil, fmt.Errorf("bad auth encoding: %w", err)
		}
		if hasPass {
			if pass, err = url.PathUnescape(pass); err != nil {
				return l, nil, fmt.Errorf("bad auth encoding: %w", err)
			}
			l.Auth = user + ":" + pass
		} else {
			l.Auth = user
		}
	}
	if l.Host, l.Ports, err = splitHostPorts(hostport); err != nil {
		return l, nil, err
	}

	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return l, nil, fmt.Errorf("bad query: %w", err)
	}
	used := map[string]bool{}
	get := func(k string) string { used[k] = true; return q.Get(k) }

	m := get("mport")
	if m == "" {
		m = get("ports")
	}
	if m != "" {
		if _, err := ParsePorts(m); err != nil {
			return l, nil, fmt.Errorf("bad mport: %w", err)
		}
		l.Ports = mergePorts(l.Ports, m)
	}
	if v := get("mportHopInt"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			l.HopInterval = (time.Duration(n) * time.Second).String()
		} else {
			warnings = append(warnings, "ignored mportHopInt "+strconv.Quote(v)+": not a number of seconds")
		}
	}
	l.UpMbps = mbps(get("up"), "up", &warnings)
	l.DownMbps = mbps(get("down"), "down", &warnings)

	obfsType, obfsPass := get("obfs"), get("obfs-password")
	switch strings.ToLower(obfsType) {
	case "salamander", "gecko":
		l.ObfsType, l.ObfsPassword = strings.ToLower(obfsType), obfsPass
	case "", "none", "plain":
		if obfsPass != "" {
			l.ObfsType, l.ObfsPassword = "salamander", obfsPass
			warnings = append(warnings, "obfs-password without obfs: assuming obfs=salamander")
		}
	default:
		return l, nil, fmt.Errorf("unsupported obfs %q", obfsType)
	}
	if fm := get("fm"); fm != "" {
		pass, warn, err := parseFinalMask(fm)
		switch {
		case err != nil:
			warnings = append(warnings, "fm: "+err.Error())
		case l.ObfsType == "" && pass != "":
			l.ObfsType, l.ObfsPassword = "salamander", pass
		}
		if warn != "" {
			warnings = append(warnings, "fm: "+warn)
		}
	}

	l.SNI = get("sni")
	if peer := get("peer"); peer != "" && l.SNI == "" {
		l.SNI = peer
	}
	if v := get("insecure"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return l, nil, fmt.Errorf("bad insecure value %q", v)
		}
		l.Insecure = b
	} else if v := get("allowInsecure"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return l, nil, fmt.Errorf("bad allowInsecure value %q", v)
		}
		l.Insecure = b
	}
	l.PinSHA256 = get("pinSHA256")
	if pcs := get("pcs"); pcs != "" && l.PinSHA256 == "" {
		l.PinSHA256 = pcs // Xray's pinnedPeerCertSha256
	}
	if l.PinSHA256 != "" && !ValidPin(l.PinSHA256) {
		warnings = append(warnings, "pinSHA256 is not a 64-digit hex SHA-256: the certificate will never match")
	}
	l.ECH = get("ech")

	var ignored []string
	for k := range q {
		if !used[k] && !cosmetic[strings.ToLower(k)] {
			ignored = append(ignored, k)
		}
	}
	sort.Strings(ignored)
	for _, k := range ignored {
		warnings = append(warnings, "ignored parameter "+k)
	}
	return l, warnings, l.Validate()
}

// Validate checks what a link must have to connect.
func (l *Link) Validate() error {
	if l.Host == "" {
		return errors.New("server host is empty")
	}
	if _, err := ParsePorts(l.Ports); err != nil {
		return err
	}
	switch strings.ToLower(l.ObfsType) {
	case "":
	case "salamander", "gecko":
		if l.ObfsPassword == "" {
			return errors.New("obfs password is empty")
		}
	default:
		return fmt.Errorf("unsupported obfs type %q", l.ObfsType)
	}
	return nil
}

// mergePorts adds the mport list to the authority port. Links that keep
// the first port in the authority usually include it in mport too.
func mergePorts(ports, extra string) string {
	own, err1 := ParsePorts(ports)
	rs, err2 := ParsePorts(extra)
	if err1 == nil && err2 == nil && len(own) == 1 {
		for _, r := range rs {
			if own[0].From >= r.From && own[0].To <= r.To {
				return strings.Join(strings.Fields(extra), "")
			}
		}
	}
	return ports + "," + extra
}

func mbps(v, name string, warnings *[]string) int {
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.ToLower(v), "mbps")))
	if err != nil || n < 0 {
		*warnings = append(*warnings, "ignored "+name+" "+strconv.Quote(v)+": not a number of Mbps")
		return 0
	}
	return n
}

// cosmetic parameters come from other protocols' link formats and mean
// nothing to Hysteria 2 (TLS fingerprint and ALPN are fixed by Hysteria).
var cosmetic = map[string]bool{"fp": true, "alpn": true, "security": true, "type": true, "encryption": true, "headertype": true}

// parseFinalMask reads Xray's "fm" JSON: {"udp":[{"type":"salamander",
// "settings":{"password":"..."}}]} and returns the salamander password.
func parseFinalMask(s string) (string, string, error) {
	var fm struct {
		UDP []struct {
			Type     string `json:"type"`
			Settings struct {
				Password string `json:"password"`
			} `json:"settings"`
		} `json:"udp"`
	}
	if err := json.Unmarshal([]byte(s), &fm); err != nil {
		return "", "", fmt.Errorf("not JSON: %v", err)
	}
	pass := ""
	var other []string
	for _, m := range fm.UDP {
		switch t := strings.ToLower(m.Type); {
		case t == "salamander" && pass == "" && m.Settings.Password != "":
			pass = m.Settings.Password
		default:
			other = append(other, m.Type)
		}
	}
	warn := ""
	if len(other) > 0 {
		warn = "unsupported mask " + strings.Join(other, ", ") + ": the profile may not connect"
	}
	return pass, warn, nil
}

func splitHostPorts(hp string) (host, ports string, err error) {
	if strings.HasPrefix(hp, "[") {
		end := strings.Index(hp, "]")
		if end < 0 {
			return "", "", errors.New("bad IPv6 host")
		}
		host, rest := hp[1:end], hp[end+1:]
		if rest == "" {
			return host, "443", nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", fmt.Errorf("bad host %q", hp)
		}
		return host, rest[1:], nil
	}
	host, ports, ok := strings.Cut(hp, ":")
	if host == "" {
		return "", "", errors.New("empty host")
	}
	if !ok {
		return host, "443", nil
	}
	return host, ports, nil
}

// String is the link in the official format: all ports in the authority,
// only the parameters the scheme defines (bandwidth and hop interval are
// client settings and are left out).
func (l Link) String() string {
	return l.build(ServerString(l.Host, l.Ports), l.query())
}

// Compat is the link for importers that parse the authority with a URL
// library (v2rayN and other System.Uri-based clients): the first port in
// the authority, the whole port list in mport, and the hop interval in
// mportHopInt, which Incy reads. For a single port it equals String.
func (l Link) Compat() string {
	q := l.query()
	ports := strings.Join(strings.Fields(l.Ports), "")
	if strings.ContainsAny(ports, ",-") {
		first, _, _ := strings.Cut(ports, ",")
		first, _, _ = strings.Cut(first, "-")
		q.Set("mport", ports)
		if l.HopInterval != "" {
			if d, err := time.ParseDuration(l.HopInterval); err == nil && d >= time.Second {
				q.Set("mportHopInt", strconv.Itoa(int(d/time.Second)))
			}
		}
		ports = first
	}
	return l.build(ServerString(l.Host, ports), q)
}

func (l Link) query() url.Values {
	q := url.Values{}
	switch t := strings.ToLower(l.ObfsType); t {
	case "salamander", "gecko":
		q.Set("obfs", t)
		q.Set("obfs-password", l.ObfsPassword)
	}
	if l.SNI != "" {
		q.Set("sni", l.SNI)
	}
	if l.Insecure {
		q.Set("insecure", "1")
	}
	if l.PinSHA256 != "" {
		q.Set("pinSHA256", l.PinSHA256)
	}
	if l.ECH != "" {
		q.Set("ech", l.ECH)
	}
	return q
}

func (l Link) build(server string, q url.Values) string {
	var b strings.Builder
	b.WriteString("hysteria2://")
	if l.Auth != "" {
		var u *url.Userinfo
		if user, pass, ok := strings.Cut(l.Auth, ":"); ok {
			u = url.UserPassword(user, pass)
		} else {
			u = url.User(l.Auth)
		}
		b.WriteString(u.String())
		b.WriteByte('@')
	}
	b.WriteString(server)
	b.WriteByte('/')
	if len(q) > 0 {
		b.WriteByte('?')
		b.WriteString(q.Encode())
	}
	if l.Name != "" {
		b.WriteByte('#')
		b.WriteString((&url.URL{Fragment: l.Name}).EscapedFragment())
	}
	return b.String()
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

// ServerString formats host with the ports spec the way Hysteria's
// "server" field and share links expect it: every IPv6 literal
// (IPv4-mapped too) in brackets, the ports without the spaces ParsePorts
// tolerates (Hysteria rejects "443, 20000-50000").
func ServerString(host, ports string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strings.Join(strings.Fields(ports), "")
}
