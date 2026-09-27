package hysteria

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// ParseURI parses hysteria2:// and hy2:// share links.
//
// Besides the official parameters (obfs, obfs-password, sni, insecure,
// pinSHA256, ech) it accepts variants found in links produced by panels and
// third-party clients (Xray, v2rayN, Throne): allowInsecure, peer (as SNI),
// mport (extra hopping ports), pcs (pinned certificate SHA-256), fm
// (Xray "finalmask" JSON carrying the salamander obfs) and obfs-password
// without obfs (salamander is assumed). Guesses and unknown parameters are
// reported in warnings; cosmetic client parameters are ignored silently.
//
// The authority is parsed by hand: net/url rejects multi-port hosts like
// "host:443,20000-50000".
func ParseURI(s string) (p Profile, warnings []string, err error) {
	s = strings.TrimSpace(s)
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok {
		return p, nil, errors.New("not a URI")
	}
	switch strings.ToLower(scheme) {
	case "hysteria2", "hy2":
	default:
		return p, nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
	rest, frag, _ := strings.Cut(rest, "#")
	rest, rawQuery, _ := strings.Cut(rest, "?")
	authority, _, _ := strings.Cut(rest, "/")

	if frag != "" {
		if p.Name, err = url.PathUnescape(frag); err != nil {
			p.Name = frag
		}
	}

	hostport := authority
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		userinfo := authority[:i]
		hostport = authority[i+1:]
		user, pass, hasPass := strings.Cut(userinfo, ":")
		if user, err = url.PathUnescape(user); err != nil {
			return p, nil, fmt.Errorf("bad auth encoding: %w", err)
		}
		if hasPass {
			if pass, err = url.PathUnescape(pass); err != nil {
				return p, nil, fmt.Errorf("bad auth encoding: %w", err)
			}
			p.Auth = user + ":" + pass
		} else {
			p.Auth = user
		}
	}
	if p.Host, p.Ports, err = splitHostPorts(hostport); err != nil {
		return p, nil, err
	}

	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return p, nil, fmt.Errorf("bad query: %w", err)
	}
	used := map[string]bool{}
	get := func(k string) string { used[k] = true; return q.Get(k) }

	if m := get("mport"); m != "" {
		if _, err := ParsePorts(m); err != nil {
			return p, nil, fmt.Errorf("bad mport: %w", err)
		}
		p.Ports = p.Ports + "," + m
	}

	obfsType, obfsPass := get("obfs"), get("obfs-password")
	switch strings.ToLower(obfsType) {
	case "salamander", "gecko":
		p.Obfs = Obfs{Type: strings.ToLower(obfsType), Password: obfsPass}
	case "", "none", "plain":
		if obfsPass != "" {
			p.Obfs = Obfs{Type: "salamander", Password: obfsPass}
			warnings = append(warnings, "obfs-password without obfs: assuming obfs=salamander")
		}
	default:
		return p, nil, fmt.Errorf("unsupported obfs %q", obfsType)
	}
	if fm := get("fm"); fm != "" {
		o, warn, err := parseFinalMask(fm)
		switch {
		case err != nil:
			warnings = append(warnings, "fm: "+err.Error())
		case p.Obfs.Type == "" && o.Type != "":
			p.Obfs = o
		}
		if warn != "" {
			warnings = append(warnings, "fm: "+warn)
		}
	}

	p.TLS.SNI = get("sni")
	if peer := get("peer"); peer != "" && p.TLS.SNI == "" {
		p.TLS.SNI = peer
	}
	if v := get("insecure"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return p, nil, fmt.Errorf("bad insecure value %q", v)
		}
		p.TLS.Insecure = b
	} else if v := get("allowInsecure"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return p, nil, fmt.Errorf("bad allowInsecure value %q", v)
		}
		p.TLS.Insecure = b
	}
	p.TLS.PinSHA256 = get("pinSHA256")
	if pcs := get("pcs"); pcs != "" && p.TLS.PinSHA256 == "" {
		p.TLS.PinSHA256 = pcs // Xray's pinnedPeerCertSha256
	}
	if p.TLS.PinSHA256 != "" && !ValidPin(p.TLS.PinSHA256) {
		warnings = append(warnings, "pinSHA256 is not a 64-digit hex SHA-256: the certificate will never match")
	}
	p.TLS.ECH = get("ech")

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
	p.PinServerIP = true
	return p, warnings, p.Validate()
}

// cosmetic parameters come from other protocols' link formats and mean
// nothing to Hysteria 2 (TLS fingerprint and ALPN are fixed by Hysteria).
var cosmetic = map[string]bool{"fp": true, "alpn": true, "security": true, "type": true, "encryption": true, "headertype": true}

// parseFinalMask reads Xray's "fm" JSON: {"udp":[{"type":"salamander",
// "settings":{"password":"..."}}]}.
func parseFinalMask(s string) (Obfs, string, error) {
	var fm struct {
		UDP []struct {
			Type     string `json:"type"`
			Settings struct {
				Password string `json:"password"`
			} `json:"settings"`
		} `json:"udp"`
	}
	if err := json.Unmarshal([]byte(s), &fm); err != nil {
		return Obfs{}, "", fmt.Errorf("not JSON: %v", err)
	}
	var o Obfs
	var other []string
	for _, m := range fm.UDP {
		switch t := strings.ToLower(m.Type); {
		case t == "salamander" && o.Type == "" && m.Settings.Password != "":
			o = Obfs{Type: "salamander", Password: m.Settings.Password}
		default:
			other = append(other, m.Type)
		}
	}
	warn := ""
	if len(other) > 0 {
		warn = "unsupported mask " + strings.Join(other, ", ") + ": the profile may not connect"
	}
	return o, warn, nil
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

// URI exports the profile in the official format. Only connection
// parameters are included (bandwidth, hop intervals etc. are not part of the
// share-link spec).
func (p *Profile) URI() string {
	q := url.Values{}
	switch t := strings.ToLower(p.Obfs.Type); t { // any case, like Validate
	case "salamander", "gecko":
		q.Set("obfs", t)
		q.Set("obfs-password", p.Obfs.Password)
	}
	if p.TLS.SNI != "" {
		q.Set("sni", p.TLS.SNI)
	}
	if p.TLS.Insecure {
		q.Set("insecure", "1")
	}
	if p.TLS.PinSHA256 != "" {
		q.Set("pinSHA256", p.TLS.PinSHA256)
	}
	if p.TLS.ECH != "" {
		q.Set("ech", p.TLS.ECH)
	}
	var b strings.Builder
	b.WriteString("hysteria2://")
	if p.Auth != "" {
		var u *url.Userinfo
		if user, pass, ok := strings.Cut(p.Auth, ":"); ok {
			u = url.UserPassword(user, pass)
		} else {
			u = url.User(p.Auth)
		}
		b.WriteString(u.String())
		b.WriteByte('@')
	}
	b.WriteString(ServerString(p.Host, p.Ports))
	b.WriteByte('/')
	if len(q) > 0 {
		b.WriteByte('?')
		b.WriteString(q.Encode())
	}
	if p.Name != "" {
		b.WriteByte('#')
		b.WriteString((&url.URL{Fragment: p.Name}).EscapedFragment())
	}
	return b.String()
}
