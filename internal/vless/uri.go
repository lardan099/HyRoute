package vless

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Link is a vless:// share link.
type Link struct {
	Name     string
	Host     string // domain or IP literal, no brackets
	Port     int
	Settings Settings
}

// Parse reads a vless:// link:
//
//	vless://<id>@<host>:<port>?type=…&security=…&…#<name>
//
// Parameters HyRoute does not use come back as warnings, so do those Xray
// no longer has (allowInsecure).
func Parse(raw string) (l Link, warnings []string, err error) {
	raw = strings.TrimSpace(raw)
	scheme, _, ok := strings.Cut(raw, "://")
	if !ok || !strings.EqualFold(scheme, "vless") {
		return l, nil, errors.New("не ссылка vless://")
	}
	u, err := url.Parse("vless" + raw[len(scheme):])
	if err != nil {
		return l, nil, fmt.Errorf("ссылка не разобрана: %v", unwrapURLError(err))
	}
	if u.User == nil {
		return l, nil, errors.New("в ссылке нет id пользователя")
	}
	l.Settings.ID = u.User.Username()
	if _, has := u.User.Password(); has {
		return l, nil, errors.New("id пользователя с двоеточием: это не ссылка VLESS")
	}
	l.Host = u.Hostname()
	if l.Host == "" {
		return l, nil, errors.New("в ссылке нет адреса сервера")
	}
	ps := u.Port()
	if ps == "" {
		return l, nil, errors.New("в ссылке нет порта сервера")
	}
	l.Port, err = strconv.Atoi(ps)
	if err != nil || l.Port < 1 || l.Port > 65535 {
		return l, nil, fmt.Errorf("порт %q", ps)
	}
	l.Name = strings.TrimSpace(u.Fragment)

	q := u.Query()
	s := &l.Settings
	get := func(k string) string {
		v := strings.TrimSpace(q.Get(k))
		q.Del(k)
		return v
	}
	s.Encryption = get("encryption")
	if s.Encryption == "none" {
		s.Encryption = ""
	}
	s.Flow = strings.ToLower(get("flow"))
	s.Network = NormalizeNetwork(get("type"))
	s.Security = strings.ToLower(get("security"))
	if s.Security == "none" {
		s.Security = ""
	}
	s.SNI = get("sni")
	if p := get("peer"); s.SNI == "" {
		s.SNI = p // older clients
	}
	s.Fingerprint = strings.ToLower(get("fp"))
	s.ALPN = get("alpn")
	s.ECH = get("ech")
	s.PinSHA256 = get("pcs")
	s.VerifyName = get("vcn")
	s.PublicKey = get("pbk")
	if p := get("password"); s.PublicKey == "" {
		s.PublicKey = p // REALITY's newer name for the key
	}
	s.ShortID = get("sid")
	s.SpiderX = get("spx")
	s.MLDSA65Verify = get("pqv")
	s.HeaderType = strings.ToLower(get("headerType"))
	if s.HeaderType == "none" {
		s.HeaderType = ""
	}
	s.Host = get("host")
	s.Path = get("path")
	s.ServiceName = get("serviceName")
	s.Authority = get("authority")
	s.Mode = get("mode")
	s.Extra = get("extra")
	if clean, dropped, err := CleanExtra(s.Extra); err == nil { // else Validate says so
		s.Extra = clean
		for _, d := range dropped {
			warnings = append(warnings, "xhttp extra: «"+d+"» из ссылки не принимается")
		}
	}
	s.Seed = get("seed")
	if raw := get("fm"); raw != "" {
		if f, err := ParseTCPFragment([]byte(raw)); err == nil && s.Network != "kcp" {
			s.TCPFragment = f
		} else {
			warnings = append(warnings, "finalmask не переносится")
		}
	}
	if s.Network == "grpc" && s.Mode == "" && s.ServiceName == "" {
		// Some panels put the service name in path.
		s.ServiceName, s.Path = s.Path, ""
	}
	if s.Network == "kcp" {
		// For mKCP "seed" travels in path in some clients' links.
		if s.Seed == "" && s.Path != "" {
			s.Seed, s.Path = s.Path, ""
		}
	}
	for _, k := range []string{"allowInsecure", "insecure"} {
		if v := get(k); v == "1" || strings.EqualFold(v, "true") {
			warnings = append(warnings, "allowInsecure: Xray больше не отключает проверку сертификата, она остаётся (закрепите сертификат через pinSHA256)")
		}
	}
	// Defaults or values with no effect on the client.
	q.Del("packetEncoding")
	for k := range q {
		warnings = append(warnings, "ignored parameter "+k)
	}
	return l, warnings, s.Validate()
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// String writes the link with the parameters that are set, in a fixed
// order.
func (l Link) String() string {
	s := l.Settings
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	enc := s.Encryption
	if enc == "" {
		enc = "none"
	}
	q.Set("encryption", enc)
	set("flow", s.Flow)
	network := s.Network
	if network == "" {
		network = "tcp"
	}
	q.Set("type", network)
	security := s.Security
	if security == "" {
		security = "none"
	}
	q.Set("security", security)
	set("sni", s.SNI)
	set("fp", s.Fingerprint)
	set("alpn", s.ALPN)
	set("ech", s.ECH)
	set("pcs", s.PinSHA256)
	set("vcn", s.VerifyName)
	set("pbk", s.PublicKey)
	set("sid", s.ShortID)
	set("spx", s.SpiderX)
	set("pqv", s.MLDSA65Verify)
	set("headerType", s.HeaderType)
	set("host", s.Host)
	set("path", s.Path)
	set("serviceName", s.ServiceName)
	set("authority", s.Authority)
	set("mode", s.Mode)
	set("extra", s.Extra)
	set("seed", s.Seed)
	if s.TCPFragment != (TCPFragment{}) {
		raw, _ := json.Marshal(s.TCPFragment.finalMask())
		q.Set("fm", string(raw))
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(s.ID),
		Host:     net.JoinHostPort(l.Host, strconv.Itoa(l.Port)),
		RawQuery: q.Encode(),
		Fragment: l.Name,
	}
	return u.String()
}
