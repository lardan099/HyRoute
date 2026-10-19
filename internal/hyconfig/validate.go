package hyconfig

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Problem is a finding of Validate. Errors stop Hysteria from starting (as
// far as the controller can tell without running it); warnings do not.
type Problem struct {
	Field   string `json:"field"` // "tls.cert", "outbounds[1].socks5.addr"
	Message string `json:"message"`
	Warning bool   `json:"warning,omitempty"`
}

// HasErrors reports whether any problem is an error.
func HasErrors(ps []Problem) bool {
	for _, p := range ps {
		if !p.Warning {
			return true
		}
	}
	return false
}

type checker struct{ ps []Problem }

func (c *checker) err(field, format string, a ...any) {
	c.ps = append(c.ps, Problem{Field: field, Message: fmt.Sprintf(format, a...)})
}

func (c *checker) warn(field, format string, a ...any) {
	c.ps = append(c.ps, Problem{Field: field, Message: fmt.Sprintf(format, a...), Warning: true})
}

// oneOf checks a type selector value (case-insensitive, like Hysteria).
func (c *checker) oneOf(field, v string, allowed ...string) bool {
	for _, a := range allowed {
		if strings.EqualFold(v, a) {
			return true
		}
	}
	c.err(field, "неизвестное значение %q", v)
	return false
}

func (c *checker) duration(field string, d Duration, min, max time.Duration) {
	if d == "" {
		return
	}
	v, err := parseDuration(d)
	if err != nil {
		c.err(field, "не длительность: %q (пример: 30s, 2m)", string(d))
		return
	}
	if digitsRe.MatchString(string(d)) && v != 0 {
		c.warn(field, "число без единиц Hysteria считает наносекундами; укажите единицы (например 30s)")
	}
	if min > 0 && v != 0 && (v < min || v > max) {
		c.err(field, "допустимо от %s до %s", min, max)
	}
}

func parseDuration(d Duration) (time.Duration, error) {
	if digitsRe.MatchString(string(d)) {
		n, err := strconv.ParseInt(string(d), 10, 64)
		return time.Duration(n), err
	}
	return time.ParseDuration(string(d))
}

// Validate checks the config the way Hysteria would, without touching any
// files. Unknown fields come back as warnings.
func (s *Server) Validate() []Problem {
	c := &checker{}
	realm := strings.Contains(s.Listen, "://")
	if realm {
		c.warn("listen", "режим Realms (P2P): controller не выдаёт для него ссылки клиентам")
	} else if s.Listen != "" {
		if _, err := ParseListen(s.Listen); err != nil {
			c.err("listen", "%s", err)
		}
	}

	switch {
	case s.TLS == nil && s.ACME == nil:
		c.err("tls", "нужен сертификат: раздел tls или acme")
	case s.TLS != nil && s.ACME != nil:
		c.err("tls", "tls и acme вместе не работают, оставьте один")
	case s.TLS != nil:
		if s.TLS.Cert == "" {
			c.err("tls.cert", "не указан файл сертификата")
		}
		if s.TLS.Key == "" {
			c.err("tls.key", "не указан файл ключа")
		}
		if s.TLS.SNIGuard != "" {
			c.oneOf("tls.sniGuard", s.TLS.SNIGuard, "dns-san", "strict", "disable")
		}
	default:
		s.ACME.validate(c)
	}

	s.Auth.validate(c)
	s.Obfs.validate(c, "obfs")
	s.Masquerade.validate(c)
	s.Bandwidth.validate(c, "bandwidth")
	s.Congestion.validate(c, "congestion")
	q := s.QUIC
	quicWindows(c, "quic", q.InitStreamReceiveWindow, q.MaxStreamReceiveWindow, q.InitConnReceiveWindow, q.MaxConnReceiveWindow)
	c.duration("quic.maxIdleTimeout", q.MaxIdleTimeout, 4*time.Second, 120*time.Second)
	if q.MaxIncomingStreams != 0 && q.MaxIncomingStreams < 8 {
		c.err("quic.maxIncomingStreams", "не меньше 8")
	}
	c.duration("udpIdleTimeout", s.UDPIdleTimeout, 2*time.Second, 600*time.Second)
	s.Resolver.validate(c)
	c.duration("sniff.timeout", s.Sniff.Timeout, 0, 0)
	if s.Sniff.TCPPorts != "" && !validPortUnion(s.Sniff.TCPPorts, true) {
		c.err("sniff.tcpPorts", "неверный список портов %q", s.Sniff.TCPPorts)
	}
	if s.Sniff.UDPPorts != "" && !validPortUnion(s.Sniff.UDPPorts, true) {
		c.err("sniff.udpPorts", "неверный список портов %q", s.Sniff.UDPPorts)
	}
	if s.ACL.File != "" && len(s.ACL.Inline) > 0 {
		c.err("acl", "acl.file и acl.inline вместе не работают, оставьте одно")
	}
	c.duration("acl.geoUpdateInterval", s.ACL.GeoUpdateInterval, 0, 0)
	names := map[string]bool{}
	for i, o := range s.Outbounds {
		o.validate(c, fmt.Sprintf("outbounds[%d]", i), names)
	}
	if s.TrafficStats.Listen != "" {
		if _, _, err := net.SplitHostPort(s.TrafficStats.Listen); err != nil {
			c.err("trafficStats.listen", "неверный адрес %q", s.TrafficStats.Listen)
		}
		if s.TrafficStats.Secret == "" {
			c.warn("trafficStats.secret", "API статистики без секрета: любой, кто до него достучится, видит трафик и может отключать клиентов")
		}
	}
	if s.Mimic.XDPMode != "" {
		c.oneOf("mimic.xdpMode", s.Mimic.XDPMode, "native", "skb")
	}
	if s.Mimic.Enabled {
		c.warn("mimic.enabled", "mimic должен быть включён и у всех клиентов, иначе они не подключатся")
	}
	s.Realm.validate(c)

	for _, f := range UnknownFields(s) {
		c.warn(f, "поле неизвестно этой версии HyRoute; оно сохранится как есть")
	}
	return c.ps
}

func (a *ACME) validate(c *checker) {
	if len(a.Domains) == 0 {
		c.err("acme.domains", "нужен хотя бы один домен")
	}
	for i, d := range a.Domains {
		if !domainRe.MatchString(strings.ToLower(d)) {
			c.err(fmt.Sprintf("acme.domains[%d]", i), "неверный домен %q", d)
		}
	}
	if a.CA != "" {
		c.oneOf("acme.ca", a.CA, "letsencrypt", "le", "zerossl", "zero")
	}
	if a.Type != "" && c.oneOf("acme.type", a.Type, "http", "tls", "dns") && strings.EqualFold(a.Type, "dns") {
		if a.DNS.Name == "" {
			c.err("acme.dns.name", "не указан DNS-провайдер")
		} else {
			c.oneOf("acme.dns.name", a.DNS.Name, "cloudflare", "duckdns", "gandi", "godaddy", "namecheap", "njalla", "porkbun", "vultr")
		}
		if len(a.DNS.Config) == 0 {
			c.err("acme.dns.config", "нет настроек DNS-провайдера")
		}
	}
	for _, p := range []struct {
		f string
		v int
	}{{"acme.http.altPort", a.HTTP.AltPort}, {"acme.tls.altPort", a.TLS.AltPort}, {"acme.altHTTPPort", a.AltHTTPPort}, {"acme.altTLSALPNPort", a.AltTLSALPNPort}} {
		if p.v < 0 || p.v > 65535 {
			c.err(p.f, "неверный порт %d", p.v)
		}
	}
}

var domainRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$`)

func (a *Auth) validate(c *checker) {
	if a.Type == "" {
		c.err("auth.type", "не выбран способ входа клиентов")
		return
	}
	if !c.oneOf("auth.type", a.Type, "password", "userpass", "http", "https", "command", "cmd") {
		return
	}
	switch strings.ToLower(a.Type) {
	case "password":
		if a.Password == "" {
			c.err("auth.password", "пустой пароль")
		} else if len(a.Password) < 8 {
			c.warn("auth.password", "короткий пароль: меньше 8 символов")
		}
	case "userpass":
		if len(a.UserPass) == 0 {
			c.err("auth.userpass", "нет ни одного пользователя")
		}
		seen := map[string]string{}
		for _, u := range sortedKeys(a.UserPass) {
			if a.UserPass[u] == "" {
				c.err("auth.userpass."+u, "пустой пароль")
			}
			if strings.Contains(u, ":") {
				c.err("auth.userpass."+u, "двоеточие в имени: клиент отделяет им имя от пароля")
			}
			// Hysteria compares user names case-insensitively.
			if prev, dup := seen[strings.ToLower(u)]; dup {
				c.err("auth.userpass."+u, "совпадает с %s без учёта регистра", prev)
			}
			seen[strings.ToLower(u)] = u
		}
	case "http", "https":
		if a.HTTP.URL == "" {
			c.err("auth.http.url", "не указан адрес")
		} else if u, err := url.Parse(a.HTTP.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			c.err("auth.http.url", "нужен адрес http:// или https://")
		}
	case "command", "cmd":
		if a.Command == "" {
			c.err("auth.command", "не указана программа")
		}
	}
}

func (o *Obfs) validate(c *checker, f string) {
	if o.Type == "" || !c.oneOf(f+".type", o.Type, "plain", "salamander", "gecko") {
		return
	}
	switch strings.ToLower(o.Type) {
	case "salamander":
		if len(o.Salamander.Password) < 4 {
			c.err(f+".salamander.password", "пароль obfs не короче 4 символов")
		}
	case "gecko":
		if o.Gecko.Password == "" {
			c.err(f+".gecko.password", "пустой пароль obfs")
		} else if len(o.Gecko.Password) < 4 {
			c.err(f+".gecko.password", "пароль obfs не короче 4 символов")
		}
		lo, hi := o.Gecko.MinPacketSize, o.Gecko.MaxPacketSize
		if lo == 0 {
			lo = 512
		}
		if hi == 0 {
			hi = 1200
		}
		if lo <= 0 || lo > hi || hi > 2048 {
			c.err(f+".gecko", "размеры пакетов: 0 < minPacketSize ≤ maxPacketSize ≤ 2048")
		}
	}
}

func (m *Masquerade) validate(c *checker) {
	if m.Type != "" && c.oneOf("masquerade.type", m.Type, "404", "file", "proxy", "string") {
		switch strings.ToLower(m.Type) {
		case "file":
			if m.File.Dir == "" {
				c.err("masquerade.file.dir", "не указана папка")
			}
		case "proxy":
			if !validProxyURL(m.Proxy.URL) {
				c.err("masquerade.proxy.url", "нужен адрес http://, https:// или путь к unix-сокету")
			}
		case "string":
			if m.String.Content == "" {
				c.err("masquerade.string.content", "пустой ответ")
			}
			if sc := m.String.StatusCode; sc != 0 && (sc < 200 || sc > 599 || sc == 233) {
				c.err("masquerade.string.statusCode", "код ответа 200–599, кроме 233")
			}
		}
	}
	if m.ListenHTTP != "" && m.ListenHTTPS == "" {
		c.err("masquerade.listenHTTPS", "HTTP без HTTPS Hysteria не поддерживает")
	}
	for _, a := range [][2]string{{"masquerade.listenHTTP", m.ListenHTTP}, {"masquerade.listenHTTPS", m.ListenHTTPS}} {
		if a[1] != "" {
			if _, _, err := net.SplitHostPort(a[1]); err != nil {
				c.err(a[0], "неверный адрес %q", a[1])
			}
		}
	}
}

func validProxyURL(s string) bool {
	if strings.HasPrefix(s, "/") {
		return true
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "http", "https":
		return u.Host != ""
	case "unix":
		return u.Path != ""
	}
	return false
}

func (b *Bandwidth) validate(c *checker, f string) {
	for _, nv := range [][2]string{{"up", b.Up}, {"down", b.Down}} {
		name, v := nv[0], nv[1]
		if v == "" {
			continue
		}
		bps, err := ParseBandwidth(v)
		if err != nil {
			c.err(f+"."+name, "неверная скорость %q (пример: 100 mbps)", v)
		} else if bps != 0 && bps < 65536 {
			c.err(f+"."+name, "не меньше 65536 байт/с (≈ 525 kbps)")
		}
	}
}

// ParseBandwidth converts "100 mbps" to bytes per second, as Hysteria does.
func ParseBandwidth(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	i := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	if i <= 0 {
		return 0, fmt.Errorf("invalid bandwidth %q", s)
	}
	v, err := strconv.ParseUint(s[:i], 10, 64)
	if err != nil {
		return 0, err
	}
	mult := map[string]uint64{
		"b": 1, "bps": 1,
		"k": 1e3, "kb": 1e3, "kbps": 1e3,
		"m": 1e6, "mb": 1e6, "mbps": 1e6,
		"g": 1e9, "gb": 1e9, "gbps": 1e9,
		"t": 1e12, "tb": 1e12, "tbps": 1e12,
	}[strings.TrimSpace(s[i:])]
	if mult == 0 {
		return 0, fmt.Errorf("invalid bandwidth unit in %q", s)
	}
	return v * mult / 8, nil
}

func (g *Congestion) validate(c *checker, f string) {
	if g.Type != "" {
		c.oneOf(f+".type", g.Type, "bbr", "reno")
	}
	if g.BBRProfile != "" && !strings.EqualFold(g.Type, "reno") {
		c.oneOf(f+".bbrProfile", g.BBRProfile, "standard", "conservative", "aggressive")
	}
}

func quicWindows(c *checker, f string, initStream, maxStream, initConn, maxConn uint64) {
	names := []string{"initStreamReceiveWindow", "maxStreamReceiveWindow", "initConnReceiveWindow", "maxConnReceiveWindow"}
	for i, v := range []uint64{initStream, maxStream, initConn, maxConn} {
		if v != 0 && v < 16384 {
			c.err(f+"."+names[i], "не меньше 16384")
		}
	}
}

func (r *Resolver) validate(c *checker) {
	if r.Type == "" || !c.oneOf("resolver.type", r.Type, "system", "tcp", "udp", "tls", "tcp-tls", "https", "http") {
		return
	}
	var addr string
	var timeout Duration
	var f string
	switch strings.ToLower(r.Type) {
	case "system":
		return
	case "tcp":
		f, addr, timeout = "resolver.tcp", r.TCP.Addr, r.TCP.Timeout
	case "udp":
		f, addr, timeout = "resolver.udp", r.UDP.Addr, r.UDP.Timeout
	case "tls", "tcp-tls":
		f, addr, timeout = "resolver.tls", r.TLS.Addr, r.TLS.Timeout
	default:
		f, addr, timeout = "resolver.https", r.HTTPS.Addr, r.HTTPS.Timeout
	}
	if addr == "" {
		c.err(f+".addr", "не указан адрес DNS-сервера")
	}
	c.duration(f+".timeout", timeout, 0, 0)
}

func (o *Outbound) validate(c *checker, f string, names map[string]bool) {
	if o.Name == "" {
		c.err(f+".name", "у выхода нет имени")
	} else if names[strings.ToLower(o.Name)] {
		c.err(f+".name", "имя %q уже занято", o.Name)
	}
	names[strings.ToLower(o.Name)] = true
	if !c.oneOf(f+".type", o.Type, "direct", "socks5", "http") {
		return
	}
	switch strings.ToLower(o.Type) {
	case "direct":
		d := o.Direct
		if d.Mode != "" {
			c.oneOf(f+".direct.mode", d.Mode, "auto", "64", "46", "6", "4")
		}
		if d.BindDevice != "" && (d.BindIPv4 != "" || d.BindIPv6 != "") {
			c.err(f+".direct", "bindDevice нельзя вместе с bindIPv4/bindIPv6")
		}
		if a, err := netip.ParseAddr(d.BindIPv4); d.BindIPv4 != "" && (err != nil || !a.Is4()) {
			c.err(f+".direct.bindIPv4", "неверный IPv4-адрес")
		}
		if a, err := netip.ParseAddr(d.BindIPv6); d.BindIPv6 != "" && (err != nil || !a.Is6()) {
			c.err(f+".direct.bindIPv6", "неверный IPv6-адрес")
		}
	case "socks5":
		if o.SOCKS5.Addr == "" {
			c.err(f+".socks5.addr", "не указан адрес прокси")
		}
	case "http":
		if u, err := url.Parse(o.HTTP.URL); o.HTTP.URL == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			c.err(f+".http.url", "нужен адрес http:// или https://")
		}
	}
}

func (r *Realm) validate(c *checker) {
	if r.IPMode != "" {
		c.oneOf("realm.ipMode", r.IPMode, "dual", "v4", "v6")
	}
	c.duration("realm.stunTimeout", r.STUNTimeout, 0, 0)
	c.duration("realm.punchTimeout", r.PunchTimeout, 0, 0)
	c.duration("realm.heartbeatInterval", r.HeartbeatInterval, 0, 0)
	c.duration("realm.portMapping.timeout", r.PortMapping.Timeout, 0, 0)
	c.duration("realm.portMapping.lifetime", r.PortMapping.Lifetime, 0, 0)
}

// Validate checks a client config (the controller checks what it hands
// out). Unknown fields come back as warnings.
func (cl *Client) Validate() []Problem {
	c := &checker{}
	if cl.Server == "" {
		c.err("server", "не указан адрес сервера")
	} else if !strings.Contains(cl.Server, "://") {
		if _, _, err := SplitServer(cl.Server); err != nil {
			c.err("server", "%s", err)
		}
	}
	if cl.Auth == "" {
		c.warn("auth", "пустой пароль")
	}
	if cl.TLS.PinSHA256 != "" && !pinRe.MatchString(cl.TLS.PinSHA256) {
		c.err("tls.pinSHA256", "pin — SHA-256 сертификата: 64 шестнадцатеричных символа")
	}
	cl.Obfs.validate(c, "obfs")
	if cl.Transport.Type != "" {
		c.oneOf("transport.type", cl.Transport.Type, "udp")
	}
	u := cl.Transport.UDP
	if u.HopInterval != "" && (u.MinHopInterval != "" || u.MaxHopInterval != "") {
		c.err("transport.udp", "hopInterval нельзя вместе с minHopInterval/maxHopInterval")
	}
	for _, h := range []struct {
		field string
		d     Duration
	}{{"transport.udp.hopInterval", u.HopInterval}, {"transport.udp.minHopInterval", u.MinHopInterval}, {"transport.udp.maxHopInterval", u.MaxHopInterval}} {
		c.duration(h.field, h.d, 0, 0)
		// Hysteria refuses a shorter interval (0 is its default, 30s).
		if v, err := parseDuration(h.d); err == nil && v != 0 && v < 5*time.Second {
			c.err(h.field, "не меньше 5s: Hysteria не принимает интервал короче")
		}
	}
	q := cl.QUIC
	quicWindows(c, "quic", q.InitStreamReceiveWindow, q.MaxStreamReceiveWindow, q.InitConnReceiveWindow, q.MaxConnReceiveWindow)
	c.duration("quic.maxIdleTimeout", q.MaxIdleTimeout, 4*time.Second, 120*time.Second)
	c.duration("quic.keepAlivePeriod", q.KeepAlivePeriod, 2*time.Second, 60*time.Second)
	cl.Congestion.validate(c, "congestion")
	cl.Bandwidth.validate(c, "bandwidth")
	if cl.SOCKS5 == nil && cl.HTTP == nil && len(cl.Unknown) == 0 {
		c.warn("socks5", "нет ни одного режима клиента (socks5, http…)")
	}
	for _, f := range UnknownFields(cl) {
		c.warn(f, "поле неизвестно этой версии HyRoute; оно сохранится как есть")
	}
	return c.ps
}

// pinRe is the certificate pin: hex, optionally with colons.
var pinRe = regexp.MustCompile(`(?i)^(?:(?:[0-9a-f]{2}:){31}[0-9a-f]{2}|[0-9a-f]{64})$`)

// UnknownFields lists the paths of all keys the model does not know
// ("quic.newThing", "outbounds[0].direct.extra"), in the order they are
// written: each level's known fields first, then its unknown keys.
func UnknownFields(v any) []string {
	var out []string
	walkUnknown(reflect.ValueOf(v), "", &out)
	return out
}

var unknownType = reflect.TypeOf(Unknown(nil))

func walkUnknown(v reflect.Value, prefix string, out *[]string) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			walkUnknown(v.Elem(), prefix, out)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			walkUnknown(v.Index(i), fmt.Sprintf("%s[%d]", prefix, i), out)
		}
	case reflect.Struct:
		t := v.Type()
		dot := prefix
		if dot != "" {
			dot += "."
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Type == unknownType {
				for _, k := range v.Field(i).Interface().(Unknown).Keys() {
					*out = append(*out, dot+k)
				}
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name != "" && name != "-" {
				walkUnknown(v.Field(i), dot+name, out)
			}
		}
	}
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
