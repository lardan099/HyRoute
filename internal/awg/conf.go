package awg

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Conf is a parsed .conf: the settings and the server's endpoint.
type Conf struct {
	// Name comes from a "# Name = …" comment, as HyRoute writes it (and
	// some panels do); "" when there is none.
	Name     string
	Host     string
	Port     int
	Settings Settings
}

// IsConf reports whether text looks like a WireGuard or AmneziaWG
// configuration (an [Interface] section).
func IsConf(text string) bool {
	return strings.Contains(strings.ToLower(text), "[interface]")
}

// SplitConfs cuts text holding several configurations at each
// [Interface] line. A "# Name" comment just above one goes with it.
func SplitConfs(text string) []string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	var out []string
	start := -1
	for i, l := range lines {
		if !strings.EqualFold(strings.TrimSpace(l), "[interface]") {
			continue
		}
		cut := i
		for cut > 0 && isComment(lines[cut-1]) && start < cut-1 {
			cut--
		}
		if start >= 0 {
			out = append(out, strings.Join(lines[start:cut], "\n"))
		}
		start = cut
	}
	if start >= 0 {
		out = append(out, strings.Join(lines[start:], "\n"))
	}
	return out
}

func isComment(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "#") }

// ParseConf reads one configuration in the format of amneziawg-tools
// and wg-quick. Keys are case-insensitive; empty values (the Amnezia
// app's template leaves "I2 = " and the like) are unset. What HyRoute does
// not use comes back as warnings.
func ParseConf(text string) (Conf, []string, error) {
	var c Conf
	var warns []string
	warned := map[string]bool{}
	warn := func(key, msg string) {
		if !warned[key] {
			warned[key] = true
			warns = append(warns, msg)
		}
	}
	section, peers := "", 0
	var allowed []string
	var endpoint string
	s := &c.Settings
	for n, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
		if strings.HasPrefix(line, "#") {
			if name, ok := nameComment(line); ok && c.Name == "" && peers == 0 {
				c.Name = name
			}
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
			case "peer":
				peers++
				if peers > 1 {
					warn("peers", "в конфиге несколько [Peer]: HyRoute подключается к первому")
				}
			default:
				return c, nil, fmt.Errorf("строка %d: неизвестный раздел [%s]", n+1, line[1:len(line)-1])
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return c, nil, fmt.Errorf("строка %d: ожидалось «ключ = значение»", n+1)
		}
		key, val := strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if val == "" || peers > 1 {
			continue
		}
		var err error
		switch section {
		case "interface":
			err = c.interfaceKey(key, val, warn)
		case "peer":
			switch key {
			case "publickey":
				s.PublicKey = val
			case "presharedkey":
				s.PresharedKey = val
			case "endpoint":
				endpoint = val
			case "allowedips":
				allowed = append(allowed, splitList(val)...)
			case "persistentkeepalive":
				if val != "off" {
					s.Keepalive = val
				}
			case "advancedsecurity":
				// The kernel module's switch: the userspace one has none.
			default:
				warn(key, fmt.Sprintf("параметр %s в [Peer] не поддерживается и пропущен", strings.TrimSpace(k)))
			}
		default:
			return c, nil, fmt.Errorf("строка %d: параметр вне раздела [Interface] или [Peer]", n+1)
		}
		if err != nil {
			return c, nil, fmt.Errorf("строка %d: %v", n+1, err)
		}
	}
	if peers == 0 {
		return c, nil, errors.New("в конфиге нет раздела [Peer] с сервером")
	}
	if endpoint == "" {
		return c, nil, errors.New("в [Peer] нет адреса сервера (Endpoint)")
	}
	host, port, err := net.SplitHostPort(endpoint)
	p, perr := strconv.Atoi(port)
	if err != nil || perr != nil || p < 1 || p > 65535 || host == "" {
		return c, nil, fmt.Errorf("Endpoint %q: нужен адрес и порт, например 203.0.113.5:51820", endpoint)
	}
	c.Host, c.Port = host, p
	if len(allowed) > 0 && !fullRoute(allowed) {
		warn("allowed", "AllowedIPs из конфига не используется: что идёт через сервер, решают правила HyRoute")
	}
	if err := s.Validate(); err != nil {
		return c, nil, err
	}
	return c, warns, nil
}

func (c *Conf) interfaceKey(key, val string, warn func(key, msg string)) error {
	s := &c.Settings
	ints := map[string]*int{"jc": &s.Jc, "jmin": &s.Jmin, "jmax": &s.Jmax, "s1": &s.S1, "s2": &s.S2, "s3": &s.S3, "s4": &s.S4, "mtu": &s.MTU}
	strs := map[string]*string{
		"privatekey": &s.PrivateKey, "h1": &s.H1, "h2": &s.H2, "h3": &s.H3, "h4": &s.H4,
		"i1": &s.I1, "i2": &s.I2, "i3": &s.I3, "i4": &s.I4, "i5": &s.I5,
		"headerprotectionkey": &s.HeaderProtectionKey, "contentpaddingaddition": &s.ContentPadding,
		"rekeyaftertime": &s.RekeyAfterTime, "rekeytimeout": &s.RekeyTimeout, "rejectaftertime": &s.RejectAfterTime,
		"keepalivetimeout": &s.KeepaliveTimeout, "maxhandshakeattempts": &s.MaxHandshakeAttempts,
	}
	bools := map[string]*bool{"randomtrailers": &s.RandomTrailers, "disablecookies": &s.DisableCookies}
	if p, ok := ints[key]; ok {
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("%s = %q: нужно целое число", key, val)
		}
		*p = n
		return nil
	}
	if p, ok := strs[key]; ok {
		*p = val
		return nil
	}
	if p, ok := bools[key]; ok {
		b, err := parseBool(val)
		if err != nil {
			return fmt.Errorf("%s = %q: нужно true или false", key, val)
		}
		*p = b
		return nil
	}
	switch key {
	case "address":
		s.Address = joinList(s.Address, val)
	case "dns":
		for _, f := range splitList(val) {
			if _, err := netip.ParseAddr(f); err != nil {
				warn("dns-search", "домены поиска из DNS пропущены: HyRoute спрашивает через туннель только серверы DNS")
				continue
			}
			s.DNS = joinList(s.DNS, f)
		}
	case "listenport", "fwmark", "table", "saveconfig":
		// The local port is any, the routing HyRoute's.
	case "preup", "postup", "predown", "postdown":
		warn("scripts", "команды PreUp, PostUp, PreDown и PostDown из конфига HyRoute не выполняет")
	case "j1", "j2", "j3", "itime":
		warn(key, "параметры J1–J3 и Itime из AmneziaWG 1.5 больше не поддерживаются и пропущены")
	default:
		warn(key, fmt.Sprintf("параметр %s в [Interface] не поддерживается и пропущен", key))
	}
	return nil
}

func joinList(list, v string) string {
	if list == "" {
		return v
	}
	return list + ", " + v
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "1", "on", "yes":
		return true, nil
	case "false", "0", "off", "no":
		return false, nil
	}
	return false, errors.New("bad bool")
}

// nameComment reads "# Name = X" or "# Name: X".
func nameComment(line string) (string, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "#"))
	if len(rest) < 5 || !strings.EqualFold(rest[:4], "name") {
		return "", false
	}
	rest = strings.TrimSpace(rest[4:])
	if rest == "" || (rest[0] != '=' && rest[0] != ':') {
		return "", false
	}
	name := strings.TrimSpace(rest[1:])
	return name, name != ""
}

// fullRoute: the AllowedIPs cover all IPv4 addresses.
func fullRoute(list []string) bool {
	for _, a := range list {
		if p, err := netip.ParsePrefix(a); err == nil && p.Bits() == 0 && p.Addr().Is4() {
			return true
		}
	}
	return false
}

// String writes the configuration as a .conf for amneziawg-tools and the
// AmneziaWG apps, secrets included.
func (c Conf) String() string {
	s := c.Settings
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			b.WriteString(k + " = " + v + "\n")
		}
	}
	num := func(k string, v int) {
		if v != 0 {
			line(k, strconv.Itoa(v))
		}
	}
	flag := func(k string, v bool) {
		if v {
			line(k, "true")
		}
	}
	if c.Name != "" {
		b.WriteString("# Name = " + strings.Join(strings.Fields(c.Name), " ") + "\n")
	}
	b.WriteString("[Interface]\n")
	line("PrivateKey", s.PrivateKey)
	line("Address", s.Address)
	line("DNS", s.DNS)
	num("MTU", s.MTU)
	num("Jc", s.Jc)
	num("Jmin", s.Jmin)
	num("Jmax", s.Jmax)
	num("S1", s.S1)
	num("S2", s.S2)
	num("S3", s.S3)
	num("S4", s.S4)
	line("H1", s.H1)
	line("H2", s.H2)
	line("H3", s.H3)
	line("H4", s.H4)
	line("I1", s.I1)
	line("I2", s.I2)
	line("I3", s.I3)
	line("I4", s.I4)
	line("I5", s.I5)
	line("HeaderProtectionKey", s.HeaderProtectionKey)
	line("ContentPaddingAddition", s.ContentPadding)
	line("RekeyAfterTime", s.RekeyAfterTime)
	line("RekeyTimeout", s.RekeyTimeout)
	line("RejectAfterTime", s.RejectAfterTime)
	line("KeepaliveTimeout", s.KeepaliveTimeout)
	line("MaxHandshakeAttempts", s.MaxHandshakeAttempts)
	flag("RandomTrailers", s.RandomTrailers)
	flag("DisableCookies", s.DisableCookies)
	b.WriteString("\n[Peer]\n")
	line("PublicKey", s.PublicKey)
	line("PresharedKey", s.PresharedKey)
	line("AllowedIPs", "0.0.0.0/0, ::/0")
	line("Endpoint", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	line("PersistentKeepalive", s.Keepalive)
	return b.String()
}
