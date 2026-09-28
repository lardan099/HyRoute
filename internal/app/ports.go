package app

// Port rules: the port options of rules text, the port of «Проверить
// адрес» and of the lists page, and the DNS lookup hook they share.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/rules"
)

// portsState is the controller state of port rules. Lock: none — set
// before the controller is used (tests only), read without c.mu.
type portsState struct {
	// lookupIP resolves a site for Explain and Inspect (nil = the system
	// resolver). Tests set a stub, so they make no DNS queries.
	lookupIP func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// lookupNetIP resolves host through the hook or the system resolver.
func (c *Controller) lookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if c.lookupIP != nil {
		return c.lookupIP(ctx, network, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// splitTarget reads what people paste into «Проверить адрес»: a URL,
// host:port, a rule-style pattern (.example.com, *.example.com) or an IP.
// port is the explicit port (0 = none or invalid), scheme the link's
// (lower-case, "" for none).
func splitTarget(s string) (host string, port uint16, scheme string) {
	s = strings.TrimSpace(s)
	p := ""
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		s, p, scheme = u.Hostname(), u.Port(), strings.ToLower(u.Scheme)
	} else if h, hp, err := net.SplitHostPort(s); err == nil {
		s, p = h, hp
	}
	if n, err := strconv.ParseUint(p, 10, 16); err == nil {
		port = uint16(n)
	}
	s = strings.TrimPrefix(s, "*.")
	return strings.Trim(s, ".[]"), port, scheme
}

// schemePort is the default port of a link scheme (0 = none).
func schemePort(scheme string) uint16 {
	switch scheme {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

// explainPort picks the port Explain checks: the field, else the one in
// the target, else the link scheme's. Notes say where it came from.
func explainPort(field int, tport uint16, scheme string) (port uint16, notes []string) {
	switch {
	case field < 0 || field > 65535:
		return 0, []string{fmt.Sprintf("Порт %d не бывает (от 1 до 65535): проверено без порта.", field)}
	case field > 0:
		implied := tport
		if implied == 0 {
			implied = schemePort(scheme)
		}
		if implied != 0 && implied != uint16(field) {
			notes = append(notes, fmt.Sprintf("Порт из адреса (%d) не учтён: проверен порт %d.", implied, field))
		}
		return uint16(field), notes
	case tport != 0:
		return tport, []string{fmt.Sprintf("Порт %d взят из адреса.", tport)}
	case schemePort(scheme) != 0:
		p := schemePort(scheme)
		return p, []string{fmt.Sprintf("Порт %d взят из ссылки.", p)}
	}
	return 0, nil
}

// inspectPort is the port the lists page asks about: a TCP connection to
// the site's web port (the one in the query, else 80 for an http:// link,
// else 443).
func inspectPort(tport uint16, scheme string) uint16 {
	switch {
	case tport != 0:
		return tport
	case scheme == "http":
		return 80
	}
	return 443
}

// lineOpts are the options of a rules text line (after "|").
type lineOpts struct {
	proto   string   // "", "tcp", "udp"
	ports   []string // canonical; nil = none
	portOpt bool     // a port option was written (even a bad one)
	off     bool
	nochild bool
}

// portKeywords start a port option, longest first: "порты 80, 443".
var portKeywords = []string{"порты", "ports", "порт", "port", "tcp", "udp"}

// parseLineOptions reads the options of a line; errs are messages for the
// line (nothing of the line is used then).
func parseLineOptions(opts string) (o lineOpts, errs []string) {
	both := false // said once however many times: | tcp | udp | tcp
	setProto := func(p string) {
		if o.proto != "" && o.proto != p && !both {
			both = true
			errs = append(errs, "в одном правиле один протокол: для TCP и UDP сразу уберите протокол (| порт 53), для разных портов — две строки")
		}
		o.proto = p
	}
	for _, raw := range strings.Split(opts, "|") {
		t := strings.TrimSpace(raw)
		switch low := strings.ToLower(t); low {
		case "":
		case "tcp", "udp":
			setProto(low)
		case "выкл", "off", "disabled":
			o.off = true
		case "без дочерних", "nochild", "nochildren":
			o.nochild = true
		case "порт", "порты", "port", "ports":
			o.portOpt = true
			errs = append(errs, fmt.Sprintf("после «%s» укажите порт, например: %s 443", low, low))
		default:
			kw, rest, ok := portOption(low)
			if !ok {
				errs = append(errs, fmt.Sprintf("непонятная опция %q (есть: tcp, udp, tcp 443, порты 80, 443, выкл, без дочерних)", t))
				continue
			}
			o.portOpt = true
			if rest == "" {
				errs = append(errs, fmt.Sprintf("после «%s» укажите порт, например: %s 443", kw, kw))
				continue
			}
			ports, err := rules.ParsePortList(rest)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
			if o.ports != nil {
				// v1.2.0 wrote several port options ("| порт 443 | порт
				// 8443"): one list; the export writes one option.
				if ports, err = rules.CanonPorts(append(o.ports, ports...)); err != nil {
					errs = append(errs, err.Error())
					continue
				}
			}
			o.ports = ports
			if kw == "tcp" || kw == "udp" {
				setProto(kw)
			}
		}
	}
	return o, errs
}

// portOption splits a port option ("tcp 443", "udp/27000-27100",
// "порты 80, 443") into its keyword and the port list: the keyword is
// followed by a space, "/" or ":".
func portOption(low string) (kw, rest string, ok bool) {
	for _, k := range portKeywords {
		if after, found := strings.CutPrefix(low, k); found && after != "" && strings.ContainsRune(" \t/:", rune(after[0])) {
			return k, strings.TrimSpace(after[1:]), true
		}
	}
	return "", "", false
}

// ruleOptionText writes the protocol/ports option ("" when none). When an
// item doesn't validate, the list is written with each bad item defanged
// (rawPortItem) so the parser reports a bad port on that line; items are
// never dropped (dropping would widen the rule on re-import). Rules text
// and the ACL converter share it.
func ruleOptionText(protocol string, items []string) string {
	proto := strings.ToLower(protocol)
	if proto == "any" {
		proto = ""
	}
	ports, err := rules.CanonPorts(items)
	text := rules.FormatPorts(ports)
	if err != nil {
		ports = items
		parts := make([]string, len(items))
		for i, it := range items {
			if pr, e := rules.ParsePortItem(it); e == nil {
				parts[i] = pr.String()
			} else {
				parts[i] = rawPortItem(it)
			}
		}
		text = strings.Join(parts, ", ")
	}
	switch {
	case len(ports) > 0 && proto != "":
		return proto + " " + text
	case len(ports) > 0:
		return rules.PortWord(ports) + " " + text
	}
	return proto
}

// rawPortItem defangs an invalid stored item for export: every rune other
// than an ASCII digit or '-' becomes '?', and "" becomes "?". The result
// never contains '|', '#', '"', ',', ';', CR/LF or spaces, so it cannot
// inject options, a comment or a new line, cannot be split into valid
// items, and still fails ParsePortItem (a '?' is never valid; an item of
// digits and '-' only was invalid as is).
func rawPortItem(s string) string {
	if s == "" {
		return "?"
	}
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '?'
	}, s)
}

// aclProtoPort reads the protocol/port argument of a Hysteria ACL line,
// line for line as Hysteria's parseProtoPort (extras/outbounds/acl,
// app/v2.12.3) does, so ok is false exactly when Hysteria refuses the
// line. Its matcher treats a start port of 0 as any port: "tcp/0" and
// "tcp/0-100" mean TCP on any port. anyPort: every protocol and port.
func aclProtoPort(extra string) (proto string, ports []string, anyPort, ok bool) {
	pp := strings.ToLower(extra)
	if pp == "" || pp == "*" || pp == "*/*" {
		return "", nil, true, true
	}
	p, port, hasPort := strings.Cut(pp, "/")
	switch p {
	case "tcp", "udp":
		proto = p
	case "*":
		if !hasPort {
			return "", nil, false, false
		}
	default:
		return "", nil, false, false
	}
	if !hasPort || port == "*" {
		return proto, nil, proto == "", true
	}
	var lo, hi uint64
	var err error
	if a, b, isRange := strings.Cut(strings.TrimSpace(port), "-"); !isRange {
		// A single port is parsed untrimmed, a range's sides after the
		// whole part was trimmed: "tcp/ 80" fails, "tcp/ 80-90" passes.
		if lo, err = strconv.ParseUint(port, 10, 16); err != nil {
			return "", nil, false, false
		}
		hi = lo
	} else {
		if lo, err = strconv.ParseUint(a, 10, 16); err != nil {
			return "", nil, false, false
		}
		if hi, err = strconv.ParseUint(b, 10, 16); err != nil || lo > hi {
			return "", nil, false, false
		}
	}
	if lo == 0 {
		return proto, nil, proto == "", true
	}
	return proto, []string{rules.PortRange{Lo: uint16(lo), Hi: uint16(hi)}.String()}, false, true
}
