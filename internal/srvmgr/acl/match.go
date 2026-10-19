package acl

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	hacl "github.com/lardan099/hyroute/third_party/hysteria-acl"
	"golang.org/x/net/idna"
)

// Request is a connection to try against the rules.
type Request struct {
	// Host is a domain or an IP. A domain in Unicode is tried as a client
	// sends it, in punycode.
	Host string `json:"host"`
	// IPs are what the domain resolves to on the server, if known: rules
	// by IP match them.
	IPs   []string `json:"ips,omitempty"`
	Proto string   `json:"proto,omitempty"` // tcp (default) or udp
	Port  int      `json:"port"`
}

// Verdict is where a request goes.
type Verdict struct {
	// Rule is the index of the rule that matched; -1: none, the default
	// outbound.
	Rule int `json:"rule"`
	// Outbound is the outbound the connection leaves by, as the config
	// names it (default is the first outbound, reject refuses it).
	Outbound string `json:"outbound"`
	Hijack   string `json:"hijack,omitempty"`
	// Builtin: Outbound is Hysteria's own (direct, reject), not one of
	// the config's of that name.
	Builtin bool `json:"builtin,omitempty"`
	// Reason says why.
	Reason string `json:"reason"`
	// Unknown are enabled rules above it that were not tried: they have
	// errors or geo names without a database. On the server one of them
	// may match first.
	Unknown []int `json:"unknown,omitempty"`
}

// Match says which rule a request matches, as the server would.
func Match(d Document, env Env, q Request) (Verdict, error) {
	h, proto, port, err := q.parse()
	if err != nil {
		return Verdict{}, err
	}
	_, valid, _ := d.compile(env)
	return compileSet(d, valid, withPrivate{env.Geo}).verdict(d, env, q, h, proto, port), nil
}

// parse checks the request and makes it what the rules see.
func (q Request) parse() (hacl.HostInfo, hacl.Protocol, uint16, error) {
	host := strings.TrimRight(strings.ToLower(strings.TrimSpace(q.Host)), ".")
	if host == "" {
		return hacl.HostInfo{}, 0, 0, errors.New("укажите домен или IP-адрес")
	}
	h := hostOf(host)
	if h.IPv4 == nil && h.IPv6 == nil {
		a, err := idna.ToASCII(host)
		if err != nil || strings.ContainsAny(a, " /:@,#()") {
			return h, 0, 0, fmt.Errorf("«%s» — не домен и не IP-адрес", q.Host)
		}
		h.Name = a
		for _, s := range q.IPs {
			ip := net.ParseIP(strings.TrimSpace(s))
			switch {
			case ip == nil:
				return h, 0, 0, fmt.Errorf("«%s» — не IP-адрес", s)
			case ip.To4() != nil:
				if h.IPv4 == nil {
					h.IPv4 = ip.To4()
				}
			case h.IPv6 == nil:
				h.IPv6 = ip
			}
		}
	}
	proto := hacl.ProtocolTCP
	switch strings.ToLower(q.Proto) {
	case "", "tcp":
	case "udp":
		proto = hacl.ProtocolUDP
	default:
		return h, 0, 0, fmt.Errorf("протокол — tcp или udp, а не «%s»", q.Proto)
	}
	if q.Port < 1 || q.Port > 65535 {
		return h, 0, 0, errors.New("порт — от 1 до 65535")
	}
	return h, proto, uint16(q.Port), nil
}

// Set is the valid enabled rules compiled together, for matching.
type Set struct {
	rs hacl.CompiledRuleSet[int]
	// tried are the rules in it.
	tried []bool
}

// compileSet compiles the rules Hysteria accepts and the controller can
// match; each matches as its index.
func compileSet(d Document, valid []bool, geo withPrivate) *Set {
	s := &Set{tried: make([]bool, len(d.Rules))}
	var trs []hacl.TextRule
	obs := map[string]int{}
	for i, r := range d.Rules {
		if !valid[i] || !geo.known(r.Address) {
			continue
		}
		tr := r.text()
		tr.Outbound = "r" + strconv.Itoa(i)
		obs[tr.Outbound] = i + 1
		trs = append(trs, tr)
		s.tried[i] = true
	}
	// Every rule compiled alone already. Should they fail together (a geo
	// database that no longer reads), none of them was tried: the verdict
	// lists them as unknown instead of matching none.
	rs, err := hacl.Compile[int](trs, obs, 1024, geo)
	if err != nil {
		clear(s.tried)
		return s
	}
	s.rs = rs
	return s
}

func (s *Set) verdict(d Document, env Env, q Request, h hacl.HostInfo, proto hacl.Protocol, port uint16) Verdict {
	i, hijack := -1, net.IP(nil)
	if s.rs != nil {
		n, ip := s.rs.Match(h, proto, port)
		i, hijack = n-1, ip
	}
	v := Verdict{Rule: i}
	end := len(d.Rules)
	if i >= 0 {
		end = i
	}
	for j := range end {
		if r := d.Rules[j]; !r.Off && !s.tried[j] {
			v.Unknown = append(v.Unknown, j)
		}
	}
	// Hysteria puts the ACL in front whenever acl.inline has a line.
	hasACL := d.Text() != ""
	if i < 0 {
		v.Outbound, v.Builtin = defaultOutbound(env, hasACL)
		v.Reason = "Ни одно правило не подошло: соединение уходит в outbound по умолчанию «" + v.Outbound + "»."
		if len(env.Outbounds) == 0 {
			v.Reason = "Ни одно правило не подошло: outbounds нет, соединение идёт напрямую."
		}
		return v
	}
	r := d.Rules[i]
	v.Outbound, v.Builtin = outboundName(r.Outbound, env, hasACL)
	if hijack != nil {
		v.Hijack = hijack.String()
	}
	v.Reason = fmt.Sprintf("Правило %d: %s.", i+1, why(r, q, h))
	switch {
	case v.Builtin && v.Outbound == "reject":
		v.Reason += " Соединение отклоняется."
	case strings.EqualFold(r.Outbound, "default") && !strings.EqualFold(v.Outbound, "default"):
		v.Reason += " default — outbound по умолчанию «" + v.Outbound + "»."
	}
	if v.Hijack != "" {
		v.Reason += " Соединение уходит на " + v.Hijack + " вместо запрошенного адреса."
	}
	return v
}

// why explains a match.
func why(r Rule, q Request, h hacl.HostInfo) string {
	addr := strings.TrimSpace(r.Address)
	ips := func() string {
		var s []string
		for _, ip := range []net.IP{h.IPv4, h.IPv6} {
			if ip != nil {
				s = append(s, ip.String())
			}
		}
		return strings.Join(s, " или ")
	}
	var s string
	switch KindOf(addr) {
	case KindAll:
		s = "подходит любое соединение"
	case KindIP:
		s = "адрес " + ips() + " совпал с " + addr
	case KindCIDR:
		s = "адрес " + ips() + " в подсети " + addr
	case KindGeoIP:
		s = "адрес " + ips() + " из " + addr
	case KindDomain:
		s = "домен " + h.Name + " совпал с " + addr
	case KindWildcard:
		s = "домен " + h.Name + " подходит под шаблон " + addr
	case KindSuffix:
		s = "домен " + h.Name + " — это " + strings.TrimPrefix(norm(addr), "suffix:") + " или его поддомен"
	case KindGeoSite:
		s = "домен " + h.Name + " есть в списке " + addr
	}
	if pp := joinProtoPort(r.Proto, r.Port); pp != "" {
		s += ", протокол и порт подходят под " + pp
	}
	if a := strings.TrimRight(strings.ToLower(strings.TrimSpace(q.Host)), "."); h.Name != a && net.ParseIP(a) == nil {
		s += " (" + q.Host + " клиент передаёт как " + h.Name + ")"
	}
	return s
}

// outboundName is the outbound a rule's name stands for, as the config
// names it, and whether it is one of Hysteria's built-in ones (an outbound
// of the config with the same name overrides it).
func outboundName(name string, env Env, hasACL bool) (string, bool) {
	for _, o := range env.Outbounds {
		if strings.EqualFold(o, name) {
			return o, false
		}
	}
	if strings.EqualFold(name, "default") {
		return defaultOutbound(env, hasACL)
	}
	return strings.ToLower(name), true
}

// defaultOutbound is where unmatched connections go: with rules, the
// config's outbound named default if there is one; else the first
// outbound; direct without outbounds.
func defaultOutbound(env Env, hasACL bool) (string, bool) {
	if hasACL {
		for _, o := range env.Outbounds {
			if strings.EqualFold(o, "default") {
				return o, false
			}
		}
	}
	if len(env.Outbounds) > 0 {
		return env.Outbounds[0], false
	}
	return "direct", true
}

// Change is a request an edit sends elsewhere.
type Change struct {
	Request Request `json:"request"`
	Before  Verdict `json:"before"`
	After   Verdict `json:"after"`
}

// maxSamples bounds the requests a dry run tries.
const maxSamples = 1000

// DryRun tries the given requests and samples of both rule sets (a
// domain, an address of a subnet, a name under a suffix) before and after
// an edit, and returns those that leave by another outbound or go to
// another address. was maps the config's outbounds after the edit to
// those before it (lower-case name → name before; a new one is not in
// it): a renamed outbound is the same one, and one that took the old name
// of another is not. Nil: an outbound is the one of the same name.
func DryRun(before, after Document, envBefore, envAfter Env, was map[string]string, extra []Request) ([]Change, error) {
	for _, q := range extra {
		if _, _, _, err := q.parse(); err != nil {
			return nil, err
		}
	}
	reqs := slices.Clone(extra)
	seen := map[string]bool{}
	for _, q := range reqs {
		seen[q.key()] = true
	}
	for _, d := range []Document{before, after} {
		for _, r := range d.Rules {
			if r.Bad() {
				continue
			}
			for _, q := range samples(r) {
				if k := q.key(); !seen[k] && len(reqs) < maxSamples {
					seen[k] = true
					reqs = append(reqs, q)
				}
			}
		}
	}
	_, vb, _ := before.compile(envBefore)
	_, va, _ := after.compile(envAfter)
	sb := compileSet(before, vb, withPrivate{envBefore.Geo})
	sa := compileSet(after, va, withPrivate{envAfter.Geo})
	var out []Change
	for _, q := range reqs {
		h, proto, port, err := q.parse()
		if err != nil {
			continue // a sample of a rule with an error
		}
		b := sb.verdict(before, envBefore, q, h, proto, port)
		a := sa.verdict(after, envAfter, q, h, proto, port)
		if !sameRoute(b, a, was) {
			out = append(out, Change{Request: q, Before: b, After: a})
		}
	}
	return out, nil
}

// sameRoute: a request leaves by the same outbound before and after the
// edit (was as in DryRun), to the same address.
func sameRoute(b, a Verdict, was map[string]string) bool {
	if b.Builtin != a.Builtin || b.Hijack != a.Hijack {
		return false
	}
	if a.Builtin || was == nil {
		return strings.EqualFold(b.Outbound, a.Outbound)
	}
	from, ok := was[strings.ToLower(a.Outbound)]
	return ok && strings.EqualFold(from, b.Outbound)
}

func (q Request) key() string {
	return strings.ToLower(q.Host) + "|" + strings.Join(q.IPs, ",") + "|" + strings.ToLower(q.Proto) + "|" + strconv.Itoa(q.Port)
}

// samples are requests a rule matches: its domain, a name under its
// suffix or wildcard, its IP or an address of its subnet. Geo rules and
// all have none.
func samples(r Rule) []Request {
	proto, port := r.Proto, 443
	if proto == "" {
		proto = "tcp"
	}
	if lo, _, ok := portRange(r.Port); ok {
		port = int(lo)
	}
	a := norm(strings.TrimSpace(r.Address))
	var hosts []string
	switch KindOf(a) {
	case KindDomain, KindIP:
		hosts = []string{a}
	case KindSuffix:
		x := strings.TrimPrefix(a, "suffix:")
		hosts = []string{x, "www." + x}
	case KindWildcard:
		hosts = []string{strings.ReplaceAll(a, "*", "a")}
	case KindCIDR:
		if _, n, err := net.ParseCIDR(a); err == nil {
			ip := slices.Clone(n.IP)
			if ones, bits := n.Mask.Size(); ones < bits {
				ip[len(ip)-1]++
			}
			hosts = []string{ip.String()}
		}
	}
	var out []Request
	for _, h := range hosts {
		out = append(out, Request{Host: h, Proto: proto, Port: port})
	}
	return out
}
