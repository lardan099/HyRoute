package acl

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	hacl "github.com/lardan099/hyroute/third_party/hysteria-acl"
	"github.com/lardan099/hyroute/third_party/hysteria-acl/v2geo"
)

// Problem levels.
const (
	Error = "error" // Hysteria refuses the config
	Warn  = "warn"
)

// Problem is what a check found.
type Problem struct {
	// Rule is the index in Document.Rules; -1: the ACL as a whole.
	Rule int `json:"rule"`
	// Line is 1-based in Document.Text() (0: none).
	Line    int    `json:"line,omitempty"`
	Level   string `json:"level"`
	Code    string `json:"code"`
	Message string `json:"message"`
	// Detail is Hysteria's own message.
	Detail string `json:"detail,omitempty"`
	// Other is the rule above that makes this one useless (shadowed,
	// duplicate).
	Other *int `json:"other,omitempty"`
	// Fix are rules to add at the top.
	Fix []Rule `json:"fix,omitempty"`
}

// Env is what the checks know about the server.
type Env struct {
	// Outbounds are the names of the config's outbounds, in order.
	Outbounds []string
	// Geo reads the controller's geo databases (P3-07); nil: there are
	// none, and geo names are not checked.
	Geo hacl.GeoLoader
	// Entry: the server is the entry of a cascade.
	Entry    bool
	Resolver hyconfig.Resolver
}

// EnvOf is the environment of a server config.
func EnvOf(c *hyconfig.Server) Env {
	e := Env{Resolver: c.Resolver}
	for _, o := range c.Outbounds {
		e.Outbounds = append(e.Outbounds, o.Name)
	}
	return e
}

// Check returns what Hysteria would refuse in d, then the lint.
func Check(d Document, env Env) []Problem {
	lines, at := d.render()
	obs := outboundMap(env.Outbounds)
	geo := withPrivate{env.Geo}
	var ps []Problem
	add := func(i int, p Problem) {
		p.Rule, p.Line = i, at[i]+1
		ps = append(ps, p)
	}
	valid := make([]bool, len(d.Rules))
	for i, r := range d.Rules {
		if r.Bad() {
			add(i, Problem{Level: Error, Code: "syntax", Message: "Hysteria не прочтёт эту строку: правило пишется как выход(адрес), выход(адрес, протокол/порт) или выход(адрес, протокол/порт, подмена)."})
			continue
		}
		if p, bad := r.fields(lines[at[i]]); bad {
			add(i, p)
			continue
		}
		if r.Off {
			continue // a comment for Hysteria
		}
		if p, bad := compileRule(r, obs, geo); bad {
			add(i, p)
			continue
		}
		valid[i] = true
	}
	return append(ps, lint(d, env, valid, at)...)
}

// fields: the rule's line reads back as the rule (no comma, "#", bracket
// or line break inside a field) and the outbound is a name Hysteria
// accepts.
func (r Rule) fields(line string) (Problem, bool) {
	if strings.ContainsAny(r.Group, "\r\n") {
		return Problem{Level: Error, Code: "chars", Message: "В имени группы не может быть перевода строки."}, true
	}
	if !wordRe(r.Outbound) {
		return Problem{Level: Error, Code: "outbound_name", Message: fmt.Sprintf("Hysteria не примет выход %q: в имени только латинские буквы, цифры и _.", r.Outbound)}, true
	}
	if back, ok := readRule(line); !ok || !same(back, r) {
		return Problem{Level: Error, Code: "chars", Message: "В поле правила недопустимый символ: запятая, #, скобка или перевод строки."}, true
	}
	return Problem{}, false
}

func wordRe(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// outboundMap maps the outbound names Hysteria knows (lower case) to
// their order; the built-in ones come after the config's.
func outboundMap(names []string) map[string]int {
	m := map[string]int{}
	for i, n := range names {
		m[strings.ToLower(n)] = i + 1
	}
	for _, n := range []string{"direct", "reject", "default"} {
		if _, ok := m[n]; !ok {
			m[n] = len(m) + 1
		}
	}
	return m
}

func (r Rule) text() hacl.TextRule {
	return hacl.TextRule{Outbound: r.Outbound, Address: r.Address, ProtoPort: joinProtoPort(r.Proto, r.Port), HijackAddress: r.Hijack, LineNum: 1}
}

// compileRule runs Hysteria's compiler on one rule. Without a geo
// database a geo name is not checked, the other fields are.
func compileRule(r Rule, obs map[string]int, geo withPrivate) (Problem, bool) {
	tr := r.text()
	_, err := hacl.Compile[int]([]hacl.TextRule{tr}, obs, 1, geo)
	var ce *hacl.CompilationError
	if errors.As(err, &ce) && !geo.known(r.Address) && !strings.HasPrefix(ce.Message, "empty ") {
		tr.Address = "all"
		_, err = hacl.Compile[int]([]hacl.TextRule{tr}, obs, 1, geo)
	}
	if err == nil {
		return Problem{}, false
	}
	return compileProblem(err), true
}

// compileProblem says in Russian what the compiler refused.
func compileProblem(err error) Problem {
	p := Problem{Level: Error, Code: "compile", Message: "Hysteria не примет это правило.", Detail: err.Error()}
	var ce *hacl.CompilationError
	if !errors.As(err, &ce) {
		return p
	}
	m := ce.Message
	p.Detail = m
	for _, c := range []struct{ prefix, code, msg string }{
		{"outbound ", "unknown_outbound", "Нет выхода «%s»: добавьте его в outbounds или выберите другой."},
		{"invalid protocol/port: ", "bad_port", "Неверный протокол или порт «%s»: протокол tcp или udp, порт 1–65535 или диапазон."},
		{"invalid hijack address (must be an IP address): ", "bad_hijack", "Подмена — только IP-адрес, а не «%s»."},
		{"invalid CIDR address: ", "bad_cidr", "Неверная подсеть «%s»."},
		{"empty GeoIP country code", "empty_geo", "Не указана страна после geoip:."},
		{"GeoIP country code ", "unknown_geo", "В базе geoip нет «%s»."},
		{"empty GeoSite name", "empty_geo", "Не указана категория после geosite:."},
		{"GeoSite name ", "unknown_geo", "В базе geosite нет «%s»."},
		{"empty domain suffix", "empty_suffix", "Не указан домен после suffix:."},
	} {
		rest, ok := strings.CutPrefix(m, c.prefix)
		if !ok {
			continue
		}
		rest = strings.TrimSuffix(rest, " not found")
		p.Code, p.Message = c.code, c.msg
		if strings.Contains(c.msg, "%s") {
			p.Message = fmt.Sprintf(c.msg, rest)
		}
		return p
	}
	return p
}

var errNoGeo = errors.New("hyroute: no geo database")

// withPrivate is the controller's geo databases; without them geoip:private
// is still known (the reserved networks, as in the databases).
type withPrivate struct{ hacl.GeoLoader }

func (g withPrivate) LoadGeoIP() (map[string]*v2geo.GeoIP, error) {
	if g.GeoLoader != nil {
		return g.GeoLoader.LoadGeoIP()
	}
	return map[string]*v2geo.GeoIP{"private": privateGeoIP}, nil
}

func (g withPrivate) LoadGeoSite() (map[string]*v2geo.GeoSite, error) {
	if g.GeoLoader != nil {
		return g.GeoLoader.LoadGeoSite()
	}
	return nil, errNoGeo
}

// known: an address can be matched (not a geo name, or a database, or
// geoip:private).
func (g withPrivate) known(address string) bool {
	k := KindOf(address)
	return g.GeoLoader != nil || (k != KindGeoIP && k != KindGeoSite) || norm(address) == "geoip:private"
}

// privateGeoIP is geoip:private as the v2fly and Loyalsoldier databases
// have it: the reserved networks.
var privateGeoIP = func() *v2geo.GeoIP {
	g := &v2geo.GeoIP{CountryCode: "PRIVATE"}
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
		"::/127", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		_, n, _ := net.ParseCIDR(c)
		ip := n.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		ones, _ := n.Mask.Size()
		g.Cidr = append(g.Cidr, &v2geo.CIDR{Ip: ip, Prefix: uint32(ones)})
	}
	return g
}()

// Address kinds.
const (
	KindAll      = "all"
	KindIP       = "ip"
	KindCIDR     = "cidr"
	KindDomain   = "domain"
	KindWildcard = "wildcard"
	KindSuffix   = "suffix"
	KindGeoIP    = "geoip"
	KindGeoSite  = "geosite"
)

// KindOf says what an address is, as Hysteria's compiler decides it.
func KindOf(address string) string {
	a := norm(address)
	switch {
	case a == "*" || a == "all":
		return KindAll
	case strings.HasPrefix(a, "geoip:"):
		return KindGeoIP
	case strings.HasPrefix(a, "geosite:"):
		return KindGeoSite
	case strings.HasPrefix(a, "suffix:"):
		return KindSuffix
	case strings.Contains(a, "/"):
		return KindCIDR
	case net.ParseIP(a) != nil:
		return KindIP
	case strings.Contains(a, "*"):
		return KindWildcard
	}
	return KindDomain
}

// norm is an address as the compiler sees it: lower case, no trailing
// dots.
func norm(address string) string { return strings.TrimRight(strings.ToLower(address), ".") }

// hostOf is the request for host: a domain, or an IP with itself as the
// resolved address.
func hostOf(host string) hacl.HostInfo {
	h := hacl.HostInfo{Name: host}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			h.IPv4 = v4
		} else {
			h.IPv6 = ip
		}
	}
	return h
}
