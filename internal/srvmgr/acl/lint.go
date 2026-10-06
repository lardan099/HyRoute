package acl

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	hacl "github.com/lardan099/hyroute/third_party/hysteria-acl"
	"golang.org/x/net/idna"
)

// private are the networks of the server itself and of the networks
// around it, each with an address to try.
var private = []struct{ cidr, sample string }{
	{"127.0.0.0/8", "127.0.0.1"},
	{"::1/128", "::1"},
	{"10.0.0.0/8", "10.0.0.1"},
	{"172.16.0.0/12", "172.16.0.1"},
	{"192.168.0.0/16", "192.168.0.1"},
	{"169.254.0.0/16", "169.254.169.254"},
	{"fc00::/7", "fd00::1"},
	{"fe80::/10", "fe80::1"},
}

// maxCovers bounds the rule pairs lint compares for shadowed rules.
const maxCovers = 1 << 17

// lint finds what Hysteria accepts but is probably not meant: rules that
// never fire, domains it never matches, the server's own networks open
// to clients, plain DNS on a cascade entry.
func lint(d Document, env Env, valid []bool, at []int) []Problem {
	geo := withPrivate{env.Geo}
	var ps []Problem
	add := func(i int, p Problem) {
		p.Rule = i
		if i >= 0 {
			p.Line = at[i] + 1
		}
		ps = append(ps, p)
	}
	// hosts are the rules' addresses alone: any protocol and port.
	hosts := make([]hacl.CompiledRuleSet[int], len(d.Rules))
	for i, r := range d.Rules {
		if valid[i] && geo.known(r.Address) {
			hosts[i], _ = hacl.Compile[int]([]hacl.TextRule{{Outbound: "x", Address: r.Address}}, map[string]int{"x": 1}, 64, geo)
		}
	}
	matches := func(i int, host string) bool {
		if hosts[i] == nil {
			return false
		}
		n, _ := hosts[i].Match(hostOf(host), hacl.ProtocolTCP, 1)
		return n == 1
	}

	// A rule is compared only with the earlier ones that may cover it:
	// rules for every address, for the same address and for suffixes of
	// its name (found by index), then wildcard, geosite and address rules,
	// each list in order. At most maxCovers comparisons in all: a large
	// ACL (an acl.file moved inline) stays quick, and past the limit a
	// cover goes unseen.
	var every, wild, sites, nets []int
	same, suffixes := map[string][]int{}, map[string][]int{}
	left := maxCovers
	for j, b := range d.Rules {
		if !valid[j] {
			continue
		}
		nb, kb := norm(b.Address), KindOf(b.Address)
		indexed := slices.Concat(every, same[nb])
		var lists [][]int
		switch kb {
		case KindDomain, KindSuffix, KindWildcard:
			name := strings.TrimPrefix(nb, "suffix:")
			if kb == KindWildcard {
				name = nb[strings.LastIndex(nb, "*")+1:]
			}
			for t, ok := name, true; ok && t != ""; _, t, ok = strings.Cut(t, ".") {
				indexed = append(indexed, suffixes[t]...)
			}
			lists = [][]int{wild}
			if kb == KindDomain {
				lists = append(lists, sites)
			}
		case KindIP, KindCIDR:
			lists = [][]int{nets}
		case KindGeoSite:
			lists = [][]int{sites}
		}
		slices.Sort(indexed)
		first := -1 // the earliest rule that covers b
		for _, l := range append([][]int{indexed}, lists...) {
			for _, i := range l {
				if left == 0 || first >= 0 && i > first {
					break
				}
				left--
				if covers(d.Rules[i], b, func(h string) bool { return matches(i, h) }) {
					first = i
					break
				}
			}
		}
		if i := first; i >= 0 {
			other := i
			if dup(d.Rules[i], b) {
				add(j, Problem{Level: Warn, Code: "duplicate", Message: fmt.Sprintf("Повтор правила %d: ничего не меняет.", i+1), Other: &other})
			} else {
				add(j, Problem{Level: Warn, Code: "shadowed", Message: fmt.Sprintf("Правило не сработает: всё, что оно выбирает, раньше забирает правило %d.", i+1), Other: &other})
			}
		}
		switch kb {
		case KindAll:
			every = append(every, j)
		case KindSuffix:
			t := strings.TrimPrefix(nb, "suffix:")
			suffixes[t] = append(suffixes[t], j)
		case KindWildcard:
			wild = append(wild, j)
		case KindGeoSite:
			sites = append(sites, j)
		case KindIP, KindCIDR, KindGeoIP:
			nets = append(nets, j)
		}
		same[nb] = append(same[nb], j)

		if u, ok := punycode(b.Address); ok {
			add(j, Problem{Level: Warn, Code: "punycode", Message: fmt.Sprintf("Hysteria сравнивает домены в Unicode, и правило с punycode не сработает: запишите адрес как «%s».", u)})
		}
	}

	userReject := slices.ContainsFunc(env.Outbounds, func(n string) bool { return strings.EqualFold(n, "reject") })
	var open []string
	var fix []Rule
	for _, p := range private {
		if !userReject && reachable(d, valid, p.sample, matches) {
			open = append(open, p.cidr)
			fix = append(fix, Rule{Outbound: "reject", Address: p.cidr})
		}
	}
	if len(open) > 0 {
		add(-1, Problem{Level: Warn, Code: "private", Fix: fix, Message: "Клиенты могут подключаться к самому серверу и к сетям вокруг него (" +
			strings.Join(open, ", ") + "): к службам на 127.0.0.1, к адресу метаданных облака 169.254.169.254. Добавьте в начало правила reject для этих сетей."})
	}

	// Databases Hysteria downloads at start, from a CDN the server may not
	// reach.
	for _, g := range []struct{ kind, file, path string }{{KindGeoIP, "geoip.dat", env.GeoIPPath}, {KindGeoSite, "geosite.dat", env.GeoSitePath}} {
		if g.path == "" && slices.ContainsFunc(d.Rules, func(r Rule) bool { return !r.Off && !r.Bad() && KindOf(r.Address) == g.kind }) {
			add(-1, Problem{Level: Warn, Code: "geo_download", Message: "Для правил " + g.kind + ": Hysteria скачивает " + g.file +
				" при старте с cdn.jsdelivr.net (и заново раз в неделю); без доступа к нему сервер не запустится. Установите базы geo на сервер."})
		}
	}

	if env.Entry {
		t := strings.ToLower(env.Resolver.Type)
		plain := t == "" || t == "system" || t == "udp" || t == "tcp"
		// With an ACL Hysteria resolves every domain before choosing the
		// outbound; a udp or tcp resolver resolves them anyway.
		if plain && (d.Text() != "" || t == "udp" || t == "tcp") {
			add(-1, Problem{Level: Warn, Code: "plain_resolver", Message: "Вход каскада узнаёт адреса сайтов через DNS без шифрования: провайдер входа видит, какие сайты открывают клиенты. Укажите resolver типа https (DoH) или tls (DoT)."})
		}
	}
	return ps
}

// reachable: a connection to sample goes somewhere other than reject on
// some protocol or port. Domain rules are left aside: they match names,
// not addresses.
func reachable(d Document, valid []bool, sample string, matches func(int, string) bool) bool {
	for i, r := range d.Rules {
		k := KindOf(r.Address)
		if !valid[i] || (k != KindAll && k != KindIP && k != KindCIDR && k != KindGeoIP) || !matches(i, sample) {
			continue
		}
		if !strings.EqualFold(r.Outbound, "reject") {
			return true
		}
		if r.Proto == "" && strings.TrimSpace(r.Port) == "" {
			return false
		}
	}
	return true
}

// covers: every connection b matches, a matches too. It says yes only
// when that is certain.
func covers(a, b Rule, aMatches func(host string) bool) bool {
	if a.Proto != "" && a.Proto != b.Proto || !portsCover(a.Port, b.Port) {
		return false
	}
	na, nb := norm(a.Address), norm(b.Address)
	ka, kb := KindOf(a.Address), KindOf(b.Address)
	if ka == KindAll || na == nb {
		return true
	}
	switch kb {
	case KindDomain:
		return aMatches(nb)
	case KindIP:
		// A domain request resolved to the IP matches b too.
		return (ka == KindIP || ka == KindCIDR || ka == KindGeoIP) && aMatches(nb)
	case KindCIDR:
		if ka != KindCIDR {
			return false
		}
		_, an, err1 := net.ParseCIDR(na)
		_, bn, err2 := net.ParseCIDR(nb)
		if err1 != nil || err2 != nil {
			return false
		}
		ao, abits := an.Mask.Size()
		bo, bbits := bn.Mask.Size()
		return abits == bbits && ao <= bo && an.Contains(bn.IP)
	case KindSuffix, KindWildcard:
		// Every name b matches ends with tail.
		tail := strings.TrimPrefix(nb, "suffix:")
		if kb == KindWildcard {
			tail = nb[strings.LastIndex(nb, "*")+1:]
		}
		switch ka {
		case KindSuffix:
			y := strings.TrimPrefix(na, "suffix:")
			return y != "" && (kb == KindSuffix && tail == y || strings.HasSuffix(tail, "."+y))
		case KindWildcard:
			rest, ok := strings.CutPrefix(na, "*")
			return ok && !strings.Contains(rest, "*") && strings.HasSuffix(tail, rest)
		}
	case KindGeoSite:
		if ka != KindGeoSite {
			return false
		}
		an, aattrs := geoName(na)
		bn, battrs := geoName(nb)
		return an == bn && !slices.ContainsFunc(aattrs, func(x string) bool { return !slices.Contains(battrs, x) })
	}
	return false
}

// dup: b is a, written again.
func dup(a, b Rule) bool {
	ha, hb := net.ParseIP(a.Hijack), net.ParseIP(b.Hijack)
	return strings.EqualFold(a.Outbound, b.Outbound) && norm(a.Address) == norm(b.Address) &&
		a.Proto == b.Proto && strings.TrimSpace(a.Port) == strings.TrimSpace(b.Port) &&
		(a.Hijack == b.Hijack || ha != nil && ha.Equal(hb))
}

// portsCover: port range a holds port range b ("": every port).
func portsCover(a, b string) bool {
	if strings.TrimSpace(a) == "" {
		return true
	}
	alo, ahi, ok1 := portRange(a)
	blo, bhi, ok2 := portRange(b)
	return ok1 && ok2 && alo <= blo && bhi <= ahi
}

func portRange(s string) (lo, hi uint64, ok bool) {
	l, h, isRange := strings.Cut(strings.TrimSpace(s), "-")
	lo, err := strconv.ParseUint(l, 10, 16)
	if err != nil {
		return 0, 0, false
	}
	hi = lo
	if isRange {
		if hi, err = strconv.ParseUint(h, 10, 16); err != nil {
			return 0, 0, false
		}
	}
	return lo, hi, true
}

// geoName splits geosite:name@attr@attr as the compiler does.
func geoName(a string) (string, []string) {
	parts := strings.Split(strings.TrimPrefix(a, "geosite:"), "@")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts[0], parts[1:]
}

// punycode returns the Unicode form of a domain address written in
// punycode.
func punycode(address string) (string, bool) {
	k := KindOf(address)
	if k != KindDomain && k != KindSuffix && k != KindWildcard {
		return "", false
	}
	a := norm(address)
	prefix := ""
	if k == KindSuffix {
		prefix, a = "suffix:", strings.TrimPrefix(a, "suffix:")
	}
	if !strings.HasPrefix(a, "xn--") && !strings.Contains(a, ".xn--") {
		return "", false
	}
	u, err := idna.ToUnicode(a)
	if err != nil || u == a {
		return "", false
	}
	return prefix + u, true
}
