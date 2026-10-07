package ruleconv

import (
	"strings"
)

// clashTypes are the rule types of Clash and Mihomo.
var clashTypes = map[string]bool{
	"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-REGEX": true, "DOMAIN-WILDCARD": true,
	"GEOSITE": true, "GEOIP": true, "IP-CIDR": true, "IP-CIDR6": true, "IP-SUFFIX": true, "IP-ASN": true,
	"SRC-GEOIP": true, "SRC-IP-ASN": true, "SRC-IP-CIDR": true, "SRC-IP-SUFFIX": true, "SRC-PORT": true,
	"DST-PORT": true, "IN-PORT": true, "IN-TYPE": true, "IN-USER": true, "IN-NAME": true,
	"PROCESS-NAME": true, "PROCESS-PATH": true, "PROCESS-NAME-REGEX": true, "PROCESS-PATH-REGEX": true,
	"NETWORK": true, "UID": true, "DSCP": true, "RULE-SET": true, "AND": true, "OR": true, "NOT": true,
	"SUB-RULE": true, "MATCH": true, "FINAL": true, "USER-AGENT": true, "URL-REGEX": true,
}

// clashFields splits a rule line ("- DOMAIN-SUFFIX,example.com,Proxy").
func clashFields(l string) []string {
	l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "- "))
	l = strings.Trim(l, `'"`)
	f := strings.Split(l, ",")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	return f
}

func clashLine(l string) bool {
	f := clashFields(l)
	return len(f) >= 2 && clashTypes[strings.ToUpper(f[0])]
}

// clash reads Clash / Mihomo rules (a config or the rules alone). Lines
// of one type to one place in a row become one rule.
func (c *conv) clash(text string) error {
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		l := strings.TrimSpace(raw)
		if !clashLine(l) {
			continue
		}
		f := clashFields(l)
		typ := strings.ToUpper(f[0])
		if typ == "MATCH" || typ == "FINAL" {
			c.target(clashTarget(f[1]), clashKind(f[1]), "")
			c.add(Rule{Target: clashTarget(f[1]), Line: n}, false)
			continue
		}
		if len(f) < 3 {
			c.warn(n, "нет цели правила — пропущено")
			continue
		}
		val, target := f[1], f[2]
		if strings.EqualFold(target, "PASS") {
			continue
		}
		r := Rule{Target: clashTarget(target), Line: n}
		var it Item
		ok := true
		switch typ {
		case "DOMAIN":
			var h string
			h, ok = hostName(val)
			it = Item{Exact, h}
		case "DOMAIN-SUFFIX":
			var h string
			h, ok = hostName(strings.TrimPrefix(val, "."))
			it = Item{Suffix, h}
		case "DOMAIN-KEYWORD":
			it = Item{Keyword, strings.ToLower(val)}
		case "DOMAIN-REGEX":
			var typed bool
			it, typed, ok = c.typedItem(n, "regexp:"+val)
			ok = ok && typed
		case "DOMAIN-WILDCARD":
			var all bool
			it, all, ok = wildcardHost(val, false)
			ok = ok && !all
		case "GEOSITE":
			it = Item{GeoSite, strings.ToLower(val)}
		case "GEOIP":
			it = Item{GeoIP, strings.ToLower(val)}
		case "IP-CIDR", "IP-CIDR6":
			it, ok = addrItem(val)
		case "PROCESS-NAME", "PROCESS-PATH":
			it = Item{App, val}
		case "DST-PORT":
			ps, all, bad := ports(strings.ReplaceAll(val, "/", ","))
			if bad != "" {
				c.warn(n, "непонятный порт %q — пропущено", bad)
				continue
			}
			if all {
				c.target(r.Target, clashKind(target), "")
				c.add(r, false)
				continue
			}
			r.Ports = ps
			c.target(r.Target, clashKind(target), "")
			c.add(r, true)
			continue
		case "NETWORK":
			p, good := network(val)
			if !good || p == "" {
				c.warn(n, "непонятная сеть %q — пропущено", val)
				continue
			}
			r.Proto, r.Ports = p, []string{"1-65535"}
			c.target(r.Target, clashKind(target), "")
			c.add(r, false)
			continue
		case "RULE-SET":
			c.warn(n, "набор правил %q — внешний файл Clash: вставьте его содержимое отдельно", val)
			continue
		case "AND", "OR", "NOT", "SUB-RULE":
			c.warn(n, "составное правило %s в HyRoute не переносится — пропущено", typ)
			continue
		default:
			c.warn(n, "правило %s (по источнику, входу, пользователю, адресу страницы) в HyRoute не переносится — пропущено", typ)
			continue
		}
		if !ok {
			c.warn(n, "не понимаю %q — пропущено", val)
			continue
		}
		c.target(r.Target, clashKind(target), "")
		r.Items = []Item{it}
		c.add(r, true)
	}
	return nil
}

func clashTarget(t string) string {
	switch u := strings.ToUpper(strings.TrimSpace(t)); u {
	case "DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINY":
		return u
	}
	return strings.TrimSpace(t)
}

func clashKind(t string) TargetKind {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "DIRECT":
		return ToDirect
	case "REJECT", "REJECT-DROP", "REJECT-TINY":
		return ToBlock
	}
	return ToProxy
}
