package ruleconv

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// singBoxJSON reads sing-box route rules: a whole config ({"route":
// {"rules": […]}}), {"rules": […]} (Throne and Hiddify route profiles)
// or a bare array of rules.
func (c *conv) singBoxJSON(text string) error {
	raw := []byte(stripJSONComments(text))
	var rules []map[string]json.RawMessage
	var final string
	if err := json.Unmarshal(raw, &rules); err != nil {
		var obj struct {
			Route struct {
				Rules []map[string]json.RawMessage `json:"rules"`
				Final string                       `json:"final"`
			} `json:"route"`
			Rules           []map[string]json.RawMessage `json:"rules"`
			Final           string                       `json:"final"`
			DefaultOutbound json.RawMessage              `json:"default_outbound"`
			DefaultID       *int                         `json:"default_outboundID"`
		}
		if err2 := json.Unmarshal(raw, &obj); err2 != nil {
			return fmt.Errorf("не JSON правил sing-box: %v", jsonErr(err))
		}
		rules, final = obj.Route.Rules, obj.Route.Final
		if len(rules) == 0 {
			rules, final = obj.Rules, obj.Final
		}
		if final == "" && obj.DefaultID != nil {
			final = throneOutbound(*obj.DefaultID)
		}
		if final == "" {
			var s string
			if json.Unmarshal(obj.DefaultOutbound, &s) == nil {
				final = s
			}
		}
	}
	if len(rules) == 0 {
		return errors.New("в JSON нет правил (rules)")
	}
	for i, r := range rules {
		c.singBoxRule(i+1, r)
	}
	if final != "" {
		c.target(final, guessKind(final), "")
		c.add(Rule{Target: final}, false)
	} else {
		c.note("В sing-box соединение, которому не подошло ни одно правило, идёт в route.final или в первый выход: выберите «Всё остальное» сами.")
	}
	return nil
}

// throneOutbound names Throne's built-in outbound IDs.
func throneOutbound(id int) string {
	switch id {
	case -1:
		return "proxy"
	case -2:
		return "direct"
	case -3:
		return "block"
	}
	return fmt.Sprintf("сервер %d", id)
}

// sbList reads a field that is a string or a list of strings (or numbers).
func sbList(m map[string]json.RawMessage, k string) []string {
	raw, ok := m[k]
	if !ok {
		return nil
	}
	var l []any
	if json.Unmarshal(raw, &l) != nil {
		var one any
		if json.Unmarshal(raw, &one) != nil {
			return nil
		}
		l = []any{one}
	}
	var out []string
	for _, e := range l {
		switch v := e.(type) {
		case string:
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		case float64:
			out = append(out, fmt.Sprint(int(v)))
		}
	}
	return out
}

// sbKnown are the fields singBoxRule handles; any other condition makes
// the rule narrower in sing-box than HyRoute could write it.
var sbKnown = map[string]bool{
	"type": true, "name": true, "outbound": true, "outboundID": true, "action": true, "actionType": true,
	"domain": true, "domain_suffix": true, "domain_keyword": true, "domain_regex": true,
	"geosite": true, "geoip": true, "ip_cidr": true, "ip_is_private": true, "rule_set": true,
	"port": true, "port_range": true, "network": true, "process_name": true, "process_path": true,
	"enabled": true, "disabled": true, "id": true, "simpleAddress": true, "simpleAction": true,
	"rule_set_ip_cidr_match_source": true, "rule_set_ipcidr_match_source": true, "no_drop": true,
	"invert": true,
}

func (c *conv) singBoxRule(n int, m map[string]json.RawMessage) {
	name := firstOf(sbList(m, "name"))
	where := fmt.Sprintf("правило %d", n)
	if name != "" {
		where = fmt.Sprintf("правило %d «%s»", n, name)
	}
	skip := func(f string, a ...any) { c.res.Warnings = append(c.res.Warnings, where+": "+fmt.Sprintf(f, a...)) }

	if t := firstOf(sbList(m, "type")); t == "logical" {
		skip("логическое правило (and/or) в HyRoute не переносится — пропущено")
		return
	}
	var inv bool
	if raw, ok := m["invert"]; ok && json.Unmarshal(raw, &inv) == nil && inv {
		skip("правило «всё, кроме» (invert) в HyRoute не переносится — пропущено")
		return
	}
	target := firstOf(sbList(m, "outbound"))
	if raw, ok := m["outboundID"]; ok {
		var id int
		if json.Unmarshal(raw, &id) == nil {
			target = throneOutbound(id)
		}
	}
	switch act := strings.ToLower(firstOf(append(sbList(m, "action"), sbList(m, "actionType")...))); act {
	case "", "route":
	case "reject":
		target = "reject"
	case "hijack-dns", "sniff", "resolve", "route-options", "dns":
		return // not a route
	default:
		skip("действие %q в HyRoute не переносится — пропущено", act)
		return
	}
	if target == "" {
		skip("нет outbound — пропущено")
		return
	}
	for k := range m {
		if !sbKnown[k] {
			skip("условие %q в HyRoute не переносится — правило пропущено", k)
			return
		}
	}
	var off bool
	if raw, ok := m["disabled"]; ok {
		_ = json.Unmarshal(raw, &off)
	}
	if raw, ok := m["enabled"]; ok {
		var en bool
		if json.Unmarshal(raw, &en) == nil {
			off = !en
		}
	}
	proto := ""
	if nw := sbList(m, "network"); len(nw) == 1 {
		p, ok := network(nw[0])
		if !ok {
			skip("непонятная сеть %q — пропущено", nw[0])
			return
		}
		proto = p
	}
	var ps []string
	for _, p := range append(sbList(m, "port"), sbList(m, "port_range")...) {
		v, all, ok := portItem(p)
		if !ok {
			skip("непонятный порт %q — пропущено", p)
			return
		}
		if all {
			ps = nil
			break
		}
		ps = append(ps, v)
	}

	var sites, apps []Item
	for _, d := range sbList(m, "domain") {
		if h, ok := hostName(d); ok {
			sites = append(sites, Item{Exact, h})
		} else {
			skip("не понимаю домен %q", d)
		}
	}
	for _, d := range sbList(m, "domain_suffix") {
		sub := strings.HasPrefix(d, ".")
		if h, ok := hostName(strings.TrimPrefix(d, ".")); ok {
			if sub && strings.Contains(h, ".") {
				sites = append(sites, Item{Sub, h})
			} else {
				sites = append(sites, Item{Suffix, h})
			}
		} else {
			skip("не понимаю суффикс %q", d)
		}
	}
	for _, k := range sbList(m, "domain_keyword") {
		sites = append(sites, Item{Keyword, strings.ToLower(k)})
	}
	for _, re := range sbList(m, "domain_regex") {
		if it, typed, ok := c.typedItem(n, "regexp:"+re); typed && ok {
			sites = append(sites, it)
		}
	}
	for _, g := range sbList(m, "geosite") {
		sites = append(sites, Item{GeoSite, strings.ToLower(g)})
	}
	for _, g := range sbList(m, "geoip") {
		sites = append(sites, Item{GeoIP, strings.ToLower(g)})
	}
	if raw, ok := m["ip_is_private"]; ok {
		var p bool
		if json.Unmarshal(raw, &p) == nil && p {
			sites = append(sites, Item{GeoIP, "private"})
		}
	}
	for _, a := range sbList(m, "ip_cidr") {
		if it, ok := addrItem(a); ok {
			sites = append(sites, it)
		} else {
			skip("не понимаю адрес %q", a)
		}
	}
	for _, rs := range sbList(m, "rule_set") {
		l := strings.ToLower(rs)
		switch {
		case strings.HasPrefix(l, "geosite-"):
			sites = append(sites, Item{GeoSite, strings.TrimPrefix(l, "geosite-")})
		case strings.HasPrefix(l, "geoip-"):
			sites = append(sites, Item{GeoIP, strings.TrimPrefix(l, "geoip-")})
		default:
			skip("набор правил %q — файл sing-box: в HyRoute пишите geosite:… или geoip:…", rs)
		}
	}
	for _, p := range append(sbList(m, "process_name"), sbList(m, "process_path")...) {
		apps = append(apps, Item{App, p})
	}
	if len(sites)+len(apps) == 0 && proto == "" && len(ps) == 0 && hasAny(m, "domain", "domain_suffix", "domain_keyword", "domain_regex", "geosite", "geoip", "ip_cidr", "rule_set", "process_name", "process_path") {
		skip("ни один сайт или адрес не распознан — пропущено")
		return
	}
	c.target(target, guessKind(target), "")
	r := Rule{Name: name, Target: target, Proto: proto, Ports: ps, Off: off, Line: n}
	if proto != "" && len(ps) == 0 && len(sites)+len(apps) == 0 {
		r.Ports = []string{"1-65535"}
	}
	// In sing-box the sites and the programs of a rule must both match.
	switch {
	case len(sites) > 0 && len(apps) > 0:
		r.Items = append(apps, sites...)
	case len(sites) > 0:
		r.Items = sites
	default:
		r.Items = apps
	}
	c.add(r, false)
}

func firstOf(l []string) string {
	if len(l) > 0 {
		return l[0]
	}
	return ""
}

func hasAny(m map[string]json.RawMessage, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}
