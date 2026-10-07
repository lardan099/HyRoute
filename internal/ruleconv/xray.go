package ruleconv

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// v2rayN reads v2rayN rules: the table of a routing set copied from the
// window (tab-separated rows starting with True/False), or JSON (the rules
// of a set, an exported set, Xray routing).
func (c *conv) v2rayN(text string) error {
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		return c.xrayJSON(t)
	}
	rows := 0
	for i, raw := range strings.Split(text, "\n") {
		if !v2rayNRow(strings.TrimSpace(raw)) {
			if strings.TrimSpace(raw) != "" {
				c.warn(i+1, "строка не похожа на правило v2rayN — пропущена")
			}
			continue
		}
		rows++
		c.v2rayNRow(i+1, strings.Split(strings.TrimRight(raw, "\r"), "\t"))
	}
	if rows == 0 {
		return errors.New("правил v2rayN не найдено: скопируйте строки из окна правил маршрутизации или экспортируйте правила в JSON")
	}
	c.firstOutbound = true
	return nil
}

// v2rayNRow: a copied row of v2rayN's rules table.
func v2rayNRow(l string) bool {
	f := strings.Split(l, "\t")
	if len(f) < 4 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(f[0])) {
	case "true", "false":
		return true
	}
	return false
}

// v2rayNRow reads the columns of the rules table: enabled, remarks, rule
// type, outbound, port, protocol, inbound, network, then the domains,
// addresses and programs as one comma list.
func (c *conv) v2rayNRow(n int, f []string) {
	col := func(i int) string {
		if i < len(f) {
			return strings.TrimSpace(f[i])
		}
		return ""
	}
	x := xrayRule{
		Remarks:     col(1),
		Enabled:     strings.EqualFold(col(0), "true"),
		RuleType:    col(2),
		OutboundTag: col(3),
		Port:        col(4),
		Network:     col(7),
	}
	if p := col(5); p != "" {
		x.Protocol = strings.Split(p, ",")
	}
	if in := col(6); in != "" {
		x.InboundTag = strings.Split(in, ",")
	}
	var mixed []string
	for i := 8; i < len(f); i++ {
		for _, it := range strings.Split(f[i], ",") {
			if it = strings.TrimSpace(it); it != "" {
				mixed = append(mixed, it)
			}
		}
	}
	// The last column has domains, addresses and programs together.
	for _, it := range mixed {
		_, isAddr := addrItem(it)
		switch {
		case hasPrefixFold(it, "geoip:"), isAddr:
			x.IP = append(x.IP, it)
		case domainPrefix(it):
			x.Domain = append(x.Domain, it)
		case isProgram(it):
			x.Process = append(x.Process, it)
		default:
			x.Domain = append(x.Domain, it)
		}
	}
	c.xrayRule(n, x)
}

// xrayRule is a rule of v2rayN (RulesItem) or Xray (routing.rules).
type xrayRule struct {
	Type        string   `json:"type"`
	Remarks     string   `json:"remarks"`
	Enabled     bool     `json:"enabled"`
	RuleType    string   `json:"ruleType"`
	OutboundTag string   `json:"outboundTag"`
	BalancerTag string   `json:"balancerTag"`
	Port        string   `json:"port"`
	Network     string   `json:"network"`
	Protocol    []string `json:"protocol"`
	InboundTag  []string `json:"inboundTag"`
	Domain      []string `json:"domain"`
	IP          []string `json:"ip"`
	Process     []string `json:"process"`
	Source      []string `json:"source"`
	User        []string `json:"user"`
	// Xray
	Attrs any `json:"attrs"`
}

// UnmarshalJSON accepts what files write differently: port as a number,
// enabled missing (= on), lists as one string.
func (x *xrayRule) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	x.Enabled = true
	str := func(k string) string {
		var s string
		if json.Unmarshal(m[k], &s) == nil {
			return s
		}
		var n json.Number
		if json.Unmarshal(m[k], &n) == nil {
			return n.String()
		}
		return ""
	}
	list := func(k string) []string {
		var l []string
		if json.Unmarshal(m[k], &l) == nil {
			return l
		}
		if s := str(k); s != "" {
			return strings.Split(s, ",")
		}
		return nil
	}
	x.Type, x.Remarks, x.RuleType = str("type"), str("remarks"), str("ruleType")
	x.OutboundTag, x.BalancerTag = str("outboundTag"), str("balancerTag")
	x.Port, x.Network = str("port"), str("network")
	x.Protocol, x.InboundTag = list("protocol"), list("inboundTag")
	x.Domain, x.IP, x.Process = list("domain"), list("ip"), list("process")
	x.Source, x.User = list("source"), list("user")
	if raw, ok := m["enabled"]; ok {
		var e bool
		if json.Unmarshal(raw, &e) == nil {
			x.Enabled = e
		}
	}
	if raw, ok := m["attrs"]; ok && string(raw) != "null" {
		x.Attrs = string(raw)
	}
	return nil
}

// xrayJSON reads v2rayN or Xray JSON: an array of rules, {"rules": […]}
// (a v2rayN routing set) or {"routing": {"rules": […]}}.
func (c *conv) xrayJSON(text string) error {
	raw := []byte(stripJSONComments(text))
	var list []xrayRule
	if err := json.Unmarshal(raw, &list); err != nil {
		var obj struct {
			Rules   []xrayRule `json:"rules"`
			Routing struct {
				Rules []xrayRule `json:"rules"`
			} `json:"routing"`
		}
		if err2 := json.Unmarshal(raw, &obj); err2 != nil {
			return fmt.Errorf("не JSON правил v2rayN/Xray: %v", jsonErr(err))
		}
		list = obj.Rules
		if len(list) == 0 {
			list = obj.Routing.Rules
		}
	}
	if len(list) == 0 {
		return errors.New("в JSON нет правил (rules)")
	}
	for i, x := range list {
		c.xrayRule(i+1, x)
	}
	c.firstOutbound = true
	return nil
}

// xrayRule converts one rule. v2rayN sends a rule's domains, addresses
// and programs as separate rules, so any of them matches; Xray needs all
// of a rule's fields at once, so a rule with sites and addresses is not
// split there.
func (c *conv) xrayRule(n int, x xrayRule) {
	name := x.Remarks
	where := fmt.Sprintf("правило %d", n)
	if name != "" {
		where = fmt.Sprintf("правило %d «%s»", n, name)
	}
	skip := func(f string, a ...any) { c.res.Warnings = append(c.res.Warnings, where+": "+fmt.Sprintf(f, a...)) }
	if strings.EqualFold(x.RuleType, "dns") {
		skip("правило только для DNS — пропущено")
		return
	}
	target := x.OutboundTag
	if target == "" && x.BalancerTag != "" {
		target = x.BalancerTag
	}
	if target == "" {
		skip("нет outboundTag — пропущено")
		return
	}
	if len(x.InboundTag) > 0 {
		skip("правило для входа %s (inboundTag) в HyRoute не переносится — пропущено", strings.Join(x.InboundTag, ", "))
		return
	}
	if len(x.Source) > 0 || len(x.User) > 0 || x.Attrs != nil {
		skip("условия по источнику, пользователю или заголовкам в HyRoute не переносятся — пропущено")
		return
	}
	if len(x.Protocol) > 0 {
		skip("протокол %s определяется по содержимому трафика, HyRoute так не умеет — пропущено", strings.Join(x.Protocol, ", "))
		return
	}
	proto, ok := network(x.Network)
	if !ok {
		skip("непонятная сеть %q — пропущено", x.Network)
		return
	}
	ps, all, bad := ports(x.Port)
	if bad != "" {
		skip("непонятный порт %q — пропущено", bad)
		return
	}
	_ = all
	var sites, apps []Item
	for _, d := range x.Domain {
		if it, ok := c.xrayDomain(n, d); ok {
			sites = append(sites, it)
		}
	}
	for _, a := range x.IP {
		if it, typed, ok := c.typedItem(n, a); typed {
			if ok && it.Kind == GeoIP {
				sites = append(sites, it)
			} else if ok {
				skip("%q в списке адресов не понятен", a)
			}
			continue
		}
		if it, ok := addrItem(a); ok {
			sites = append(sites, it)
		} else {
			skip("не понимаю адрес %q", a)
		}
	}
	for _, p := range x.Process {
		if p = strings.TrimSpace(p); p != "" {
			apps = append(apps, Item{App, p})
		}
	}
	had := len(x.Domain) + len(x.IP) + len(x.Process)
	if had > 0 && len(sites)+len(apps) == 0 {
		skip("ни один сайт или адрес не распознан — пропущено")
		return
	}
	c.target(target, guessKind(target), "")
	r := Rule{Name: name, Target: target, Proto: proto, Ports: ps, Off: !x.Enabled, Line: n}
	if len(sites) == 0 && len(apps) == 0 {
		c.add(r, false)
		return
	}
	if len(sites) > 0 {
		s := r
		s.Items = sites
		c.add(s, false)
	}
	if len(apps) > 0 {
		a := r
		a.Items = apps
		if len(sites) > 0 && name != "" {
			a.Name = name + " (программы)"
		}
		c.add(a, false)
	}
}

// xrayDomain reads an entry of a domain list: a name without a prefix is
// a keyword in Xray ("google" matches any name containing it).
func (c *conv) xrayDomain(n int, d string) (Item, bool) {
	d = strings.TrimSpace(d)
	if d == "" {
		return Item{}, false
	}
	if it, typed, ok := c.typedItem(n, d); typed {
		return it, ok
	}
	if strings.HasPrefix(d, "#") {
		return Item{}, false
	}
	if a, ok := addrItem(d); ok {
		return a, true
	}
	c.plain++
	return Item{Keyword, strings.ToLower(d)}, true
}

// nekorayJSON reads the simple routing of Nekoray and Throne: lists of
// domains and addresses for direct, proxy and block, one per line.
func (c *conv) nekorayJSON(text string) error {
	var m map[string]any
	if err := json.Unmarshal([]byte(stripJSONComments(text)), &m); err != nil {
		return fmt.Errorf("не JSON: %v", jsonErr(err))
	}
	str := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case []any:
			var out []string
			for _, e := range v {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
			return strings.Join(out, "\n")
		}
		return ""
	}
	// Nekoray checks block, then direct, then proxy.
	for _, t := range []struct{ key, target string }{{"block", "block"}, {"direct", "direct"}, {"proxy", "proxy"}} {
		var sites []Item
		for _, d := range splitList(str(t.key + "_domain")) {
			if it, ok := c.xrayDomain(0, d); ok {
				sites = append(sites, it)
			}
		}
		for _, a := range splitList(str(t.key + "_ip")) {
			if it, typed, ok := c.typedItem(0, a); typed {
				if ok {
					sites = append(sites, it)
				}
				continue
			}
			if it, ok := addrItem(a); ok {
				sites = append(sites, it)
			} else {
				c.warn(0, "не понимаю адрес %q", a)
			}
		}
		if len(sites) == 0 {
			continue
		}
		c.target(t.target, guessKind(t.target), "")
		c.add(Rule{Name: t.target, Target: t.target, Items: sites}, false)
	}
	if def := str("def_outbound"); def != "" {
		c.target(def, guessKind(def), "")
		c.res.Default = def
	}
	if str("custom") != "" {
		c.warn(0, "свои правила (custom) в формате sing-box: вставьте их отдельно — конвертер поймёт и их")
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, l := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' }) {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// domainPrefix: an entry of a domain list with its Xray prefix.
func domainPrefix(s string) bool {
	for _, p := range []string{"geosite:", "domain:", "full:", "regexp:", "keyword:", "ext:", "dotless:"} {
		if hasPrefixFold(s, p) {
			return true
		}
	}
	return false
}

func hasPrefixFold(s, p string) bool {
	return len(s) >= len(p) && strings.EqualFold(s[:len(p)], p)
}

// jsonErr shortens a JSON error for the user.
func jsonErr(err error) string {
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Sprintf("ошибка синтаксиса около символа %d", se.Offset)
	}
	return err.Error()
}
