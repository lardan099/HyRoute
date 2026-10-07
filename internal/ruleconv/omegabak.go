package ruleconv

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// omegaProfile is a profile of a SwitchyOmega / ZeroOmega backup (.bak):
// the options are a JSON object, "+name" keys are profiles. The auth of a
// proxy profile is not read.
type omegaProfile struct {
	Name    string      `json:"name"`
	Type    string      `json:"profileType"`
	Default string      `json:"defaultProfileName"`
	Rules   []omegaRule `json:"rules"`
	Proxy   *omegaProxy `json:"fallbackProxy"`
}

type omegaRule struct {
	Profile   string         `json:"profileName"`
	Condition map[string]any `json:"condition"`
}

type omegaProxy struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

// omegaBackup: a JSON object with SwitchyOmega profiles.
func omegaBackup(m map[string]any) bool {
	for k, v := range m {
		if strings.HasPrefix(k, "+") {
			if p, ok := v.(map[string]any); ok && p["profileType"] != nil {
				return true
			}
		}
	}
	return false
}

// omegaBak reads a SwitchyOmega / ZeroOmega backup: the rules of the
// switch profile it starts with (or the first one), in order, then its
// default profile.
func (c *conv) omegaBak(text string) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return fmt.Errorf("не JSON резервной копии SwitchyOmega: %v", jsonErr(err))
	}
	profiles := map[string]omegaProfile{}
	var names []string
	for k, v := range raw {
		if !strings.HasPrefix(k, "+") {
			continue
		}
		var p omegaProfile
		if json.Unmarshal(v, &p) != nil || p.Type == "" {
			continue
		}
		if p.Name == "" {
			p.Name = k[1:]
		}
		profiles[p.Name] = p
		names = append(names, p.Name)
	}
	sort.Strings(names)
	var start string
	if v, ok := raw["-startupProfileName"]; ok {
		_ = json.Unmarshal(v, &start)
	}
	sw, ok := profiles[start]
	if !ok || sw.Type != "SwitchProfile" {
		sw, ok = omegaProfile{}, false
		for _, n := range names {
			if profiles[n].Type == "SwitchProfile" {
				sw, ok = profiles[n], true
				break
			}
		}
	}
	if !ok {
		return errors.New("в резервной копии нет профиля «Переключение» (Switch) с правилами")
	}
	if start != "" && start != sw.Name {
		c.note("Перенесены правила профиля «%s»: профиль при запуске («%s») — не переключатель.", sw.Name, start)
	} else {
		c.note("Перенесены правила профиля «%s».", sw.Name)
	}

	resolve := func(n int, name string) string {
		switch strings.ToLower(name) {
		case "direct":
			c.target("direct", ToDirect, "")
			return "direct"
		case "system":
			c.target("system", ToProxy, "системный прокси")
			return "system"
		}
		p, known := profiles[name]
		switch {
		case !known:
			c.target(name, guessKind(name), "")
		case p.Type == "FixedProfile" && p.Proxy != nil:
			c.target(name, ToProxy, strings.TrimSpace(fmt.Sprintf("%s %s:%d", p.Proxy.Scheme, p.Proxy.Host, p.Proxy.Port)))
		case p.Type == "PacProfile":
			c.target(name, ToProxy, "PAC-профиль")
			c.warnOnce("pac:"+name, n, "«%s» — PAC-профиль: правила внутри него не переносятся, весь его трафик идёт туда, куда вы выберете", name)
		case p.Type == "SwitchProfile" || p.Type == "RuleListProfile" || p.Type == "VirtualProfile":
			c.target(name, ToProxy, "профиль-переключатель")
			c.warnOnce("sw:"+name, n, "«%s» сам выбирает прокси по своим правилам: здесь он один выход, выберите для него сервер", name)
		default:
			c.target(name, ToProxy, "")
		}
		return name
	}
	for i, r := range sw.Rules {
		n := i + 1
		cond := omegaCondString(r.Condition)
		if cond == "" {
			c.warn(n, "условие без типа — пропущено")
			continue
		}
		items, all, ok := c.omegaCond(n, cond)
		if !ok {
			continue
		}
		rule := Rule{Target: resolve(n, r.Profile), Items: items, Line: n}
		if all {
			rule.Items = nil
		}
		c.add(rule, true)
	}
	if sw.Default != "" {
		c.add(Rule{Target: resolve(0, sw.Default)}, false)
	}
	return nil
}

// omegaCondString writes a condition object as a line of SwitchyOmega
// rules text ("UrlWildcard: *://x/*"), which omegaCond reads.
func omegaCondString(m map[string]any) string {
	typ, _ := m["conditionType"].(string)
	typ = strings.TrimSuffix(typ, "Condition")
	if typ == "" {
		return ""
	}
	str := func(k string) string {
		switch v := m[k].(type) {
		case string:
			return v
		case float64:
			return fmt.Sprint(int(v))
		}
		return ""
	}
	switch typ {
	case "Ip":
		ip, bits := str("ip"), str("prefixLength")
		if bits != "" {
			return "Ip: " + ip + "/" + bits
		}
		return "Ip: " + ip
	case "True", "False":
		return typ + ":"
	}
	return typ + ": " + str("pattern")
}

// warnOnce warns once per key (a profile used by many rules).
func (c *conv) warnOnce(key string, n int, f string, a ...any) {
	if c.once == nil {
		c.once = map[string]bool{}
	}
	if c.once[key] {
		return
	}
	c.once[key] = true
	c.warn(n, f, a...)
}
