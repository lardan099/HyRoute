package ruleconv

import (
	"fmt"
	"regexp"
	"strings"
)

// Names of the places rule lists without results send traffic to.
const (
	matchTarget   = "Совпадение"
	excludeTarget = "Исключение"
	listTarget    = "Список"
)

// omegaTypes maps SwitchyOmega condition types and their short forms.
var omegaTypes = map[string]string{
	"hostwildcard": "hw", "w": "hw", "hw": "hw", "wildcard": "hw",
	"hostregex": "hr", "r": "hr", "hr": "hr", "regex": "hr",
	"urlwildcard": "uw", "u": "uw", "uw": "uw", "url": "uw",
	"urlregex": "ur", "ur": "ur", "uregex": "ur",
	"keyword": "kw", "k": "kw", "kw": "kw",
	"ip":     "ip",
	"bypass": "bypass", "b": "bypass",
	"true": "true", "1": "true",
	"false": "false", "0": "false",
	"hostlevels": "other", "lv": "other", "level": "other", "levels": "other", "hl": "other",
	"weekday": "other", "wd": "other", "week": "other", "day": "other",
	"time": "other", "t": "other", "hour": "other", "hours": "other",
}

var omegaTyped = regexp.MustCompile(`^([A-Za-z]+[0-9]?)\s*:\s*(.*)$`)

// omega reads SwitchyOmega rules text: "[SwitchyOmega Conditions]", with
// "@with result" lines "condition +Profile", without it a rule list
// (conditions and "!" exclusions). Lines "pattern +Profile" without the
// header are read too (what HyRoute's ACL converter writes).
func (c *conv) omega(text string) error {
	withResult := false
	var match, excl []Rule
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		l := strings.TrimSpace(raw)
		switch {
		case l == "", strings.HasPrefix(l, ";"), strings.HasPrefix(l, "#"):
			continue
		case strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]"):
			continue
		case strings.HasPrefix(l, "@"):
			if strings.EqualFold(strings.Join(strings.Fields(l), " "), "@with result") {
				withResult = true
			}
			continue
		}
		target, neg := "", false
		if k := strings.LastIndex(l, " +"); k >= 0 {
			target, l = strings.TrimSpace(l[k+2:]), strings.TrimSpace(l[:k])
		} else if withResult {
			c.warn(n, "нет профиля после «+»: строка пропущена")
			continue
		}
		if target == "" {
			if strings.HasPrefix(l, "!") {
				neg, l = true, strings.TrimSpace(l[1:])
			}
			target = matchTarget
			if neg {
				target = excludeTarget
			}
		}
		items, all, ok := c.omegaCond(n, l)
		if !ok {
			continue
		}
		c.target(target, guessKind(target), "")
		r := Rule{Target: target, Items: items, Line: n}
		if all {
			r.Items = nil
		}
		if neg {
			excl = append(excl, r)
		} else {
			match = append(match, r)
		}
	}
	if len(excl) > 0 || (len(match) > 0 && match[0].Target == matchTarget) {
		c.note("Это список условий без профилей: «%s» — профиль, выбранный для списка в SwitchyOmega, «%s» — строки с «!», они проверяются первыми.", matchTarget, excludeTarget)
	}
	for _, r := range append(excl, match...) {
		c.add(r, true)
	}
	return nil
}

// omegaCond reads one SwitchyOmega condition. all: it matches everything.
func (c *conv) omegaCond(n int, s string) (items []Item, all, ok bool) {
	typ, val := "hw", s
	if m := omegaTyped.FindStringSubmatch(s); m != nil {
		if t, known := omegaTypes[strings.ToLower(m[1])]; known {
			typ, val = t, strings.TrimSpace(m[2])
		}
	}
	switch typ {
	case "hw":
		it, all, ok := wildcardHost(val, true)
		if !ok {
			c.warn(n, "не понимаю шаблон %q", val)
			return nil, false, false
		}
		if all {
			return nil, true, true
		}
		return []Item{it}, false, true
	case "hr":
		it, err := jsHostRegex(val)
		if err != nil {
			c.warn(n, "%v", err)
			return nil, false, false
		}
		return []Item{it}, false, true
	case "uw":
		host, path, ok := urlHost(val)
		if !ok {
			c.warn(n, "шаблон адреса %q пропущен: HyRoute выбирает по сайту, а сайта в шаблоне не видно", val)
			return nil, false, false
		}
		it, all, ok := wildcardHost(host, true)
		if !ok {
			c.warn(n, "не понимаю сайт в шаблоне %q", val)
			return nil, false, false
		}
		if path {
			c.warn(n, "в %q есть путь страницы: HyRoute выбирает по сайту, правило перенесено для всего сайта", val)
		}
		if all {
			if path {
				c.warn(n, "правило %q зависит только от пути страницы — пропущено", val)
				return nil, false, false
			}
			return nil, true, true
		}
		return []Item{it}, false, true
	case "ur":
		c.warn(n, "регулярное выражение по адресу страницы (%s) пропущено: HyRoute выбирает по сайту", val)
		return nil, false, false
	case "kw":
		if val == "" {
			return nil, false, false
		}
		c.warn(n, "ключевое слово %q в SwitchyOmega ищется во всём адресе страницы, в HyRoute — только в имени сайта", val)
		return []Item{{Keyword, strings.ToLower(val)}}, false, true
	case "ip":
		it, ok := addrItem(val)
		if !ok {
			c.warn(n, "не понимаю адрес %q", val)
			return nil, false, false
		}
		return []Item{it}, false, true
	case "true":
		return nil, true, true
	case "false":
		return nil, false, false
	case "bypass":
		c.warn(n, "условие обхода %q пропущено: локальные адреса HyRoute и так не трогает", val)
		return nil, false, false
	}
	c.warn(n, "условие %q (уровни имени, день недели, время) в HyRoute не переносится", s)
	return nil, false, false
}

// autoProxy reads an AutoProxy list (GFWList), plain or base64: matches
// go through the proxy, "@@" exceptions are checked first.
func (c *conv) autoProxy(text string) error {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "[autoproxy") {
		if b, ok := decodeBase64(text); ok {
			text = strings.ReplaceAll(string(b), "\r\n", "\n")
		}
	}
	var match, excl []Rule
	var paths, regexps int
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "!") || strings.HasPrefix(l, "[") {
			continue
		}
		neg := false
		if rest, ok := strings.CutPrefix(l, "@@"); ok {
			neg, l = true, rest
		}
		var it Item
		switch {
		case strings.HasPrefix(l, "/") && strings.HasSuffix(l, "/") && len(l) > 2:
			regexps++
			continue
		case strings.HasPrefix(l, "||"):
			h := strings.TrimRight(strings.TrimPrefix(l, "||"), "^/*")
			if i := strings.IndexAny(h, "/^"); i >= 0 {
				h = h[:i]
				paths++
			}
			x, all, ok := wildcardHost("*."+h, true)
			if !ok || all {
				c.warn(n, "не понимаю %q", l)
				continue
			}
			it = x
		case strings.HasPrefix(l, "|"):
			host, path, ok := urlHost(strings.TrimPrefix(l, "|"))
			if !ok {
				c.warn(n, "не понимаю %q", l)
				continue
			}
			if path {
				paths++
			}
			x, all, ok := wildcardHost(host, false)
			if !ok || all {
				c.warn(n, "не понимаю %q", l)
				continue
			}
			it = x
		default:
			h := strings.TrimPrefix(l, ".")
			if k := strings.IndexAny(h, "/^"); k >= 0 {
				h = h[:k]
				paths++
			}
			if !strings.Contains(h, ".") {
				// A word, not a site: AutoProxy looks for it in the address.
				it = Item{Keyword, strings.ToLower(h)}
				break
			}
			x, all, ok := wildcardHost("*."+h, true)
			if !ok || all {
				c.warn(n, "не понимаю %q", l)
				continue
			}
			it = x
		}
		r := Rule{Target: matchTarget, Items: []Item{it}, Line: n}
		if neg {
			r.Target = excludeTarget
			excl = append(excl, r)
		} else {
			match = append(match, r)
		}
	}
	if paths > 0 {
		c.note("%d правил с путём страницы перенесены для всего сайта: HyRoute выбирает по сайту, а не по адресу страницы.", paths)
	}
	if regexps > 0 {
		c.warn(0, "%d регулярных выражений по адресу страницы (/…/) пропущены: HyRoute выбирает по сайту", regexps)
	}
	if len(excl) > 0 {
		c.target(excludeTarget, ToDirect, "")
	}
	if len(match) > 0 {
		c.target(matchTarget, ToProxy, "")
	}
	c.note("В списке AutoProxy совпадения идут через прокси («%s»), исключения @@ — мимо него («%s», проверяются первыми).", matchTarget, excludeTarget)
	for _, r := range append(excl, match...) {
		c.add(r, true)
	}
	return nil
}

// list reads one site or address per line: a site with its subdomains.
func (c *conv) list(text string) error {
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") || strings.HasPrefix(l, ";") || strings.HasPrefix(l, "!") {
			continue
		}
		for _, f := range strings.FieldsFunc(l, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			it, ok := c.listItem(n, f)
			if !ok {
				continue
			}
			c.target(listTarget, ToProxy, "")
			c.add(Rule{Target: listTarget, Items: []Item{it}, Line: n}, true)
		}
	}
	return nil
}

func (c *conv) listItem(n int, s string) (Item, bool) {
	if it, typed, ok := c.typedItem(n, s); typed {
		return it, ok
	}
	if host, _, ok := urlHost(s); ok {
		s = host
	}
	if isProgram(s) {
		return Item{App, s}, true
	}
	it, all, ok := wildcardHost(s, true)
	if !ok || all {
		c.warn(n, "не понимаю %q", s)
		return Item{}, false
	}
	if it.Kind == Exact {
		it.Kind = Suffix // a list of sites: each with its subdomains
	}
	return it, true
}

// typedItem reads an item with an Xray-style prefix (geosite:, geoip:,
// domain:, full:, keyword:, regexp:, ext:); typed is false when s has no
// known prefix.
func (c *conv) typedItem(n int, s string) (it Item, typed, ok bool) {
	s = strings.TrimSpace(s)
	pre, val, found := strings.Cut(s, ":")
	if !found {
		return Item{}, false, false
	}
	val = strings.TrimSpace(val)
	switch strings.ToLower(pre) {
	case "geosite":
		if val == "" {
			return Item{}, true, false
		}
		if strings.HasPrefix(val, "!") {
			c.warn(n, "%q (всё, кроме категории) в HyRoute не переносится", s)
			return Item{}, true, false
		}
		return Item{GeoSite, strings.ToLower(val)}, true, true
	case "geoip":
		if val == "" {
			return Item{}, true, false
		}
		if strings.HasPrefix(val, "!") {
			c.warn(n, "%q (всё, кроме категории) в HyRoute не переносится", s)
			return Item{}, true, false
		}
		return Item{GeoIP, strings.ToLower(val)}, true, true
	case "domain":
		h, ok := hostName(strings.TrimPrefix(val, "*."))
		if !ok {
			c.warn(n, "не понимаю %q", s)
			return Item{}, true, false
		}
		return Item{Suffix, h}, true, true
	case "full":
		h, ok := hostName(val)
		if !ok {
			c.warn(n, "не понимаю %q", s)
			return Item{}, true, false
		}
		return Item{Exact, h}, true, true
	case "keyword":
		if val == "" {
			return Item{}, true, false
		}
		return Item{Keyword, strings.ToLower(val)}, true, true
	case "regexp":
		if _, err := regexp.Compile(val); err != nil {
			c.warn(n, "регулярное выражение %q не поддерживается (HyRoute понимает синтаксис RE2)", val)
			return Item{}, true, false
		}
		return Item{Regexp, val}, true, true
	case "ext", "ext-domain", "ext-ip":
		c.warn(n, "%q — категория из своего файла: в HyRoute пишите geosite:… или geoip:… из выбранной базы", s)
		return Item{}, true, false
	case "dotless":
		c.warn(n, "%q (имена без точки) в HyRoute не переносится", s)
		return Item{}, true, false
	}
	return Item{}, false, false
}

func (k Kind) String() string {
	return [...]string{"suffix", "exact", "sub", "keyword", "regexp", "geosite", "geoip", "ip", "app"}[k]
}

func (it Item) String() string { return fmt.Sprintf("%s:%s", it.Kind, it.Value) }
