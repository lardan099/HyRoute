package ruleconv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// foxyPattern is a pattern of a FoxyProxy proxy.
type foxyPattern struct {
	Title   string          `json:"title"`
	Pattern string          `json:"pattern"`
	Type    json.RawMessage `json:"type"` // "wildcard"/"regex" (v8), 1/2 (older)
	Active  *bool           `json:"active"`
}

type foxyProxy struct {
	Title   string          `json:"title"`
	Type    json.RawMessage `json:"type"`
	Host    string          `json:"hostname"`
	Address string          `json:"address"`
	Port    json.RawMessage `json:"port"`
	Active  *bool           `json:"active"`
	Index   *int            `json:"index"`
	Include []foxyPattern   `json:"include"`
	Exclude []foxyPattern   `json:"exclude"`
	White   []foxyPattern   `json:"whitePatterns"`
	Black   []foxyPattern   `json:"blackPatterns"`
}

// foxyProxy reads a FoxyProxy export: v8 ({"data": [proxies]}) or older
// ({"<id>": proxy, …}). In FoxyProxy proxies are tried in order; a site
// that matches an exclude pattern of a proxy skips that proxy.
func (c *conv) foxyProxy(text string) error {
	raw := []byte(stripJSONComments(text))
	var v8 struct {
		Data []foxyProxy `json:"data"`
	}
	var list []foxyProxy
	if json.Unmarshal(raw, &v8) == nil && len(v8.Data) > 0 {
		list = v8.Data
	} else {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("не JSON FoxyProxy: %v", jsonErr(err))
		}
		for _, k := range orderedKeys(raw) {
			var p foxyProxy
			if json.Unmarshal(m[k], &p) == nil && (p.White != nil || p.Black != nil) {
				list = append(list, p)
			}
		}
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].Index == nil || list[j].Index == nil {
				return false
			}
			return *list[i].Index < *list[j].Index
		})
	}
	if len(list) == 0 {
		return fmt.Errorf("в файле FoxyProxy нет прокси")
	}
	withPatterns := 0
	for _, p := range list {
		if len(p.Include)+len(p.White) > 0 {
			withPatterns++
		}
	}
	for i, p := range list {
		if p.Active != nil && !*p.Active {
			continue
		}
		title := strings.TrimSpace(p.Title)
		host := p.Host
		if host == "" {
			host = p.Address
		}
		if title == "" {
			title = fmt.Sprintf("Прокси %d", i+1)
			if host != "" {
				title = host
			}
		}
		kind := strings.ToLower(strings.Trim(string(p.Type), `"`))
		detail := ""
		if host != "" {
			detail = strings.TrimSpace(fmt.Sprintf("%s %s:%s", foxyType(kind), host, strings.Trim(string(p.Port), `"`)))
		}
		tk := ToProxy
		if kind == "direct" || kind == "5" {
			tk = ToDirect
		}
		incl := append(append([]foxyPattern{}, p.Include...), p.White...)
		excl := append(append([]foxyPattern{}, p.Exclude...), p.Black...)
		if len(incl) == 0 {
			continue
		}
		if len(excl) > 0 {
			exTarget := "Мимо «" + title + "»"
			var items []Item
			for _, x := range excl {
				if it, ok := c.foxyItem(title, x); ok {
					items = append(items, it)
				}
			}
			if len(items) > 0 {
				c.target(exTarget, ToDirect, "")
				c.add(Rule{Name: exTarget, Target: exTarget, Items: items}, false)
				if withPatterns > 1 {
					c.warn(0, "исключения прокси «%s» перенесены отдельным правилом: в FoxyProxy такие сайты шли дальше по списку прокси, здесь — туда, куда вы выберете", title)
				}
			}
		}
		var items []Item
		all := false
		for _, x := range incl {
			if strings.TrimSpace(x.Pattern) == "*" {
				all = true
				continue
			}
			if it, ok := c.foxyItem(title, x); ok {
				items = append(items, it)
			}
		}
		c.target(title, tk, detail)
		if len(items) > 0 {
			c.add(Rule{Name: title, Target: title, Items: items}, false)
		}
		if all {
			c.add(Rule{Target: title}, false)
		}
	}
	return nil
}

func foxyType(k string) string {
	switch k {
	case "1":
		return "http"
	case "2":
		return "https"
	case "3":
		return "socks5"
	case "4":
		return "socks4"
	}
	return k
}

// foxyItem reads a pattern: a host wildcard (with or without a scheme) or
// a regular expression over the host.
func (c *conv) foxyItem(proxy string, x foxyPattern) (Item, bool) {
	if x.Active != nil && !*x.Active {
		return Item{}, false
	}
	pat := strings.TrimSpace(x.Pattern)
	typ := strings.ToLower(strings.Trim(string(x.Type), `"`))
	where := fmt.Sprintf("«%s», шаблон %q", proxy, pat)
	if typ == "regex" || typ == "2" {
		if strings.Contains(pat, "://") || strings.Contains(pat, `:\/\/`) {
			c.warn(0, "%s: регулярное выражение по адресу страницы пропущено, HyRoute выбирает по сайту", where)
			return Item{}, false
		}
		it, err := jsHostRegex(pat)
		if err != nil {
			c.warn(0, "%s: %v", where, err)
			return Item{}, false
		}
		return it, true
	}
	if host, path, ok := urlHost(pat); ok {
		if path {
			c.warn(0, "%s: путь страницы отброшен, правило перенесено для всего сайта", where)
		}
		pat = host
	} else if i := strings.IndexByte(pat, '/'); i >= 0 {
		pat = pat[:i]
	}
	it, all, ok := wildcardHost(pat, true)
	if !ok || all {
		c.warn(0, "%s: не понимаю", where)
		return Item{}, false
	}
	return it, true
}

// orderedKeys lists the keys of a JSON object in file order.
func orderedKeys(raw []byte) []string {
	d := json.NewDecoder(bytes.NewReader(raw))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var keys []string
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return keys
		}
		k, _ := t.(string)
		keys = append(keys, k)
		var skip json.RawMessage
		if d.Decode(&skip) != nil {
			return keys
		}
	}
	return keys
}
