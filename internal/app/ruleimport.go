package app

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/lardan099/hyroute/internal/ruleconv"
	"github.com/lardan099/hyroute/internal/rules"
)

// Importing rules of other programs (SwitchyOmega, v2rayN, Throne,
// FoxyProxy, Clash, PAC …): ruleconv reads them, the user picks where each
// place of the source goes in HyRoute, and the result is rules text — the
// window adds it to the rules or makes a rule profile of it.

// RulesImportFormat is a source format the window offers.
type RulesImportFormat struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// RulesImportTarget is a place the source sends traffic to and where it goes
// in HyRoute.
type RulesImportTarget struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // direct, block, proxy
	Detail string `json:"detail,omitempty"`
	// Rules: rules of the result that go there (0: only «всё остальное»).
	Rules int `json:"rules"`
	// To: where it goes — vpn, direct, block or id:<server or group>.
	To string `json:"to"`
	// Guess: To is a server or group picked by its name ("kazah" →
	// «🇰🇿 Казахстан»), not chosen by the user.
	Guess bool `json:"guess,omitempty"`
}

// RulesImport is a converted source.
type RulesImport struct {
	Format  string              `json:"format"`
	Title   string              `json:"title"`
	Formats []RulesImportFormat `json:"formats"`
	Targets []RulesImportTarget `json:"targets"`
	// Text: the rules as rules text, without «всё остальное».
	Text  string `json:"text"`
	Count int    `json:"count"`
	// Default: the source's place for everything else ("" = it does not
	// say); DefaultLine: that route as a rules text line.
	Default     string   `json:"default"`
	DefaultLine string   `json:"defaultLine"`
	Warnings    []string `json:"warnings"`
	Notes       []string `json:"notes"`
}

func importFormats() []RulesImportFormat {
	out := make([]RulesImportFormat, 0, len(ruleconv.Formats))
	for _, f := range ruleconv.Formats {
		out = append(out, RulesImportFormat{ID: string(f), Title: f.Title()})
	}
	return out
}

// ImportRules converts rules of another program. format "" detects it;
// to maps a source place to vpn, direct, block or id:<server or group>
// (a place not in it goes where its kind suggests).
func (c *Controller) ImportRules(text, format string, to map[string]string) (RulesImport, error) {
	res := RulesImport{Formats: importFormats(), Targets: []RulesImportTarget{}, Warnings: []string{}, Notes: []string{}}
	f := ruleconv.Format(format)
	if f == ruleconv.Auto {
		f = ruleconv.Detect(text)
	}
	res.Format, res.Title = string(f), f.Title()
	if f == ruleconv.Hysteria {
		// The ACL converter's own mapping: direct, reject and the rest.
		conv, err := c.ConvertACL(text, "rules", "", "")
		if err != nil {
			return res, err
		}
		res.Count, res.Warnings = conv.Count, conv.Warnings
		res.Text, res.DefaultLine = splitDefaultLine(conv.Text)
		res.Notes = append(res.Notes, "ACL сервера Hysteria: direct → напрямую, reject → блок, остальные выходы → vpn. Поменяйте сервер в тексте, если нужен другой.")
		return res, nil
	}
	cr, err := ruleconv.Convert(text, f)
	if err != nil {
		return res, err
	}
	res.Warnings = append(res.Warnings, cr.Warnings...)
	res.Notes = append(res.Notes, cr.Notes...)
	res.Default = cr.Default

	c.mu.Lock()
	ts := c.targetsLocked()
	c.mu.Unlock()

	// Where each place goes.
	type route struct {
		act     rules.Action
		profile string
	}
	routes := map[string]route{}
	for _, t := range cr.Targets {
		it := RulesImportTarget{Name: t.Name, Kind: string(t.Kind), Detail: t.Detail, To: suggestTo(t.Kind)}
		if want := strings.TrimSpace(to[t.Name]); want != "" {
			it.To = want
		} else if t.Kind == ruleconv.ToProxy {
			if id := guessServer(t.Name, ts); id != "" {
				it.To, it.Guess = "id:"+id, true
			}
		}
		act, profile, err := parseTarget(it.To, ts)
		if err != nil {
			// A server deleted since the choice: back to the suggestion.
			it.To = suggestTo(t.Kind)
			act, profile, _ = parseTarget(it.To, ts)
		}
		routes[t.Name] = route{act, profile}
		res.Targets = append(res.Targets, it)
	}

	var rs []rules.Rule
	for _, r := range cr.Rules {
		rt := routes[r.Target]
		rule := rules.Rule{Name: importName(r, cr.Format), Protocol: r.Proto, Ports: rules.PortList(r.Ports), Action: rt.act, Profile: rt.profile}
		if r.Off {
			off := false
			rule.Enabled = &off
		}
		for _, it := range r.Items {
			if it.Kind == ruleconv.App {
				rule.Apps = append(rule.Apps, rules.AppMatch{Pattern: it.Value, InheritChildren: true})
			} else {
				rule.Domains = append(rule.Domains, importSite(it))
			}
		}
		rs = append(rs, rule)
		for i := range res.Targets {
			if res.Targets[i].Name == r.Target {
				res.Targets[i].Rules++
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Импорт: %s. Правила проверяются сверху вниз, как и там.\n", f.Title())
	writeRuleLines(&b, rs, ts)
	res.Text, res.Count = b.String(), len(rs)
	if cr.Default != "" {
		rt := routes[cr.Default]
		res.DefaultLine = "* -> " + targetWords(rt.act, rt.profile, nil, ts)
	}

	// The text must read back as the same rules: what it cannot hold is
	// said, not saved.
	back := parseRulesText(res.Text, ts)
	for _, e := range back.Errors {
		res.Warnings = append(res.Warnings, fmt.Sprintf("в результате, строка %d: %s — исправьте её перед сохранением", e.Line, e.Text))
	}
	return res, nil
}

// suggestTo is where a kind of place goes by default.
func suggestTo(k ruleconv.TargetKind) string {
	switch k {
	case ruleconv.ToDirect:
		return "direct"
	case ruleconv.ToBlock:
		return "block"
	}
	return "vpn"
}

// importName names a rule: its own name, or the place of the source
// ("SwitchyOmega: Proxy A") for rules made of many lines.
func importName(r ruleconv.Rule, f ruleconv.Format) string {
	if r.Name != "" {
		return r.Name
	}
	src := map[ruleconv.Format]string{
		ruleconv.Omega: "Omega", ruleconv.PAC: "PAC", ruleconv.AutoProxy: "AutoProxy", ruleconv.V2RayN: "v2rayN",
		ruleconv.Xray: "Xray", ruleconv.SingBox: "sing-box", ruleconv.Nekoray: "Nekoray", ruleconv.FoxyProxy: "FoxyProxy",
		ruleconv.Clash: "Clash", ruleconv.List: "Список",
	}[f]
	name := r.Target
	if src != "" && src != name {
		name = src + " " + name
	}
	if r := []rune(name); len(r) > 60 {
		name = string(r[:59]) + "…"
	}
	return name
}

// importSite writes an item the way rules keep destinations.
func importSite(it ruleconv.Item) string {
	switch it.Kind {
	case ruleconv.Suffix:
		return "." + it.Value
	case ruleconv.Sub:
		return "*." + it.Value
	case ruleconv.Keyword:
		return "keyword:" + it.Value
	case ruleconv.Regexp:
		return "regexp:" + it.Value
	case ruleconv.GeoSite:
		return "geosite:" + it.Value
	case ruleconv.GeoIP:
		return "geoip:" + it.Value
	}
	return it.Value // Exact, IP
}

// splitDefaultLine takes the "* -> …" line out of rules text.
func splitDefaultLine(text string) (rest, def string) {
	var keep []string
	for _, l := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "* ->") && !strings.Contains(t, "|") {
			def = t
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "\n"), def
}

// guessServer picks the server or group a source place most likely means
// by its name: "nl" → «🇳🇱 NL Amsterdam», "kazah" → «Казахстан», "hyst"
// → «Hysteria US». Only a single best match counts; "" when none or a tie.
func guessServer(name string, ts []target) string {
	want := nameWords(name)
	if len(want) == 0 {
		return ""
	}
	best, bestID, tie := 0, "", false
	for _, t := range ts {
		score := 0
		for _, w := range want {
			for _, h := range nameWords(t.Name) {
				score = max(score, wordMatch(w, h))
			}
		}
		switch {
		case score > best:
			best, bestID, tie = score, t.ID, false
		case score == best && score > 0:
			tie = true
		}
	}
	if tie {
		return ""
	}
	return bestID
}

// wordMatch scores two normalized words: 3 equal, 2 one starts the other,
// 1 a long common start ("kazah" and "kazakhstan"); 0 no match. Short
// words only count when equal ("nl", "us").
func wordMatch(a, b string) int {
	switch {
	case a == b:
		return 3
	case len(a) < 3 || len(b) < 3:
		return 0
	case strings.HasPrefix(b, a) || strings.HasPrefix(a, b):
		return 2
	}
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	if n >= 4 && n*5 >= min(len(a), len(b))*4 {
		return 1
	}
	return 0
}

// nameWords splits a name into lower-case Latin words: Cyrillic is
// transliterated ("Казахстан" → kazahstan) and a flag emoji becomes its
// country code (🇳🇱 → nl).
func nameWords(s string) []string {
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if isFlagLetter(r) && i+1 < len(rs) && isFlagLetter(rs[i+1]) {
			b.WriteString(" " + string(rune('a'+r-0x1F1E6)) + string(rune('a'+rs[i+1]-0x1F1E6)) + " ")
			i++
			continue
		}
		r = unicode.ToLower(r)
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case translit[r] != "" || r == 'ь' || r == 'ъ':
			b.WriteString(translit[r])
		default:
			b.WriteByte(' ')
		}
	}
	return strings.Fields(b.String())
}

func isFlagLetter(r rune) bool { return r >= 0x1F1E6 && r <= 0x1F1FF }

var translit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e", 'ж': "zh", 'з': "z", 'и': "i", 'й': "y",
	'к': "k", 'л': "l", 'м': "m", 'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u", 'ф': "f",
	'х': "h", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "sch", 'ы': "y", 'э': "e", 'ю': "yu", 'я': "ya",
}
