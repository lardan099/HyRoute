package app

import (
	"fmt"
	"strings"

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
