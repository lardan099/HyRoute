package rules

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/procinfo"
)

// Step is one rule's verdict in an explanation.
type Step struct {
	Index   int    `json:"index"` // -1 = default route
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Matched bool   `json:"matched"`
	Winner  bool   `json:"winner"`
	Reason  string `json:"reason"`
	Action  Action `json:"action"`
	Profile string `json:"profile"` // resolved profile ID for Tunnel
}

// Query describes a hypothetical connection.
type Query struct {
	// App is an exe name ("discord.exe") or a full path.
	App string `json:"app"`
	// Domain may be empty; Names are other known names of the address
	// (DNS cache) used when Domain is empty, each its own site. Sites are
	// such names grouped by site, as dnscache.Cache.Sites gives them: the
	// queried name first, then its CNAMEs.
	Domain string     `json:"domain"`
	Names  []string   `json:"names"`
	Sites  [][]string `json:"sites"`
	// IP is the destination address when known (for IP and geoip rules).
	IP    netip.Addr `json:"ip"`
	Proto uint8      `json:"proto"` // 6 or 17
}

// Explanation is the full trace.
type Explanation struct {
	Steps  []Step `json:"steps"`
	Winner Step   `json:"winner"`
	// Notes list caveats (unknown path, inheritance, ambiguous names).
	Notes []string `json:"notes"`
}

// Explain evaluates q against every rule of c (disabled ones included, for
// the trace) in order; the first enabled match wins. main resolves Tunnel
// rules without a profile.
func Explain(c Config, main string, q Query) Explanation {
	var ex Explanation
	var proc *procinfo.Info
	app := strings.TrimSpace(q.App)
	pathKnown := strings.ContainsAny(app, `\/`)
	if app != "" {
		proc = &procinfo.Info{Name: strings.ToLower(filepath.Base(strings.ReplaceAll(app, `\`, "/")))}
		if pathKnown {
			proc.Path = app
		} else if !strings.ContainsAny(proc.Name, ".*?") && !nameRule(c, proc.Name) {
			// "chrome" is chrome.exe, as in rules text and the editor; a
			// rule for this very name ("app:vmmem", System) keeps it.
			proc.Name += ".exe"
			ex.Notes = append(ex.Notes, "Программа указана без расширения: проверена как "+proc.Name+".")
		}
	}
	domain := NormalizeDomain(q.Domain)
	names := []string{domain}
	// siteOf maps the label of a cached site (in names) to all its names:
	// a rule matches the site when it matches any of them.
	siteOf := map[string][]string{}
	if domain == "" {
		names = nil
		sites := slices.Clone(q.Sites)
		for _, n := range q.Names {
			sites = append(sites, []string{n})
		}
		for _, site := range sites {
			var all []string
			for _, n := range site {
				if n = NormalizeDomain(n); n != "" && !slices.Contains(all, n) {
					all = append(all, n)
				}
			}
			if len(all) == 0 {
				continue
			}
			label := all[0]
			if len(all) > 1 {
				label += " (CNAME: " + strings.Join(all[1:], ", ") + ")"
			}
			if _, dup := siteOf[label]; !dup {
				siteOf[label] = all
				names = append(names, label)
			}
		}
	}
	dom := ""
	if len(names) > 0 {
		dom = names[0]
	}
	if app != "" && !pathKnown {
		ex.Notes = append(ex.Notes, "Указано только имя файла: правила по полному пути и по маске папки проверить нельзя.")
	}
	res := func(a Action, p string) (Action, string) {
		if a != Tunnel {
			return a, ""
		}
		if p == "" {
			p = main
		}
		return a, p
	}
	crs := make([]compiled, len(c.Rules))
	errs := make([]error, len(c.Rules))
	for i, r := range c.Rules {
		crs[i], errs[i] = compileRule(i, r)
	}
	// trace runs the rules for one domain or cached site ("" = not known).
	trace := func(dom string) (steps []Step, winner Step) {
		site := siteOf[dom]
		if site == nil {
			site = []string{dom}
		}
		won := false
		for i, r := range c.Rules {
			st := Step{Index: i, Name: ruleName(i, r), Enabled: r.Enabled == nil || *r.Enabled}
			st.Action, st.Profile = res(r.Action, r.Profile)
			switch {
			case errs[i] != nil:
				st.Reason = "ошибка в правиле: " + errs[i].Error()
			default:
				st.Matched, st.Reason = crs[i].explainSite(proc, pathKnown, q.Proto, site, q.IP.Unmap())
			}
			if !st.Enabled {
				if st.Matched {
					st.Reason = "выключено (иначе совпало бы: " + st.Reason + ")"
				} else {
					st.Reason = "выключено; " + st.Reason
				}
				st.Matched = false
			}
			if st.Matched && !won {
				st.Winner, won = true, true
				winner = st
			} else if st.Matched {
				st.Reason = "совпало бы, но выше уже сработало другое правило"
			}
			steps = append(steps, st)
		}
		def := Step{Index: -1, Name: "по умолчанию", Enabled: true, Matched: !won, Winner: !won, Reason: "ни одно правило не подошло"}
		def.Action, def.Profile = res(c.DefaultAction, c.DefaultProfile)
		if won {
			def.Reason = "не используется: сработало правило выше"
		} else {
			winner = def
		}
		return append(steps, def), winner
	}
	ex.Steps, ex.Winner = trace(dom)
	for _, n := range names {
		if len(siteOf[n]) > 1 {
			ex.Notes = append(ex.Notes, "Имена одной цепочки CNAME считаются одним сайтом: доменное правило срабатывает, если подходит любое из них.")
			break
		}
	}
	if len(names) > 1 {
		// Like Set.EvaluateSites: when the sites of the address lead to
		// different routes, the engine needs the exact name (SNI/Host) and
		// without it decides as if no domain rule matched (always so for
		// UDP). The names of one CNAME chain are one site and never split.
		s := &Set{Main: main}
		fallback := func(st Step) string {
			if st.Action != Tunnel {
				return ""
			}
			fb := c.DefaultFallback
			if st.Index >= 0 {
				fb = c.Rules[st.Index].Fallback
			}
			return strings.Join(s.resolveFallback(st.Profile, fb), ",")
		}
		split := false
		byName := []string{names[0] + " — «" + ex.Winner.Name + "»"}
		for _, n := range names[1:] {
			_, w := trace(n)
			byName = append(byName, n+" — «"+w.Name+"»")
			if w.Action != ex.Winner.Action || w.Profile != ex.Winner.Profile || fallback(w) != fallback(ex.Winner) {
				split = true
			}
		}
		all := strings.Join(names, ", ")
		switch {
		case !split:
			ex.Notes = append(ex.Notes, "У адреса несколько имён в DNS-кэше ("+all+"); результат для всех одинаковый.")
		case q.Proto == 17:
			ex.Steps, ex.Winner = trace("")
			ex.Notes = append(ex.Notes, "У адреса несколько имён в DNS-кэше ("+all+"), и правила для них расходятся. В UDP имя сайта не видно, поэтому HyRoute решает без имени: доменные правила не срабатывают. "+
				"QUIC (UDP 443) при «Блокировать QUIC с неизвестным сайтом» отбрасывается, и браузер переходит на TCP.")
		default:
			// As the engine decides when SNI/Host gives no name; with a name
			// it decides by that name.
			ex.Steps, ex.Winner = trace("")
			if len(byName) > 10 {
				byName = append(byName[:10], "…")
			}
			ex.Notes = append(ex.Notes, "У адреса несколько имён в DNS-кэше ("+all+"), и правила для них расходятся. Показан результат без имени: так HyRoute решает, если имени сайта нет в SNI/Host. "+
				"Для HTTPS и HTTP он возьмёт точное имя и решит по нему: "+strings.Join(byName, "; ")+".")
		}
	}
	for _, r := range c.Rules {
		inherit := false
		for _, a := range r.AllApps() {
			inherit = inherit || a.InheritChildren
		}
		if inherit && (r.Enabled == nil || *r.Enabled) {
			ex.Notes = append(ex.Notes, "Правила «и дочерние» проверяют и родительские процессы; здесь цепочка родителей неизвестна.")
			break
		}
	}
	if ex.Notes == nil {
		ex.Notes = []string{}
	}
	return ex
}

// nameRule reports whether a rule has a program given by this very file
// name (lower-case).
func nameRule(c Config, name string) bool {
	for _, r := range c.Rules {
		for _, a := range r.AllApps() {
			p := strings.TrimSpace(a.Pattern)
			kind := strings.ToLower(a.Kind)
			if kind == "" {
				kind = AppKind(p)
			}
			if kind == "name" && normPath(p) == name {
				return true
			}
		}
	}
	return false
}

func (r *compiled) explain(p *procinfo.Info, pathKnown bool, proto uint8, domain string, ip netip.Addr) (bool, string) {
	var why []string
	if r.proto != 0 {
		if proto != 0 && r.proto != proto {
			return false, fmt.Sprintf("протокол: правило только для %s", protoName(r.proto))
		}
		why = append(why, "протокол "+protoName(r.proto))
	}
	if r.hasApp() {
		var list []string
		byPathOnly := true
		for _, a := range r.apps {
			list = append(list, a.src)
			if a.kind == "name" {
				byPathOnly = false
			}
		}
		pats := strings.Join(list, ", ")
		switch {
		case p == nil:
			return false, "программа не указана, а правило только для " + pats
		case byPathOnly && !pathKnown:
			return false, "правило задано путём (" + pats + "), а указано только имя файла"
		}
		hit := ""
		for i := range r.apps {
			if r.apps[i].matchOne(p) {
				hit = r.apps[i].src
				break
			}
		}
		if hit == "" {
			return false, "программа не из списка: " + pats
		}
		why = append(why, "программа совпадает с "+hit)
	}
	if r.hasDest() {
		var list []string
		for _, d := range r.doms {
			list = append(list, d.src)
		}
		for _, a := range r.ips {
			list = append(list, a.src)
		}
		hit := ""
		for i := range r.ips {
			if r.ips[i].match(ip) {
				hit = ip.String() + " входит в " + r.ips[i].src
				break
			}
		}
		for i := range r.doms {
			if hit == "" && domain != "" && r.doms[i].match(domain) {
				hit = domain + " подходит под " + r.doms[i].src
				if r.doms[i].kind == domGeo {
					hit = domain + " есть в " + r.doms[i].src
				}
			}
		}
		if hit == "" {
			what := domain
			if what == "" && ip.IsValid() {
				what = ip.String()
			}
			switch {
			case what == "":
				return false, "адрес неизвестен, а правило только для " + strings.Join(list, ", ")
			case !ip.IsValid() && len(r.doms) == 0:
				return false, "IP-адрес неизвестен, а правило только для адресов: " + strings.Join(list, ", ")
			case domain == "" && len(r.ips) == 0:
				return false, "имя сайта неизвестно, а правило только для " + strings.Join(list, ", ")
			case len(list) == 1 && len(r.doms) == 1:
				return false, what + " не подходит под " + r.doms[0].src + " (" + r.doms[0].descr() + ")"
			case len(list) == 1:
				return false, what + " не входит в " + r.ips[0].descr()
			}
			return false, what + " не подходит ни под один сайт или адрес правила: " + strings.Join(list, ", ")
		}
		why = append(why, hit)
	}
	if len(why) == 0 {
		return true, "без условий"
	}
	return true, strings.Join(why, ", ")
}

// explainSite is explain for a site known by several names (a CNAME
// chain): the rule matches when any name does.
func (r *compiled) explainSite(p *procinfo.Info, pathKnown bool, proto uint8, site []string, ip netip.Addr) (bool, string) {
	var why []string
	for _, n := range site {
		ok, reason := r.explain(p, pathKnown, proto, n, ip)
		if ok {
			return true, reason
		}
		if !slices.Contains(why, reason) {
			why = append(why, reason)
		}
	}
	return false, strings.Join(why, "; ")
}

func protoName(p uint8) string {
	if p == 6 {
		return "TCP"
	}
	return "UDP"
}

func (d *domPat) descr() string {
	switch d.kind {
	case domExact:
		return "только " + d.dom
	case domSub:
		return "только поддомены " + d.dom
	case domKeyword:
		return "имена со словом «" + d.dom + "»"
	case domRegex:
		return "имена по регулярному выражению"
	case domGeo:
		if d.geo == nil {
			return "категория недоступна"
		}
		return "сайты из категории базы"
	}
	return d.dom + " и все поддомены"
}

// Issue is a lint finding for one rule.
type Issue struct {
	Index    int    `json:"index"`
	Severity string `json:"severity"` // warn | info
	Text     string `json:"text"`
}

// Lint finds rules that can never match (an earlier enabled rule catches
// every connection they would) and invalid rules.
func Lint(c Config) []Issue {
	out := []Issue{}
	type entry struct {
		i  int
		cr compiled
	}
	var prev []entry
	for i, r := range c.Rules {
		cr, err := compileRule(i, r)
		if err != nil {
			out = append(out, Issue{Index: i, Severity: "warn", Text: err.Error()})
			continue
		}
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		for _, w := range cr.warns {
			out = append(out, Issue{Index: i, Severity: "warn", Text: w})
		}
		// Kept by Compile (settings saved before must still load), but
		// such a site never matches.
		for _, d := range r.AllDomains() {
			if w := SiteProblem(d); w != "" {
				out = append(out, Issue{Index: i, Severity: "warn", Text: w})
			}
		}
		for _, e := range prev {
			if e.cr.covers(&cr) {
				text := fmt.Sprintf("Никогда не сработает: правило «%s» выше уже забирает все такие соединения", e.cr.name)
				if e.cr.action == cr.action && e.cr.profile == cr.profile {
					text = fmt.Sprintf("Лишнее: всё, что оно ловит, уже ловит правило «%s» выше с тем же действием", e.cr.name)
				}
				out = append(out, Issue{Index: i, Severity: "warn", Text: text})
				break
			}
		}
		prev = append(prev, entry{i, cr})
	}
	return out
}

// covers reports whether every connection matching b also matches r.
func (r *compiled) covers(b *compiled) bool {
	if r.proto != 0 && r.proto != b.proto {
		return false
	}
	if r.hasApp() {
		if !b.hasApp() {
			return false
		}
		for i := range b.apps {
			if !r.coversApp(&b.apps[i]) {
				return false
			}
		}
	}
	if !r.hasDest() {
		return true
	}
	if !b.hasDest() {
		return false
	}
	for i := range b.doms {
		ok := false
		for j := range r.doms {
			if r.doms[j].covers(&b.doms[i]) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for i := range b.ips {
		ok := false
		for j := range r.ips {
			if r.ips[j].covers(&b.ips[i]) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (r *compiled) coversApp(b *appPat) bool {
	for i := range r.apps {
		a := &r.apps[i]
		if b.inherit && !a.inherit {
			continue
		}
		switch {
		case a.kind == b.kind && a.app == b.app:
			return true
		case a.kind == "glob" && b.kind == "path" && globMatch(a.app, b.app):
			return true
		case a.kind == "name" && b.kind == "path" && strings.HasSuffix(b.app, `\`+a.app):
			return true
		}
	}
	return false
}

func (a *domPat) covers(b *domPat) bool {
	under := func(y string) bool { return strings.HasSuffix(y, "."+a.dom) }
	switch {
	case a.kind >= domKeyword || b.kind >= domKeyword:
		if a.kind == domKeyword && b.kind <= domSuffix {
			// every name under b contains the word
			if u, ok := a.alt(b.dom); ok {
				return strings.Contains(u, a.dom)
			}
			return strings.Contains(b.dom, a.dom)
		}
		return a.kind == b.kind && a.dom == b.dom
	}
	switch a.kind {
	case domExact:
		return b.kind == domExact && b.dom == a.dom
	case domSub:
		if b.kind == domSub {
			return b.dom == a.dom || under(b.dom)
		}
		return under(b.dom)
	}
	return b.dom == a.dom || under(b.dom)
}
