package app

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
)

// Rules as text: many rules at once, one per line.
//
//	# comment
//	YouTube: youtube.com googlevideo.com ytimg.com -> 🇳🇱 Нидерланды
//	discord.exe -> de
//	*.ru -> напрямую
//	ads.example.com -> блок | tcp
//
//	[chrome.exe]                 rules below apply to Chrome only (sites only)
//	instagram.com -> 🇩🇪 DE
//	=example.org -> vpn          "=" = only this address, no subdomains
//
//	[*]                          back to every program
//	* -> напрямую                everything else
//
// Items: an item with ".exe" or a path is a program (a bare word such as
// "discord" means discord.exe), anything else a site. "example.com" means the site and its subdomains,
// "=example.com" only that address, "*.example.com" only subdomains,
// ".lan" a one-label domain and its subdomains; a link gives its site.
// "=game.exe" is the program without the processes it starts.
// Typed items are kept as written: geosite:youtube, geoip:ru, 1.2.3.4,
// 10.0.0.0/8, keyword:torrent, regexp:…, full:…, domain:…. An item with
// spaces, "|" or an arrow is written in quotes, and so is a name that could
// be read as something else: "#1 YouTube": youtube.com -> vpn.
// Targets: vpn / основной (main server or group), a server name (or a
// unique part of it, or id:<id>), a server group (группа:Имя or group:Имя,
// or its bare name when no server reads the same), напрямую / direct,
// блок / block. Servers after a comma are fallbacks, tried in order when
// the first one is down: "-> DE, NL", "-> группа:Авто, NL".
// Options after "|": tcp, udp, a port list — tcp 443, udp 27000-27100,
// порт 443, порты 80, 443 —, выкл / off, без дочерних / nochild.
// "* -> X | tcp 22" is a rule with ports only; "* -> X" without a port is
// the default route.

// RuleLine is a problem at a line of rules text.
type RuleLine struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

type RulesTextResult struct {
	Rules          []rules.Rule `json:"rules"`
	HasDefault     bool         `json:"hasDefault"`
	DefaultAction  rules.Action `json:"defaultAction"`
	DefaultProfile string       `json:"defaultProfile"`
	// DefaultFallback: fallback servers of "* ->".
	DefaultFallback []string   `json:"defaultFallback,omitempty"`
	Errors          []RuleLine `json:"errors"`
	Warnings        []RuleLine `json:"warnings"`
	Summary         string     `json:"summary"`
	// Skipped: appended rules left out because the list has them already
	// (rules.Duplicate), set by ApplyRulesText.
	Skipped int `json:"skipped,omitempty"`
	// Repeats: lines (rules text only) whose rule repeats an earlier line
	// and can go without changing what the rules do («Убрать повторы»).
	Repeats []int `json:"repeats,omitempty"`
}

// ParseRulesText parses rules text (or rules JSON, cli) against the
// current servers and groups, for appending.
func (c *Controller) ParseRulesText(text string) RulesTextResult {
	return c.ParseRulesTextAs(text, "auto", false)
}

// target is a server or a server group that rules text can name.
type target struct {
	ID, Name string
	Group    bool
}

// serverTargets lists servers as targets.
func serverTargets(ps []hysteria.Profile) []target {
	out := make([]target, 0, len(ps))
	for _, p := range ps {
		out = append(out, target{ID: p.ID, Name: p.Name})
	}
	return out
}

// targetsLocked: the servers, then the loaded groups (c.mu held).
func (c *Controller) targetsLocked() []target {
	ts := serverTargets(c.profiles.List)
	if c.groupsBroken == nil {
		for _, g := range c.groupsFile.Groups {
			ts = append(ts, target{ID: g.ID, Name: g.Name, Group: true})
		}
	}
	return ts
}

func parseRulesText(text string, ts []target) RulesTextResult {
	res := RulesTextResult{Rules: []rules.Rule{}, Errors: []RuleLine{}, Warnings: []RuleLine{}}
	var section []rules.AppMatch // current [program] block; nil = every program
	sectionText, defaultLine := "", 0
	var lines []int // line of each rule in res.Rules
	fail := func(n int, f string, a ...any) { res.Errors = append(res.Errors, RuleLine{n, fmt.Sprintf(f, a...)}) }

	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = nil
			inner := strings.TrimSpace(line[1 : len(line)-1])
			if inner == "" || inner == "*" || strings.EqualFold(inner, "все") || strings.EqualFold(inner, "всё") || strings.EqualFold(inner, "all") {
				continue
			}
			sectionText = line
			items, quoted := splitQuoted(inner)
			if msg := splitPath(items, quoted); msg != "" {
				fail(n, "%s", msg)
				continue
			}
			for _, it := range items {
				a, warn, ok := sectionApp(it)
				if !ok {
					fail(n, "в [ ] пишутся программы (discord, chrome.exe, путь или маска папки), а «%s» — не программа", it)
					continue
				}
				if warn != "" {
					res.Warnings = append(res.Warnings, RuleLine{n, warn})
				}
				section = append(section, a)
			}
			continue
		}

		body, opts := line, ""
		if i := indexOutside(line, "|"); i >= 0 {
			body, opts = line[:i], line[i+1:]
		}
		lhs, target, ok := cutArrow(body)
		if !ok {
			if _, _, later := cutArrow(line); later {
				fail(n, "«|» стоит раньше «->»: опции пишутся в конце строки, а элемент с «|» (например, regexp:) возьмите в кавычки")
			} else {
				fail(n, "нет стрелки «->»: пишите «что -> куда»")
			}
			continue
		}
		act, profile, fallback, err := parseTargets(strings.TrimSpace(target), ts)
		if err != nil {
			fail(n, "%v", err)
			continue
		}
		o, oerrs := parseLineOptions(opts)
		lhs = strings.TrimSpace(lhs)
		if lhs == "*" && !o.portOpt {
			if section != nil {
				fail(n, "«* -> …» (всё остальное) пишется вне блока программы, после [*]; с портом — правило для этой программы: * -> vpn | udp 443")
				continue
			}
			if strings.Trim(opts, " \t|") != "" {
				fail(n, "у «* -> …» (всё остальное) нет опций: tcp, udp, выкл и без дочерних пишутся у отдельных правил. Правило только по порту пишется с портом: * -> напрямую | tcp 22")
				continue
			}
			if defaultLine > 0 {
				// A second one would silently replace the first.
				fail(n, "«* -> …» (всё остальное) уже есть в строке %d: оставьте одну такую строку", defaultLine)
				continue
			}
			defaultLine = n
			res.HasDefault, res.DefaultAction, res.DefaultProfile, res.DefaultFallback = true, act, profile, fallback
			continue
		}
		for _, e := range oerrs {
			fail(n, "%s", e)
		}
		if len(oerrs) > 0 {
			continue
		}
		r := rules.Rule{Action: act, Profile: profile, Fallback: fallback}
		if name, rest, ok := quotedName(lhs); ok {
			r.Name, lhs = name, rest
		} else if name, rest, found, msg := unquotedName(lhs); msg != "" {
			fail(n, "%s", msg)
			continue
		} else if found {
			r.Name, lhs = name, rest
		}
		r.Protocol, r.Ports = o.proto, o.ports
		if o.off {
			off := false
			r.Enabled = &off
		}
		inherit := !o.nochild
		for _, a := range section {
			a.InheritChildren = a.InheritChildren && inherit
			r.Apps = append(r.Apps, a)
		}
		items, quoted := splitQuoted(lhs)
		if strings.TrimSpace(lhs) == "*" && len(r.Ports) > 0 {
			items, quoted = nil, nil // a rule with ports only
		}
		if msg := splitPath(items, quoted); msg != "" {
			fail(n, "%s", msg)
			continue
		}
		errsBefore := len(res.Errors)
		for _, it := range items {
			if a, ok := lineApp(it); ok {
				if section != nil {
					// The programs of a rule are "any of": this one would be
					// added to the block's program, not narrow it.
					fail(n, "в строках под %s пишутся только сайты, а «%s» — программа: правило для неё пишите после [*]", sectionText, it)
					continue
				}
				a.InheritChildren = a.InheritChildren && inherit
				r.Apps = append(r.Apps, a)
				continue
			}
			d := ""
			if host, link := linkHost(it); rules.IsSpecialItem(it) {
				d = typedItem(it)
			} else if link {
				switch {
				case host == "":
					fail(n, "в ссылке «%s» нет имени сайта", it)
					continue
				case rules.IsAddressItem(host):
					r.Domains = append(r.Domains, host)
					continue
				}
				// As in the rule editor: a link to www.site is the site.
				d = strings.ToLower(host)
				if h, ok := strings.CutPrefix(d, "www."); ok && strings.Contains(h, ".") {
					d = h
				}
				d = "." + d
			} else {
				d = strings.ToLower(it)
				switch {
				case strings.HasPrefix(d, "="):
					d = d[1:]
				case strings.HasPrefix(d, "*.") || strings.HasPrefix(d, "."):
				default:
					d = "." + d
				}
			}
			// A name no site has matches nothing: say so rather than save it.
			if msg := rules.SiteProblem(d); msg != "" {
				fail(n, "%s", msg)
				continue
			}
			r.Domains = append(r.Domains, d)
		}
		// A line whose items were refused is not left as a rule with
		// ports only: that would widen it to every program and site.
		if len(r.Apps) == 0 && len(r.Domains) == 0 && (len(r.Ports) == 0 || len(res.Errors) > errsBefore) {
			if len(res.Errors) == errsBefore { // not when its items were refused
				fail(n, "не указано, что направлять")
			}
			continue
		}
		// Messages start with the rule name, cut below; a quoted name may
		// have ": " in it. A line with "выкл" is checked as well (Compile
		// skips disabled rules), without warnings: it matches nothing yet.
		rc := r
		rc.Name, rc.Enabled = "-", nil
		set, err := rules.Compile(rules.Config{Rules: []rules.Rule{rc}})
		if err != nil {
			msg := err.Error()
			if _, after, ok := strings.Cut(msg, ": "); ok {
				msg = after
			}
			fail(n, "%s", msg)
			continue
		}
		if r.Enabled != nil && !*r.Enabled {
			set.Warnings = nil
		}
		for _, w := range set.Warnings {
			if _, after, ok := strings.Cut(w, ": "); ok {
				w = after
			}
			res.Warnings = append(res.Warnings, RuleLine{n, w})
		}
		res.Rules = append(res.Rules, r)
		lines = append(lines, n)
	}
	repeatLines(&res, lines)
	res.Summary = fmt.Sprintf("Правил: %d", len(res.Rules))
	if res.HasDefault {
		res.Summary += ", всё остальное — " + targetWords(res.DefaultAction, res.DefaultProfile, res.DefaultFallback, ts)
	}
	return res
}

// repeatLines finds the rules that repeat an earlier line (rules.RepeatKey:
// the same conditions and route) and can go without changing what the
// rules do: the earlier one is on, so the repeat never decides a
// connection, or the repeat itself is off. An enabled copy of a disabled
// rule stays: it is the one that works.
func repeatLines(res *RulesTextResult, lines []int) {
	first := map[string]int{}   // key -> index of the first rule
	firstOn := map[string]int{} // key -> index of the first enabled rule
	for i, r := range res.Rules {
		k := rules.RepeatKey(r)
		if k == "" {
			continue
		}
		j, seen := firstOn[k]
		if !seen && !r.On() {
			j, seen = first[k]
		}
		if seen {
			res.Repeats = append(res.Repeats, lines[i])
			res.Warnings = append(res.Warnings, RuleLine{lines[i], fmt.Sprintf("повторяет правило в строке %d (те же условия и тот же маршрут): эту строку можно убрать", lines[j])})
		}
		if _, ok := first[k]; !ok {
			first[k] = i
		}
		if _, ok := firstOn[k]; !ok && r.On() {
			firstOn[k] = i
		}
	}
}

// cutArrow cuts at the first arrow of any kind outside quotes: in
// "a.com → DE -> NL" the rule is a.com and the rest is the server chain.
func cutArrow(s string) (string, string, bool) {
	at, size := -1, 0
	for _, a := range []string{"->", "→", "=>"} {
		if i := indexOutside(s, a); i >= 0 && (at < 0 || i < at) {
			at, size = i, len(a)
		}
	}
	if at < 0 {
		return "", "", false
	}
	return s[:at], s[at+size:], true
}

// indexOutside is strings.Index that skips "quoted" parts, so that a
// quoted name or item may hold "|" and arrows. A quote without a pair is
// an ordinary character.
func indexOutside(s, sep string) int {
	for i := 0; i < len(s); {
		if s[i] == '"' {
			if end := strings.IndexByte(s[i+1:], '"'); end >= 0 {
				i += end + 2
				continue
			}
		}
		if strings.HasPrefix(s[i:], sep) {
			return i
		}
		i++
	}
	return -1
}

// quotedName reads a rule name in quotes ("" inside is a quote) at the
// start of s: `"#1 YouTube": youtube.com` gives "#1 YouTube".
func quotedName(s string) (name, rest string, ok bool) {
	if !strings.HasPrefix(s, `"`) {
		return "", "", false
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] != '"':
			b.WriteByte(s[i])
		case strings.HasPrefix(s[i+1:], `"`):
			b.WriteByte('"')
			i++
		default:
			// The name ends with `":`; a quoted item is followed by a space.
			rest, ok = strings.CutPrefix(s[i+1:], ":")
			if ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
				return b.String(), rest, true
			}
			return "", "", false
		}
	}
	return "", "", false
}

// unquotedName reads a rule name without quotes: "YouTube: youtube.com",
// or "YouTube:" alone (a rule without items: an error below). The text
// before ": " is items, not a name, when its last item itself ends with
// ":" (2001:db8::, regexp:a:) or is a link. A name with . \ / * would be
// read as a site or a program, so msg asks for quotes instead.
func unquotedName(lhs string) (name, rest string, found bool, msg string) {
	s := lhs + " "
	i := indexOutside(s, ": ")
	if i < 0 {
		return "", "", false, ""
	}
	head := lhs[:i]
	if items := splitItems(head); len(items) > 0 {
		last := items[len(items)-1]
		if strings.Contains(last, "://") || strings.Contains(last, ":") && rules.IsSpecialItem(last+":") {
			return "", "", false, ""
		}
	}
	name = strings.TrimSpace(head)
	if strings.ContainsAny(name, `.\/*`) {
		return "", "", false, fmt.Sprintf("«%s:» — это название? Название с точкой, слешем или «*» пишется в кавычках: %s: …", name, nameText(name))
	}
	return name, s[i+2:], true, ""
}

// splitPath finds a path with spaces written without quotes: the spaces
// cut it into pieces that never match ("C:\Program Files (x86)\x.exe"
// gives C:\Program, Files.exe and (x86)\x.exe). That is an absolute path,
// not to an .exe, followed anywhere on the line by a relative path, or,
// when it has no extension, followed by a program or a bare word ("Files"
// would be Files.exe). Quoted items (quoted[i]) are whole: neither such a
// path nor a piece of one.
func splitPath(items []string, quoted []bool) string {
	// A relative item that is not a link or an address (10.0.0.0/8).
	rel := func(j int) (string, bool) {
		b := strings.TrimPrefix(items[j], "=")
		_, link := linkHost(b)
		return b, !quoted[j] && !absPath(b) && !link && !rules.IsSpecialItem(b)
	}
	for i, a := range items {
		a = strings.TrimPrefix(a, "=")
		if quoted[i] || !pathPiece(a) {
			continue
		}
		msg := func(j int) string {
			return fmt.Sprintf("«%s» — путь с пробелами? Такой путь пишется в кавычках целиком: \"C:\\Program Files\\…\\app.exe\"", strings.Join(items[i:j+1], " "))
		}
		if i+1 < len(items) && !strings.Contains(a[strings.LastIndexAny(a, `\/`)+1:], ".") {
			if b, ok := rel(i + 1); ok && (isProgram(b) || !strings.ContainsAny(b, `.\/*?=:`)) {
				return msg(i + 1)
			}
		}
		for j := i + 1; j < len(items); j++ {
			if b, ok := rel(j); ok && strings.ContainsAny(b, `\/`) {
				return msg(j)
			}
		}
	}
	return ""
}

// absPath: C:\x, C:/x or \\server\share.
func absPath(p string) bool {
	return strings.HasPrefix(p, `\\`) ||
		len(p) >= 3 && (p[0]|0x20 >= 'a' && p[0]|0x20 <= 'z') && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

// pathPiece: p may be the first piece of a path cut at its spaces (see
// splitPath): an absolute path, not to an .exe, without a mask.
func pathPiece(p string) bool {
	return absPath(p) && !strings.ContainsAny(p, "*?") && !strings.HasSuffix(strings.ToLower(p), ".exe")
}

// splitItems splits by spaces and commas, keeping quoted paths with spaces
// ("C:\Program Files\X\x.exe"); "" inside quotes is a quote.
func splitItems(s string) []string {
	out, _ := splitQuoted(s)
	return out
}

// splitQuoted is splitItems that also reports which items were quoted.
func splitQuoted(s string) (out []string, quoted []bool) {
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t,;")
		if s == "" {
			break
		}
		if s[0] == '"' {
			if it, rest, ok := quotedItem(s); ok {
				out, quoted = append(out, it), append(quoted, true)
				s = rest
				continue
			}
		}
		end := strings.IndexAny(s, " \t,;")
		if end < 0 {
			end = len(s)
		}
		out, quoted = append(out, s[:end]), append(quoted, false)
		s = s[end:]
	}
	return out, quoted
}

// quotedItem reads the quoted item at the start of s.
func quotedItem(s string) (it, rest string, ok bool) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] != '"':
			b.WriteByte(s[i])
		case strings.HasPrefix(s[i+1:], `"`):
			b.WriteByte('"')
			i++
		default:
			return b.String(), s[i+1:], true
		}
	}
	return "", "", false
}

// typedItem lower-cases the type prefix: GeoSite:YouTube -> geosite:YouTube.
func typedItem(it string) string {
	if p, rest, ok := strings.Cut(it, ":"); ok {
		switch l := strings.ToLower(p); l {
		case "geosite", "geoip", "keyword", "regexp", "full", "domain":
			return l + ":" + rest
		}
	}
	return it
}

func isProgram(it string) bool {
	l := strings.ToLower(it)
	return strings.HasSuffix(l, ".exe") || strings.ContainsAny(l, `\/`)
}

// isAppPattern: a program name or path, or a mask such as "*chrome*" (a
// site has "*" only in front of a dot: *.example.com).
func isAppPattern(it string) bool {
	return isProgram(it) || strings.ContainsAny(it, "*?") && !strings.HasPrefix(it, "*.")
}

// appItem reads a program item: a name with ".exe", a path or a mask (a
// bare word such as "discord" is discord.exe). "=" in front, as for sites,
// means only this program, without the processes it starts. "app:" keeps
// any name as a program as written: "app:my.app" (a site otherwise),
// "app:vmmem" (vmmem.exe otherwise).
func appItem(it string) (rules.AppMatch, bool) {
	if a, ok := prefixedApp(it); ok {
		return a, true
	}
	if !strings.ContainsAny(it, `.\/*?=`) {
		it += ".exe" // "discord" is a program: a site needs a dot
	}
	only := false
	if p, ok := strings.CutPrefix(it, "="); ok && isAppPattern(p) {
		it, only = p, true
	}
	if !isAppPattern(it) {
		return rules.AppMatch{}, false
	}
	return rules.AppMatch{Pattern: it, InheritChildren: !only}, true
}

// prefixedApp reads "app:name" and "=app:name".
func prefixedApp(it string) (rules.AppMatch, bool) {
	p, only := strings.CutPrefix(it, "=")
	if len(p) <= len("app:") || !strings.EqualFold(p[:len("app:")], "app:") {
		return rules.AppMatch{}, false
	}
	return rules.AppMatch{Pattern: p[len("app:"):], InheritChildren: !only}, true
}

// lineApp reads an item of a rule line as a program, in the order the
// parser tries: "app:", then lists, addresses and links (not programs),
// then appItem.
func lineApp(it string) (rules.AppMatch, bool) {
	if a, ok := prefixedApp(it); ok {
		return a, true
	}
	if _, link := linkHost(it); link || rules.IsSpecialItem(it) {
		return rules.AppMatch{}, false
	}
	return appItem(it)
}

// sectionApp reads an item of a [program] line as appItem does. A name
// that a rule line reads as a site ("my.app", "*.scr") can only be a
// program here: it is kept as written, with a warning. Links, lists,
// addresses, ".x" and "=" in front of anything but a program are refused.
func sectionApp(it string) (a rules.AppMatch, warn string, ok bool) {
	if a, ok := prefixedApp(it); ok {
		return a, "", true
	}
	if _, link := linkHost(it); link || rules.IsSpecialItem(it) {
		return a, "", false
	}
	if a, ok := appItem(it); ok {
		return a, "", true
	}
	if strings.HasPrefix(it, ".") || strings.HasPrefix(it, "=") {
		return a, "", false
	}
	return rules.AppMatch{Pattern: it, InheritChildren: true},
		fmt.Sprintf("«%s» в [ ] — программа с таким именем файла, а не сайт: сайты пишутся в строках под [ ]", it), true
}

// linkHost is the site of a pasted link: "https://example.com/page" and
// "example.com/page" give example.com (rules match sites, not pages).
// ok is false for other items; host is "" for a link without a site.
func linkHost(it string) (host string, ok bool) {
	s := it
	if !strings.Contains(s, "://") {
		h, _, found := strings.Cut(s, "/")
		if !found || !strings.Contains(h, ".") || strings.ContainsAny(h, `\*?="`) || isProgram(h) || rules.IsAddressItem(h) ||
			strings.HasSuffix(strings.ToLower(s), ".exe") {
			return "", false // a path ("Steam.old/steam.exe"), a mask or a network
		}
		s = "//" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", true
	}
	return u.Hostname(), true
}

// parseTargets reads "куда": one target, or a chain of servers separated
// by "->" or commas (the first one, then fallbacks). A trailing "блок" is
// allowed: when every server is down the connection is refused anyway.
func parseTargets(t string, ts []target) (rules.Action, string, []string, error) {
	parts := splitChain(t)
	if len(parts) > 1 {
		// A server named with a comma or an arrow, written in full.
		for _, p := range ts {
			if strings.EqualFold(strings.TrimSpace(p.Name), strings.TrimSpace(t)) {
				return rules.Tunnel, p.ID, nil, nil
			}
		}
	}
	act, profile, err := parseTarget(parts[0], ts)
	if err != nil || len(parts) == 1 {
		return act, profile, nil, err
	}
	if act != rules.Tunnel {
		return 0, "", nil, fmt.Errorf("запасные серверы бывают только у «через VPN»: «%s -> …» не работает", parts[0])
	}
	var fallback []string
	for i, p := range parts[1:] {
		if p == "" {
			return 0, "", nil, fmt.Errorf("после «%s ->» допишите запасной сервер (или уберите стрелку)", parts[i])
		}
		a, id, err := parseTarget(p, ts)
		if err != nil {
			return 0, "", nil, fmt.Errorf("запасной сервер: %v", err)
		}
		switch {
		case a == rules.Block && i == len(parts)-2:
			continue // the end of every chain
		case a == rules.Direct:
			return 0, "", nil, fmt.Errorf("запасным может быть только сервер: когда недоступны все, соединение блокируется, а не идёт напрямую")
		case a != rules.Tunnel:
			return 0, "", nil, fmt.Errorf("«блок» может стоять только последним")
		}
		fallback = append(fallback, id)
	}
	return act, profile, fallback, nil
}

// splitChain splits "DE -> NL, US" into trimmed parts.
func splitChain(t string) []string {
	for _, a := range []string{"→", "=>", ","} {
		t = strings.ReplaceAll(t, a, "->")
	}
	parts := strings.Split(t, "->")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// groupPrefixes name a group explicitly: группа:Авто.
var groupPrefixes = []string{"группа:", "group:"}

// reservedTarget: a word parseTarget reads as a route, not a name.
func reservedTarget(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "direct", "напрямую", "прямо", "block", "блок", "заблокировать", "блокировать",
		"vpn", "tunnel", "туннель", "впн", "основной", "main":
		return true
	}
	return false
}

func parseTarget(t string, ts []target) (rules.Action, string, error) {
	switch strings.ToLower(t) {
	case "":
		return 0, "", fmt.Errorf("после «->» укажите, куда: vpn, имя сервера, напрямую или блок")
	case "direct", "напрямую", "прямо":
		return rules.Direct, "", nil
	case "block", "блок", "заблокировать", "блокировать":
		return rules.Block, "", nil
	case "vpn", "tunnel", "туннель", "впн", "основной", "main":
		return rules.Tunnel, "", nil
	}
	if id, ok := strings.CutPrefix(t, "id:"); ok {
		for _, p := range ts {
			if p.ID == id {
				return rules.Tunnel, id, nil
			}
		}
		if groups.IsGroupID(id) {
			return 0, "", fmt.Errorf("группы с id %s нет", id)
		}
		return 0, "", fmt.Errorf("сервера с id %s нет", id)
	}
	onlyGroups := false
	for _, pre := range groupPrefixes {
		if len(t) > len(pre) && strings.EqualFold(t[:len(pre)], pre) {
			t, onlyGroups = strings.TrimSpace(t[len(pre):]), true
			break
		}
	}
	low := strings.ToLower(t)
	var exact, part []target
	for _, p := range ts {
		if onlyGroups && !p.Group {
			continue
		}
		// The text is trimmed, so is the name: " FI " is written as "FI".
		n := strings.ToLower(strings.TrimSpace(p.Name))
		switch {
		case n == low:
			exact = append(exact, p)
		case strings.Contains(n, low):
			part = append(part, p)
		}
	}
	pick := exact
	if len(pick) == 0 {
		pick = part
	}
	switch len(pick) {
	case 1:
		return rules.Tunnel, pick[0].ID, nil
	case 0:
		if onlyGroups {
			return 0, "", fmt.Errorf("группа «%s» не найдена", t)
		}
		return 0, "", fmt.Errorf("сервер «%s» не найден (или напишите vpn, напрямую, блок)", t)
	}
	var names []string
	group := ""
	for _, p := range pick {
		if p.Group {
			names = append(names, "группа «"+p.Name+"»")
			if group == "" {
				group = p.Name
			}
		} else {
			names = append(names, "сервер «"+p.Name+"»")
		}
	}
	if group == "" {
		for i, p := range pick {
			names[i] = "«" + p.Name + "»"
		}
		return 0, "", fmt.Errorf("«%s» подходит к нескольким серверам: %s — уточните", t, strings.Join(names, ", "))
	}
	return 0, "", fmt.Errorf("«%s» подходит к нескольким: %s — уточните (для группы: группа:%s)", t, strings.Join(names, ", "), group)
}

// targetWords is targetWord plus ", fallback" for each fallback server.
func targetWords(a rules.Action, profile string, fallback []string, ts []target) string {
	w := targetWord(a, profile, ts)
	if a == rules.Tunnel {
		for _, id := range fallback {
			w += " -> " + targetWord(rules.Tunnel, id, ts)
		}
	}
	return w
}

func targetWord(a rules.Action, profile string, ts []target) string {
	switch a {
	case rules.Direct:
		return "напрямую"
	case rules.Block:
		return "блок"
	}
	if profile == "" {
		return "vpn"
	}
	var found *target
	same := 0
	for i := range ts {
		if ts[i].ID == profile {
			found = &ts[i]
		}
	}
	if found == nil {
		return "id:" + profile
	}
	for _, p := range ts {
		if p.Group == found.Group && strings.EqualFold(p.Name, found.Name) {
			same++
		}
	}
	// A line break (from a link's %0A) would cut the rule line in two.
	if same > 1 || found.Name == "" || strings.ContainsAny(found.Name, "|#,→\"") || strings.ContainsFunc(found.Name, lineBreak) ||
		strings.Contains(found.Name, "->") || strings.Contains(found.Name, "=>") {
		return "id:" + profile
	}
	// A name that reads back as something else: "Direct", "VPN", "Блок",
	// "id:x", or a part of another server's name. A group is written with
	// its prefix, and never under a reserved word.
	name := strings.TrimSpace(found.Name)
	if found.Group {
		if reservedTarget(name) {
			return "id:" + profile
		}
		name = "группа:" + name
	}
	if a, id, fb, err := parseTargets(name, ts); err != nil || a != rules.Tunnel || id != profile || len(fb) > 0 {
		return "id:" + profile
	}
	return name
}

// lineBreak: characters that break a line of the text (or are not
// visible in it): control characters and the Unicode line separators.
func lineBreak(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Zl, unicode.Zp) }

// RulesText renders the saved rules in the text format. Rules that share
// exactly one program and have sites are grouped under [program].
func (c *Controller) RulesText() string {
	v, _ := c.RulesTextFor("") // the active rules never fail
	return v.Text
}

func formatRulesText(cfg rules.Config, ts []target) string {
	var b strings.Builder
	b.WriteString("# Одна строка — одно правило: что -> куда. Проверяются сверху вниз.\n")
	b.WriteString("# Куда: vpn (основной), имя сервера, группа:Имя, напрямую, блок. Опции после |: tcp, udp, порты (tcp 443), выкл.\n\n")
	writeRuleLines(&b, cfg.Rules, ts)
	b.WriteString("\n# Всё остальное\n* -> " + targetWords(cfg.DefaultAction, cfg.DefaultProfile, cfg.DefaultFallback, ts) + "\n")
	return b.String()
}

// writeRuleLines writes rules as lines of rules text, a [program] block
// for rules of one program with sites.
func writeRuleLines(b *strings.Builder, rs []rules.Rule, ts []target) {
	section := ""
	for _, r := range rs {
		apps, doms := r.AllApps(), r.AllDomains()
		sec, lineApps := "", apps
		if len(apps) == 1 && len(doms) > 0 && apps[0].InheritChildren && inSection(apps[0].Pattern) {
			sec, lineApps = apps[0].Pattern, nil
		}
		if sec != section {
			if sec == "" {
				b.WriteString("\n[*]\n")
			} else {
				b.WriteString("\n[" + quoteItem(sec) + "]\n")
			}
			section = sec
		}
		var items []string
		// "| без дочерних" when no program has children; when only some
		// have, "=" marks the others (the option is for the whole line).
		inherit := 0
		for _, a := range lineApps {
			if a.InheritChildren {
				inherit++
			}
		}
		nochild := len(lineApps) > 0 && inherit == 0
		for _, a := range lineApps {
			items = append(items, appText(a.Pattern, !a.InheritChildren && inherit > 0))
		}
		for _, d := range doms {
			items = append(items, siteText(d))
		}
		line := strings.Join(items, " ")
		name := nameText(r.Name)
		if line == "*" && (name == "" || len(r.Ports) > 0) {
			line = "app:*" // "* ->" alone is everything else, "* -> … | порт" a rule with ports only
		}
		if line == "" && len(r.Ports) > 0 {
			line = "*" // no items, but ports: a rule with ports only
		}
		if name != "" {
			line = name + ": " + line
		}
		line += " -> " + targetWords(r.Action, r.Profile, r.Fallback, ts)
		var opts []string
		if o := ruleOptionText(r.Protocol, r.Ports); o != "" {
			opts = append(opts, o)
		}
		if r.Enabled != nil && !*r.Enabled {
			opts = append(opts, "выкл")
		}
		if nochild {
			opts = append(opts, "без дочерних")
		}
		if len(opts) > 0 {
			line += " | " + strings.Join(opts, " | ")
		}
		b.WriteString(line + "\n")
	}
	if section != "" {
		b.WriteString("\n[*]\n")
	}
}

// inSection reports whether [p] reads back as exactly this program (with
// the processes it starts): "vmmem" would become vmmem.exe, ".x" a site,
// and [*] means every program.
func inSection(p string) bool {
	a, _, ok := sectionApp(p)
	return ok && a.Pattern == p && a.InheritChildren && p != "*"
}

// appText writes program p so that a rule line reads it back as p: as is,
// or with "app:" when it would read as something else ("my.app" a site,
// "vmmem" vmmem.exe). only puts "=" in front (without the processes it
// starts). A path that could be a piece of one with spaces (C:\Tools\run
// before another program) is quoted: the parser would refuse it.
func appText(p string, only bool) string {
	w := p
	if a, ok := lineApp(p); !ok || a.Pattern != p || !a.InheritChildren {
		w = "app:" + p
	}
	if only {
		w = "=" + w
	}
	if pathPiece(p) {
		return `"` + strings.ReplaceAll(w, `"`, `""`) + `"`
	}
	return quoteItem(w)
}

// quoteItem puts an item in quotes ("" for a quote inside) when it has
// spaces, separators or quotes, or could be read as options, an arrow or
// a comment: regexp:^(ads|track)\.
func quoteItem(s string) string {
	if strings.ContainsAny(s, " \t,;|→\"") || strings.Contains(s, "->") || strings.Contains(s, "=>") ||
		strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "[") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// siteText writes a site so that parseRulesText reads it back as the same
// site, not as a program: ".lan" keeps its dot ("lan" is lan.exe).
func siteText(d string) string {
	switch {
	case rules.IsSpecialItem(d):
		return quoteItem(d)
	case strings.HasPrefix(d, "*."):
		// "*.setup.exe" reads back as a program mask: there is no typed
		// "subdomains only" to write it with, and no .exe zone either.
		return d
	case strings.HasPrefix(d, "."):
		switch s := d[1:]; {
		case isProgram(s):
			return "domain:" + s
		case !strings.Contains(s, "."):
			return d
		default:
			return s
		}
	case isProgram(d):
		return "full:" + d
	}
	return "=" + d
}

// nameText writes a rule name for the start of a line: as is, or in quotes
// ("" for a quote inside) when it could be read as something else: "#1"
// is a comment, "RU -> NL" has an arrow, "т.д." looks like a site.
func nameText(n string) string {
	n = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(n))
	if strings.ContainsAny(n, `.\/*:|"→`) || strings.Contains(n, "->") || strings.Contains(n, "=>") ||
		strings.HasPrefix(n, "#") || strings.HasPrefix(n, "[") {
		return `"` + strings.ReplaceAll(n, `"`, `""`) + `"`
	}
	return n
}

// ApplyRulesText saves parsed text: replace=true makes it the whole rule
// list (and "* ->" the default route); otherwise the rules are appended
// and "* ->" is refused: adding rules must not change the default route.
// Nothing is saved when any line has an error. g is the revision of the
// text a replace was made from (RulesTextView); appending needs none.
func (c *Controller) ApplyRulesText(text string, replace bool, g EditGuard) (SaveResult, RulesTextResult, error) {
	return c.ApplyRulesTextAs(text, "auto", replace, g) // cli: rules JSON too
}

// RulesTextView is the rules as text with the revision it was read at,
// sent back by a replace (ApplyRulesText). Wails only.
type RulesTextView struct {
	Text    string `json:"text"`
	Ruleset string `json:"ruleset"`
	Rev     uint64 `json:"rev"`
	EditRev uint64 `json:"editRev,omitempty"`
}

// RulesTextFor renders the rules the token names as text: "" or the active
// token = the active rules, "edit:<id>" = inactive rule profile id. The
// view carries the token and revisions read with the rules. A token that
// no longer names what it was read for gets a refusal that says to reopen
// (nothing was being saved).
func (c *Controller) RulesTextFor(token string) (RulesTextView, error) {
	c.mu.Lock()
	editID, err := c.rulesetTargetLocked(token)
	if errors.Is(err, errRulesetChanged) {
		err = rulesetChangedError("Профиль правил сменился, пока было открыто это окно: закройте его и откройте снова.")
	}
	cfg, _ := c.configOfLocked(editID)
	v := RulesTextView{Ruleset: c.tokenLocked(), Rev: c.settingsRev.Load()}
	if editID != "" {
		v.Ruleset, v.EditRev = token, c.rsRev
	}
	ts := c.targetsLocked()
	c.mu.Unlock()
	if err != nil {
		return RulesTextView{}, err
	}
	v.Text = formatRulesText(*cfg, ts)
	return v, nil
}
