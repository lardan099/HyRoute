// Package ruleconv reads routing rules written for other programs —
// SwitchyOmega (rules text, PAC), AutoProxy lists, v2rayN and Xray,
// Throne/Nekoray and sing-box, FoxyProxy, Clash — into one neutral form
// that the app turns into HyRoute rules.
//
// Each source rule keeps the name of the place it sent traffic to
// (Target): "proxy", "+My server", "DIRECT". The user decides what each
// becomes in HyRoute. What HyRoute cannot do (a path in a URL, a sniffed
// protocol, an inbound) is left out with a warning naming the line: a
// rule is never widened silently.
package ruleconv

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Format is a source format.
type Format string

const (
	Auto      Format = ""
	Omega     Format = "omega"     // [SwitchyOmega Conditions] and "pattern +Profile" lines
	OmegaBak  Format = "omegabak"  // SwitchyOmega / ZeroOmega backup (.bak, JSON)
	PAC       Format = "pac"       // FindProxyForURL, SwitchyOmega's exported PAC too
	AutoProxy Format = "autoproxy" // AutoProxy / GFWList (base64 or plain)
	V2RayN    Format = "v2rayn"    // v2rayN rules: the table copied, or JSON
	Xray      Format = "xray"      // Xray / V2Ray routing JSON
	SingBox   Format = "singbox"   // sing-box route rules (Throne, Hiddify, sing-box)
	Nekoray   Format = "nekoray"   // Nekoray / Throne simple routing lists
	FoxyProxy Format = "foxyproxy" // FoxyProxy export (v8+ and older)
	Clash     Format = "clash"     // Clash / Mihomo rules
	Hysteria  Format = "hysteria"  // Hysteria server ACL: the app converts it
	List      Format = "list"      // one site or address per line
)

// Formats in the order the window offers them.
var Formats = []Format{Omega, OmegaBak, PAC, AutoProxy, V2RayN, Xray, SingBox, Nekoray, FoxyProxy, Clash, Hysteria, List}

// Title is a format's name for the user.
func (f Format) Title() string {
	switch f {
	case Omega:
		return "SwitchyOmega / ZeroOmega (правила текстом)"
	case OmegaBak:
		return "SwitchyOmega / ZeroOmega (резервная копия .bak)"
	case PAC:
		return "PAC-файл (в том числе из SwitchyOmega)"
	case AutoProxy:
		return "Список AutoProxy / GFWList"
	case V2RayN:
		return "v2rayN (таблица правил или JSON)"
	case Xray:
		return "Xray / V2Ray (routing JSON)"
	case SingBox:
		return "sing-box / Throne / Hiddify (route rules)"
	case Nekoray:
		return "Nekoray / Throne (простые списки)"
	case FoxyProxy:
		return "FoxyProxy (экспорт настроек)"
	case Clash:
		return "Clash / Mihomo (rules)"
	case Hysteria:
		return "ACL сервера Hysteria"
	case List:
		return "Список сайтов и адресов"
	}
	return string(f)
}

// Kind is what an item matches.
type Kind int

const (
	Suffix  Kind = iota // the domain and its subdomains
	Exact               // only this name
	Sub                 // only subdomains (*.example.com)
	Keyword             // names containing the word
	Regexp              // names matching (RE2)
	GeoSite             // a geosite.dat category
	GeoIP               // a geoip.dat category
	IP                  // an address or a network
	App                 // a program: exe name or path
)

// Item is one thing a rule matches.
type Item struct {
	Kind  Kind
	Value string
}

// Rule is a source rule to Target. Items are its sites and addresses
// (any of them) and its programs (any of them); with both, a rule matches
// the programs' connections to the sites, as a HyRoute rule does. Proto
// and Ports narrow it.
type Rule struct {
	Name   string
	Target string
	Items  []Item
	Proto  string   // "", "tcp" or "udp"
	Ports  []string // "443", "8000-8100"; empty = any
	Off    bool
	Line   int // first source line (0 = none)
	merged bool
}

// TargetKind is what a source target is.
type TargetKind string

const (
	ToDirect TargetKind = "direct"
	ToBlock  TargetKind = "block"
	ToProxy  TargetKind = "proxy"
)

// Target is a place source rules send traffic to.
type Target struct {
	Name   string     `json:"name"`
	Kind   TargetKind `json:"kind"`
	Detail string     `json:"detail,omitempty"` // "PROXY 127.0.0.1:1080", "socks5 …"
}

// Result is a converted source.
type Result struct {
	Format Format
	Rules  []Rule
	// Default is the target of "everything else" ("" = the source does not
	// say).
	Default  string
	Targets  []Target
	Warnings []string
	// Notes explain what the conversion assumed (not problems).
	Notes []string
}

// ErrEmpty: no rule was found.
var ErrEmpty = errors.New("правил не найдено: вставьте правила или откройте файл программы")

// maxText bounds the input (a GFWList is about 200 KB, a PAC with many
// rules a few MB).
const maxText = 16 << 20

// Convert reads text in format f (Auto: detect).
func Convert(text string, f Format) (Result, error) {
	if len(text) > maxText {
		return Result{}, fmt.Errorf("слишком большой текст: больше %d МБ", maxText>>20)
	}
	if !utf8.ValidString(text) {
		return Result{}, errors.New("это не текст: откройте файл правил (PAC, JSON, txt), а не архив или программу")
	}
	text = strings.TrimPrefix(strings.ReplaceAll(text, "\r\n", "\n"), "\ufeff")
	if f == Auto {
		f = Detect(text)
	}
	c := &conv{res: Result{Format: f}}
	var err error
	switch f {
	case Omega:
		err = c.omega(text)
	case OmegaBak:
		err = c.omegaBak(text)
	case PAC:
		err = c.pac(text)
	case AutoProxy:
		err = c.autoProxy(text)
	case V2RayN:
		err = c.v2rayN(text)
	case Xray:
		err = c.xrayJSON(text)
	case SingBox:
		err = c.singBoxJSON(text)
	case Nekoray:
		err = c.nekorayJSON(text)
	case FoxyProxy:
		err = c.foxyProxy(text)
	case Clash:
		err = c.clash(text)
	case List:
		err = c.list(text)
	case Hysteria:
		return c.res, errors.New("ACL сервера Hysteria переводит конвертер ACL")
	default:
		return c.res, fmt.Errorf("неизвестный формат %q", f)
	}
	if err != nil {
		return c.res, err
	}
	c.finish()
	if len(c.res.Rules) == 0 && c.res.Default == "" {
		if len(c.res.Warnings) > 0 {
			return c.res, fmt.Errorf("ни одно правило не перенесено: %s", c.res.Warnings[0])
		}
		return c.res, ErrEmpty
	}
	return c.res, nil
}

// Detect guesses the format of text.
func Detect(text string) Format {
	t := strings.TrimSpace(strings.TrimPrefix(text, "\ufeff"))
	head := strings.ToLower(firstLine(t))
	switch {
	case strings.HasPrefix(head, "[switchyomega") || strings.HasPrefix(head, "[switchysharp"):
		return Omega
	case strings.HasPrefix(head, "[autoproxy"):
		return AutoProxy
	}
	// JSON first: a SwitchyOmega backup holds PAC scripts too.
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		if f := detectJSON(t); f != "" {
			return f
		}
	}
	if strings.Contains(t, "FindProxyForURL") {
		return PAC
	}
	if b, ok := decodeBase64(t); ok && strings.HasPrefix(strings.ToLower(strings.TrimSpace(string(b))), "[autoproxy") {
		return AutoProxy
	}
	lines := contentLines(t)
	if len(lines) == 0 {
		return List
	}
	var tsv, clash, acl, omega, ap int
	for _, l := range lines {
		switch {
		case v2rayNRow(l):
			tsv++
		case clashLine(l):
			clash++
		case aclLine.MatchString(l):
			acl++
		case omegaResultLine.MatchString(l):
			omega++
		case strings.HasPrefix(l, "||") || strings.HasPrefix(l, "@@") || strings.HasPrefix(l, "|http"):
			ap++
		}
	}
	best, f := 0, List
	for _, c := range []struct {
		n int
		f Format
	}{{tsv, V2RayN}, {clash, Clash}, {acl, Hysteria}, {omega, Omega}, {ap, AutoProxy}} {
		if c.n > best {
			best, f = c.n, c.f
		}
	}
	return f
}

// detectJSON tells the JSON formats apart by their keys.
func detectJSON(t string) Format {
	var v any
	if json.Unmarshal([]byte(stripJSONComments(t)), &v) != nil {
		return ""
	}
	switch x := v.(type) {
	case []any:
		return rulesFormat(x)
	case map[string]any:
		if omegaBackup(x) {
			return OmegaBak
		}
		if d, ok := x["data"].([]any); ok && len(d) > 0 {
			if m, ok := d[0].(map[string]any); ok && (m["include"] != nil || m["exclude"] != nil || m["hostname"] != nil) {
				return FoxyProxy
			}
		}
		for _, e := range x {
			if m, ok := e.(map[string]any); ok && (m["whitePatterns"] != nil || m["blackPatterns"] != nil) {
				return FoxyProxy
			}
		}
		for _, k := range []string{"proxy_domain", "direct_domain", "block_domain", "proxy_ip", "direct_ip", "block_ip"} {
			if _, ok := x[k]; ok {
				return Nekoray
			}
		}
		if _, ok := x["route"]; ok {
			return SingBox
		}
		if r, ok := x["routing"].(map[string]any); ok && r["rules"] != nil {
			return Xray
		}
		if rs, ok := x["rules"].([]any); ok {
			return rulesFormat(rs)
		}
	}
	return ""
}

// rulesFormat tells v2rayN (outboundTag) and sing-box (outbound, action,
// domain_suffix …) rule lists apart by any of their rules.
func rulesFormat(rs []any) Format {
	for _, e := range rs {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if m["outboundTag"] != nil || m["balancerTag"] != nil {
			return V2RayN
		}
		for _, k := range []string{"outbound", "outboundID", "action", "domain_suffix", "domain_keyword", "rule_set", "ip_cidr", "process_name"} {
			if m[k] != nil {
				return SingBox
			}
		}
	}
	return V2RayN
}

func firstLine(t string) string {
	l, _, _ := strings.Cut(t, "\n")
	return strings.TrimSpace(l)
}

// contentLines: the non-empty lines that are not comments.
func contentLines(t string) []string {
	var out []string
	for _, l := range strings.Split(t, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "//") || strings.HasPrefix(l, ";") || strings.HasPrefix(l, "!") {
			continue
		}
		out = append(out, l)
	}
	return out
}

var (
	aclLine         = regexp.MustCompile(`^-?\s*[A-Za-z0-9_-]+\s*\(.*\)\s*$`)
	omegaResultLine = regexp.MustCompile(`^\S+\s+\+\S.*$`)
)

func decodeBase64(t string) ([]byte, bool) {
	s := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, t)
	if len(s) < 16 {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil && utf8.Valid(b) {
			return b, true
		}
	}
	return nil, false
}

// conv collects the result of one conversion.
type conv struct {
	res     Result
	stopped bool // a rule for everything was met: the rest is unreachable
	stopAt  int
	skipped int // rules after it
	plain   int // Xray items without a prefix, read as keyword:
	// firstOutbound: in the source, what no rule matches goes to the first
	// outbound (Xray, v2rayN).
	firstOutbound bool
	once          map[string]bool // warnOnce
}

func (c *conv) warn(line int, f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	if line > 0 {
		msg = fmt.Sprintf("строка %d: %s", line, msg)
	}
	c.res.Warnings = append(c.res.Warnings, msg)
}

func (c *conv) note(f string, a ...any) { c.res.Notes = append(c.res.Notes, fmt.Sprintf(f, a...)) }

// target records a place traffic goes to (once, in order of appearance).
func (c *conv) target(name string, k TargetKind, detail string) {
	for i, t := range c.res.Targets {
		if t.Name == name {
			if c.res.Targets[i].Detail == "" {
				c.res.Targets[i].Detail = detail
			}
			return
		}
	}
	c.res.Targets = append(c.res.Targets, Target{Name: name, Kind: k, Detail: detail})
}

// add appends a rule. merge: a rule from a line format (one condition a
// line) joins the rule before it when they go to the same place with the
// same protocol and ports, so 300 lines of Omega make one HyRoute rule.
func (c *conv) add(r Rule, merge bool) {
	if c.stopped {
		c.skipped++
		return
	}
	if len(r.Items) == 0 && r.Proto == "" && len(r.Ports) == 0 {
		// A rule for everything: the default route. Rules below it are
		// never reached in the source program.
		if r.Off {
			c.warn(r.Line, "выключенное правило «для всего» пропущено")
			return
		}
		c.res.Default = r.Target
		c.stopped, c.stopAt = true, r.Line
		return
	}
	if merge && len(c.res.Rules) > 0 {
		p := &c.res.Rules[len(c.res.Rules)-1]
		if p.merged && p.Target == r.Target && p.Proto == r.Proto && p.Off == r.Off && equal(p.Ports, r.Ports) {
			p.Items = append(p.Items, r.Items...)
			return
		}
	}
	r.merged = merge
	c.res.Rules = append(c.res.Rules, r)
}

func (c *conv) finish() {
	if c.skipped > 0 {
		at := ""
		if c.stopAt > 0 {
			at = fmt.Sprintf(" (строка %d)", c.stopAt)
		}
		c.warn(0, "правило для всего остального%s ловит весь трафик, правил ниже него (%d) в исходной программе не достигает — они пропущены", at, c.skipped)
	}
	if c.plain > 0 {
		c.note("%d записей без приставки перенесены как keyword: — в Xray и v2rayN такая запись значит «имя сайта содержит это слово». Чтобы правило ловило только сайт и его поддомены, в исходной программе пишут domain:сайт.", c.plain)
	}
	if c.firstOutbound && c.res.Default == "" {
		c.note("Соединение, которому не подошло ни одно правило, там идёт в первый выход (в v2rayN обычно proxy): выберите «Всё остальное» сами.")
	}
	for i := range c.res.Rules {
		c.res.Rules[i].Items = dedupe(c.res.Rules[i].Items)
	}
	if c.res.Default != "" {
		used := false
		for _, t := range c.res.Targets {
			used = used || t.Name == c.res.Default
		}
		if !used {
			c.target(c.res.Default, guessKind(c.res.Default), "")
		}
	}
}

func dedupe(items []Item) []Item {
	seen := map[Item]bool{}
	out := items[:0]
	for _, it := range items {
		if !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// guessKind reads common names of built-in outbounds.
func guessKind(name string) TargetKind {
	switch strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "+")) {
	case "direct", "bypass", "напрямую", "прямо", "domestic":
		return ToDirect
	case "block", "reject", "reject-drop", "reject-no-drop", "blackhole", "блок", "deny", "adblock":
		return ToBlock
	}
	return ToProxy
}

// ---- items ----

var hostRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.?$`)

// hostName normalizes a name: lower case, no trailing dot, punycode kept
// as is. ok is false for anything that is not a plain name.
func hostName(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" {
		return "", false
	}
	if hostRe.MatchString(s) {
		return s, true
	}
	// Internationalized names are kept: the rules model converts them.
	if !strings.ContainsAny(s, " /\\:*?()[]{}|+^$,;\"'") && strings.Contains(s, ".") {
		return s, true
	}
	return "", false
}

// addrItem reads an IP or a network ("1.2.3.4", "10.0.0.0/8", "::1").
func addrItem(s string) (Item, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return Item{IP, p.Masked().String()}, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return Item{IP, a.String()}, true
	}
	return Item{}, false
}

// wildcardHost reads a host wildcard. apex: "*.example.com" also matches
// example.com (SwitchyOmega, FoxyProxy) rather than only subdomains (PAC
// shExpMatch). all is true for "*".
func wildcardHost(p string, apex bool) (it Item, all, ok bool) {
	p = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(p)), ".")
	switch p {
	case "", "*", "*.*":
		return Item{}, p != "", p != ""
	}
	if rest, found := strings.CutPrefix(p, "*."); found && !strings.ContainsAny(rest, "*?") {
		if h, ok := hostName(rest); ok {
			if apex {
				return Item{Suffix, h}, false, true
			}
			return Item{Sub, h}, false, true
		}
	}
	if rest, found := strings.CutPrefix(p, "."); found && !strings.ContainsAny(rest, "*?") {
		if h, ok := hostName(rest); ok {
			return Item{Suffix, h}, false, true
		}
	}
	if !strings.ContainsAny(p, "*?") {
		if a, ok := addrItem(p); ok {
			return a, false, true
		}
		if h, ok := hostName(p); ok {
			return Item{Exact, h}, false, true
		}
		return Item{}, false, false
	}
	// Any other wildcard: a regular expression over the name.
	var b strings.Builder
	b.WriteString("^")
	for _, r := range p {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return Item{Regexp, b.String()}, false, true
}

// urlHost takes the host part of a URL pattern ("*://*.example.com/*",
// "https://example.com/path"). path is true when the pattern has a path
// that matters (HyRoute cannot match by path).
func urlHost(p string) (host string, path, ok bool) {
	p = strings.TrimSpace(p)
	if _, rest, found := strings.Cut(p, "://"); found {
		p = rest
	} else {
		return "", false, false
	}
	if i := strings.IndexAny(p, "/?#"); i >= 0 {
		tail := p[i:]
		p = p[:i]
		path = tail != "/" && tail != "/*" && tail != "*"
	}
	if at := strings.LastIndex(p, "@"); at >= 0 {
		p = p[at+1:]
	}
	if h, port, found := strings.Cut(p, ":"); found && !strings.Contains(port, ":") && !strings.HasPrefix(p, "[") {
		p = h
	}
	return p, path, p != ""
}

var (
	reSuffix = regexp.MustCompile(`^\(\?:\^\|\\\.\)((?:[a-z0-9_*-]+\\\.)*[a-z0-9_*-]+)\$$`)
	reExact  = regexp.MustCompile(`^\^((?:[a-z0-9_-]+\\\.)*[a-z0-9_-]+)\$$`)
	reSub    = regexp.MustCompile(`^\\\.((?:[a-z0-9_-]+\\\.)*[a-z0-9_-]+)\$$`)
)

// jsHostRegex reads a JavaScript regular expression over a host: the
// shapes SwitchyOmega writes become sites, anything else stays a regexp:
// when RE2 understands it.
func jsHostRegex(re string) (Item, error) {
	re = strings.TrimSpace(re)
	low := strings.ToLower(re)
	if m := reSuffix.FindStringSubmatch(low); m != nil && !strings.Contains(m[1], "*") {
		return Item{Suffix, strings.ReplaceAll(m[1], `\.`, ".")}, nil
	}
	if m := reExact.FindStringSubmatch(low); m != nil {
		return Item{Exact, strings.ReplaceAll(m[1], `\.`, ".")}, nil
	}
	if m := reSub.FindStringSubmatch(low); m != nil {
		return Item{Sub, strings.ReplaceAll(m[1], `\.`, ".")}, nil
	}
	if _, err := regexp.Compile(re); err != nil {
		return Item{}, fmt.Errorf("регулярное выражение %q не поддерживается (HyRoute понимает синтаксис RE2)", re)
	}
	return Item{Regexp, re}, nil
}

// portItem normalizes a port or a range: "443", "1000-2000", "1000:2000".
// all is true for the whole range.
func portItem(s string) (p string, all, ok bool) {
	s = strings.ReplaceAll(strings.TrimSpace(s), ":", "-")
	lo, hi, rng := strings.Cut(s, "-")
	a, okA := atoiPort(lo)
	if !rng {
		return lo, false, okA && a > 0
	}
	b, okB := atoiPort(hi)
	if !okA || !okB || a > b {
		return "", false, false
	}
	if a <= 1 && b >= 65535 {
		return "", true, true
	}
	if a == 0 {
		a = 1
	}
	if a == b {
		return fmt.Sprint(a), false, true
	}
	return fmt.Sprintf("%d-%d", a, b), false, true
}

func atoiPort(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 5 {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, n <= 65535
}

// ports reads a comma list of ports. all: the list covers every port.
func ports(s string) (out []string, all bool, bad string) {
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		v, a, ok := portItem(p)
		switch {
		case !ok:
			return nil, false, p
		case a:
			return nil, true, ""
		}
		out = append(out, v)
	}
	return out, false, ""
}

// network reads "tcp", "udp", "tcp,udp" ("" = both).
func network(s string) (string, bool) {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	switch s {
	case "", "tcp,udp", "udp,tcp", "both", "any", "all":
		return "", true
	case "tcp", "udp":
		return s, true
	}
	return "", false
}

func isProgram(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return strings.HasSuffix(l, ".exe") || strings.Contains(l, `\`)
}

// stripJSONComments drops // and /* */ comments outside strings (v2rayN
// and sing-box files are often JSON with comments).
func stripJSONComments(s string) string {
	if !strings.Contains(s, "//") && !strings.Contains(s, "/*") {
		return s
	}
	var b strings.Builder
	in, esc := false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if in {
			b.WriteByte(ch)
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				in = false
			}
			continue
		}
		switch {
		case ch == '"':
			in = true
			b.WriteByte(ch)
		case ch == '/' && i+1 < len(s) && s[i+1] == '/':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			if i < len(s) {
				b.WriteByte('\n')
			}
		case ch == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return b.String()
			}
			i += end + 3
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}
