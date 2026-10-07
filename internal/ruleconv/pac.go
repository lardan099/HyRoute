package ruleconv

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// pac reads a PAC file: the one SwitchyOmega exports (profiles as
// functions in an object, "+Profile" results) and a hand-written
// FindProxyForURL with if (…) return "…"; lines.
func (c *conv) pac(text string) error {
	src := stripJSComments(text)
	if init, profiles, ok := omegaPAC(src); ok {
		return c.omegaPAC(src, init, profiles)
	}
	body, line, ok := pacFunction(src)
	if !ok {
		return fmt.Errorf("в PAC-файле не найдена функция FindProxyForURL")
	}
	c.pacBody(body, line, c.pacResult)
	return nil
}

// pacProfile is a function of SwitchyOmega's PAC.
type pacProfile struct {
	name       string
	body, line int // body: offset of "{" in the source
	end        int
}

var omegaInit = regexp.MustCompile(`\}\(\s*"(\+[^"]*)"\s*,\s*\{`)
var omegaFunc = regexp.MustCompile(`"(\+[^"]*)"\s*:\s*function\s*\([^)]*\)\s*\{`)

// omegaPAC finds the profiles of SwitchyOmega's PAC and the first one.
func omegaPAC(src string) (string, map[string]pacProfile, bool) {
	m := omegaInit.FindStringSubmatch(src)
	if m == nil {
		return "", nil, false
	}
	profiles := map[string]pacProfile{}
	for _, loc := range omegaFunc.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		open := loc[1] - 1
		end := matchBrace(src, open)
		if end < 0 {
			continue
		}
		profiles[name] = pacProfile{name: name, body: open, end: end, line: lineOf(src, open)}
	}
	if _, ok := profiles[m[1]]; !ok {
		return "", nil, false
	}
	return m[1], profiles, true
}

func (c *conv) omegaPAC(src, init string, profiles map[string]pacProfile) error {
	// A profile whose function only returns a proxy (after skipping local
	// addresses) is a server; one with conditions is a switch.
	server := map[string]string{}
	for name, p := range profiles {
		if res, ok := serverProfile(src[p.body+1 : p.end]); ok {
			server[name] = res
		}
	}
	// Another switch profile as a result stays a place to choose for.
	p := profiles[init]
	c.pacBody(src[p.body+1:p.end], lineOf(src, p.body+1), func(res string) string {
		if !strings.HasPrefix(res, "+") {
			return c.pacResult(res)
		}
		t := strings.TrimPrefix(res, "+")
		if d, ok := server[res]; ok {
			c.target(t, ToProxy, d)
		} else {
			c.target(t, guessKind(t), "")
		}
		return t
	})
	return nil
}

// serverProfile: the function returns one proxy, maybe after "DIRECT"
// for local addresses. res is that proxy.
func serverProfile(body string) (string, bool) {
	rets := pacReturn.FindAllStringSubmatch(body, -1)
	if len(rets) == 0 {
		return "", false
	}
	last := rets[len(rets)-1][2]
	if strings.HasPrefix(last, "+") || strings.EqualFold(strings.TrimSpace(last), "DIRECT") {
		return "", false
	}
	for _, r := range rets[:len(rets)-1] {
		if !strings.EqualFold(strings.TrimSpace(r[2]), "DIRECT") {
			return "", false
		}
	}
	for _, cond := range pacIfs(body) {
		if !localCond(cond.cond) {
			return "", false
		}
	}
	return proxyDetail(last), true
}

var (
	pacReturn    = regexp.MustCompile(`\breturn\s+(["'])(.*?)(["'])`)
	reReturnHead = regexp.MustCompile(`^return\s+(["'])(.*?)(["'])`)
	reIfEnd      = regexp.MustCompile(`\bif\s*$`)
)

var localHosts = regexp.MustCompile(`^/\^(127\\\.0\\\.0\\\.1|::1|localhost|\[::1\])\$/\.test\(host\)$`)

// localCond: a condition only about local addresses (SwitchyOmega's
// bypass list of a proxy profile).
func localCond(cond string) bool {
	for _, d := range splitTop(cond, "||") {
		d = unparen(d)
		if !localHosts.MatchString(d) && !strings.Contains(d, "isPlainHostName") && !strings.Contains(d, "<local>") {
			return false
		}
	}
	return true
}

func proxyDetail(res string) string {
	first, _, _ := strings.Cut(res, ";")
	return strings.TrimSpace(first)
}

// pacResult names the target of a PAC result: DIRECT, or the proxy.
func (c *conv) pacResult(res string) string {
	first := proxyDetail(res)
	if strings.EqualFold(first, "DIRECT") {
		c.target("DIRECT", ToDirect, "")
		return "DIRECT"
	}
	c.target(first, ToProxy, first)
	return first
}

// pacFunction finds the body of FindProxyForURL.
func pacFunction(src string) (string, int, bool) {
	i := strings.Index(src, "FindProxyForURL")
	if i < 0 {
		return "", 0, false
	}
	open := strings.Index(src[i:], "{")
	if open < 0 {
		return "", 0, false
	}
	open += i
	end := matchBrace(src, open)
	if end < 0 {
		return "", 0, false
	}
	return src[open+1 : end], lineOf(src, open+1), true
}

type pacIf struct {
	cond, res string
	block     bool // { … } with more than one return: not understood
	off       int
}

var pacIfStart = regexp.MustCompile(`\bif\s*\(`)

// pacIfs finds "if (cond) return "x";" and "if (cond) { return "x"; }"
// at the top level of body.
func pacIfs(body string) []pacIf {
	var out []pacIf
	for _, loc := range pacIfStart.FindAllStringIndex(body, -1) {
		if depthAt(body, loc[0]) != 0 {
			continue
		}
		open := loc[1] - 1
		end := matchParen(body, open)
		if end < 0 {
			continue
		}
		p := pacIf{cond: strings.TrimSpace(body[open+1 : end]), off: loc[0]}
		rest := strings.TrimSpace(body[end+1:])
		if strings.HasPrefix(rest, "{") {
			close := matchBrace(rest, 0)
			if close < 0 {
				continue
			}
			inner := rest[1:close]
			rets := pacReturn.FindAllStringSubmatch(inner, -1)
			if len(rets) != 1 || strings.Contains(inner, "if") {
				p.block = true
			} else {
				p.res = rets[0][2]
			}
		} else if m := reReturnHead.FindStringSubmatch(rest); m != nil {
			p.res = m[2]
		} else {
			p.block = true
		}
		out = append(out, p)
	}
	return out
}

// pacBody converts the ifs of a function body; the last top-level return
// is the default. resolve maps a result to a target name.
func (c *conv) pacBody(body string, line int, resolve func(string) string) {
	ifs := pacIfs(body)
	for _, p := range ifs {
		n := line + strings.Count(body[:p.off], "\n")
		if p.block {
			c.warn(n, "условие с несколькими действиями внутри { } не распознано — пропущено")
			continue
		}
		t := resolve(p.res)
		items, all, ok := c.pacCond(n, p.cond)
		if !ok {
			continue
		}
		if all {
			items = nil
		}
		c.add(Rule{Target: t, Items: items, Line: n}, true)
	}
	// The default: the last return outside any if.
	for _, loc := range pacReturn.FindAllStringSubmatchIndex(body, -1) {
		if depthAt(body, loc[0]) != 0 || afterIf(body, loc[0]) {
			continue
		}
		c.add(Rule{Target: resolve(body[loc[4]:loc[5]]), Line: line + strings.Count(body[:loc[0]], "\n")}, false)
		break
	}
	if extra := strings.Count(body, "for (") + strings.Count(body, "for(") + strings.Count(body, "while"); extra > 0 && len(ifs) == 0 {
		c.warn(0, "PAC-файл выбирает адреса циклом по спискам: такой PAC не распознаётся, перенесено только действие по умолчанию")
	}
}

// afterIf: the return at i belongs to an if without braces.
func afterIf(body string, i int) bool {
	before := strings.TrimRight(body[:i], " \t\n")
	return strings.HasSuffix(before, ")") && !strings.HasSuffix(before, "{") && ifBefore(before)
}

func ifBefore(s string) bool {
	// Walk back over the condition's parentheses.
	depth := 0
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case ')':
			depth++
		case '(':
			depth--
			if depth == 0 {
				return reIfEnd.MatchString(s[:i])
			}
		}
	}
	return false
}

var (
	reTestHost = regexp.MustCompile(`^/(.*)/[a-z]*\.test\(\s*host\s*\)$`)
	reTestURL  = regexp.MustCompile(`^/(.*)/[a-z]*\.test\(\s*url\s*\)$`)
	reShExp    = regexp.MustCompile(`^shExpMatch\(\s*(host|url)\s*,\s*["'](.*)["']\s*\)$`)
	reDNSIs    = regexp.MustCompile(`^(?:dnsDomainIs|localHostOrDomainIs)\(\s*host\s*,\s*["'](.*)["']\s*\)$`)
	reHostEq   = regexp.MustCompile(`^host\s*===?\s*["'](.*)["']$`)
	reInNet    = regexp.MustCompile(`^isInNet\(\s*(?:host|dnsResolve\(\s*host\s*\)|[a-zA-Z_]+)\s*,\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*\)$`)
	reIndexOf  = regexp.MustCompile(`^(host|url)\.indexOf\(\s*["'](.*)["']\s*\)\s*(>=\s*0|>\s*-1|!==?\s*-1)$`)
	reScheme   = regexp.MustCompile(`^scheme\s*===?\s*["'][a-z]+["']$`)
)

// pacCond reads a PAC condition: a || of the shapes PAC files use.
func (c *conv) pacCond(n int, cond string) (items []Item, all, ok bool) {
	for _, d := range splitTop(cond, "||") {
		d = unparen(d)
		if d == "true" {
			return nil, true, true
		}
		if strings.Contains(d, "&&") {
			parts := splitTop(d, "&&")
			// SwitchyOmega's URL wildcard: scheme === "https" && /…/.test(host).
			if len(parts) == 2 && reScheme.MatchString(unparen(parts[0])) {
				d = unparen(parts[1])
				c.warn(n, "условие только для одной схемы (%s) перенесено для всех соединений с сайтом", unparen(parts[0]))
			} else {
				c.warn(n, "сложное условие %q пропущено", short(d))
				continue
			}
		}
		switch {
		case reTestHost.MatchString(d):
			re := reTestHost.FindStringSubmatch(d)[1]
			it, err := jsHostRegex(unescapeSlash(re))
			if err != nil {
				c.warn(n, "%v", err)
				continue
			}
			items = append(items, it)
		case reTestURL.MatchString(d):
			c.warn(n, "регулярное выражение по адресу страницы пропущено: HyRoute выбирает по сайту")
		case reShExp.MatchString(d):
			m := reShExp.FindStringSubmatch(d)
			pat := m[2]
			if m[1] == "url" {
				host, path, ok := urlHost(pat)
				if !ok {
					c.warn(n, "шаблон адреса %q пропущен: сайта в нём не видно", pat)
					continue
				}
				if path {
					c.warn(n, "в %q есть путь страницы: правило перенесено для всего сайта", pat)
				}
				pat = host
			}
			it, a, ok := wildcardHost(pat, false)
			if !ok {
				c.warn(n, "не понимаю шаблон %q", pat)
				continue
			}
			if a {
				return nil, true, true
			}
			items = append(items, it)
		case reDNSIs.MatchString(d):
			v := reDNSIs.FindStringSubmatch(d)[1]
			if strings.HasPrefix(v, ".") {
				if h, ok := hostName(v[1:]); ok {
					items = append(items, Item{Sub, h})
					continue
				}
			} else if h, ok := hostName(v); ok {
				items = append(items, Item{Suffix, h})
				continue
			}
			c.warn(n, "не понимаю %q", v)
		case reHostEq.MatchString(d):
			v := reHostEq.FindStringSubmatch(d)[1]
			if it, ok := addrItem(v); ok {
				items = append(items, it)
			} else if h, ok := hostName(v); ok {
				items = append(items, Item{Exact, h})
			} else {
				c.warn(n, "не понимаю %q", v)
			}
		case reInNet.MatchString(d):
			m := reInNet.FindStringSubmatch(d)
			p, ok := maskPrefix(m[1], m[2])
			if !ok {
				c.warn(n, "не понимаю сеть %s/%s", m[1], m[2])
				continue
			}
			items = append(items, Item{IP, p})
		case reIndexOf.MatchString(d):
			m := reIndexOf.FindStringSubmatch(d)
			if m[1] == "url" {
				c.warn(n, "слово %q ищется во всём адресе страницы, в HyRoute — только в имени сайта", m[2])
			}
			items = append(items, Item{Keyword, strings.ToLower(m[2])})
		case strings.Contains(d, "isPlainHostName"), localHosts.MatchString(d):
			c.warn(n, "условие для локальных адресов пропущено: их HyRoute и так не трогает")
		default:
			c.warn(n, "условие %q не распознано — пропущено", short(d))
		}
	}
	return items, false, len(items) > 0
}

func maskPrefix(ip, mask string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return "", false
	}
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() {
		return "", false
	}
	b := m.As4()
	bits := 0
	seenZero := false
	for _, x := range b {
		for i := 7; i >= 0; i-- {
			if x&(1<<i) != 0 {
				if seenZero {
					return "", false
				}
				bits++
			} else {
				seenZero = true
			}
		}
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return "", false
	}
	if bits == 32 {
		return a.String(), true
	}
	return p.String(), true
}

func unescapeSlash(s string) string { return strings.ReplaceAll(s, `\/`, "/") }

func short(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 80 {
		return string(r[:77]) + "…"
	}
	return s
}

func lineOf(s string, off int) int { return strings.Count(s[:off], "\n") + 1 }

// unparen strips parentheses around the whole expression.
func unparen(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "(") && matchParen(s, 0) == len(s)-1 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	return s
}

// splitTop splits s at sep outside parentheses, strings and regex literals.
func splitTop(s, sep string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch ch := s[i]; {
		case ch == '"' || ch == '\'':
			i = skipString(s, i)
		case ch == '/' && regexStart(s, i):
			i = skipRegex(s, i)
		case ch == '(' || ch == '[' || ch == '{':
			depth++
		case ch == ')' || ch == ']' || ch == '}':
			depth--
		case depth == 0 && strings.HasPrefix(s[i:], sep):
			out = append(out, strings.TrimSpace(s[start:i]))
			i += len(sep) - 1
			start = i + 1
		}
	}
	return append(out, strings.TrimSpace(s[start:]))
}

// depthAt is the brace depth at offset i of body.
func depthAt(body string, at int) int {
	depth := 0
	for i := 0; i < at && i < len(body); i++ {
		switch ch := body[i]; {
		case ch == '"' || ch == '\'':
			i = skipString(body, i)
		case ch == '/' && regexStart(body, i):
			i = skipRegex(body, i)
		case ch == '{':
			depth++
		case ch == '}':
			depth--
		}
	}
	return depth
}

func matchBrace(s string, open int) int { return matchPair(s, open, '{', '}') }
func matchParen(s string, open int) int { return matchPair(s, open, '(', ')') }

func matchPair(s string, open int, o, cl byte) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch ch := s[i]; {
		case ch == '"' || ch == '\'':
			i = skipString(s, i)
		case ch == '/' && i > open && regexStart(s, i):
			i = skipRegex(s, i)
		case ch == o:
			depth++
		case ch == cl:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// skipString returns the offset of the quote closing the string at i.
func skipString(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case q:
			return j
		case '\n':
			return j
		}
	}
	return len(s) - 1
}

// regexStart: a "/" at i starts a regex literal (after an operator or a
// parenthesis, not after a value).
func regexStart(s string, i int) bool {
	if i+1 < len(s) && (s[i+1] == '/' || s[i+1] == '*') {
		return false
	}
	j := i - 1
	for j >= 0 && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n') {
		j--
	}
	if j < 0 {
		return true
	}
	return strings.IndexByte("(,=:[!&|?{};+-*%<>~^", s[j]) >= 0 || strings.HasSuffix(s[:j+1], "return")
}

func skipRegex(s string, i int) int {
	class := false
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '[':
			class = true
		case ']':
			class = false
		case '/':
			if !class {
				return j
			}
		case '\n':
			return j
		}
	}
	return len(s) - 1
}

// stripJSComments drops // and /* */ comments outside strings and regex
// literals, keeping line breaks so line numbers stay right.
func stripJSComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"' || ch == '\'':
			j := skipString(s, i)
			b.WriteString(s[i : j+1])
			i = j
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
			b.WriteString(strings.Repeat("\n", strings.Count(s[i:i+2+end+2], "\n")))
			i += end + 3
		case ch == '/' && regexStart(s, i):
			j := skipRegex(s, i)
			b.WriteString(s[i : j+1])
			i = j
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}
