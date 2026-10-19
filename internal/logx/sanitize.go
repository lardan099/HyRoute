package logx

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sanitize is Privacy mode for text that leaves the program (exported
// logs, diagnostics): public IP addresses are masked (85.xxx.xxx.249,
// 2a01:xxxx::xxxx), domain names keep only the top-level domain
// (***.com: visited sites and SNI are as telling as addresses), the given
// host names become "***" and URLs keep only their scheme. Private, loopback and link-local addresses stay: they
// identify nothing. A path's user name is masked (C:\Users\***\…, as the
// frontend's hideUserPath). The frontend (privacy.ts) applies the same
// rules.
func Sanitize(s string, hosts []string) string {
	for _, h := range hosts {
		if len(h) >= 4 {
			if _, err := netip.ParseAddr(h); err != nil {
				s = strings.ReplaceAll(s, h, "***")
			}
		}
	}
	s = urlre.ReplaceAllString(s, "$1***/…")
	s = usersre.ReplaceAllString(s, "${1}***")
	// Domains before IPs: a masked IP (85.xxx.xxx.249) looks like a name.
	s = MaskDomains(s)
	s = v4re.ReplaceAllStringFunc(s, func(m string) string {
		a, err := netip.ParseAddr(m)
		if err != nil || !public(a) {
			return m
		}
		b := a.As4()
		return itoa(b[0]) + ".xxx.xxx." + itoa(b[3])
	})
	s = v6re.ReplaceAllStringFunc(s, func(m string) string {
		if !strings.Contains(m, "::") && strings.Count(m, ":") < 7 {
			return m // 12:34:56 and the like
		}
		a, err := netip.ParseAddr(m)
		if err != nil || !public(a) {
			return m
		}
		first, _, _ := strings.Cut(strings.ToLower(m), ":")
		if first == "" {
			return "xxxx::xxxx"
		}
		return first + ":xxxx::xxxx"
	})
	return s
}

// MaskDomains replaces domain names with "***.<tld>". Labels may be
// Unicode (пример.рф): rule sites are kept as typed, not punycode. File
// names (hysteria.exe, rules.json) are left alone. Some extensions are real
// top-level domains too (999.md, example.zip): such a name counts as a file
// only right after another extension (geosite.dat.new, not go.md).
func MaskDomains(s string) string {
	var b strings.Builder
	last := 0
	for pos := 0; pos < len(s); {
		loc := domre.FindStringIndex(s[pos:])
		if loc == nil {
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		if r, _ := utf8.DecodeLastRuneInString(s[:start]); start > 0 && wordRune(r) {
			// Inside a word (x_example.com): so is every start up to the
			// first "." or "-".
			pos = start + strings.IndexAny(s[start:end], ".-")
			continue
		}
		if e := domainEnd(s, start, end); e >= 0 {
			pos, end = e, e
		} else {
			// Part of a longer word (example.com2). A name starting later in
			// s[start:end] could only end where this one could, so skip it all.
			pos = end
			continue
		}
		m := s[start:end]
		i := strings.LastIndexByte(m, '.')
		if tld := strings.ToLower(m[i+1:]); fileExt[tld] {
			rest := m[:i]
			j := strings.LastIndexByte(rest, '.')
			if !tldExt[tld] || j >= 0 && fileExt[strings.ToLower(rest[j+1:])] {
				continue
			}
		}
		b.WriteString(s[last:start])
		b.WriteString("***.")
		b.WriteString(m[i+1:])
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// domainEnd is where the name found at s[start:end] ends, given that it
// must not be followed by a letter, digit or "_" (the lookahead of
// privacy.ts domRe, which RE2 lacks): end itself or, as the JS
// backtracking finds, the longest shorter name ending at a "." or "-";
// -1 if there is none. s[start:end] is a match, so a prefix of it is a name
// when it has a "." and the part after the last one is a top-level domain:
// only that part is checked, which keeps this linear in the match.
func domainEnd(s string, start, end int) int {
	if r, _ := utf8.DecodeRuneInString(s[end:]); end == len(s) || !wordRune(r) {
		return end
	}
	for e := end - 1; e > start; e-- {
		if s[e] != '.' && s[e] != '-' {
			continue
		}
		if i := strings.LastIndexByte(s[start:e], '.'); i >= 0 && tldre.MatchString(s[start+i+1:e]) {
			return e
		}
	}
	return -1
}

func wordRune(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r) }

const tldPattern = `(?:xn--[a-z0-9-]{2,59}|\p{L}{2,63})`

var (
	// domre is privacy.ts domRe without the lookarounds, which MaskDomains
	// does by hand; tldre is its last label.
	domre   = regexp.MustCompile(`(?i)(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+` + tldPattern)
	tldre   = regexp.MustCompile(`(?i)^` + tldPattern + `$`)
	fileExt = map[string]bool{"exe": true, "dll": true, "sys": true, "dat": true, "json": true, "yaml": true, "yml": true, "log": true,
		"txt": true, "zip": true, "ps1": true, "md": true, "go": true, "tmp": true, "old": true, "new": true, "part": true,
		"ini": true, "conf": true, "html": true, "js": true, "css": true, "png": true, "svg": true}
	// tldExt are the extensions in fileExt that are top-level domains too.
	tldExt = map[string]bool{"md": true, "zip": true, "new": true}
)

var (
	v4re  = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	v6re  = regexp.MustCompile(`[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*`)
	urlre = regexp.MustCompile(`\b(https?://)[^\s"'<>]+`)
	// usersre: the folder name after \Users\ (or /Users/) of a path.
	usersre = regexp.MustCompile(`(?i)([\\/]Users[\\/])[^\\/\s"'«»<>]+`)
)

func public(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalMulticast() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 { // CGNAT
			return false
		}
		if b[0] == 0 || b[0] >= 240 {
			return false
		}
	}
	return true
}

func itoa(b byte) string {
	const d = "0123456789"
	if b >= 100 {
		return string([]byte{d[b/100], d[b/10%10], d[b%10]})
	}
	if b >= 10 {
		return string([]byte{d[b/10], d[b%10]})
	}
	return string(d[b])
}
