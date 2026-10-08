package diag

import (
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

// Kinds of pseudonyms: a value becomes <kind>-<n>.
const (
	kindServer = "server"
	kindHost   = "host"
	kindDomain = "domain"
	kindUser   = "user"
	kindEmail  = "email"
	kindChain  = "chain"
)

// common are user and host names that identify no one and that the texts
// use as ordinary words (the OS, system users, roles): they stay.
var common = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`root admin administrator user owner operator readonly hysteria nobody
		ubuntu debian centos fedora rocky almalinux alma alpine arch archlinux ec2-user opc
		localhost server vps vds host node linux`) {
		common[w] = true
	}
}

// public are domains of the services HyRoute and Hysteria use themselves:
// they identify no installation, and the logs read better with them.
// publicIPs are the public DNS resolvers a config may name.
var publicIPs = map[string]bool{
	"1.1.1.1": true, "1.0.0.1": true, "8.8.8.8": true, "8.8.4.4": true, "9.9.9.9": true, "149.112.112.112": true,
	"2606:4700:4700::1111": true, "2606:4700:4700::1001": true, "2001:4860:4860::8888": true, "2001:4860:4860::8844": true,
	"2620:fe::fe": true, "2620:fe::9": true,
}

// pseudonyms takes everything identifying out of the texts of one bundle:
// exact secret values and redact's patterns become [REDACTED], other key
// material goes too, and names, addresses, domains and users get
// pseudonyms. A value gets the next <kind>-<n> the first time it is seen
// and keeps it in every file. The table stays in memory: it never goes
// into the bundle.
type pseudonyms struct {
	red   *redact.Redactor
	names map[string]string // key of a value → its pseudonym
	count map[string]int    // pseudonyms given, by kind
	known []literal         // what the texts are searched for
	dirty bool              // known is not sorted
}

// literal is a form of a value as texts may have it (folded) and its
// pseudonym.
type literal struct{ text, alias string }

func newPseudonyms() *pseudonyms {
	return &pseudonyms{red: redact.New(), names: map[string]string{}, count: map[string]int{}}
}

// secret registers exact secret values; each line of a value of several
// (a private key) is one too.
func (p *pseudonyms) secret(vs ...string) {
	var all []string
	for _, v := range vs {
		all = append(all, v)
		if strings.Contains(v, "\n") {
			for _, l := range strings.Split(v, "\n") {
				if l = strings.TrimSpace(l); len(l) >= 16 {
					all = append(all, l)
				}
			}
		}
	}
	p.red.Add(all...)
}

// name is the pseudonym of v as a value of kind ("" for ""). The same
// value gets the same pseudonym whatever kind it was first seen as (a
// server's address that is also its SNI). User and host names that
// identify no one (root, localhost, loopback and private addresses, the
// public resolvers) stay as they are.
func (p *pseudonyms) name(kind, v string) string {
	v = strings.TrimSpace(v)
	if kind == kindHost || kind == kindDomain {
		v = strings.TrimSuffix(v, ".")
	}
	if v == "" {
		return ""
	}
	key := p.key(kind, v)
	if alias, ok := p.names[key]; ok {
		return alias
	}
	if (kind == kindUser || kind == kindHost || kind == kindDomain) && keep(key) {
		return v
	}
	p.count[kind]++
	alias := kind + "-" + strconv.Itoa(p.count[kind])
	p.names[key] = alias
	p.learn(v, key, alias)
	return alias
}

func (p *pseudonyms) key(kind, v string) string {
	switch kind {
	case kindHost, kindDomain:
		return hostKey(v)
	}
	return fold(v)
}

// hostKey is a host as the table keeps it: an address in its canonical
// form, a name in lower case and punycode, without the root dot.
func hostKey(v string) string {
	h := strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.WithZone("").String()
	}
	h = strings.TrimSuffix(fold(h), ".")
	if a, err := idna.ToASCII(h); err == nil && a != "" {
		h = a
	}
	return h
}

// keep: a user or host name that identifies no one.
func keep(key string) bool {
	if common[key] || publicIPs[key] {
		return true
	}
	if a, err := netip.ParseAddr(key); err == nil {
		return a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast()
	}
	if redact.PublicName(key) {
		return true
	}
	return false
}

// learn adds the forms of v texts may have: as it is, quoted by %q (the
// controller's log), in punycode and in Unicode, an address in its
// canonical form. Too short a value, a number or a common word (a server
// called "ubuntu") would replace parts of ordinary text: it is replaced
// only where the bundle names it as a field.
func (p *pseudonyms) learn(v, key, alias string) {
	forms := []string{v, key}
	if q := strconv.Quote(v); q[1:len(q)-1] != v {
		forms = append(forms, q[1:len(q)-1])
	}
	if u, err := idna.ToUnicode(key); err == nil {
		forms = append(forms, u)
	}
	seen := map[string]bool{}
	for _, f := range forms {
		f = fold(f)
		if seen[f] || !searchable(f) || common[f] {
			continue
		}
		seen[f] = true
		p.known = append(p.known, literal{f, alias})
		p.dirty = true
	}
}

// searchable: three runes at least, and not a bare number.
func searchable(s string) bool {
	if utf8.RuneCountInString(s) < 3 {
		return false
	}
	return strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsDigit(r) })
}

// fold lowers s rune by rune where that keeps the length in bytes, so
// offsets in the folded text are offsets in s.
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		if l := unicode.ToLower(r); utf8.RuneLen(l) == utf8.RuneLen(r) {
			return l
		}
		return r
	}, s)
}

var (
	// Key material redact leaves: certificates and public keys,
	// fingerprints and pins, long hex strings (hashes and pins), and long
	// random-looking strings (a secret nothing registered).
	pemRe    = regexp.MustCompile(`(?s)-----BEGIN ([A-Z0-9 ]+)-----.*?(?:-----END [A-Z0-9 ]+-----|$)`)
	sshKeyRe = regexp.MustCompile(`\b((?:ssh|ecdsa|sk)-[a-z0-9@.-]+)\s+AAAA[0-9A-Za-z+/]+=*`)
	hexRe    = regexp.MustCompile(`\b[0-9A-Fa-f]{40,}\b|\b(?:[0-9A-Fa-f]{2}:){19,}[0-9A-Fa-f]{2}\b`)
	blobRe   = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}={0,2}`)

	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z][A-Za-z0-9-]+)`)
	ipv4Re   = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	ipv6Re   = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	domainRe = regexp.MustCompile(`(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+\p{L}(?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?`)
)

// String is s without secrets and with pseudonyms.
func (p *pseudonyms) String(s string) string {
	if s == "" {
		return s
	}
	s = strings.ToValidUTF8(s, string(utf8.RuneError)) // fold keeps offsets of valid text only
	s = p.red.String(s)
	s = maskKeys(s)
	// Each pattern runs only on a text that may have a match: a bundle
	// has thousands of short lines.
	if strings.IndexByte(s, '@') >= 0 {
		s = replace(s, emailRe, func(s string, i, j int) (string, bool) {
			at := strings.LastIndexByte(s[i:j], '@')
			if !isDomain(s[i+at+1 : j]) {
				return "", false
			}
			return p.name(kindEmail, s[i:j]), true
		})
	}
	s = p.replaceKnown(s)
	if strings.Count(s, ":") >= 2 {
		s = replace(s, ipv6Re, p.ipv6)
	}
	if strings.IndexByte(s, '.') < 0 {
		return s
	}
	if digitDot(s) {
		s = replace(s, ipv4Re, p.ipv4)
	}
	return replace(s, domainRe, func(s string, i, j int) (string, bool) {
		if !isDomain(s[i:j]) {
			return "", false
		}
		return p.name(kindDomain, s[i:j]), true
	})
}

// digitDot: s has a digit before a dot (an IPv4 address may be in it).
func digitDot(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] == '.' && isDigit(s[i-1]) {
			return true
		}
	}
	return false
}

// longRun: s has n bytes in a row of the characters base64 and hex
// strings are made of.
func longRun(s string, n int) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; isAlnum(c) || c == '+' || c == '/' || c == '_' || c == '-' || c == ':' {
			if run++; run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func maskKeys(s string) string {
	if strings.Contains(s, "-----BEGIN ") {
		s = pemRe.ReplaceAllString(s, "-----BEGIN ${1}----- "+redact.Mask+" -----END ${1}-----")
	}
	if strings.Contains(s, "AAAA") {
		s = sshKeyRe.ReplaceAllString(s, "${1} "+redact.Mask)
	}
	if !longRun(s, 16) {
		return s
	}
	s = redact.Fingerprints(s)
	s = hexRe.ReplaceAllString(s, redact.Mask)
	return blobRe.ReplaceAllStringFunc(s, func(m string) string {
		if strings.ContainsFunc(m, unicode.IsUpper) && strings.ContainsFunc(m, unicode.IsLower) && strings.ContainsFunc(m, unicode.IsDigit) {
			return redact.Mask
		}
		return m
	})
}

// replace puts fix's text in place of the matches of re it takes.
func replace(s string, re *regexp.Regexp, fix func(s string, i, j int) (string, bool)) string {
	ms := re.FindAllStringIndex(s, -1)
	if ms == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range ms {
		if out, ok := fix(s, m[0], m[1]); ok {
			b.WriteString(s[last:m[0]])
			b.WriteString(out)
			last = m[1]
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// replaceKnown replaces the registered values, whole words only, the
// longest where two overlap.
func (p *pseudonyms) replaceKnown(s string) string {
	if len(p.known) == 0 {
		return s
	}
	if p.dirty {
		sort.Slice(p.known, func(i, j int) bool {
			a, b := p.known[i].text, p.known[j].text
			if len(a) != len(b) {
				return len(a) > len(b)
			}
			return a < b
		})
		p.dirty = false
	}
	f := fold(s)
	type hit struct {
		i, j  int
		alias string
	}
	var hits []hit
	for _, l := range p.known {
		for at := 0; at < len(f); {
			k := strings.Index(f[at:], l.text)
			if k < 0 {
				break
			}
			i, j := at+k, at+k+len(l.text)
			if whole(s, i, j) {
				hits = append(hits, hit{i, j, l.alias})
			}
			at = i + 1
		}
	}
	if hits == nil {
		return s
	}
	sort.Slice(hits, func(a, b int) bool {
		if hits[a].i != hits[b].i {
			return hits[a].i < hits[b].i
		}
		return hits[a].j > hits[b].j
	})
	var b strings.Builder
	last := 0
	for _, h := range hits {
		if h.i < last {
			continue
		}
		b.WriteString(s[last:h.i])
		b.WriteString(h.alias)
		last = h.j
	}
	b.WriteString(s[last:])
	return b.String()
}

func isWord(r rune) bool { return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) }

// whole: s[i:j] is not a part of a longer word.
func whole(s string, i, j int) bool {
	if first, _ := utf8.DecodeRuneInString(s[i:]); i > 0 && isWord(first) {
		if r, _ := utf8.DecodeLastRuneInString(s[:i]); isWord(r) {
			return false
		}
	}
	if last, _ := utf8.DecodeLastRuneInString(s[:j]); j < len(s) && isWord(last) {
		if r, _ := utf8.DecodeRuneInString(s[j:]); isWord(r) {
			return false
		}
	}
	return true
}

func (p *pseudonyms) ipv4(s string, i, j int) (string, bool) {
	if i > 0 && (s[i-1] == '.' || isDigit(s[i-1])) {
		return "", false
	}
	if j < len(s) && (isDigit(s[j]) || s[j] == '.' && j+1 < len(s) && isDigit(s[j+1])) {
		return "", false
	}
	a, err := netip.ParseAddr(s[i:j])
	if err != nil {
		return "", false
	}
	out := p.name(kindHost, a.String())
	return out, out != a.String()
}

// ipv6 takes a run of hex digits, colons and dots that parses as an IPv6
// address, maybe with a port or a colon of the text after it.
func (p *pseudonyms) ipv6(s string, i, j int) (string, bool) {
	if i > 0 && isAlnum(s[i-1]) || j < len(s) && isAlnum(s[j]) {
		return "", false
	}
	m := s[i:j]
	tail := ""
	a, err := netip.ParseAddr(m)
	if err != nil {
		trimmed := strings.TrimRight(m, ":.")
		if a, err = netip.ParseAddr(trimmed); err == nil {
			tail = m[len(trimmed):]
		} else if k := strings.LastIndexByte(trimmed, ':'); k > 0 {
			if _, perr := strconv.Atoi(trimmed[k+1:]); perr == nil {
				if a, err = netip.ParseAddr(trimmed[:k]); err == nil {
					tail = m[k:]
				}
			}
		}
	}
	if err != nil || !a.Is6() || a.Is4In6() && keep(a.Unmap().String()) {
		return "", false
	}
	out := p.name(kindHost, a.String())
	if out == a.String() {
		return "", false
	}
	return out + tail, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnum(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isDomain: name is a host name under a public suffix (redact.IsDomain).
func isDomain(name string) bool { return redact.IsDomain(name) }

// hostOf is the host of an address as configs write it: host:port, a
// URL, [IPv6]:port or a bare host.
func hostOf(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil {
			return u.Hostname()
		}
		return ""
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
}

// maskKey: a field of this name holds a secret, a pin or a fingerprint.
func maskKey(name string) bool {
	if redact.IsSecretKey(name) {
		return true
	}
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "pin") || strings.Contains(n, "fingerprint")
}

// authKinds are the values of "auth" that name a kind of auth, not a
// secret (the params of a deploy).
var authKinds = map[string]bool{"password": true, "userpass": true, "http": true, "https": true, "command": true, "cmd": true}

// value is a decoded JSON value with its strings through String and the
// scalars of secret fields masked; key is the field it is in.
func (p *pseudonyms) value(key string, v any) any {
	switch x := v.(type) {
	case string:
		if x != "" && maskKey(key) && !authKinds[strings.ToLower(x)] {
			return redact.Mask
		}
		return p.String(x)
	case json.Number:
		if maskKey(key) {
			return redact.Mask
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[p.String(k)] = p.value(k, e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = p.value(key, e)
		}
		return out
	}
	return v
}

// raw is a JSON document from the database through value; text that is
// not JSON goes through String as a string.
func (p *pseudonyms) raw(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil || d.More() {
		return p.String(string(b))
	}
	return p.value("", v)
}
