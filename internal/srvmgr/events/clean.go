package events

import (
	"context"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

// Address replaces an address in an event text.
const Address = "[адрес]"

var (
	// urlRe: a URL (a release, a webhook) is an address too.
	urlRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s"'<>«»]+`)
	// ipv4Re: an IPv4 address, with a port or not.
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)
	// ipv6Re finds what may be an IPv6 address (with brackets, a zone, a
	// port); ParseIP decides, so "12:30:45" stays.
	ipv6Re = regexp.MustCompile(`\[?[0-9A-Fa-f:]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*(?:%[0-9A-Za-z._-]+)?\]?(?::\d{1,5})?`)
	// hostPortRe: a name with a port (a check target, a dial error).
	hostPortRe = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z][a-z0-9-]{0,62}\.?:\d{1,5}\b`)
)

// Clean makes text fit for an event: secrets out (red and the patterns
// of redact), the address of each server replaced by its name, and any
// other address — IP, URL, name with a port, a domain other than a
// public service's — by Address; key fingerprints and pins are masked.
func Clean(text string, red *redact.Redactor, servers []model.Server) string {
	text = red.String(text)
	// Longest first: a host that contains another one is replaced whole.
	list := make([]model.Server, 0, len(servers))
	for _, s := range servers {
		if s.Host != "" {
			list = append(list, s)
		}
	}
	sort.Slice(list, func(i, j int) bool { return len(list[i].Host) > len(list[j].Host) })
	for _, s := range list {
		text = replaceHost(text, s.Host, "«"+s.Name+"»")
	}
	text = urlRe.ReplaceAllStringFunc(text, func(m string) string {
		// Punctuation after a URL ends the sentence, not the URL.
		trimmed := strings.TrimRight(m, ".,;:!?)")
		return Address + m[len(trimmed):]
	})
	text = ipv6Re.ReplaceAllStringFunc(text, func(m string) string {
		if isIPv6(m) {
			return Address
		}
		return m
	})
	text = ipv4Re.ReplaceAllString(text, Address)
	text = hostPortRe.ReplaceAllString(text, Address)
	// A bare domain (a certificate's name, a failed lookup) is an address
	// too, a key fingerprint is looked up like one.
	text = redact.Domains(text, Address)
	return redact.Fingerprints(text)
}

// replaceHost replaces host in text, in any case of ASCII letters, where
// it stands as a whole name: not a part of a longer name or address
// (192.0.2.1 in 192.0.2.10, example.com in example.community). Brackets
// around it (an IPv6 address) go with it.
func replaceHost(text, host, with string) string {
	if host == "" {
		return text
	}
	lower, h := asciiLower(text), asciiLower(host)
	var b strings.Builder
	last := 0
	for i := 0; i <= len(lower)-len(h); {
		j := strings.Index(lower[i:], h)
		if j < 0 {
			break
		}
		start, end := i+j, i+j+len(h)
		if !hostEdge(text, start-1, false) || !hostEdge(text, end, true) {
			i = start + 1
			continue
		}
		if start > 0 && end < len(text) && text[start-1] == '[' && text[end] == ']' {
			start, end = start-1, end+1
		}
		b.WriteString(text[last:start])
		b.WriteString(with)
		last, i = end, end
	}
	if last == 0 {
		return text
	}
	b.WriteString(text[last:])
	return b.String()
}

// hostEdge reports whether the byte at i (outside text: yes) ends a name
// there: not a letter, digit, '-', '_' or ':', nor '.' — except a '.'
// that ends a sentence (after reports the byte after the name).
func hostEdge(text string, i int, after bool) bool {
	if i < 0 || i >= len(text) {
		return true
	}
	c := text[i]
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-', c == '_', c == ':' && !after:
		return false
	case c == '.':
		return after && (i+1 >= len(text) || !isNameByte(text[i+1]))
	}
	return true
}

func isNameByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_'
}

// asciiLower lower-cases ASCII letters only: byte offsets stay those of s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// isIPv6 reports whether m is an IPv6 address, maybe in brackets, with a
// zone or a port.
func isIPv6(m string) bool {
	s := m
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			s = s[1:i]
		}
	}
	s = strings.TrimSuffix(s, "]")
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	if ip := net.ParseIP(s); ip != nil && strings.Contains(s, ":") {
		return true
	}
	// A port after an address without brackets: 2001:db8::1:443 parses
	// as an address already; try without the last group otherwise.
	if i := strings.LastIndexByte(s, ':'); i > 0 {
		if ip := net.ParseIP(s[:i]); ip != nil && strings.Contains(s[:i], ":") {
			return true
		}
	}
	return false
}

// clean is Clean with the bus's redactor and the servers in the store.
func (b *Bus) clean(ctx context.Context, text string) string {
	servers, _ := b.Store.ListServers(ctx)
	return Clean(text, b.Redact, servers)
}
