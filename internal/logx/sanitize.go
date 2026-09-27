package logx

import (
	"net/netip"
	"regexp"
	"strings"
)

// Sanitize is Privacy mode for text that leaves the program (exported
// logs, diagnostics): public IP addresses are masked (85.xxx.xxx.249,
// 2a01:xxxx::xxxx), domain names keep only the top-level domain
// (***.com: visited sites and SNI are as telling as addresses), the given
// host names become "***" and URLs keep only their scheme. Private, loopback and link-local addresses stay: they
// identify nothing. The frontend (privacy.ts) applies the same rules.
func Sanitize(s string, hosts []string) string {
	for _, h := range hosts {
		if len(h) >= 4 {
			if _, err := netip.ParseAddr(h); err != nil {
				s = strings.ReplaceAll(s, h, "***")
			}
		}
	}
	s = urlre.ReplaceAllString(s, "$1***/…")
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

// MaskDomains replaces domain names with "***.<tld>". File names
// (hysteria.exe, rules.json) are left alone.
func MaskDomains(s string) string {
	return domre.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.LastIndexByte(m, '.')
		tld := strings.ToLower(m[i+1:])
		if fileExt[tld] {
			return m
		}
		return "***." + m[i+1:]
	})
}

var (
	domre   = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})\b`)
	fileExt = map[string]bool{"exe": true, "dll": true, "sys": true, "dat": true, "json": true, "yaml": true, "yml": true, "log": true,
		"txt": true, "zip": true, "ps1": true, "md": true, "go": true, "tmp": true, "old": true, "new": true, "part": true,
		"ini": true, "conf": true, "html": true, "js": true, "css": true, "png": true, "svg": true}
)

var (
	v4re  = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	v6re  = regexp.MustCompile(`[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*`)
	urlre = regexp.MustCompile(`\b(https?://)[^\s"'<>]+`)
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
