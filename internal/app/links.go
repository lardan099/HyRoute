package app

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/lardan099/hyroute/internal/hysteria"
)

// Links is the result of parsing pasted text or a subscription body.
type Links struct {
	Profiles []hysteria.Profile
	Warnings []string
	Errors   []string
	// Ignored counts share links of other protocols (vless://, vmess://,
	// ss://, trojan://, tuic://, hysteria:// v1 …) by scheme.
	Ignored map[string]int
	// Base64: the text was a base64-encoded link list.
	Base64 bool
}

func (l *Links) IgnoredTotal() int {
	n := 0
	for _, v := range l.Ignored {
		n += v
	}
	return n
}

// ParseLinks finds hysteria2:// and hy2:// links in text (one per line or
// separated by spaces). A body without any "://" is tried as base64 (the
// common subscription format).
func ParseLinks(text string) Links {
	res := Links{Ignored: map[string]int{}}
	text = strings.TrimPrefix(strings.TrimSpace(text), "\ufeff")
	if !strings.Contains(text, "://") {
		if dec, ok := decodeBase64(text); ok && strings.Contains(dec, "://") {
			text, res.Base64 = dec, true
		}
	}
	n := 0
	for _, f := range splitLinks(text) {
		scheme, _, _ := strings.Cut(f, "://")
		scheme = strings.ToLower(scheme)
		if scheme != "hysteria2" && scheme != "hy2" {
			res.Ignored[scheme]++
			continue
		}
		n++
		p, warns, err := hysteria.ParseURI(f)
		label := p.Name
		if label == "" {
			label = p.Host
		}
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("ссылка %d: %v", n, err))
			continue
		}
		for _, w := range warns {
			res.Warnings = append(res.Warnings, label+": "+w)
		}
		if p.Name == "" {
			p.Name = p.Host
		}
		res.Profiles = append(res.Profiles, p)
	}
	if res.Warnings == nil {
		res.Warnings = []string{}
	}
	if res.Errors == nil {
		res.Errors = []string{}
	}
	return res
}

// linkStart finds "scheme://" at the start of a line or after whitespace
// or a byte order mark (a base64 list may encode one, and so may each
// file of lists joined together).
var linkStart = regexp.MustCompile(`(?:^|[\s\x{FEFF}])([A-Za-z][A-Za-z0-9+.\-]*://)`)

// splitLinks returns the share links in text. A link runs to the end of
// its line or to the next link on the same line, so names (the #fragment)
// may contain spaces: "hy2://…#🇳🇱 Нидерланды напрямую".
func splitLinks(text string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		idx := linkStart.FindAllStringSubmatchIndex(line, -1)
		for i, m := range idx {
			end := len(line)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			if l := strings.TrimSpace(line[m[2]:end]); l != "" {
				out = append(out, l)
			}
		}
	}
	return out
}

// decodeBase64 accepts standard and URL alphabets, with or without
// padding, and ignores line breaks.
func decodeBase64(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return "", false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return "", false
}
