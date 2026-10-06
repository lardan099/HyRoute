// Package redact removes secrets from text before it is logged, stored in
// job logs or returned by the API: passwords and tokens in key/value form
// (YAML, JSON, logfmt, query strings), Hysteria share links, URL
// passwords, Authorization headers, PEM private keys, Telegram bot tokens,
// and any exact values registered with a Redactor (the passwords a job is
// working with).
package redact

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Mask replaces a secret.
const Mask = "[REDACTED]"

// secretKey matches names of fields that hold secrets: anything ending in
// password, secret, token, passphrase, api key, secret key or private key
// (obfs-password, ssh_password, csrfToken, bot_token,
// porkbun_api_secret_key…), and "auth" itself (the Hysteria client's auth
// string).
const secretKey = `(?:[a-z0-9_.-]*?(?:password|passwd|secret|token|passphrase|api[_-]?key|secret[_-]?key|private[_-]?key)|auth)`

var (
	secretKeyRe = regexp.MustCompile(`(?i)^` + secretKey + `$`)

	pemRe      = regexp.MustCompile(`(?s)-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	hyURIRe    = regexp.MustCompile(`(?i)\b(hysteria2\+realm(?:\+http)?|hysteria2|hy2)://[^\s"'<>]+`)
	urlPassRe  = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@"'<>]*):[^/\s@"'<>]+@`) // the user may be empty
	authHdrRe  = regexp.MustCompile(`(?i)\b((?:proxy-)?authorization["']?\s*[:=]\s*)("[^"]*"|[^\r\n,}]+)`)
	keyValueRe = regexp.MustCompile(`(?i)(["']?\b` + secretKey + `["']?[ \t]*[:=][ \t]*)(` + regexp.QuoteMeta(Mask) + `|"(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|[^\s,;&}\]"']+)`)
	telegramRe = regexp.MustCompile(`\b\d{6,12}:[A-Za-z0-9_-]{30,}\b`)
)

// IsSecretKey reports whether a field of this name holds a secret.
func IsSecretKey(name string) bool { return secretKeyRe.MatchString(name) }

// String redacts the patterns (not registered values) from s.
func String(s string) string {
	if s == "" {
		return s
	}
	s = pemRe.ReplaceAllString(s, "-----BEGIN ${1}PRIVATE KEY----- "+Mask+" -----END ${1}PRIVATE KEY-----")
	s = hyURIRe.ReplaceAllString(s, "${1}://"+Mask)
	s = urlPassRe.ReplaceAllString(s, "${1}:"+Mask+"@")
	s = authHdrRe.ReplaceAllString(s, "${1}"+Mask)
	// The pattern takes the mask whole: text redacted once stays as it is.
	s = keyValueRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := keyValueRe.FindStringSubmatch(m)
		if sub[2] == Mask || strings.Trim(sub[2], `"'`) == Mask {
			return m
		}
		return sub[1] + Mask
	})
	s = telegramRe.ReplaceAllString(s, Mask)
	return s
}

// minValue is the shortest registered value that is replaced: shorter ones
// would mangle ordinary words.
const minValue = 4

// Redactor is String plus exact secret values known at run time.
type Redactor struct {
	mu       sync.RWMutex
	values   map[string]struct{}
	replacer *strings.Replacer
}

// New returns a Redactor without registered values.
func New() *Redactor { return &Redactor{values: map[string]struct{}{}} }

// Add registers exact secret values; values shorter than 4 bytes are
// ignored.
func (r *Redactor) Add(values ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for _, v := range values {
		if len(v) < minValue || v == Mask {
			continue
		}
		if _, ok := r.values[v]; !ok {
			r.values[v] = struct{}{}
			changed = true
		}
	}
	if !changed {
		return
	}
	// Longest first: a secret that contains another one is masked whole.
	vs := make([]string, 0, len(r.values))
	for v := range r.values {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return len(vs[i]) > len(vs[j]) })
	pairs := make([]string, 0, 2*len(vs))
	for _, v := range vs {
		pairs = append(pairs, v, Mask)
	}
	r.replacer = strings.NewReplacer(pairs...)
}

// String redacts registered values, then the patterns.
func (r *Redactor) String(s string) string {
	if r != nil {
		r.mu.RLock()
		rep := r.replacer
		r.mu.RUnlock()
		if rep != nil {
			s = rep.Replace(s)
		}
	}
	return String(s)
}
