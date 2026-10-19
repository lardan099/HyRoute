package redact

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// publicSites are the sites of public services texts may name (releases,
// certificates, public DNS): they identify nobody.
var publicSites = map[string]bool{
	"github.com": true, "githubusercontent.com": true, "golang.org": true, "go.dev": true,
	"hysteria.network": true, "hy2.io": true, "hy2.sh": true, "letsencrypt.org": true, "zerossl.com": true,
	"cloudflare-dns.com": true, "dns.google": true, "quad9.net": true,
}

// fold lower-cases the letters whose lower case is as long in UTF-8.
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		if l := unicode.ToLower(r); utf8.RuneLen(l) == utf8.RuneLen(r) {
			return l
		}
		return r
	}, s)
}

// IsDomain reports a host name under a public suffix (an ICANN one or a
// dynamic DNS zone like duckdns.org), not a file name (config.yaml) or
// the suffix itself.
func IsDomain(name string) bool {
	a, err := idna.ToASCII(fold(name))
	if err != nil {
		return false
	}
	suffix, icann := publicsuffix.PublicSuffix(a)
	return (icann || strings.Contains(suffix, ".")) && suffix != a
}

// PublicName reports a name of a public service (see publicSites).
func PublicName(name string) bool {
	a, err := idna.ToASCII(fold(strings.TrimSuffix(name, ".")))
	if err != nil {
		return false
	}
	site, err := publicsuffix.EffectiveTLDPlusOne(a)
	return err == nil && publicSites[site]
}

var (
	// domainRe finds what may be a host name; IsDomain decides.
	domainRe = regexp.MustCompile(`(?:[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?\.)+\p{L}(?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?`)
	// fingerprintRe: a key fingerprint (an SSH host key, a certificate)
	// is looked up in scan databases like an address.
	fingerprintRe = regexp.MustCompile(`\b(SHA256|SHA1|MD5):[0-9A-Za-z+/:=]{16,}`)
	// pinRe: a certificate pin in hex.
	pinRe = regexp.MustCompile(`(?i)(pin(?:sha256)?["']?\s*[:=]\s*["']?)[0-9a-f:]{16,}`)
)

// Fingerprints masks key fingerprints and certificate pins in s.
func Fingerprints(s string) string {
	s = fingerprintRe.ReplaceAllString(s, "${1}:"+Mask)
	return pinRe.ReplaceAllString(s, "${1}"+Mask)
}

// Domains replaces the host names in s that are domains (IsDomain) and
// not public services (PublicName) with with.
func Domains(s, with string) string {
	return domainRe.ReplaceAllStringFunc(s, func(m string) string {
		if !IsDomain(m) || PublicName(m) {
			return m
		}
		return with
	})
}
