package rules

import (
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// One notion of "site" for everything that groups names: Registrable for
// a «Весь сайт» rule made from a connection and the DNS suffixes, Site for
// the sticky key of server groups (internal/groups/runtime.go). Statistics
// never keep sites.

// Registrable is the registrable domain of name ("www.bbc.co.uk" ->
// "bbc.co.uk", "u.github.io" -> "u.github.io"). ok is false for names
// HostName refuses (IP literals, the short IPv4 forms like "1.2.3", "bad
// name.com"), single-label names and names that are a public suffix
// themselves ("github.io", "co.uk"): a "whole site" rule on them would
// cover unrelated sites.
func Registrable(name string) (site string, ok bool) {
	n, ok := HostName(name)
	if !ok {
		return "", false
	}
	s, err := publicsuffix.EffectiveTLDPlusOne(n)
	if err != nil {
		return "", false
	}
	return s, true
}

// Site is Registrable, or the normalized name itself when !ok (the sticky
// key of groups); "" for "".
func Site(name string) string {
	if s, ok := Registrable(name); ok {
		return s
	}
	return NormalizeDomain(name)
}

// HostName normalizes name (NormalizeDomain) and reports whether it is a
// usable DNS host name: not an IP literal, total length ≤ 253, every label
// 1–63 bytes of [a-z0-9_-], and the last label not all digits (a TLD never
// is, RFC 3696 §2; Windows reads "1.2.3" or "01.02.03.04" as an IPv4
// address).
func HostName(name string) (string, bool) {
	n := NormalizeDomain(name)
	if n == "" || len(n) > 253 || isIPLiteral(n) {
		return "", false
	}
	labels := strings.Split(n, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return "", false
		}
		for i := 0; i < len(l); i++ {
			switch c := l[i]; {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return "", false
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", false
	}
	return n, true
}

// isIPLiteral: an IPv4 or IPv6 address, also in brackets or with a zone.
func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"))
	return err == nil
}
