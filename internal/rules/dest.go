package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync/atomic"
	"unicode"
)

// Destinations of a rule ("domains" in the JSON) are sites and addresses:
//
//	example.com / .example.com / *.example.com   see parseDomainPattern
//	full:example.com                              only this name
//	domain:example.com                            the name and subdomains
//	keyword:google                                names containing the word
//	regexp:^ad[0-9]+\.                            names matching (RE2)
//	geosite:youtube, geosite:google@cn            a category of geosite.dat
//	1.2.3.4, 10.0.0.0/8, 2001:db8::/32            addresses
//	geoip:ru, geoip:private                       a category of geoip.dat

// DomainMatcher is a geosite category.
type DomainMatcher interface{ Match(name string) bool }

// IPMatcher is a geoip category.
type IPMatcher interface{ Contains(ip netip.Addr) bool }

// Geo resolves geosite:/geoip: categories.
type Geo interface {
	Site(name string) (DomainMatcher, error)
	IP(name string) (IPMatcher, error)
}

type geoBox struct{ g Geo }

var geo atomic.Pointer[geoBox]

// SetGeo installs the category resolver used by Compile. Rules compiled
// before keep the data they were compiled with; recompile after an update.
func SetGeo(g Geo) { geo.Store(&geoBox{g}) }

// ErrGeoNoData is returned by a Geo whose database is not downloaded yet.
var ErrGeoNoData = errors.New("база правил ещё не скачана")

func currentGeo() Geo {
	if b := geo.Load(); b != nil {
		return b.g
	}
	return nil
}

// IsAddressItem reports whether a destination item is an address rather
// than a name: an IP, a CIDR or geoip:.
func IsAddressItem(s string) bool {
	s = strings.TrimSpace(s)
	if hasPrefixFold(s, "geoip:") {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}

// IsSpecialItem reports whether a destination item has a type prefix
// (geosite:, keyword:, …) or is an address: written as is in rules text.
func IsSpecialItem(s string) bool {
	if IsAddressItem(s) {
		return true
	}
	for _, p := range []string{"geosite:", "keyword:", "regexp:", "full:", "domain:"} {
		if hasPrefixFold(s, p) {
			return true
		}
	}
	return false
}

func hasPrefixFold(s, p string) bool {
	return len(s) >= len(p) && strings.EqualFold(s[:len(p)], p)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

type ipPat struct {
	pfx netip.Prefix // valid for a literal address or network
	geo IPMatcher    // geoip:; nil when missing
	src string
	// pending: a geoip: category unusable only because the database is
	// not downloaded yet (conn-rules: it may match once it is).
	pending bool
}

func (p *ipPat) match(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if p.pfx.IsValid() {
		return p.pfx.Contains(ip)
	}
	return p.geo != nil && p.geo.Contains(ip)
}

func (p *ipPat) descr() string {
	if p.pfx.IsValid() {
		if p.pfx.IsSingleIP() {
			return "адрес " + p.pfx.Addr().String()
		}
		return "сеть " + p.pfx.String()
	}
	return "адреса из базы " + p.src
}

func (p *ipPat) covers(b *ipPat) bool {
	if p.pfx.IsValid() && b.pfx.IsValid() {
		return p.pfx.Bits() <= b.pfx.Bits() && p.pfx.Contains(b.pfx.Addr())
	}
	return !p.pfx.IsValid() && !b.pfx.IsValid() && strings.EqualFold(p.src, b.src)
}

// parseIPPattern parses an address item; warn is set when a geoip
// category cannot be used (it then matches nothing).
func parseIPPattern(s string, g Geo) (p ipPat, warn string, err error) {
	s = strings.TrimSpace(s)
	p.src = s
	if hasPrefixFold(s, "geoip:") {
		name := strings.ToLower(strings.TrimSpace(s[len("geoip:"):]))
		if name == "" {
			return p, "", errors.New("после geoip: укажите категорию, например geoip:ru")
		}
		p.src = "geoip:" + name
		if g == nil {
			p.pending = true
			return p, geoWarn(p.src, ErrGeoNoData), nil
		}
		m, gerr := g.IP(name)
		if gerr != nil {
			p.pending = errors.Is(gerr, ErrGeoNoData)
			return p, geoWarn(p.src, gerr), nil
		}
		p.geo = m
		return p, "", nil
	}
	if pfx, perr := netip.ParsePrefix(s); perr == nil {
		p.pfx = pfx.Masked()
		if pfx.Addr().Is4In6() {
			p.pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96).Masked()
		}
		return p, "", nil
	}
	a, perr := netip.ParseAddr(strings.Trim(s, "[]"))
	if perr != nil {
		return p, "", fmt.Errorf("неверный адрес %q", s)
	}
	a = a.Unmap()
	p.pfx = netip.PrefixFrom(a, a.BitLen())
	return p, "", nil
}

func geoWarn(src string, err error) string {
	if errors.Is(err, ErrGeoNoData) {
		return src + ": база правил ещё не скачана, пока не срабатывает (Настройки → Базы правил)"
	}
	return src + ": " + err.Error() + ", пока не срабатывает"
}

// parseTypedDomain handles geosite:, keyword:, regexp:, full:, domain:.
// ok is false for a plain pattern.
func parseTypedDomain(s string, g Geo) (d domPat, warn string, ok bool, err error) {
	s = strings.TrimSpace(s)
	pfx, rest, found := strings.Cut(s, ":")
	if !found {
		return d, "", false, nil
	}
	rest = strings.TrimSpace(rest)
	switch strings.ToLower(pfx) {
	case "geosite":
		name := strings.ToLower(rest)
		d = domPat{kind: domGeo, dom: name, src: "geosite:" + name}
		if name == "" {
			return d, "", true, errors.New("после geosite: укажите категорию, например geosite:youtube")
		}
		if g == nil {
			d.pending = true
			return d, geoWarn(d.src, ErrGeoNoData), true, nil
		}
		m, gerr := g.Site(name)
		if gerr != nil {
			d.pending = errors.Is(gerr, ErrGeoNoData)
			return d, geoWarn(d.src, gerr), true, nil
		}
		d.geo = m
		return d, "", true, nil
	case "keyword":
		if rest == "" {
			return d, "", true, errors.New("после keyword: укажите слово")
		}
		w := strings.ToLower(rest)
		return domPat{kind: domKeyword, dom: w, src: "keyword:" + w, uni: !isASCII(w)}, "", true, nil
	case "regexp":
		// Names are matched in lower case: (?i), as geosite's regexps, so
		// that "regexp:YouTube" matches youtube.com.
		re, rerr := regexp.Compile("(?i)" + rest)
		if rerr != nil || rest == "" {
			return d, "", true, fmt.Errorf("неверное регулярное выражение %q", rest)
		}
		return domPat{kind: domRegex, dom: rest, re: re, src: "regexp:" + rest, uni: !isASCII(rest)}, "", true, nil
	case "full", "domain":
		n := NormalizeDomain(rest)
		if n == "" || strings.ContainsAny(n, "*/ :") {
			return d, "", true, fmt.Errorf("неверный домен %q", s)
		}
		k := domExact
		if strings.EqualFold(pfx, "domain") {
			k = domSuffix
		}
		return domPat{kind: k, dom: n, src: s}, "", true, nil
	}
	return d, "", false, nil
}

// SiteProblem says why a site item can never match: a character that no
// site name has («youtube.com», (a.com), a.com!) or an empty part
// (..a.com, a..com, domain:.a.com). It is "" for a good name and for
// other items (addresses, geosite:, keyword:, regexp:); characters that
// Compile refuses are left to its error.
func SiteProblem(item string) string {
	s := strings.TrimSpace(item)
	if IsAddressItem(s) {
		return ""
	}
	if pfx, rest, typed := strings.Cut(s, ":"); typed {
		if !strings.EqualFold(pfx, "full") && !strings.EqualFold(pfx, "domain") {
			return ""
		}
		s = strings.TrimSpace(rest)
	} else if strings.HasPrefix(s, "*.") {
		s = s[2:]
	} else if strings.HasPrefix(s, ".") {
		s = s[1:]
	}
	if s == "" || strings.ContainsAny(s, "*/ :") {
		return ""
	}
	if strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return fmt.Sprintf("«%s»: в имени сайта пустая часть (лишняя точка), такое правило не сработает", item)
	}
	for _, c := range s {
		// Letters of any script (IDN), digits, "-", "_", the dots IDNA
		// maps to "." and the joiners and dots IDNA allows by context
		// (col·legi.cat): ZWNJ, ZWJ, U+00B7, U+0375, U+05F3, U+05F4, U+30FB.
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && !unicode.IsMark(c) &&
			!strings.ContainsRune("-_.。．｡\u200c\u200d\u00b7\u0375\u05f3\u05f4\u30fb", c) {
			return fmt.Sprintf("«%s»: в имени сайта не бывает символа «%c», такое правило не сработает (кавычки и скобки уберите)", item, c)
		}
	}
	return ""
}
