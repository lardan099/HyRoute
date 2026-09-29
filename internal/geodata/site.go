package geodata

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Domain types of v2ray's routercommon.Domain.
const (
	typePlain  = 0 // keyword: substring
	typeRegex  = 1
	typeDomain = 2 // the domain and its subdomains
	typeFull   = 3 // exactly this name
)

// DomainSet is one geosite category.
type DomainSet struct {
	full    []string // sorted
	suffix  []string // sorted
	keyword []string
	regex   []*regexp.Regexp
}

// Len is the number of entries.
func (d *DomainSet) Len() int {
	return len(d.full) + len(d.suffix) + len(d.keyword) + len(d.regex)
}

// Match reports whether a normalized (lower-case, no trailing dot) name is
// in the category.
func (d *DomainSet) Match(name string) bool {
	if name == "" {
		return false
	}
	if has(d.full, name) {
		return true
	}
	for s := name; ; {
		if has(d.suffix, s) {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	for _, k := range d.keyword {
		if strings.Contains(name, k) {
			return true
		}
	}
	for _, re := range d.regex {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func has(sorted []string, s string) bool {
	_, ok := slices.BinarySearch(sorted, s)
	return ok
}

// splitAttrs splits "google@cn@ads" into the category and the attributes
// an entry must all have, as in v2ray/Xray.
func splitAttrs(name string) (string, []string) {
	cat, rest, _ := strings.Cut(name, "@")
	var attrs []string
	for _, a := range strings.Split(rest, "@") {
		if a = strings.TrimSpace(a); a != "" {
			attrs = append(attrs, a)
		}
	}
	return strings.TrimSpace(cat), attrs
}

// hasAttrs reports whether an entry has every attribute of want.
func hasAttrs(attrs, want []string) bool {
	for _, a := range want {
		if !slices.Contains(attrs, a) {
			return false
		}
	}
	return true
}

// attrsError: no entry of a category has the attributes asked for (a typo,
// or attributes the list does not use), so the item would never match.
func attrsError(cat string, attrs []string) error {
	if len(attrs) == 1 {
		return fmt.Errorf("в geosite:%s нет записей с атрибутом @%s", cat, attrs[0])
	}
	return fmt.Errorf("в geosite:%s нет записей со всеми атрибутами @%s", cat, strings.Join(attrs, " @"))
}

// decodeSite decodes a GeoSite message. attrs keeps only entries with all
// of these attributes ("google@cn"); none keeps everything. total counts
// the entries before the filter.
func decodeSite(b []byte, want []string) (_ *DomainSet, total int, err error) {
	defer recoverDecode(&err)
	d := &DomainSet{}
	p := pb{b}
	for !p.done() {
		num, wire, err := p.field()
		if err != nil {
			return nil, 0, err
		}
		if num != 2 || wire != 2 {
			if err := p.skip(wire); err != nil {
				return nil, 0, err
			}
			continue
		}
		raw, err := p.bytes()
		if err != nil {
			return nil, 0, err
		}
		typ, val, attrs, err := decodeDomain(raw)
		if err != nil {
			return nil, 0, err
		}
		total++
		if !hasAttrs(attrs, want) {
			continue
		}
		val = normValue(typ, val)
		switch typ {
		case typeFull:
			d.full = append(d.full, strings.TrimSuffix(val, "."))
		case typeDomain:
			d.suffix = append(d.suffix, strings.Trim(val, "."))
		case typePlain:
			if val != "" {
				d.keyword = append(d.keyword, val)
			}
		case typeRegex:
			if re, err := compileRegex(val); err == nil {
				d.regex = append(d.regex, re)
			}
		}
	}
	slices.Sort(d.full)
	d.full = slices.Compact(d.full)
	slices.Sort(d.suffix)
	d.suffix = slices.Compact(d.suffix)
	return d, total, nil
}

// normValue lower-cases an entry for matching against normalized names.
// A regexp keeps its case, as in v2ray/Xray: \S, \D, \W, \B mean the
// opposite of \s, \d, \w, \b, and \P, \Q, (?U) do not compile in lower
// case.
func normValue(typ int, val string) string {
	if typ == typeRegex {
		return val
	}
	return strings.ToLower(val)
}

// compileRegex compiles a regexp entry. Names are lower case, so the
// pattern ignores case instead of being lower-cased (see normValue).
func compileRegex(expr string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + expr)
}

func decodeDomain(b []byte) (typ int, val string, attrs []string, err error) {
	p := pb{b}
	for !p.done() {
		num, wire, err := p.field()
		if err != nil {
			return 0, "", nil, err
		}
		switch {
		case num == 1 && wire == 0:
			v, err := p.varint()
			if err != nil {
				return 0, "", nil, err
			}
			typ = int(v)
		case num == 2 && wire == 2:
			v, err := p.bytes()
			if err != nil {
				return 0, "", nil, err
			}
			val = string(v)
		case num == 3 && wire == 2:
			a, err := p.bytes()
			if err != nil {
				return 0, "", nil, err
			}
			if k, err := entryCode(a); err == nil {
				attrs = append(attrs, strings.ToLower(k))
			}
		default:
			if err := p.skip(wire); err != nil {
				return 0, "", nil, err
			}
		}
	}
	return typ, val, attrs, nil
}

// MatchUnder reports whether the category may hold a name below dom (a
// subdomain of it), or dom itself when self is set: for telling whether a
// rule ".dom" or "*.dom" overlaps the category. A keyword or regexp entry
// counts as holding one.
func (d *DomainSet) MatchUnder(dom string, self bool) bool {
	if dom == "" {
		return false
	}
	if len(d.keyword) > 0 || len(d.regex) > 0 {
		return true
	}
	if self && has(d.full, dom) {
		return true
	}
	for s := dom; ; { // a suffix entry at dom or above it
		if has(d.suffix, s) {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	tail := "." + dom
	for _, l := range [][]string{d.full, d.suffix} {
		for _, e := range l {
			if strings.HasSuffix(e, tail) {
				return true
			}
		}
	}
	return false
}
