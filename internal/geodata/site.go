package geodata

import (
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

// decodeSite decodes a GeoSite message. attr keeps only entries with that
// attribute ("google@cn"); "" keeps everything.
func decodeSite(b []byte, attr string) (_ *DomainSet, err error) {
	defer recoverDecode(&err)
	d := &DomainSet{}
	p := pb{b}
	for !p.done() {
		num, wire, err := p.field()
		if err != nil {
			return nil, err
		}
		if num != 2 || wire != 2 {
			if err := p.skip(wire); err != nil {
				return nil, err
			}
			continue
		}
		raw, err := p.bytes()
		if err != nil {
			return nil, err
		}
		typ, val, attrs, err := decodeDomain(raw)
		if err != nil {
			return nil, err
		}
		if attr != "" && !slices.Contains(attrs, attr) {
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
	return d, nil
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
