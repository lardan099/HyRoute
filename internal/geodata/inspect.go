package geodata

import (
	"fmt"
	"net/netip"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Reverse lookups for the list inspector: which categories contain a name
// or an address, and what a category contains. The .dat files have
// include: already expanded, so a parent list such as
// category-ai-chat-!cn is found directly.

// SiteHit is a geosite category that matches a name.
type SiteHit struct {
	Category string `json:"category"`
	Entry    string `json:"entry"` // the matching entry: "domain:openai.com"
	Attrs    string `json:"attrs"` // attributes of that entry: "@cn @ads"
	Size     int    `json:"size"`  // entries in the category
}

// IPHit is a geoip category that contains an address.
type IPHit struct {
	Category string `json:"category"`
	Entry    string `json:"entry"` // the matching network
	Size     int    `json:"size"`
	Reverse  bool   `json:"reverse"` // reverse_match: matches everything outside
}

func entryText(typ int, val string) string {
	switch typ {
	case typePlain:
		return "keyword:" + val
	case typeRegex:
		return "regexp:" + val
	case typeFull:
		return "full:" + val
	}
	return "domain:" + val
}

// matchEntry tests one geosite entry against a normalized name.
func matchEntry(typ int, val, name string, re func(string) bool) bool {
	switch typ {
	case typeFull:
		return name == val
	case typeDomain:
		return name == val || strings.HasSuffix(name, "."+val)
	case typePlain:
		return val != "" && strings.Contains(name, val)
	case typeRegex:
		return re != nil && re(name)
	}
	return false
}

// spans returns the current index of a database and its categories
// sorted by name.
func (db *DB) spans(k Kind) (string, []string, *dbFile, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	f, err := db.file(k)
	if err != nil {
		return "", nil, nil, err
	}
	names := make([]string, 0, len(f.index))
	for n := range f.index {
		names = append(names, n)
	}
	sort.Strings(names)
	return db.path(k), names, f, nil
}

// parallel runs fn for every category on all CPUs.
func parallel(names []string, fn func(name string)) {
	work := make(chan string)
	var wg sync.WaitGroup
	for range max(1, runtime.NumCPU()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range work {
				fn(n)
			}
		}()
	}
	for _, n := range names {
		work <- n
	}
	close(work)
	wg.Wait()
}

// FindSite lists every geosite category containing name (normalized:
// lower case, no trailing dot).
func (db *DB) FindSite(name string) ([]SiteHit, error) {
	path, names, f, err := db.spans(Site)
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	var hits []SiteHit
	var firstErr error
	parallel(names, func(cat string) {
		b, err := readSpan(path, f.index[cat])
		if err == nil {
			var hit *SiteHit
			hit, err = scanSite(b, name)
			if hit != nil {
				hit.Category = cat
				mu.Lock()
				hits = append(hits, *hit)
				mu.Unlock()
			}
		}
		if err != nil {
			mu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
		}
	})
	sort.Slice(hits, func(i, j int) bool { return hits[i].Category < hits[j].Category })
	return hits, firstErr
}

func scanSite(b []byte, name string) (*SiteHit, error) {
	var hit *SiteHit
	n := 0
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
		n++
		if hit != nil {
			continue // keep counting
		}
		typ, val, attrs, err := decodeDomain(raw)
		if err != nil {
			return nil, err
		}
		val = normValue(typ, val)
		var re func(string) bool
		if typ == typeRegex {
			re = compileLoose(val)
		}
		if matchEntry(typ, val, name, re) {
			hit = &SiteHit{Entry: entryText(typ, val)}
			for _, a := range attrs {
				hit.Attrs = strings.TrimSpace(hit.Attrs + " @" + a)
			}
		}
	}
	if hit != nil {
		hit.Size = n
	}
	return hit, nil
}

// FindIP lists every geoip category containing ip.
func (db *DB) FindIP(ip netip.Addr) ([]IPHit, error) {
	ip = ip.Unmap()
	path, names, f, err := db.spans(IP)
	if err != nil {
		if err == ErrNoData && Private.Contains(ip) {
			return []IPHit{{Category: "private", Entry: "встроенный список", Size: Private.Len()}}, nil
		}
		return nil, err
	}
	var mu sync.Mutex
	var hits []IPHit
	parallel(names, func(cat string) {
		b, err := readSpan(path, f.index[cat])
		if err != nil {
			return
		}
		if h := scanIP(b, ip); h != nil {
			h.Category = cat
			mu.Lock()
			hits = append(hits, *h)
			mu.Unlock()
		}
	})
	if _, ok := f.index["private"]; !ok && Private.Contains(ip) {
		hits = append(hits, IPHit{Category: "private", Entry: "встроенный список", Size: Private.Len()})
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Category < hits[j].Category })
	return hits, nil
}

func scanIP(b []byte, ip netip.Addr) *IPHit {
	var match netip.Prefix
	n := 0
	reverse := false
	p := pb{b}
	for !p.done() {
		num, wire, err := p.field()
		if err != nil {
			return nil
		}
		switch {
		case num == 2 && wire == 2:
			raw, err := p.bytes()
			if err != nil {
				return nil
			}
			n++
			if !match.IsValid() {
				if pfx, ok := decodeCIDR(raw); ok && pfx.Contains(ip) {
					match = pfx
				}
			}
		case num == 3 && wire == 0:
			v, err := p.varint()
			if err != nil {
				return nil
			}
			reverse = v != 0
		default:
			if p.skip(wire) != nil {
				return nil
			}
		}
	}
	if match.IsValid() == reverse {
		return nil
	}
	h := &IPHit{Size: n, Reverse: reverse, Entry: match.String()}
	if reverse {
		h.Entry = "всё, кроме списка"
	}
	return h
}

// Listing is a page of a category's entries.
type Listing struct {
	Category string   `json:"category"`
	Kind     string   `json:"kind"` // site | ip
	Total    int      `json:"total"`
	Matched  int      `json:"matched"` // entries passing the filter
	Entries  []string `json:"entries"`
}

type listCache struct {
	key     string
	entries []string
}

var lastList struct {
	sync.Mutex
	listCache
}

// List returns entries of a category ("domain:x", "full:x", "keyword:x",
// "regexp:x" with " @attr" suffixes, or networks for geoip), filtered by a
// substring, from offset. The last category listed is kept in memory for
// paging.
func (db *DB) List(k Kind, name, filter string, offset, limit int) (Listing, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	out := Listing{Category: name, Kind: "site"}
	if k == IP {
		out.Kind = "ip"
	}
	path, _, f, err := db.spans(k)
	var entries []string
	var idx map[string]span
	var gen uint64
	if err != nil {
		if !(k == IP && name == "private" && err == ErrNoData) {
			return out, err
		}
	} else {
		idx, gen = f.index, f.gen
	}
	// A new, replaced or rolled back file (or Forget) gets a new
	// generation, so the list is never shown from the old one.
	key := fmt.Sprintf("%d|%s|%s", gen, out.Kind, name)
	lastList.Lock()
	if lastList.key == key {
		entries = lastList.entries
	}
	lastList.Unlock()
	if entries == nil {
		sp, ok := idx[name]
		switch {
		case !ok && k == IP && name == "private":
			entries = privateList
		case !ok:
			return out, &UnknownError{Kind: k, Name: name, Similar: similar(idx, name)}
		default:
			b, err := readSpan(path, sp)
			if err != nil {
				return out, err
			}
			if entries, err = listEntries(k, b); err != nil {
				return out, err
			}
		}
		lastList.Lock()
		lastList.key, lastList.entries = key, entries
		lastList.Unlock()
	}
	out.Total = len(entries)
	filter = strings.ToLower(strings.TrimSpace(filter))
	if limit <= 0 {
		limit = 500
	}
	for _, e := range entries {
		if filter != "" && !strings.Contains(strings.ToLower(e), filter) {
			continue
		}
		if out.Matched >= offset && len(out.Entries) < limit {
			out.Entries = append(out.Entries, e)
		}
		out.Matched++
	}
	if out.Entries == nil {
		out.Entries = []string{}
	}
	return out, nil
}

var privateList = func() []string {
	var out []string
	for _, r := range Private.v4 {
		out = append(out, netip.AddrFrom4([4]byte{byte(r.lo >> 24), byte(r.lo >> 16), byte(r.lo >> 8), byte(r.lo)}).String()+" …")
	}
	return out
}()

func listEntries(k Kind, b []byte) ([]string, error) {
	var out []string
	p := pb{b}
	for !p.done() {
		num, wire, err := p.field()
		if err != nil {
			return nil, err
		}
		if num == 3 && wire == 0 && k == IP {
			if v, _ := p.varint(); v != 0 {
				out = append([]string{"# reverse_match: список совпадает со всем, что НЕ ниже"}, out...)
			}
			continue
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
		if k == IP {
			if pfx, ok := decodeCIDR(raw); ok {
				out = append(out, pfx.String())
			}
			continue
		}
		typ, val, attrs, err := decodeDomain(raw)
		if err != nil {
			return nil, err
		}
		s := entryText(typ, normValue(typ, val))
		for _, a := range attrs {
			s += " @" + a
		}
		out = append(out, s)
	}
	return out, nil
}

// Expand returns the plain names of a category for conversion to other
// formats: domain: and full: entries; keyword: and regexp: entries cannot
// be listed and are counted in skipped.
func (db *DB) Expand(name string) (domains []string, skipped int, err error) {
	name = strings.ToLower(strings.TrimSpace(name))
	cat, attr, _ := strings.Cut(name, "@")
	path, _, f, err := db.spans(Site)
	if err != nil {
		return nil, 0, err
	}
	sp, ok := f.index[cat]
	if !ok {
		return nil, 0, &UnknownError{Kind: Site, Name: cat, Similar: similar(f.index, cat)}
	}
	b, err := readSpan(path, sp)
	if err != nil {
		return nil, 0, err
	}
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
		if attr != "" && !containsStr(attrs, attr) {
			continue
		}
		switch typ {
		case typeDomain, typeFull:
			domains = append(domains, strings.ToLower(strings.Trim(val, ".")))
		default:
			skipped++
		}
	}
	return domains, skipped, nil
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// compileLoose compiles a regexp entry once; invalid ones never match.
var reCache sync.Map // string -> *regexp.Regexp (nil when invalid)

func compileLoose(expr string) func(string) bool {
	v, ok := reCache.Load(expr)
	if !ok {
		re, err := compileRegex(expr)
		if err != nil {
			re = nil
		}
		v, _ = reCache.LoadOrStore(expr, re)
	}
	re := v.(*regexp.Regexp)
	if re == nil {
		return nil
	}
	return re.MatchString
}
