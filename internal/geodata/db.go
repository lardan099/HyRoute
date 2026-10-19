package geodata

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Kind is a database file.
type Kind int

const (
	Site Kind = iota // geosite.dat
	IP               // geoip.dat
)

func (k Kind) File() string {
	if k == IP {
		return "geoip.dat"
	}
	return "geosite.dat"
}

func (k Kind) Prefix() string {
	if k == IP {
		return "geoip"
	}
	return "geosite"
}

// ErrNoData: the database file has not been downloaded yet.
var ErrNoData = errors.New("база ещё не скачана")

// UnknownError is a category that is not in the database.
type UnknownError struct {
	Kind    Kind
	Name    string
	Similar []string
}

func (e *UnknownError) Error() string {
	s := fmt.Sprintf("категории %s:%s нет в выбранной базе", e.Kind.Prefix(), e.Name)
	kind := "site"
	if e.Kind == IP {
		kind = "ip"
	}
	if in, ok := onlyIn[kind+":"+e.Name]; ok {
		var names []string
		for _, id := range in {
			if src, ok := FindSource(id); ok {
				names = append(names, src.Short)
			}
		}
		return s + ", она есть в базе " + strings.Join(names, " и ") + " (Настройки → Базы правил)"
	}
	if len(e.Similar) > 0 {
		s += " (похожие: " + strings.Join(e.Similar, ", ") + ")"
	}
	return s
}

// DB serves categories from Dir/geosite.dat and Dir/geoip.dat. Decoded
// categories are cached until the file changes.
type DB struct {
	Dir string

	mu    sync.Mutex
	files [2]*dbFile
}

type dbFile struct {
	gen   uint64 // unique per index built: keys caches outside the DB
	mod   time.Time
	size  int64
	index map[string]span
	sites map[string]*DomainSet
	ips   map[string]*IPSet
	// noAttrs: "category@attr" names no entry matches, so a rule with a
	// typo does not decode the category again on every compile.
	noAttrs map[string]error
}

var fileGen atomic.Uint64

func (db *DB) path(k Kind) string { return filepath.Join(db.Dir, k.File()) }

// Missing reports a database file that is not there or empty (deleted by
// the user, an antivirus or a disk error), whatever geo.json says.
func (db *DB) Missing(k Kind) bool {
	fi, err := os.Stat(db.path(k))
	return err != nil || !fi.Mode().IsRegular() || fi.Size() == 0
}

// file returns the current index, rebuilding it when the file changed.
// db.mu must be held.
func (db *DB) file(k Kind) (*dbFile, error) {
	fi, err := os.Stat(db.path(k))
	if errors.Is(err, os.ErrNotExist) {
		db.files[k] = nil
		return nil, ErrNoData
	}
	if err != nil {
		return nil, err
	}
	if f := db.files[k]; f != nil && f.mod.Equal(fi.ModTime()) && f.size == fi.Size() {
		return f, nil
	}
	idx, err := buildIndex(db.path(k))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", k.File(), err)
	}
	f := &dbFile{gen: fileGen.Add(1), mod: fi.ModTime(), size: fi.Size(), index: idx, sites: map[string]*DomainSet{}, ips: map[string]*IPSet{}, noAttrs: map[string]error{}}
	db.files[k] = f
	return f, nil
}

// Forget drops cached data (after a file was replaced within the same
// modification time granularity).
func (db *DB) Forget() {
	db.mu.Lock()
	db.files = [2]*dbFile{}
	db.mu.Unlock()
}

// Site returns a geosite category: "youtube" or "google@cn" (only entries
// with the attribute; "google@cn@ads": with both).
func (db *DB) Site(name string) (*DomainSet, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	cat, attrs := splitAttrs(name)
	db.mu.Lock()
	defer db.mu.Unlock()
	f, err := db.file(Site)
	if err != nil {
		return nil, err
	}
	if d, ok := f.sites[name]; ok {
		return d, nil
	}
	if err, ok := f.noAttrs[name]; ok {
		return nil, err
	}
	sp, ok := f.index[cat]
	if !ok {
		return nil, &UnknownError{Kind: Site, Name: cat, Similar: similar(f.index, cat)}
	}
	b, err := readSpan(db.path(Site), sp)
	if err != nil {
		return nil, err
	}
	d, total, err := decodeSite(b, attrs)
	if err != nil {
		return nil, fmt.Errorf("geosite:%s: %w", cat, err)
	}
	if d.Len() == 0 && total > 0 && len(attrs) > 0 {
		f.noAttrs[name] = attrsError(cat, attrs)
		return nil, f.noAttrs[name]
	}
	f.sites[name] = d
	return d, nil
}

// Retain keeps in memory only the decoded categories named (without the
// "geosite:"/"geoip:" prefix): those the rules in use need. Others, e.g.
// tried in the rule editor and removed, are decoded again when asked for.
func (db *DB) Retain(k Kind, names []string) {
	keep := map[string]bool{}
	for _, n := range names {
		keep[strings.ToLower(strings.TrimSpace(n))] = true
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	f := db.files[k]
	if f == nil {
		return
	}
	for n := range f.sites {
		if !keep[n] {
			delete(f.sites, n)
		}
	}
	for n := range f.ips {
		if !keep[n] {
			delete(f.ips, n)
		}
	}
}

// IP returns a geoip category. "private" works without a database.
func (db *DB) IP(name string) (*IPSet, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	db.mu.Lock()
	defer db.mu.Unlock()
	f, err := db.file(IP)
	if err != nil {
		if name == "private" {
			return Private, nil
		}
		return nil, err
	}
	if s, ok := f.ips[name]; ok {
		return s, nil
	}
	sp, ok := f.index[name]
	if !ok {
		if name == "private" {
			return Private, nil
		}
		return nil, &UnknownError{Kind: IP, Name: name, Similar: similar(f.index, name)}
	}
	b, err := readSpan(db.path(IP), sp)
	if err != nil {
		return nil, err
	}
	s, err := decodeIP(b)
	if err != nil {
		return nil, fmt.Errorf("geoip:%s: %w", name, err)
	}
	f.ips[name] = s
	return s, nil
}

// Has reports whether a downloaded database has a category ("private"
// always counts for geoip). ok is false when the file is not downloaded.
func (db *DB) Has(k Kind, name string) (has, ok bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	cat, _ := splitAttrs(name)
	db.mu.Lock()
	defer db.mu.Unlock()
	f, err := db.file(k)
	if err != nil {
		return false, false
	}
	_, has = f.index[cat]
	return has || (k == IP && cat == "private"), true
}

// Names lists the categories of a database (sorted).
func (db *DB) Names(k Kind) ([]string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	f, err := db.file(k)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(f.index))
	for n := range f.index {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// Check validates a file (e.g. a fresh download) and returns its number
// of categories.
func Check(path string) (int, error) {
	idx, err := buildIndex(path)
	return len(idx), err
}

// similar suggests up to three category names for a typo.
func similar(idx map[string]span, name string) []string {
	var out []string
	for n := range idx {
		if strings.Contains(n, name) || (len(n) >= 3 && strings.Contains(name, n)) || editDistance(n, name) <= 2 {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		di, dj := editDistance(out[i], name), editDistance(out[j], name)
		if di != dj {
			return di < dj
		}
		return out[i] < out[j]
	})
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

func editDistance(a, b string) int {
	if len(a) > 40 || len(b) > 40 {
		return 99
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			c := prev[j-1]
			if a[i-1] != b[j-1] {
				c++
			}
			cur[j] = min(c, prev[j]+1, cur[j-1]+1)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
