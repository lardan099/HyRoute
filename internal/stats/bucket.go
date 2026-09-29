package stats

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"
)

// maxCount is the largest value a counter holds: JavaScript numbers stay
// exact up to 2^53-1, and every add saturates there.
const maxCount = 1<<53 - 1

// Limits of a file this version reads (anything more is not ours: the file
// is refused as corrupt).
const (
	maxFileBytes = 4 << 20
	maxModeBytes = 4 << 10
	maxRows      = 20000
	maxKey       = 1024
	maxName      = 256
)

// The lists of a bucket, in File order.
const (
	listApps = iota
	listSites
	listServers
	listGroups
	nLists
)

// Row caps per list (apps, sites, servers, groups): rows over a cap are
// folded into "*" («Остальные»).
var (
	memCaps    = [nLists]int{2000, 10000, 1000, 500} // one day's unflushed delta
	dayCaps    = [nLists]int{200, 500, 300, 100}
	monthCaps  = [nLists]int{300, 1000, 300, 100}
	reportCaps = [nLists]int{1000, 1000, 1000, 1000}
)

// Others is the key of the row that holds what did not fit.
const Others = "*"

// add saturates at maxCount (both values are within [0, maxCount]).
func add(a, b int64) int64 {
	if b > maxCount-a {
		return maxCount
	}
	return a + b
}

func clamp(v int64) int64 {
	switch {
	case v < 0:
		return 0
	case v > maxCount:
		return maxCount
	}
	return v
}

// Counters are the numbers of one bucket, row or day (see designs: tc/tu/td
// tunnel connections and bytes up/down, dc/du direct attempts and bytes up,
// bc blocked, f failed, fo failovers of tunnel connections).
type Counters struct {
	TC int64 `json:"tc,omitempty"`
	TU int64 `json:"tu,omitempty"`
	TD int64 `json:"td,omitempty"`
	DC int64 `json:"dc,omitempty"`
	DU int64 `json:"du,omitempty"`
	BC int64 `json:"bc,omitempty"`
	F  int64 `json:"f,omitempty"`
	FO int64 `json:"fo,omitempty"`
}

func (c *Counters) add(o Counters) {
	c.TC, c.TU, c.TD = add(c.TC, o.TC), add(c.TU, o.TU), add(c.TD, o.TD)
	c.DC, c.DU, c.BC = add(c.DC, o.DC), add(c.DU, o.DU), add(c.BC, o.BC)
	c.F, c.FO = add(c.F, o.F), add(c.FO, o.FO)
}

func (c *Counters) clamp() {
	c.TC, c.TU, c.TD = clamp(c.TC), clamp(c.TU), clamp(c.TD)
	c.DC, c.DU, c.BC = clamp(c.DC), clamp(c.DU), clamp(c.BC)
	c.F, c.FO = clamp(c.F), clamp(c.FO)
}

func (c Counters) bytes() int64 { return add(add(c.TU, c.TD), c.DU) }
func (c Counters) conns() int64 { return add(add(add(c.TC, c.DC), c.BC), c.F) }

// Row is one program, site, server or group.
type Row struct {
	Key  string `json:"k"`
	Name string `json:"n,omitempty"`
	Counters
	Drops int64 `json:"drops,omitempty"`
	Gone  bool  `json:"gone,omitempty"` // report only: the server/group/proxy no longer exists
}

func (r *Row) add(o *Row) {
	r.Counters.add(o.Counters)
	r.Drops = add(r.Drops, o.Drops)
	if o.Name != "" {
		r.Name = o.Name // the latest name wins
	}
}

// Events are counts that belong to no connection.
type Events struct {
	Drops       int64 `json:"drops,omitempty"`
	EngineFails int64 `json:"engineFails,omitempty"`
}

func (e *Events) add(o Events) {
	e.Drops, e.EngineFails = add(e.Drops, o.Drops), add(e.EngineFails, o.EngineFails)
}

// File is the on-disk bucket (day or month).
type File struct {
	V       int       `json:"v"`
	Day     string    `json:"day,omitempty"`
	Month   string    `json:"month,omitempty"`
	Days    []string  `json:"days,omitempty"` // month: the days folded in
	Updated time.Time `json:"updated"`
	Total   Counters  `json:"total"`
	Events  Events    `json:"events"`
	Apps    []Row     `json:"apps"`
	Sites   []Row     `json:"sites"`
	Servers []Row     `json:"servers"`
	Groups  []Row     `json:"groups"`
	// Imported: the file holds its share of HyRoute 1.2.0's statistics (a
	// repeated import leaves it alone).
	Imported bool `json:"imported,omitempty"`

	// hadSites: the file as read held sites (earlier builds kept them);
	// they are dropped on reading, and the file is rewritten without them
	// (purgeSitesLocked).
	hadSites bool
}

func (f *File) list(i int) *[]Row {
	switch i {
	case listApps:
		return &f.Apps
	case listSites:
		return &f.Sites
	case listServers:
		return &f.Servers
	}
	return &f.Groups
}

func (f *File) clone() *File {
	g := *f
	g.Days = append([]string(nil), f.Days...)
	for i := range nLists {
		l := g.list(i)
		*l = append([]Row(nil), *l...)
	}
	return &g
}

// mem is one day's unflushed delta: plain maps, bounded by memCaps.
type mem struct {
	total  Counters
	events Events
	lists  [nLists]map[string]*Row
}

func newMem() *mem {
	m := &mem{}
	for i := range m.lists {
		m.lists[i] = map[string]*Row{}
	}
	return m
}

// row returns the row of key in list i, or "*" once the list is full.
func (m *mem) row(i int, key, name string) *Row {
	l := m.lists[i]
	r := l[key]
	if r == nil {
		if len(l) >= memCaps[i] {
			key, name = Others, ""
			if r = l[key]; r != nil {
				return r
			}
		}
		r = &Row{Key: key}
		l[key] = r
	}
	if name != "" {
		r.Name = name
	}
	return r
}

// merge adds o into m (the caps apply).
func (m *mem) merge(o *mem) {
	m.total.add(o.total)
	m.events.add(o.events)
	for i := range o.lists {
		for _, r := range o.lists[i] {
			m.row(i, r.Key, r.Name).add(r)
		}
	}
}

// addMem adds a delta into a file.
func (f *File) addMem(m *mem) {
	f.Total.add(m.total)
	f.Events.add(m.events)
	for i := range nLists {
		rows := make([]*Row, 0, len(m.lists[i]))
		for _, r := range m.lists[i] {
			rows = append(rows, r)
		}
		mergeRows(f.list(i), rows)
	}
}

// addFile adds o into f (totals, events, rows by key); the sum holds the
// import of 1.2.0's statistics when o does.
func (f *File) addFile(o *File) {
	f.Imported = f.Imported || o.Imported
	f.Total.add(o.Total)
	f.Events.add(o.Events)
	for i := range nLists {
		src := *o.list(i)
		rows := make([]*Row, len(src))
		for j := range src {
			rows[j] = &src[j]
		}
		mergeRows(f.list(i), rows)
	}
}

func mergeRows(dst *[]Row, src []*Row) {
	if len(src) == 0 {
		return
	}
	at := make(map[string]int, len(*dst))
	for i, r := range *dst {
		at[r.Key] = i
	}
	for _, r := range src {
		if i, ok := at[r.Key]; ok {
			(*dst)[i].add(r)
			continue
		}
		at[r.Key] = len(*dst)
		n := Row{Key: r.Key}
		n.add(r)
		*dst = append(*dst, n)
	}
}

// sortRows orders rows by bytes, then connections, then key, "*" last.
func sortRows(l []Row) {
	sort.Slice(l, func(i, j int) bool {
		a, b := &l[i], &l[j]
		if (a.Key == Others) != (b.Key == Others) {
			return b.Key == Others
		}
		if x, y := a.bytes(), b.bytes(); x != y {
			return x > y
		}
		if x, y := a.conns(), b.conns(); x != y {
			return x > y
		}
		return a.Key < b.Key
	})
}

// trimRows keeps cap-1 rows and folds the rest (and any "*") into "*".
func trimRows(l []Row, limit int) []Row {
	sortRows(l)
	if len(l) <= limit {
		return l
	}
	other := Row{Key: Others}
	for i := limit - 1; i < len(l); i++ {
		r := l[i]
		r.Name = ""
		other.add(&r)
	}
	return append(l[:limit-1:limit-1], other)
}

// trim applies the per-list caps to every list.
func (f *File) trim(caps [nLists]int) {
	for i := range nLists {
		l := f.list(i)
		*l = trimRows(*l, caps[i])
	}
}

// Errors of loading a file.
var (
	errNewer   = errors.New("written by a newer version")
	errInvalid = errors.New("invalid")
)

// parseFile reads and checks the file called name (without ".json"). A
// file of a newer format is errNewer; anything not valid is errInvalid.
func parseFile(name string, b []byte) (*File, error) {
	var head struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalid, err)
	}
	if head.V > 1 {
		return nil, errNewer
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalid, err)
	}
	if err := f.validate(name); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalid, err)
	}
	// Sites are never kept (see Mode): whatever a file holds is dropped.
	f.hadSites, f.Sites = len(f.Sites) > 0, nil
	return &f, nil
}

// validate checks a parsed file against its name and the limits, clamps
// the counters and merges rows that share a key.
func (f *File) validate(name string) error {
	if f.V != 1 {
		return fmt.Errorf("version %d", f.V)
	}
	kind, date, ok := parseName(name)
	switch {
	case !ok || kind == kindMode:
		return errors.New("bad name")
	case kind == kindDay && (f.Day != date || f.Month != "" || len(f.Days) > 0):
		return errors.New("day does not match the name")
	case kind == kindMonth && (f.Month != date || f.Day != ""):
		return errors.New("month does not match the name")
	}
	if kind == kindMonth {
		if len(f.Days) > 31 {
			return errors.New("too many days")
		}
		seen := map[string]bool{}
		for _, d := range f.Days {
			if !validDay(d) || d[:7] != date || seen[d] {
				return fmt.Errorf("day %q", d)
			}
			seen[d] = true
		}
		sort.Strings(f.Days)
	}
	f.Total.clamp()
	f.Events.Drops, f.Events.EngineFails = clamp(f.Events.Drops), clamp(f.Events.EngineFails)
	for i := range nLists {
		l := f.list(i)
		if len(*l) > maxRows {
			return errors.New("too many rows")
		}
		out := make([]Row, 0, len(*l))
		at := map[string]int{}
		for _, r := range *l {
			if len(r.Key) > maxKey || len(r.Name) > maxName || !utf8.ValidString(r.Key) || !utf8.ValidString(r.Name) {
				return errors.New("row key or name too long")
			}
			r.Counters.clamp()
			r.Drops = clamp(r.Drops)
			if i != listServers {
				r.Drops = 0
			}
			r.Gone = false
			if j, ok := at[r.Key]; ok {
				out[j].add(&r)
				continue
			}
			at[r.Key] = len(out)
			out = append(out, r)
		}
		*l = out
	}
	return nil
}

// marshal is the file's JSON (lists never null, sites always empty).
func (f *File) marshal() ([]byte, error) {
	f.Sites = nil
	for i := range nLists {
		if l := f.list(i); *l == nil {
			*l = []Row{}
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
