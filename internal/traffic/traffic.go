// Package traffic keeps the statistics of VPN traffic across runs: bytes
// per server and per program, by day (and by hour for the last two days).
// Only tunneled traffic is counted. Sites and addresses are never recorded:
// there is no history of what was visited, only how much went through the
// VPN and by which program.
package traffic

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Retention: days of totals per server, days of totals per program, hours
// of the hourly series.
const (
	keepDays    = 400
	keepAppDays = 92
	keepHours   = 48
)

// Pair is bytes sent to and received from the internet.
type Pair struct {
	Sent int64 `json:"sent"`
	Recv int64 `json:"recv"`
}

func (p *Pair) add(sent, recv int64) {
	p.Sent += sent
	p.Recv += recv
}

// Total is Sent + Recv.
func (p Pair) Total() int64 { return p.Sent + p.Recv }

type day struct {
	Servers map[string]*Pair `json:"servers"`
	Apps    map[string]*Pair `json:"apps,omitempty"`
}

type file struct {
	Version int                         `json:"version"`
	Days    map[string]*day             `json:"days"`  // "2006-01-02", local time
	Hours   map[string]map[string]*Pair `json:"hours"` // "2006-01-02T15" -> server -> bytes
	// Names: the last known name of each server ID, so that a deleted
	// server still reads as a name.
	Names map[string]string `json:"names"`
}

// Stats is safe for concurrent use.
type Stats struct {
	path string
	now  func() time.Time

	mu    sync.Mutex
	f     file
	dirty bool
}

// Open loads path (a missing or unreadable file starts empty: statistics
// are not worth refusing to start over). "" keeps them in memory only.
func Open(path string) *Stats {
	s := &Stats{path: path, now: time.Now}
	s.reset()
	if path == "" {
		return s
	}
	if b, err := os.ReadFile(path); err == nil {
		var f file
		if json.Unmarshal(b, &f) == nil {
			s.f = f
			s.fill()
		}
	}
	return s
}

func (s *Stats) reset() {
	s.f = file{Version: 1}
	s.fill()
}

func (s *Stats) fill() {
	if s.f.Days == nil {
		s.f.Days = map[string]*day{}
	}
	if s.f.Hours == nil {
		s.f.Hours = map[string]map[string]*Pair{}
	}
	if s.f.Names == nil {
		s.f.Names = map[string]string{}
	}
}

const (
	dayFmt  = "2006-01-02"
	hourFmt = "2006-01-02T15"
)

// Add counts bytes of tunneled traffic of server (profile ID; name is its
// current name) from program app ("" when unknown).
func (s *Stats) Add(server, name, app string, sent, recv int64) {
	if sent < 0 {
		sent = 0
	}
	if recv < 0 {
		recv = 0
	}
	if sent == 0 && recv == 0 || server == "" {
		return
	}
	if app == "" {
		app = "?"
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	dk := now.Format(dayFmt)
	d := s.f.Days[dk]
	if d == nil {
		d = &day{Servers: map[string]*Pair{}, Apps: map[string]*Pair{}}
		s.f.Days[dk] = d
		s.pruneLocked(now)
	}
	if d.Apps == nil {
		d.Apps = map[string]*Pair{}
	}
	get(d.Servers, server).add(sent, recv)
	get(d.Apps, app).add(sent, recv)
	hk := now.Format(hourFmt)
	h := s.f.Hours[hk]
	if h == nil {
		h = map[string]*Pair{}
		s.f.Hours[hk] = h
	}
	get(h, server).add(sent, recv)
	if name != "" {
		s.f.Names[server] = name
	}
	s.dirty = true
}

func get(m map[string]*Pair, k string) *Pair {
	p := m[k]
	if p == nil {
		p = &Pair{}
		m[k] = p
	}
	return p
}

// pruneLocked drops what is older than the retention.
func (s *Stats) pruneLocked(now time.Time) {
	days := now.AddDate(0, 0, -keepDays).Format(dayFmt)
	apps := now.AddDate(0, 0, -keepAppDays).Format(dayFmt)
	for k, d := range s.f.Days {
		switch {
		case k < days:
			delete(s.f.Days, k)
		case k < apps:
			d.Apps = nil
		}
	}
	hours := now.Add(-keepHours * time.Hour).Format(hourFmt)
	for k := range s.f.Hours {
		if k < hours {
			delete(s.f.Hours, k)
		}
	}
	used := map[string]bool{}
	for _, d := range s.f.Days {
		for id := range d.Servers {
			used[id] = true
		}
	}
	for id := range s.f.Names {
		if !used[id] {
			delete(s.f.Names, id)
		}
	}
}

// Flush writes the file when something changed.
func (s *Stats) Flush() error {
	s.mu.Lock()
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	b, err := json.Marshal(s.f)
	s.dirty = false
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := writeAtomic(s.path, b); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return err
	}
	return nil
}

// Clear forgets everything, on disk too.
func (s *Stats) Clear() error {
	s.mu.Lock()
	s.reset()
	s.dirty = false
	s.mu.Unlock()
	if s.path == "" {
		return nil
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Item is a server or a program with its bytes.
type Item struct {
	ID   string `json:"id"`   // server ID or program name
	Name string `json:"name"` // server name (servers only)
	Pair
}

// Point is one bar of the series.
type Point struct {
	Label string `json:"label"` // "14" (hour) or "2006-01-02" (day)
	Pair
}

// Report is the statistics over a period.
type Report struct {
	Period  string  `json:"period"` // day | week | month | year
	From    string  `json:"from"`   // first day, "2006-01-02"
	Total   Pair    `json:"total"`
	Servers []Item  `json:"servers"`
	Apps    []Item  `json:"apps"`
	Series  []Point `json:"series"`
	// AppsFrom: the first day programs are known for (older days keep
	// only the totals per server), "" when it is From.
	AppsFrom string `json:"appsFrom,omitempty"`
	// Since is the first day with any statistics, "" when none.
	Since string `json:"since"`
}

// Report sums a period ending today: day (today, by hour), week (7 days),
// month (30 days) or year (365 days), by day. name resolves server IDs
// (nil or "" = the stored name).
func (s *Stats) Report(period string, name func(id string) string) Report {
	now := s.now()
	n := map[string]int{"day": 1, "week": 7, "month": 30, "year": 365}[period]
	if n == 0 {
		period, n = "week", 7
	}
	from := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, -(n - 1))
	r := Report{Period: period, From: from.Format(dayFmt), Servers: []Item{}, Apps: []Item{}, Series: []Point{}}
	servers, apps := map[string]*Pair{}, map[string]*Pair{}
	s.mu.Lock()
	defer s.mu.Unlock()
	appsCut := now.AddDate(0, 0, -keepAppDays).Format(dayFmt)
	for k := range s.f.Days {
		if r.Since == "" || k < r.Since {
			r.Since = k
		}
	}
	for i := 0; i < n; i++ {
		k := from.AddDate(0, 0, i).Format(dayFmt)
		d := s.f.Days[k]
		var p Pair
		if d != nil {
			for id, v := range d.Servers {
				get(servers, id).add(v.Sent, v.Recv)
				p.add(v.Sent, v.Recv)
			}
			for a, v := range d.Apps {
				get(apps, a).add(v.Sent, v.Recv)
			}
		}
		r.Total.add(p.Sent, p.Recv)
		if period != "day" {
			r.Series = append(r.Series, Point{Label: k, Pair: p})
		}
	}
	if period == "day" {
		day := now.Format(dayFmt)
		for h := 0; h <= now.Hour(); h++ {
			k := day + "T" + twoDigits(h)
			var p Pair
			for _, v := range s.f.Hours[k] {
				p.add(v.Sent, v.Recv)
			}
			r.Series = append(r.Series, Point{Label: twoDigits(h), Pair: p})
		}
	}
	if r.From < appsCut && r.Since != "" && r.Since < appsCut {
		r.AppsFrom = appsCut
	}
	for id, p := range servers {
		nm := ""
		if name != nil {
			nm = name(id)
		}
		if nm == "" || nm == id {
			if stored := s.f.Names[id]; stored != "" {
				nm = stored
			}
		}
		r.Servers = append(r.Servers, Item{ID: id, Name: nm, Pair: *p})
	}
	for a, p := range apps {
		r.Apps = append(r.Apps, Item{ID: a, Pair: *p})
	}
	sortItems(r.Servers)
	sortItems(r.Apps)
	return r
}

func twoDigits(n int) string {
	return string([]byte{byte('0' + n/10), byte('0' + n%10)})
}

func sortItems(l []Item) {
	sort.Slice(l, func(i, j int) bool {
		if a, b := l[i].Total(), l[j].Total(); a != b {
			return a > b
		}
		return l[i].ID < l[j].ID
	})
}

func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(b)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}
