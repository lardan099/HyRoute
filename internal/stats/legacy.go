package stats

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// HyRoute 1.2.0 kept VPN traffic in traffic.json: bytes per day by server
// and by program (and by hour for two days). It is imported once into day
// and month files: tunnel bytes per day, server and program (all under
// the site «не определён»: 1.2.0 kept no sites). Connections, sites and
// hours were never in it. The old file is left where it is.
//
// «Once» is the mark in mode.json, written when the import succeeded or
// the file turned out not to be importable, and when the user deleted or
// replaced the statistics meanwhile (Reset, Replace). A mode.json that
// exists but cannot be read counts as marked: only this version writes it,
// and losing an import is cheaper than counting it twice. A transient
// failure (the file or a statistics file busy, a failed write) is retried
// later in the run and at the next start; every file the import wrote is
// marked Imported (a month keeps the mark of the days folded into it), so
// a repeated import adds only what is still missing, also into a day file
// this version wrote meanwhile.
//
// 1.2.0 promised to keep no sites: an upgraded user (no mode.json yet, and
// the data folder held files of an earlier version: traffic.json, or the
// servers, rules, preferences or proxies; 1.2.0 wrote traffic.json only
// after VPN traffic and «Очистить» deleted it) starts with «Без сайтов», a
// new one with «Всё». The default goes into mode.json with the first write
// into the folder, so a later start does not decide again.

// Legacy is where the 1.2.0 statistics come from (internal/store).
type Legacy interface {
	// ReadLegacy reads traffic.json: fs.ErrNotExist when absent,
	// ErrCorrupt for a link or an oversize file.
	ReadLegacy() ([]byte, error)
	// Upgraded reports that the data folder holds files of an earlier
	// version: something at the place of traffic.json, or the servers,
	// rules, preferences or proxies (without reading them).
	Upgraded() bool
}

// Retries of an import that failed for a transient reason.
const (
	legacyRetryMin = time.Minute
	legacyRetryMax = time.Hour
)

type legacyPair struct {
	Sent int64 `json:"sent"`
	Recv int64 `json:"recv"`
}

type legacyDay struct {
	Servers map[string]*legacyPair `json:"servers"`
	Apps    map[string]*legacyPair `json:"apps"`
}

type legacyFile struct {
	Version int                   `json:"version"`
	Days    map[string]*legacyDay `json:"days"`
	Names   map[string]string     `json:"names"`
}

// errLegacyFormat: the file is not the 1.2.0 format (not imported).
var errLegacyFormat = errors.New("not the statistics format of HyRoute 1.2.0")

// legacyProxyPrefix starts the program name 1.2.0 gave a local proxy.
const legacyProxyPrefix = "Локальный прокси "

// importLegacyLocked tries the import of the 1.2.0 statistics while it is
// due (ioMu held).
func (c *Collector) importLegacyLocked(now time.Time) {
	if c.legacyDone || c.legacy == nil || c.files == nil || now.Before(c.legacyRetry) {
		return
	}
	b, err := c.legacy.ReadLegacy()
	if errors.Is(err, fs.ErrNotExist) {
		c.legacyDone = true // nothing to import; the next start looks again
		return
	}
	n := 0
	if err == nil {
		n, err = c.importLegacy(now, b)
	}
	if err != nil && !errors.Is(err, errLegacyFormat) && !errors.Is(err, ErrCorrupt) {
		c.legacyWait = min(max(2*c.legacyWait, legacyRetryMin), legacyRetryMax)
		c.legacyRetry = now.Add(c.legacyWait)
		c.Log.Warn("stats: statistics of HyRoute 1.2.0 not imported yet, will retry", "file", "traffic.json", "err", shortErr(err), "retry", c.legacyWait)
		return
	}
	c.legacyDone, c.imported = true, true
	if err != nil {
		c.Log.Warn("stats: statistics of HyRoute 1.2.0 not imported", "file", "traffic.json", "err", shortErr(err))
	} else if n > 0 {
		c.Log.Info("stats: statistics of HyRoute 1.2.0 imported (traffic.json is kept)", "days", n)
	}
	if err := c.writeMode(c.Mode()); err != nil {
		c.Log.Warn("stats: import of HyRoute 1.2.0's statistics not marked as done, the next start repeats it", "err", shortErr(err))
	}
}

// Bounds of traffic.json (1.2.0 kept 400 days and a row per server and
// program): a file over them is not 1.2.0's (not imported, not retried).
const (
	maxLegacyDays = 800
	maxLegacyRows = maxRows // servers or programs of one day
)

// legacyFiles converts traffic.json into this version's files; days is
// how many days it held. Entries that make no sense (null days or pairs,
// keys that are not dates, negative numbers) are skipped. A local proxy
// becomes that proxy's program row when proxy finds it (nil: never). The
// rows of a day are summed in maps and trimmed to the day caps before a
// month takes them: linear in the size of the file.
func legacyFiles(now time.Time, b []byte, mode Mode, proxy func(string) (string, string, bool)) (files map[string]*File, days int, err error) {
	var lf legacyFile
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, 0, errLegacyFormat
	}
	if lf.Version != 1 || len(lf.Days) > maxLegacyDays {
		return nil, 0, errLegacyFormat
	}
	for _, ld := range lf.Days {
		if ld != nil && (len(ld.Servers) > maxLegacyRows || len(ld.Apps) > maxLegacyRows) {
			return nil, 0, errLegacyFormat
		}
	}
	today := dayOf(now)
	oldestDay := addDays(today, -(keepDays - 1))
	oldestMonth := addMonths(today[:7], -(keepMonths - 1))
	files = map[string]*File{}
	keys := make([]string, 0, len(lf.Days))
	for k := range lf.Days {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, d := range keys {
		ld := lf.Days[d]
		if ld == nil || !validDay(d) || d > addDays(today, futureDays) || d[:7] < oldestMonth {
			continue
		}
		f := &File{V: 1, Day: d, Updated: now}
		servers := map[string]*Row{}
		for id, p := range ld.Servers {
			if p == nil || id == "" || len(id) > maxKey || !utf8.ValidString(id) {
				continue
			}
			c := Counters{TU: clamp(p.Sent), TD: clamp(p.Recv)}
			f.Total.add(c)
			legacyRow(servers, id, shortName(lf.Names[id]), c)
		}
		if f.Total == (Counters{}) {
			continue
		}
		f.Servers = legacyRows(servers)
		apps := map[string]*Row{}
		var sum Counters
		for name, p := range ld.Apps {
			if p == nil || len(name) > maxKey || !utf8.ValidString(name) {
				continue
			}
			key, label := strings.ToLower(name), shortName(name)
			switch {
			case name == "?" || name == "":
				key, label = "", "" // «Программа не определена»
			case proxy != nil && strings.HasPrefix(name, legacyProxyPrefix):
				if k, l, ok := proxy(name); ok {
					key, label = k, l
				}
			}
			c := Counters{TU: clamp(p.Sent), TD: clamp(p.Recv)}
			sum.add(c)
			legacyRow(apps, key, label, c)
		}
		// Programs were kept for 92 days only: the rest of a day's
		// servers is «Остальные».
		if rest := (Counters{TU: max(f.Total.TU-sum.TU, 0), TD: max(f.Total.TD-sum.TD, 0)}); rest != (Counters{}) {
			legacyRow(apps, Others, "", rest)
		}
		f.Apps = legacyRows(apps)
		f.trim(dayCaps)
		days++
		if d >= oldestDay {
			files["day-"+d] = f
			continue
		}
		mname := "month-" + d[:7]
		m := files[mname]
		if m == nil {
			m = &File{V: 1, Month: d[:7], Updated: now}
			files[mname] = m
		}
		m.addFile(f)
		m.Days = append(m.Days, d)
	}
	for _, f := range files {
		sort.Strings(f.Days)
		if f.Month != "" {
			f.trim(monthCaps)
		}
	}
	return files, days, nil
}

// legacyRow adds c (and the name, when set) to the row of key in m.
func legacyRow(m map[string]*Row, key, name string, c Counters) {
	r := m[key]
	if r == nil {
		r = &Row{Key: key}
		m[key] = r
	}
	r.add(&Row{Name: name, Counters: c})
}

func legacyRows(m map[string]*Row) []Row {
	out := make([]Row, 0, len(m))
	for _, r := range m {
		out = append(out, *r)
	}
	return out
}

// shortName cuts a display name to the limit on a rune boundary.
func shortName(s string) string {
	if len(s) <= maxName {
		return s
	}
	s = s[:maxName]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// importLegacy writes the files of traffic.json, each added to the file
// of the same name unless that one already holds its import (a newer
// version's file is left alone). Returns how many days traffic.json held.
func (c *Collector) importLegacy(now time.Time, b []byte) (int, error) {
	mode := c.Mode()
	files, days, err := legacyFiles(now, b, mode, c.LegacyProxy)
	if err != nil {
		return 0, err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names) // day-… before month-…: the newest data first
	for _, n := range names {
		f := files[n]
		cur, st, err := c.load(n, now)
		switch st {
		case loadTransient:
			return 0, fmt.Errorf("%s.json: %w", n, err)
		case loadNewer:
			c.Log.Warn("stats: statistics of HyRoute 1.2.0 not imported into a file of a newer version", "file", n)
			continue
		case loadCorrupt:
			c.Log.Warn("stats: replacing a damaged statistics file", "file", n)
		case loadOK:
			if cur.Imported {
				continue // an earlier attempt wrote it
			}
			cur.addFile(f)
			caps := dayCaps
			if cur.Month != "" {
				caps = monthCaps
				for _, d := range f.Days {
					if k := sort.SearchStrings(cur.Days, d); k == len(cur.Days) || cur.Days[k] != d {
						cur.Days = append(cur.Days, d)
						sort.Strings(cur.Days)
					}
				}
			}
			cur.trim(caps)
			cur.Updated = now
			f = cur
		}
		f.Imported = true
		if err := c.write(n, f, now); err != nil {
			return 0, fmt.Errorf("%s.json: %w", n, err)
		}
	}
	return days, nil
}
