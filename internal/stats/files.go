package stats

import (
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"time"
)

// Files is the storage of the statistics (internal/store implements it;
// tests use a map). Names: "day-YYYY-MM-DD", "month-YYYY-MM" and "mode",
// without ".json".
type Files interface {
	List() ([]string, error)          // valid day/month names (never "mode"); empty when the folder is absent
	Read(name string) ([]byte, error) // os.ErrNotExist when absent; ErrCorrupt for a link/oversize/non-regular file
	Write(name string, b []byte) error
	Remove(name string) error
	// SweepTemp removes writeAtomic leftovers (".tmp-*") last modified
	// before the given time; returns how many were removed.
	SweepTemp(before time.Time) (int, error)
}

// ErrCorrupt: the file is not something a statistics file can be (a
// link, too large, not a regular file).
var ErrCorrupt = errors.New("stats: file is not a valid statistics file")

// ErrBusy: FlushWithin could not take the files in time.
var ErrBusy = errors.New("stats: statistics files are busy")

const (
	kindDay = iota + 1
	kindMonth
	kindMode
)

var (
	dayName   = regexp.MustCompile(`^day-(\d{4}-\d{2}-\d{2})$`)
	monthName = regexp.MustCompile(`^month-(\d{4}-\d{2})$`)
)

func validDay(d string) bool {
	_, err := time.Parse(dayFmt, d)
	return err == nil && len(d) == len(dayFmt)
}

// parseName splits a file name (without ".json") into its kind and date.
func parseName(name string) (kind int, date string, ok bool) {
	if name == "mode" {
		return kindMode, "", true
	}
	if m := dayName.FindStringSubmatch(name); m != nil && validDay(m[1]) {
		return kindDay, m[1], true
	}
	if m := monthName.FindStringSubmatch(name); m != nil {
		if _, err := time.Parse(monthFmt, m[1]); err == nil {
			return kindMonth, m[1], true
		}
	}
	return 0, "", false
}

// ValidName reports a statistics file name (without ".json").
func ValidName(name string) bool {
	_, _, ok := parseName(name)
	return ok
}

// Calendar arithmetic on dates. It is done in UTC, which has no daylight
// saving: where DST starts at midnight (Chile, Cuba) the local midnight
// of that day does not exist, and a local date plus one day would stay on
// the same date. Only dayOf uses local time (which day it is now).
func addDays(day string, n int) string {
	t, _ := time.Parse(dayFmt, day)
	return t.AddDate(0, 0, n).Format(dayFmt)
}

func addMonths(month string, n int) string {
	t, _ := time.Parse(monthFmt, month)
	return t.AddDate(0, n, 0).Format(monthFmt)
}

// Retention.
const (
	keepDays   = 90 // day files: today-89 … today
	keepMonths = 24 // month files: current month-23 … current month
	futureDays = 2  // a day file dated later than today+2 is "future"
)

// future: a day file dated more than two days after today, or a month
// file after the current month. Such files are ignored everywhere (never
// loaded, written or removed) except by Reset.
func future(name string, now time.Time) bool {
	kind, date, _ := parseName(name)
	today := dayOf(now)
	switch kind {
	case kindDay:
		return date > addDays(today, futureDays)
	case kindMonth:
		return date > today[:7]
	}
	return false
}

// ---- parsed file cache ----

// fileCache keeps parsed files by name, least recently used first out,
// bounded by the sum of their sizes on disk. A file over 1 MiB is not
// cached unless it is today's: a planted large file cannot pin memory.
type fileCache struct {
	ll    *list.List
	at    map[string]*list.Element
	bytes int64
}

type cached struct {
	name string
	f    *File
	size int64
}

const (
	cacheBytes   = 16 << 20
	cacheFileMax = 1 << 20
)

func (fc *fileCache) init() {
	fc.ll, fc.at, fc.bytes = list.New(), map[string]*list.Element{}, 0
}

func (fc *fileCache) get(name string) *File {
	if e := fc.at[name]; e != nil {
		fc.ll.MoveToFront(e)
		return e.Value.(*cached).f
	}
	return nil
}

func (fc *fileCache) put(name string, f *File, size int64, today bool) {
	fc.drop(name)
	if size > cacheFileMax && !today {
		return
	}
	fc.at[name] = fc.ll.PushFront(&cached{name, f, size})
	fc.bytes += size
	for fc.bytes > cacheBytes && fc.ll.Len() > 1 {
		fc.drop(fc.ll.Back().Value.(*cached).name)
	}
}

func (fc *fileCache) drop(name string) {
	if e := fc.at[name]; e != nil {
		fc.bytes -= e.Value.(*cached).size
		fc.ll.Remove(e)
		delete(fc.at, name)
	}
}

// ---- loading ----

type loadState int

const (
	loadOK loadState = iota
	loadAbsent
	loadCorrupt
	loadNewer
	loadTransient
)

// bad reasons
const (
	badCorrupt = "повреждён"
	badNewer   = "новее"
)

// load returns a copy of the file called name (ioMu held): from the
// cache, else read and parsed. A corrupt or newer file is noted in bad; a
// transient read error returns err and marks nothing.
func (c *Collector) load(name string, now time.Time) (*File, loadState, error) {
	c.mu.Lock()
	f := c.cache.get(name)
	c.mu.Unlock()
	if f != nil {
		return f.clone(), loadOK, nil
	}
	b, err := c.files.Read(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c.mu.Lock()
		delete(c.bad, name)
		c.mu.Unlock()
		return nil, loadAbsent, nil
	case errors.Is(err, ErrCorrupt):
		c.markBad(name, badCorrupt)
		return nil, loadCorrupt, nil
	case err != nil:
		return nil, loadTransient, err
	}
	f, err = parseFile(name, b)
	switch {
	case errors.Is(err, errNewer):
		c.markBad(name, badNewer)
		return nil, loadNewer, nil
	case err != nil:
		c.markBad(name, badCorrupt)
		return nil, loadCorrupt, nil
	}
	c.mu.Lock()
	delete(c.bad, name)
	c.cache.put(name, f, int64(len(b)), name == "day-"+dayOf(now))
	c.mu.Unlock()
	return f.clone(), loadOK, nil
}

func (c *Collector) markBad(name, why string) {
	c.mu.Lock()
	c.bad[name] = why
	c.cache.drop(name)
	c.mu.Unlock()
}

// write stores a file and remembers it parsed (ioMu held). The first one
// writes the default mode first (a failure is retried with the next).
func (c *Collector) write(name string, f *File, now time.Time) error {
	if c.modeUnsaved {
		if err := c.writeMode(c.Mode()); err != nil {
			c.Log.Warn("stats: collection mode not saved", "err", shortErr(err))
		}
	}
	b, err := f.marshal()
	if err == nil {
		err = c.files.Write(name, b)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.cache.drop(name)
		return err
	}
	delete(c.bad, name)
	c.cache.put(name, f.clone(), int64(len(b)), name == "day-"+dayOf(now))
	return nil
}

func (c *Collector) remove(name string) error {
	err := c.files.Remove(name)
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	c.mu.Lock()
	c.cache.drop(name)
	if err == nil {
		delete(c.bad, name)
	}
	c.mu.Unlock()
	return err
}

// shortErr drops the path from an I/O error: texts shown to the user and
// logged carry file names only.
func shortErr(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		return le.Err.Error()
	}
	return err.Error()
}

// fileErr and dirErr are texts of an I/O error about a statistics file
// or the folder, without paths.
func fileErr(name string, err error) error {
	return fmt.Errorf("%s.json: %s", name, shortErr(err))
}

func dirErr(err error) error { return fmt.Errorf("папка stats: %s", shortErr(err)) }

// ---- configuration and mode ----

// Configure attaches the files (once, from the controller's Load) and
// reads the collection mode (mode.json): absent = «Всё» («Без сайтов» for
// an upgraded user, see legacy.go); unreadable, corrupt or unknown = off
// until the user picks a mode. A new install's «Всё» is written at once:
// by the next start its servers and prefs would look like an upgrade's.
// An upgraded user's default is written with the first statistics file
// (no stats folder until something is collected).
func (c *Collector) Configure(files Files) {
	c.ioMu.Lock()
	defer c.ioMu.Unlock()
	c.files = files
	c.legacy, _ = files.(Legacy)
	mode, imported, absent, err := c.readMode()
	fresh := absent && c.legacy != nil && !c.legacy.Upgraded()
	if absent && c.legacy != nil && !fresh {
		mode = ModeNoSites
	}
	c.modeUnsaved = absent
	c.mode.Store(mode)
	// Unreadable mode.json: only this version writes it, so the import
	// is taken as done (the next writeMode keeps the mark).
	c.imported = imported || err != nil
	c.legacyDone = c.imported
	c.legacyRetry, c.legacyWait = time.Time{}, 0
	c.mu.Lock()
	c.modeErr = ""
	if err != nil {
		c.modeErr = "не удалось прочитать режим сбора (mode.json), сбор выключен до выбора режима"
	}
	c.mu.Unlock()
	if err != nil {
		c.Log.Warn("stats: collection mode not read, collection is off", "err", shortErr(err))
	}
	if fresh {
		if err := c.writeMode(mode); err != nil { // the first statistics file retries
			c.Log.Warn("stats: collection mode not saved", "err", shortErr(err))
		}
	}
}

// modeFile is mode.json. Imported: the statistics of HyRoute 1.2.0 were
// imported (or could never be), not to be tried again.
type modeFile struct {
	V        int    `json:"v"`
	Mode     string `json:"mode"`
	Imported bool   `json:"imported,omitempty"`
}

// readMode reads mode.json: the mode, the import mark, and whether the
// file is absent.
func (c *Collector) readMode() (mode Mode, imported, absent bool, err error) {
	b, err := c.files.Read("mode")
	if errors.Is(err, fs.ErrNotExist) {
		return ModeAll, false, true, nil
	}
	if err != nil {
		return ModeOff, false, false, err
	}
	if len(b) > maxModeBytes {
		return ModeOff, false, false, ErrCorrupt
	}
	var m modeFile
	if err := json.Unmarshal(b, &m); err != nil {
		return ModeOff, false, false, err
	}
	if m.V < 1 {
		return ModeOff, false, false, fmt.Errorf("mode.json: version %d", m.V)
	}
	mode, err = ParseMode(m.Mode)
	if err != nil {
		return ModeOff, false, false, fmt.Errorf("mode.json: mode %q", m.Mode)
	}
	return mode, m.Imported, false, nil
}

// writeMode writes mode.json with the import mark (ioMu held).
func (c *Collector) writeMode(m Mode) error {
	b, _ := json.Marshal(modeFile{V: 1, Mode: string(m), Imported: c.imported})
	err := c.files.Write("mode", b)
	if err == nil {
		c.modeUnsaved = false
	}
	return err
}

// settleLegacy ends the import of v1.2.0's statistics for good: the user
// deleted or replaced the statistics, which must not come back (ioMu
// held). Reports whether it was still pending; the caller writes the mark.
func (c *Collector) settleLegacy() (pending bool) {
	pending = c.legacy != nil && !c.legacyDone
	c.legacyDone, c.imported = true, true
	return pending
}

// lockIO takes ioMu and tries the one-time import of v1.2.0's statistics
// when it is still due.
func (c *Collector) lockIO(now time.Time) {
	c.ioMu.Lock()
	c.importLegacyLocked(now)
}

// SetMode sets the collection mode: mode.json is written first, and the
// mode applies in memory whether or not that worked (the user's latest
// choice holds for this run). «Без сайтов» also removes the sites already
// collected, from memory and from every file (a corrupt file, which may
// hold sites and cannot be cleaned, is removed). Returns the first error.
func (c *Collector) SetMode(now time.Time, m Mode) error {
	if c.files != nil {
		c.lockIO(now)
		defer c.ioMu.Unlock()
	}
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	if c.files != nil {
		if err := c.writeMode(m); err != nil {
			keep(fmt.Errorf("режим применён, но не сохранён: %s", shortErr(err)))
		}
	}
	c.mode.Store(m)
	c.mu.Lock()
	c.modeErr = ""
	if m == ModeNoSites {
		for _, d := range c.delta {
			d.lists[listSites] = map[string]*Row{}
		}
		c.cache.init()
	}
	c.mu.Unlock()
	if m != ModeNoSites || c.files == nil {
		return first
	}
	const notAll = "сайты удалены не из всех файлов статистики: "
	names, err := c.files.List()
	if err != nil {
		keep(fmt.Errorf(notAll+"папка stats: %s", shortErr(err)))
	}
	for _, name := range names {
		if future(name, now) {
			continue
		}
		f, st, err := c.load(name, now)
		switch st {
		case loadOK:
			if len(f.Sites) > 0 {
				f.Sites = nil
				if err := c.write(name, f, now); err != nil {
					keep(fmt.Errorf(notAll+"%s.json: %s", name, shortErr(err)))
				}
			}
		case loadCorrupt:
			if err := c.remove(name); err != nil {
				keep(fmt.Errorf(notAll+"%s.json: %s", name, shortErr(err)))
			} else {
				c.Log.Info("stats: damaged statistics file removed", "file", name)
			}
		case loadTransient:
			keep(fmt.Errorf(notAll+"%s.json: %s", name, shortErr(err)))
		}
	}
	return first
}

// ---- flush ----

// DayChanged reports that the day of now has no delta yet while an
// earlier one has (the sampler flushes then).
func (c *Collector) DayChanged(now time.Time) bool {
	today := dayOf(now)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.delta[today] != nil {
		return false
	}
	return len(c.delta) > 0
}

// Flush writes the unflushed deltas into their files. It never compacts.
func (c *Collector) Flush(now time.Time) error {
	if c.files == nil {
		return nil
	}
	c.lockIO(now)
	defer c.ioMu.Unlock()
	return c.flushLocked(now)
}

// FlushWithin is Flush if the files can be taken within wait, else
// ErrBusy (the end of the Windows session must not hang on a report). It
// does not try the import of v1.2.0's statistics (LegacyProxy may wait
// for a Controller lock); the next start does.
func (c *Collector) FlushWithin(now time.Time, wait time.Duration) error {
	if c.files == nil {
		return nil
	}
	deadline := time.Now().Add(wait)
	for !c.ioMu.TryLock() {
		if time.Now().After(deadline) {
			return ErrBusy
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer c.ioMu.Unlock()
	return c.flushLocked(now)
}

// flushLocked: ioMu held.
func (c *Collector) flushLocked(now time.Time) error {
	c.mu.Lock()
	taken := c.delta
	c.delta = map[string]*mem{}
	c.mu.Unlock()
	if len(taken) == 0 {
		return nil
	}
	mode := c.Mode()
	days := make([]string, 0, len(taken))
	for d := range taken {
		days = append(days, d)
	}
	sort.Strings(days)
	today := dayOf(now)
	var readded bool
	var failed error
	readd := func(d string) {
		readded = true
		c.mu.Lock()
		c.readdLocked(d, taken[d])
		c.mu.Unlock()
	}
	for i, d := range days {
		if failed != nil {
			readd(d)
			continue
		}
		m := taken[d]
		name, month := "day-"+d, d < addDays(today, -(keepDays-1))
		if month {
			// A late delta for a day already outside the window.
			name = "month-" + d[:7]
		}
		if future(name, now) {
			c.Log.Warn("stats: statistics of a day dropped: date in the future", "day", d)
			continue
		}
		f, st, err := c.load(name, now)
		switch st {
		case loadNewer:
			c.Log.Warn("stats: statistics of a day dropped: file of a newer version", "file", name)
			continue
		case loadTransient:
			c.mu.Lock()
			c.writeErr = "не удалось прочитать " + name + ".json: " + shortErr(err)
			c.mu.Unlock()
			readd(d)
			continue
		case loadCorrupt:
			c.Log.Warn("stats: replacing a damaged statistics file", "file", name)
			f = nil
		}
		if f == nil {
			f = &File{V: 1}
			if month {
				f.Month = d[:7]
			} else {
				f.Day = d
			}
		}
		f.addMem(m)
		caps := dayCaps
		if month {
			caps = monthCaps
			if k := sort.SearchStrings(f.Days, d); k == len(f.Days) || f.Days[k] != d {
				f.Days = append(f.Days, d)
				sort.Strings(f.Days)
			}
		}
		if mode == ModeNoSites {
			f.Sites = nil
		}
		f.trim(caps)
		f.Updated = now
		if err := c.write(name, f, now); err != nil {
			c.mu.Lock()
			c.writeErr = "не удалось записать " + name + ".json: " + shortErr(err)
			c.mu.Unlock()
			c.Log.Warn("stats: statistics not saved", "file", name, "err", shortErr(err))
			failed = fileErr(name, err)
			readd(days[i])
		}
	}
	if !readded {
		c.mu.Lock()
		c.writeErr, c.lost = "", ""
		c.mu.Unlock()
	}
	return failed
}

// ---- compaction ----

// CompactDue reports that today's compaction has not run yet.
func (c *Collector) CompactDue(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.compactAt != dayOf(now)
}

// Compact applies the retention (the stats goroutine only): day files
// older than 90 days are folded into their month file and removed,
// month files older than 24 months removed, corrupt old day files removed,
// writeAtomic leftovers older than an hour swept. Future and newer files
// are left alone (a newer day file only by date retention).
func (c *Collector) Compact(now time.Time) error {
	if c.files == nil {
		return nil
	}
	c.lockIO(now)
	defer c.ioMu.Unlock()
	names, err := c.files.List()
	if err != nil {
		return dirErr(err)
	}
	today := dayOf(now)
	oldestDay := addDays(today, -(keepDays - 1))
	oldestMonth := addMonths(today[:7], -(keepMonths - 1))
	var days, months []string
	for _, n := range names {
		if future(n, now) {
			continue
		}
		kind, date, _ := parseName(n)
		switch {
		case kind == kindDay && date < oldestDay:
			days = append(days, date)
		case kind == kindMonth && date < oldestMonth:
			months = append(months, n)
		}
	}
	sort.Strings(days)
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	removeFile := func(name string) error {
		if err := c.remove(name); err != nil {
			return fileErr(name, err)
		}
		return nil
	}
	for _, d := range days {
		name := "day-" + d
		if d[:7] < oldestMonth {
			keep(removeFile(name))
			continue
		}
		f, st, err := c.load(name, now)
		switch st {
		case loadCorrupt:
			if err := removeFile(name); err == nil {
				c.Log.Info("stats: damaged statistics file removed", "file", name)
			} else {
				keep(err)
			}
			continue
		case loadNewer, loadAbsent:
			continue
		case loadTransient:
			keep(fileErr(name, err))
			continue
		}
		if f.Imported && !c.legacyDone {
			// The pending import may still write this month: the month
			// must not carry the mark before that.
			continue
		}
		mname := "month-" + d[:7]
		m, mst, err := c.load(mname, now)
		switch mst {
		case loadNewer:
			continue // cannot fold into a file this version does not understand
		case loadTransient:
			keep(fileErr(mname, err))
			continue
		case loadCorrupt:
			c.Log.Warn("stats: replacing a damaged statistics file", "file", mname)
			m = nil
		}
		if m == nil {
			m = &File{V: 1, Month: d[:7]}
		}
		if i := sort.SearchStrings(m.Days, d); i == len(m.Days) || m.Days[i] != d {
			m.addFile(f) // an imported day makes an imported month
			m.Days = append(m.Days, d)
			sort.Strings(m.Days)
			m.trim(monthCaps)
			m.Updated = now
			if err := c.write(mname, m, now); err != nil {
				keep(fileErr(mname, err))
				continue
			}
		}
		// After a crash between the two steps the next compaction only
		// removes the day: its month already holds it.
		keep(removeFile(name))
	}
	for _, n := range months {
		keep(removeFile(n))
	}
	if n, err := c.files.SweepTemp(now.Add(-time.Hour)); err != nil {
		keep(dirErr(err))
	} else if n > 0 {
		c.Log.Info("stats: leftover temporary files removed", "count", n)
	}
	if first == nil {
		c.mu.Lock()
		c.compactAt = today
		c.mu.Unlock()
	}
	return first
}

// Reset deletes every day and month file (future and newer ones too: the
// user asked to delete everything) and every unflushed delta. The mode is
// kept; live flows add only their new bytes. A pending import of v1.2.0's
// statistics is dropped: what the user deleted does not come back.
func (c *Collector) Reset(now time.Time) error {
	if c.files != nil {
		c.lockIO(now)
		defer c.ioMu.Unlock()
		c.mu.Lock()
		modeKnown := c.modeErr == ""
		c.mu.Unlock()
		// With an unreadable mode.json the mark is set already, and the
		// user's next choice of a mode writes it.
		if c.settleLegacy() && modeKnown {
			if err := c.writeMode(c.Mode()); err != nil {
				c.Log.Warn("stats: the dropped import of HyRoute 1.2.0's statistics not marked, the next start may repeat it", "err", shortErr(err))
			}
		}
	}
	c.mu.Lock()
	c.delta = map[string]*mem{}
	c.cache.init()
	c.bad = map[string]string{}
	c.writeErr, c.readErr, c.lost = "", "", ""
	c.mu.Unlock()
	if c.files == nil {
		return nil
	}
	const notAll = "статистика удалена не полностью: "
	names, err := c.files.List()
	if err != nil {
		return fmt.Errorf(notAll+"папка stats: %s", shortErr(err))
	}
	var first error
	for _, n := range names {
		if err := c.remove(n); err != nil && first == nil {
			first = fmt.Errorf(notAll+"%s.json: %s", n, shortErr(err))
		}
	}
	return first
}
