package stats

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// The «Статистика» section of a backup: replace only, validated
// completely before anything is written.

// MaxExport bounds the section (backup's own limit relies on it).
const MaxExport = 32 << 20

// exportLimit is MaxExport (tests lower it).
var exportLimit = MaxExport

// maxExportFiles: 90 days and 24 months fit with room for files older
// than the retention (the next compaction folds them).
const maxExportFiles = 200

type envelope struct {
	V     int                        `json:"v"`
	Mode  string                     `json:"mode"`
	Files map[string]json.RawMessage `json:"files"`
}

func plural(n int, one, few, many string) string {
	m10, m100 := n%10, n%100
	switch {
	case m10 == 1 && m100 != 11:
		return one
	case m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20):
		return few
	}
	return many
}

func ruDate(day string) string {
	t, err := time.Parse(dayFmt, day)
	if err != nil {
		return day
	}
	return t.Format("02.01.2006")
}

// describe is «с 12.07.2026 · 92 дня · сбор: всё» for a set of files.
func describe(files map[string]*File, mode Mode) string {
	days := map[string]bool{}
	for name, f := range files {
		kind, date, _ := parseName(name)
		if kind == kindDay {
			days[date] = true
		} else {
			for _, d := range f.Days {
				days[d] = true
			}
		}
	}
	since := ""
	for d := range days {
		if since == "" || d < since {
			since = d
		}
	}
	s := ""
	if since != "" {
		s = "с " + ruDate(since) + " · " + strconv.Itoa(len(days)) + " " + plural(len(days), "день", "дня", "дней") + " · "
	}
	return s + "сбор: " + mode.Label()
}

// loadAll returns every valid, non-future v1 file (ioMu held).
func (c *Collector) loadAll(now time.Time) (map[string]*File, error) {
	names, err := c.files.List()
	if err != nil {
		return nil, dirErr(err)
	}
	out := map[string]*File{}
	for _, n := range names {
		if future(n, now) {
			continue
		}
		f, st, err := c.load(n, now)
		switch st {
		case loadOK:
			out[n] = f
		case loadTransient:
			return nil, fmt.Errorf("%s.json: %s", n, shortErr(err))
		}
	}
	return out, nil
}

// Summary is the detail of the export dialog; empty: nothing to save.
func (c *Collector) Summary(now time.Time) (detail string, empty bool) {
	c.mu.Lock()
	pending := len(c.delta) > 0
	c.mu.Unlock()
	if c.files == nil {
		return describe(nil, c.Mode()), !pending
	}
	c.lockIO(now)
	defer c.ioMu.Unlock()
	// Cheap: the day files by name; only the (few, small) month files
	// are read, for the days they hold. A month file that cannot be
	// read counts no days.
	names, err := c.files.List()
	if err != nil {
		return describe(nil, c.Mode()), !pending
	}
	files := map[string]*File{}
	for _, n := range names {
		if future(n, now) {
			continue
		}
		f := &File{}
		if kind, _, _ := parseName(n); kind == kindMonth {
			if m, st, _ := c.load(n, now); st == loadOK {
				f = m
			}
		}
		files[n] = f
	}
	return describe(files, c.Mode()), len(files) == 0 && !pending
}

// Export flushes, then returns the section: month files first, then day
// files newest first while they fit in MaxExport (the oldest days are
// then left out, and the detail says so). Corrupt, newer and future files
// are left out. cut: some days were left out for size.
func (c *Collector) Export(now time.Time) (_ json.RawMessage, detail string, cut bool, _ error) {
	if c.files == nil {
		return nil, "", false, errors.New("статистика не сохраняется на диск")
	}
	c.lockIO(now)
	defer c.ioMu.Unlock()
	const notSaved = "статистика не сохранена в копию: "
	if err := c.flushLocked(now); err != nil {
		return nil, "", false, errors.New(notSaved + err.Error())
	}
	files, err := c.loadAll(now)
	if err != nil {
		return nil, "", false, errors.New(notSaved + err.Error())
	}
	var monthNames, dayNames []string
	for n := range files {
		if kind, _, _ := parseName(n); kind == kindMonth {
			monthNames = append(monthNames, n)
		} else {
			dayNames = append(dayNames, n)
		}
	}
	sort.Strings(monthNames)
	sort.Sort(sort.Reverse(sort.StringSlice(dayNames)))
	env := envelope{V: 1, Mode: string(c.Mode()), Files: map[string]json.RawMessage{}}
	kept := map[string]*File{}
	size := 64 + len(env.Mode)
	cutAt := ""
	for _, n := range append(monthNames, dayNames...) {
		if len(kept) >= maxExportFiles {
			cutAt = n
			break
		}
		b, err := files[n].marshal()
		if err != nil {
			return nil, "", false, errors.New(notSaved + err.Error())
		}
		if size+len(n)+len(b)+8 > exportLimit {
			cutAt = n
			break
		}
		size += len(n) + len(b) + 8
		env.Files[n], kept[n] = b, files[n]
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(env); err != nil {
		return nil, "", false, errors.New(notSaved + err.Error())
	}
	detail = describe(kept, c.Mode())
	if cutAt != "" {
		_, date, _ := parseName(cutAt)
		detail += " · без дней до " + ruDate(date) + ": слишком много данных"
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), detail, cutAt != "", nil
}

// checked is a validated payload: its files (future ones dropped), mode.
type checked struct {
	files   map[string]*File
	mode    Mode
	dropped int
}

func checkPayload(now time.Time, raw []byte) (*checked, error) {
	if len(raw) > MaxExport {
		return nil, errors.New("статистика в копии слишком большая")
	}
	var head struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("статистика в копии не читается: %v", err)
	}
	if head.V > 1 {
		return nil, errors.New("статистика в копии сделана более новой версией HyRoute")
	}
	var env envelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("статистика в копии не читается: %v", err)
	}
	if env.V != 1 {
		return nil, fmt.Errorf("статистика в копии: неизвестная версия %d", env.V)
	}
	mode, err := ParseMode(env.Mode)
	if err != nil {
		return nil, fmt.Errorf("статистика в копии: %v", err)
	}
	if len(env.Files) > maxExportFiles {
		return nil, errors.New("статистика в копии: слишком много файлов")
	}
	out := &checked{files: map[string]*File{}, mode: mode}
	for name, b := range env.Files {
		kind, _, ok := parseName(name)
		if !ok || kind == kindMode {
			return nil, fmt.Errorf("статистика в копии: неверное имя файла %q", name)
		}
		f, err := parseFile(name, b)
		if err != nil {
			return nil, fmt.Errorf("статистика в копии: файл %s повреждён", name)
		}
		if future(name, now) {
			out.dropped++
			continue
		}
		out.files[name] = f
	}
	return out, nil
}

// CheckImport validates a section completely without writing anything
// (and without the files' locks); the detail names the backup's mode and
// what the mode becomes.
func (c *Collector) CheckImport(now time.Time, raw []byte) (string, error) {
	p, err := checkPayload(now, raw)
	if err != nil {
		return "", err
	}
	detail := describe(p.files, p.mode)
	if eff := Stricter(c.Mode(), p.mode); eff != p.mode {
		detail += " (останется «" + eff.Label() + "»)"
	}
	if p.dropped > 0 {
		detail += " · " + strconv.Itoa(p.dropped) + " " + plural(p.dropped, "файл", "файла", "файлов") + " с датой в будущем пропущено"
	}
	return detail, nil
}

// Replace validates the section again, then replaces the statistics:
// every payload file is written (not over a current file of a newer
// version), current v1 and corrupt files not in the payload are removed
// (never newer or future ones), and the mode becomes the stricter of the
// current and the backup's. Unflushed deltas stay and are merged into the
// restored files at the next flush. A pending import of v1.2.0's
// statistics is dropped (the restored files may hold it already). There
// is no rollback: every file is written whole, so a failure leaves a mix
// of complete files.
func (c *Collector) Replace(now time.Time, raw []byte) error {
	p, err := checkPayload(now, raw)
	if err != nil {
		return err
	}
	if c.files == nil {
		return errors.New("статистика не сохраняется на диск")
	}
	c.lockIO(now)
	defer c.ioMu.Unlock()
	current, err := c.files.List()
	if err != nil {
		return fmt.Errorf("часть файлов статистики не записана: %s", shortErr(err))
	}
	mode := Stricter(c.Mode(), p.mode)
	c.settleLegacy() // mode.json below carries the mark
	c.mu.Lock()
	c.cache.init()
	c.bad = map[string]string{}
	c.compactAt = ""
	c.modeErr = ""
	c.mode.Store(mode)
	if mode == ModeNoSites {
		for _, d := range c.delta {
			d.lists[listSites] = map[string]*Row{}
		}
	}
	c.mu.Unlock()
	fail := func(name string, err error) error {
		return fmt.Errorf("часть файлов статистики не записана: %s.json: %s", name, shortErr(err))
	}
	names := make([]string, 0, len(p.files))
	for n := range p.files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, st, _ := c.load(n, now); st == loadNewer {
			c.Log.Info("stats: restore keeps a file of a newer version", "file", n)
			continue
		}
		f := p.files[n]
		if mode == ModeNoSites {
			f.Sites = nil
		}
		if err := c.write(n, f, now); err != nil {
			return fail(n, err)
		}
	}
	for _, n := range current {
		if _, ok := p.files[n]; ok || future(n, now) {
			continue
		}
		if _, st, _ := c.load(n, now); st == loadNewer || st == loadTransient {
			continue
		}
		if err := c.remove(n); err != nil {
			return fail(n, err)
		}
	}
	if err := c.writeMode(mode); err != nil {
		return fail("mode", err)
	}
	return nil
}
