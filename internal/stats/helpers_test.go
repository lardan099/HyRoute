package stats

import (
	"encoding/json"
	"errors"
	"io/fs"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
)

// memFiles is a map-backed Files (and Legacy) with failure hooks.
type memFiles struct {
	mu      sync.Mutex
	m       map[string][]byte
	tmp     map[string]time.Time // ".tmp-*" leftovers and their mtime
	corrupt map[string]bool      // Read returns ErrCorrupt
	readErr map[string]error
	listErr error
	// onWrite runs before a write (outside mu); an error fails it.
	onWrite func(name string) error
	legacy  []byte
	// legacyErr fails ReadLegacy while set.
	legacyErr error
	writes    int
	removes   int
	earlier   bool // the data folder holds other files of an earlier version
}

func newFiles() *memFiles {
	return &memFiles{m: map[string][]byte{}, tmp: map[string]time.Time{}, corrupt: map[string]bool{}, readErr: map[string]error{}}
}

func (f *memFiles) List() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []string
	for n := range f.m {
		if n != "mode" && ValidName(n) {
			out = append(out, n)
		}
	}
	for n := range f.corrupt {
		if _, ok := f.m[n]; !ok && n != "mode" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (f *memFiles) Read(name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.corrupt[name] {
		return nil, ErrCorrupt
	}
	if err := f.readErr[name]; err != nil {
		return nil, err
	}
	b, ok := f.m[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return append([]byte(nil), b...), nil
}

func (f *memFiles) Write(name string, b []byte) error {
	f.mu.Lock()
	hook := f.onWrite
	f.mu.Unlock()
	if hook != nil {
		if err := hook(name); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[name] = append([]byte(nil), b...)
	delete(f.corrupt, name)
	f.writes++
	return nil
}

func (f *memFiles) Remove(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.m[name]
	if !ok && !f.corrupt[name] {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
	}
	delete(f.m, name)
	delete(f.corrupt, name)
	f.removes++
	return nil
}

func (f *memFiles) SweepTemp(before time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for k, t := range f.tmp {
		if t.Before(before) {
			delete(f.tmp, k)
			n++
		}
	}
	return n, nil
}

func (f *memFiles) Upgraded() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.earlier || f.legacy != nil || f.legacyErr != nil && !errors.Is(f.legacyErr, fs.ErrNotExist)
}

func (f *memFiles) ReadLegacy() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.legacyErr != nil {
		return nil, f.legacyErr
	}
	if f.legacy == nil {
		return nil, fs.ErrNotExist
	}
	return f.legacy, nil
}

func (f *memFiles) get(name string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[name]
}

func (f *memFiles) has(name string) bool { return f.get(name) != nil }

func (f *memFiles) put(name string, b []byte) {
	f.mu.Lock()
	f.m[name] = b
	f.mu.Unlock()
}

// file parses a stored file (the test fails when it is not valid).
func (f *memFiles) file(t *testing.T, name string) *File {
	t.Helper()
	b := f.get(name)
	if b == nil {
		t.Fatalf("%s: absent", name)
	}
	p, err := parseFile(name, b)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return p
}

// clock is a settable fake clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (k *clock) now() time.Time { k.mu.Lock(); defer k.mu.Unlock(); return k.t }
func (k *clock) add(d time.Duration) {
	k.mu.Lock()
	k.t = k.t.Add(d)
	k.mu.Unlock()
}
func (k *clock) set(t time.Time) { k.mu.Lock(); k.t = t; k.mu.Unlock() }

var t0 = time.Date(2026, 9, 28, 12, 0, 0, 0, time.Local)

// rig is a collector with map files, a fake clock and one registry whose
// closes it observes.
type rig struct {
	c     *Collector
	files *memFiles
	clk   *clock
	reg   *flows.Registry
	src   *Source
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{c: New(nil), files: newFiles(), clk: &clock{t: t0}, reg: flows.NewRegistry(10)}
	r.c.Now = r.clk.now
	r.c.Configure(r.files)
	r.src = r.c.NewSource()
	r.reg.OnClose = r.src.Closed
	return r
}

// open opens a record of app (full path) with fields set by set.
func (r *rig) open(path string, set func(f *flows.Fields)) *flows.Record {
	name := path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '\\' {
			name = path[i+1:]
			break
		}
	}
	rec := r.reg.Open(&flows.Record{Proto: 6, Process: name, Path: path, Start: r.clk.now()})
	if set != nil {
		rec.Set(set)
	}
	return rec
}

func tunnel(profile, outcome string) func(f *flows.Fields) {
	return func(f *flows.Fields) { f.Route, f.Profile, f.Outcome = "tunnel", profile, outcome }
}

func (r *rig) sample()                 { r.src.Sample(r.clk.now(), r.reg) }
func (r *rig) close(rec *flows.Record) { r.reg.Close(rec, r.clk.now()) }
func (r *rig) report(t *testing.T, period string) Report {
	t.Helper()
	rep, err := r.c.Report(r.clk.now(), period)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func (r *rig) today(t *testing.T) Counters { t.Helper(); return r.report(t, "today").Total }

func rowOf(rows []Row, key string) Row {
	for _, r := range rows {
		if r.Key == key {
			return r
		}
	}
	return Row{Key: "<none>"}
}

// validFile is a minimal day or month file.
func validFile(t *testing.T, name string, total Counters) []byte {
	t.Helper()
	kind, date, _ := parseName(name)
	f := &File{V: 1, Total: total, Apps: []Row{{Key: "a.exe", Counters: total}}}
	if kind == kindDay {
		f.Day = date
	} else {
		f.Month = date
	}
	b, err := f.marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
