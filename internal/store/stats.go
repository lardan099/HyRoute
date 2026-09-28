package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lardan099/hyroute/internal/stats"
)

// StatsFiles are the statistics files (internal/stats):
// %APPDATA%\HyRoute\stats\day-*.json, month-*.json and mode.json. The
// folder is guarded on first use, not in Open: a refused folder costs only
// the statistics. Reading an absent folder never creates it (a user who
// never collected anything gets no folder); the first write does.
type StatsFiles struct {
	s  *Store
	mu sync.Mutex
	ok bool // the folder passed Guard in this process
}

var _ stats.Files = (*StatsFiles)(nil)
var _ stats.Legacy = (*StatsFiles)(nil)

// Size limits of what is read: a day or month file, mode.json, and the
// statistics of HyRoute 1.2.0 (traffic.json).
const (
	statsFileMax   = 4 << 20
	statsModeMax   = 4 << 10
	legacyStatsMax = 16 << 20
	statsListMax   = 2000
)

// StatsFiles returns the statistics storage of s.
func (s *Store) StatsFiles() *StatsFiles { return &StatsFiles{s: s} }

func (f *StatsFiles) dir() string { return filepath.Join(f.s.Dir, "stats") }

func (f *StatsFiles) path(name string) string { return filepath.Join(f.dir(), name+".json") }

// ValidStatsName reports a statistics file name (without ".json"):
// day-YYYY-MM-DD, month-YYYY-MM or mode.
func ValidStatsName(name string) bool { return stats.ValidName(name) }

var errStatsName = errors.New("неверное имя файла статистики")

// present reports whether the folder exists. A folder that is not a plain
// directory (a link, a junction, a file) is refused before anything in it
// is read.
func (f *StatsFiles) present() (bool, error) {
	fi, err := os.Lstat(f.dir())
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if fi.Mode().Type() != fs.ModeDir { // a link, a junction, a file
		return false, &os.PathError{Op: "open", Path: f.dir(), Err: ErrNotRegular}
	}
	return true, nil
}

// guard runs Guard on the folder once per process (retried after a
// failure); it creates the folder.
func (f *StatsFiles) guard() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ok {
		return nil
	}
	if err := statsGuard(f.dir()); err != nil {
		return guardErr(f.dir(), err)
	}
	f.ok = true
	return nil
}

// statsGuard is Guard (tests replace it).
var statsGuard = Guard

// errStatsRefused is Guard's refusal of the folder (a link, a lock file that
// is a link, unusual permissions), without the path Guard's text names:
// the statistics show their errors and log them with file names only.
var errStatsRefused = errors.New("папка stats не прошла проверку (ссылка на другое место или необычные права доступа), HyRoute не пишет в неё. Замените её обычной папкой")

// guardErr is a refusal of Guard as an *os.PathError, whose message
// (what the statistics show) has no path: a *fs.PathError stays as it
// is, a system error is kept without Guard's text around it, anything
// else (a refusal) becomes errStatsRefused.
func guardErr(dir string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return err
	}
	reason := errStatsRefused
	var errno syscall.Errno // Guard's own system errors carry the path in their text
	if errors.As(err, &errno) {
		reason = errno
	}
	return &os.PathError{Op: "guard", Path: dir, Err: reason}
}

// ready: present and guarded; false when the folder is absent.
func (f *StatsFiles) ready() (bool, error) {
	ok, err := f.present()
	if err != nil || !ok {
		return false, err
	}
	return true, f.guard()
}

// List returns the valid day and month names in the folder (at most
// statsListMax), none when it is absent.
func (f *StatsFiles) List() ([]string, error) {
	ok, err := f.ready()
	if err != nil || !ok {
		return nil, err
	}
	ents, err := os.ReadDir(f.dir())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || name == "mode" || !ValidStatsName(name) || !e.Type().IsRegular() {
			continue
		}
		out = append(out, name)
		if len(out) >= statsListMax {
			break
		}
	}
	return out, nil
}

// Read reads a statistics file by handle (readDataFile): a link, a hard
// link, a folder or an oversize file is stats.ErrCorrupt.
func (f *StatsFiles) Read(name string) ([]byte, error) {
	if !ValidStatsName(name) {
		return nil, errStatsName
	}
	ok, err := f.ready()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &os.PathError{Op: "open", Path: name + ".json", Err: fs.ErrNotExist}
	}
	max := int64(statsFileMax)
	if name == "mode" {
		max = statsModeMax
	}
	b, err := readDataFile(f.path(name), max)
	if errors.Is(err, ErrNotRegular) || errors.Is(err, ErrTooLarge) {
		return nil, fmt.Errorf("%w: %s.json: %v", stats.ErrCorrupt, name, err)
	}
	return b, err
}

// Write replaces a statistics file (writeAtomic); the first write creates
// the folder.
func (f *StatsFiles) Write(name string, b []byte) error {
	if !ValidStatsName(name) {
		return errStatsName
	}
	if ok, err := f.present(); err != nil {
		return err
	} else if !ok {
		f.mu.Lock()
		f.ok = false // a folder removed meanwhile is guarded again
		f.mu.Unlock()
	}
	if err := f.guard(); err != nil {
		return err
	}
	return writeAtomic(f.path(name), b)
}

// Remove deletes a statistics file (a link itself, never its target).
func (f *StatsFiles) Remove(name string) error {
	if !ValidStatsName(name) {
		return errStatsName
	}
	ok, err := f.ready()
	if err != nil || !ok {
		return err
	}
	return os.Remove(f.path(name))
}

// SweepTemp removes the ".tmp-*" leftovers of writeAtomic (a crash or a
// kill in the middle of a write) last modified before before. Entries
// that are not regular files (a folder, a link) are left, except a link,
// which is removed itself.
func (f *StatsFiles) SweepTemp(before time.Time) (int, error) {
	ok, err := f.ready()
	if err != nil || !ok {
		return 0, err
	}
	ents, err := os.ReadDir(f.dir())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		p := filepath.Join(f.dir(), e.Name())
		fi, err := os.Lstat(p)
		if err != nil || fi.IsDir() || !fi.Mode().IsRegular() && fi.Mode()&fs.ModeSymlink == 0 || !fi.ModTime().Before(before) {
			continue
		}
		if os.Remove(p) == nil {
			n++
		}
	}
	return n, nil
}

// earlierFiles are the files whose presence before the statistics' mode
// was decided marks an upgrade (stats.Legacy.Upgraded).
var earlierFiles = []string{"traffic.json", "profiles.json", "settings.json", "prefs.json", "proxies.json", "subscriptions.json"}

// Upgraded reports that the data folder holds files of an earlier version:
// traffic.json (HyRoute 1.2.0's statistics), or the servers, rules,
// preferences or proxies. An error other than «not found» counts as there.
func (f *StatsFiles) Upgraded() bool {
	for _, n := range earlierFiles {
		if _, err := os.Lstat(f.s.path(n)); !errors.Is(err, fs.ErrNotExist) {
			return true
		}
	}
	return false
}

// ReadLegacy reads the statistics of HyRoute 1.2.0 (traffic.json) by
// handle, at most 16 MiB; a link or a larger file is stats.ErrCorrupt
// (never imported, not retried).
func (f *StatsFiles) ReadLegacy() ([]byte, error) {
	b, err := f.s.readRegular("traffic.json", legacyStatsMax)
	if errors.Is(err, ErrNotRegular) || errors.Is(err, ErrTooLarge) {
		return nil, fmt.Errorf("%w: traffic.json: %w", stats.ErrCorrupt, err)
	}
	return b, err
}
