// Package backup makes and restores copies of the controller's database
// (P4-01). A copy is a consistent snapshot of the SQLite file (VACUUM
// INTO), optionally encrypted with a passphrase. The master key never
// goes into a copy: a copy restores only with the key it was made with.
package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/datadir"
)

// Snapshotter writes a consistent copy of the database to a new file.
type Snapshotter interface {
	Snapshot(ctx context.Context, path string) error
}

// Info is a copy in the backups directory.
type Info struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	At        time.Time `json:"at"`
	Encrypted bool      `json:"encrypted"`
}

// Result is how the latest copy of this process went.
type Result struct {
	At    time.Time `json:"at"`
	Name  string    `json:"name,omitempty"`
	Error string    `json:"error,omitempty"`
}

// Copies are named by the UTC time they were made, so names sort by age.
const timeLayout = "20060102-150405"

var nameRE = regexp.MustCompile(`^hyroute-server-(\d{8}-\d{6})(-\d+)?\.db(\.enc)?$`)

// ErrNotFound: no copy with this name.
var ErrNotFound = errors.New("копия не найдена")

// Manager keeps the copies in Dir: Make adds one and drops the oldest
// beyond Keep, Run makes them every Interval.
type Manager struct {
	DB  Snapshotter
	Dir string
	// Keep is how many copies Make leaves (0: all).
	Keep int
	// Passphrase encrypts the copies ("": they are not encrypted).
	Passphrase string
	// Interval is how often Run makes a copy (0: Run does nothing).
	Interval time.Duration
	// Tick is how often Run looks whether a copy is due (0: 5 minutes).
	Tick time.Duration
	Log  *slog.Logger
	Now  func() time.Time

	mu   sync.Mutex
	last Result
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) log() *slog.Logger {
	if m.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return m.Log
}

// Last is the result of the latest Make of this process (zero: none).
func (m *Manager) Last() Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

// Make adds a copy and drops the oldest ones beyond Keep.
func (m *Manager) Make(ctx context.Context) (Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info, err := m.make(ctx)
	m.last = Result{At: m.now(), Name: info.Name}
	if err != nil {
		m.last.Error = err.Error()
		return Info{}, err
	}
	if err := m.prune(); err != nil {
		m.log().Warn("backup: drop old copies", "err", err)
	}
	return info, nil
}

func (m *Manager) make(ctx context.Context) (Info, error) {
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		return Info{}, err
	}
	if err := datadir.Dir(m.Dir); err != nil {
		return Info{}, err
	}
	at := m.now().UTC()
	ext := ".db"
	if m.Passphrase != "" {
		ext = ".db.enc"
	}
	base := "hyroute-server-" + at.Format(timeLayout)
	name := base + ext
	for i := 2; exists(filepath.Join(m.Dir, name)); i++ {
		name = fmt.Sprintf("%s-%d%s", base, i, ext)
	}
	path := filepath.Join(m.Dir, name)
	// The snapshot is the whole database unencrypted: it is taken in the
	// data directory, never next to the copies, which may be synced
	// elsewhere.
	tmp := filepath.Dir(m.Dir)
	m.sweep(tmp)
	if err := Write(ctx, m.DB, tmp, path, m.Passphrase); err != nil {
		return Info{}, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return Info{}, err
	}
	return Info{Name: name, Size: st.Size(), At: at, Encrypted: m.Passphrase != ""}, nil
}

// leftover is how old a snapshot or a part of a copy must be before a
// later copy takes it for the remains of a killed run: one of a copy in
// progress elsewhere (the command next to the service) is younger.
const leftover = time.Hour

// sweep removes the remains of copies a killed process left: snapshots
// in the data directory, unfinished copies in Dir.
func (m *Manager) sweep(tmp string) {
	for _, d := range []struct{ dir, prefix string }{{tmp, ".snapshot-hyroute-server-"}, {m.Dir, ".part-hyroute-server-"}, {m.Dir, ".snapshot-hyroute-server-"}} {
		entries, err := os.ReadDir(d.dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasPrefix(e.Name(), d.prefix) || !e.Type().IsRegular() {
				continue
			}
			if st, err := e.Info(); err == nil && m.now().Sub(st.ModTime()) > leftover {
				os.Remove(filepath.Join(d.dir, e.Name()))
			}
		}
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// Write makes a copy of db at path, encrypted when passphrase is set. The
// snapshot is taken in tmpDir, an owner-only directory (SQLite creates it
// with the umask's mode); path is created owner-only, never over an
// existing file, and appears only once complete.
func Write(ctx context.Context, db Snapshotter, tmpDir, path, passphrase string) (err error) {
	if exists(path) {
		return fmt.Errorf("%s already exists", path)
	}
	snap := filepath.Join(tmpDir, ".snapshot-"+filepath.Base(path))
	os.Remove(snap) // a leftover of a killed run
	if err := db.Snapshot(ctx, snap); err != nil {
		os.Remove(snap)
		return fmt.Errorf("snapshot: %w", err)
	}
	defer os.Remove(snap)
	if err := os.Chmod(snap, 0o600); err != nil {
		return err
	}
	src, err := os.Open(snap)
	if err != nil {
		return err
	}
	defer src.Close()
	part := filepath.Join(filepath.Dir(path), ".part-"+filepath.Base(path))
	os.Remove(part)
	f, err := datadir.Create(part)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(part)
		}
	}()
	if passphrase != "" {
		err = encrypt(f, src, passphrase)
	} else {
		_, err = io.Copy(f, src)
	}
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if exists(path) {
		return fmt.Errorf("%s already exists", path)
	}
	return datadir.Replace(part, path)
}

// List is the copies in Dir, newest first.
func (m *Manager) List() ([]Info, error) {
	entries, err := os.ReadDir(m.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, e := range entries {
		sub := nameRE.FindStringSubmatch(e.Name())
		if sub == nil || !e.Type().IsRegular() {
			continue
		}
		at, err := time.Parse(timeLayout, sub[1])
		if err != nil {
			continue
		}
		st, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{Name: e.Name(), Size: st.Size(), At: at, Encrypted: sub[3] != ""})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return copyNumber(out[i].Name) > copyNumber(out[j].Name)
	})
	return out, nil
}

// copyNumber is N of a name …-N.db (1 without it).
func copyNumber(name string) int {
	sub := nameRE.FindStringSubmatch(name)
	n := 1
	if sub != nil && sub[2] != "" {
		fmt.Sscanf(sub[2], "-%d", &n)
	}
	return n
}

// prune removes the oldest copies beyond Keep; files with other names
// are not touched.
func (m *Manager) prune() error {
	if m.Keep <= 0 {
		return nil
	}
	list, err := m.List()
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range list[min(m.Keep, len(list)):] {
		if err := os.Remove(filepath.Join(m.Dir, c.Name)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Open opens a copy by its name for download.
func (m *Manager) Open(name string) (*os.File, Info, error) {
	if !nameRE.MatchString(name) || strings.ContainsAny(name, `/\`) {
		return nil, Info{}, ErrNotFound
	}
	list, err := m.List()
	if err != nil {
		return nil, Info{}, err
	}
	for _, c := range list {
		if c.Name == name {
			f, err := os.Open(filepath.Join(m.Dir, name))
			if errors.Is(err, os.ErrNotExist) {
				return nil, Info{}, ErrNotFound
			}
			return f, c, err
		}
	}
	return nil, Info{}, ErrNotFound
}

// Run makes a copy whenever the newest one is Interval old, until ctx
// ends.
func (m *Manager) Run(ctx context.Context) {
	if m.Interval <= 0 {
		return
	}
	tick := m.Tick
	if tick == 0 {
		tick = 5 * time.Minute
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		m.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round makes a copy when one is due: there is none, or the newest is
// Interval old. A failed copy is tried again after an hour (or Interval,
// when shorter), not every tick.
func (m *Manager) Round(ctx context.Context) {
	list, err := m.List()
	if err != nil {
		m.log().Warn("backup: list copies", "dir", m.Dir, "err", err)
		return
	}
	now := m.now()
	if len(list) > 0 && now.Sub(list[0].At) < m.Interval {
		return
	}
	if last := m.Last(); last.Error != "" && now.Sub(last.At) < min(m.Interval, time.Hour) {
		return
	}
	info, err := m.Make(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log().Warn("backup failed", "dir", m.Dir, "err", err)
		}
		return
	}
	m.log().Info("backup made", "file", filepath.Join(m.Dir, info.Name), "size", info.Size, "encrypted", info.Encrypted)
}

// Passphrase is the passphrase of the copies: the environment variable
// env, else the file (owner-only on Unix, like the master key), else "".
func Passphrase(getenv func(string) string, env, file string) (string, error) {
	if v := strings.TrimSpace(getenv(env)); v != "" {
		return v, nil
	}
	if file == "" {
		return "", nil
	}
	st, err := os.Stat(file)
	if err != nil {
		return "", fmt.Errorf("backup passphrase: %w", err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("backup passphrase file %s has mode %v: allow only its owner (chmod 600)", file, st.Mode().Perm())
	}
	if err := datadir.Check(file, false); err != nil {
		return "", fmt.Errorf("backup passphrase file: %w", err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("backup passphrase: %w", err)
	}
	p := strings.TrimSpace(string(b))
	if p == "" {
		return "", fmt.Errorf("backup passphrase file %s is empty", file)
	}
	return p, nil
}
