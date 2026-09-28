// Package core manages the Hysteria binary: the one shipped next to
// HyRoute and updates downloaded from apernet/hysteria releases. Updated
// cores live in a directory only administrators can write (HyRoute runs
// elevated and must not execute a file a normal process could replace),
// are verified by SHA256 before every start, and the previous core is kept
// for a rollback.
package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/release"
	"github.com/lardan099/hyroute/internal/update"
)

const (
	Repo      = "apernet/hysteria"
	AssetName = "hysteria-windows-amd64.exe"
	// Major is the Hysteria major version HyRoute's config generator
	// speaks; other majors are never offered.
	Major = 2
)

type entry struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type state struct {
	Current  *entry `json:"current,omitempty"`
	Previous *entry `json:"previous,omitempty"`
}

type Manager struct {
	// Dir holds <version>\hysteria.exe and core.json (protected).
	Dir string
	// Bundled is the hysteria.exe next to HyRoute.
	Bundled string
	Client  *release.Client
	// Version runs "hysteria version" (hysteria.ExeVersion).
	Version func(path string) (string, error)

	mu       sync.Mutex
	st       state
	loaded   bool
	loadErr  string               // core.json refused (see load)
	verCache map[string]verResult // path|mtime -> version
	hashOK   map[string]string    // path|mtime|size -> sha256 verified
}

type verResult struct {
	v     string
	retry time.Time // zero: final; else a failure, run again after it
}

// verRetry is how long a failed "hysteria version" is not repeated: the
// UI asks often, and a core that hangs takes seconds each time.
var verRetry = time.Minute

// ownerOK is CheckOwner (tests replace it).
var ownerOK = CheckOwner

// load reads core.json. The file and its folder must be ones only an
// administrator could have written: a folder a normal process created
// first (and still owns) would name its own hysteria.exe and hash, and
// HyRoute would start it elevated.
func (m *Manager) load() {
	if m.loaded {
		return
	}
	m.loaded = true
	p := filepath.Join(m.Dir, "core.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	for _, f := range []string{m.Dir, p} {
		if err := ownerOK(f); err != nil {
			m.loadErr = "обновление ядра не используется: " + err.Error()
			return
		}
	}
	json.Unmarshal(b, &m.st)
}

func (m *Manager) save() error {
	b, _ := json.MarshalIndent(m.st, "", "  ")
	tmp := filepath.Join(m.Dir, "core.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(m.Dir, "core.json"))
}

func (m *Manager) path(e *entry) string {
	return filepath.Join(m.Dir, e.Version, "hysteria.exe")
}

// verified reports whether e's file still has its recorded hash.
func (m *Manager) verified(e *entry) bool {
	p := m.path(e)
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	key := fmt.Sprintf("%s|%d|%d", p, fi.ModTime().UnixNano(), fi.Size())
	if m.hashOK[key] == e.SHA256 {
		return true
	}
	sum, err := fileSHA256(p)
	if err != nil || !strings.EqualFold(sum, e.SHA256) {
		return false
	}
	if m.hashOK == nil {
		m.hashOK = map[string]string{}
	}
	m.hashOK[key] = e.SHA256
	return true
}

// Path is the hysteria.exe to start: the installed update when its hash
// checks out and it is newer than the bundled core, otherwise the bundled
// one.
func (m *Manager) Path() string {
	m.mu.Lock()
	m.load()
	cur := m.st.Current
	ok := cur != nil && m.verified(cur)
	m.mu.Unlock()
	if !ok {
		return m.Bundled
	}
	// A HyRoute update may bring a bundled core as new as the downloaded
	// one or newer: that one runs, and the downloads are retired.
	if release.Compare(m.version(m.Bundled), cur.Version) >= 0 {
		m.retire(cur)
		return m.Bundled
	}
	return m.path(cur)
}

// retire goes back to the bundled core for good once it has caught up
// with cur (unless an install or rollback changed the state meanwhile):
// the downloaded cores are older, so neither is a rollback target. While
// a HyRoute update is still on trial (its journal exists until the new
// version reports healthy), the updater may yet bring back the previous
// HyRoute with its older bundled core: the downloads are then only left
// unused by this run, and retired for good on a later start.
func (m *Manager) retire(cur *entry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.Current != cur {
		return
	}
	m.st = state{}
	if m.updateOnTrial() {
		return
	}
	if m.save() == nil {
		m.prune()
	}
}

// updateOnTrial reports whether hyroute-updater's journal exists: it lies
// in %ProgramData%\HyRoute next to Dir (core.DefaultDir).
func (m *Manager) updateOnTrial() bool {
	_, err := os.Lstat(filepath.Join(filepath.Dir(m.Dir), update.JournalName))
	return err == nil
}

// Paths lists the cores that may be running: the one Path picks, the
// bundled one and the previous one (profiles started before a core
// update or rollback keep it until they restart). The kill switch lets
// them all through.
func (m *Manager) Paths() []string {
	out := []string{m.Path(), m.Bundled}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st.Previous != nil && m.verified(m.st.Previous) {
		out = append(out, m.path(m.st.Previous))
	}
	return out
}

// Info describes the cores for the UI.
type Info struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Bundled  string `json:"bundled"`  // bundled core version
	Updated  bool   `json:"updated"`  // an installed update is in use
	Previous string `json:"previous"` // rollback target ("" = none)
	Error    string `json:"error"`    // e.g. tampered file
}

func (m *Manager) Info() Info {
	p := m.Path()
	in := Info{Path: p, Version: m.version(p), Bundled: m.version(m.Bundled)}
	m.mu.Lock()
	defer m.mu.Unlock()
	in.Updated = p != m.Bundled
	if m.st.Current != nil && !in.Updated {
		in.Error = "установленное обновление ядра повреждено или изменено, используется встроенное"
	}
	if m.loadErr != "" {
		in.Error = m.loadErr
	}
	// A previous core no newer than the bundled one is never started (see
	// Path): a rollback lands on the bundled core. On the bundled core
	// (Current nil, e.g. after a rollback) there is nothing to roll back.
	if m.st.Current != nil && m.st.Previous != nil && m.verified(m.st.Previous) && release.Compare(m.st.Previous.Version, in.Bundled) > 0 {
		in.Previous = m.st.Previous.Version
	} else if in.Updated {
		in.Previous = "встроенное " + in.Bundled
	}
	return in
}

func (m *Manager) version(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return "не найден"
	}
	key := fmt.Sprintf("%s|%d", p, fi.ModTime().UnixNano())
	m.mu.Lock()
	c, ok := m.verCache[key]
	m.mu.Unlock()
	if ok && (c.retry.IsZero() || time.Now().Before(c.retry)) {
		return c.v
	}
	// A failure may be passing (a slow start at sign-in, an antivirus
	// scan): it is remembered only for a while.
	c = verResult{}
	c.v, err = m.Version(p)
	if err != nil {
		c.v, c.retry = "не запускается: "+err.Error(), time.Now().Add(verRetry)
	}
	m.mu.Lock()
	if m.verCache == nil {
		m.verCache = map[string]verResult{}
	}
	m.verCache[key] = c
	m.mu.Unlock()
	return c.v
}

// Update is an available core release.
type Update struct {
	Version   string    `json:"version"` // v2.12.4
	Tag       string    `json:"tag"`
	Notes     string    `json:"notes"`
	Published time.Time `json:"published"`
	Page      string    `json:"page"`
	url       string
	sha256    []string
}

// Check finds the newest stable Hysteria 2 release newer than the core in
// use. ok is false when the core is up to date.
func (m *Manager) Check(ctx context.Context) (u Update, ok bool, err error) {
	list, err := m.Client.Releases(ctx, Repo)
	if err != nil {
		return u, false, err
	}
	r, found := release.Latest(list, false, func(tag string) bool {
		v, err := release.Parse(tag)
		return err == nil && strings.HasPrefix(tag, "app/") && v.Major == Major
	})
	if !found {
		return u, false, errors.New("стабильных релизов Hysteria 2 не найдено")
	}
	cur := m.version(m.Path())
	if _, err := release.Parse(cur); err != nil {
		// Unknown is not older: the release may be the very core in use.
		return u, false, fmt.Errorf("версия текущего ядра неизвестна (%s)", cur)
	}
	if release.Compare(r.Tag, cur) <= 0 {
		return u, false, nil
	}
	a, has := r.Asset(AssetName)
	if !has {
		return u, false, fmt.Errorf("в релизе %s нет %s", r.Tag, AssetName)
	}
	u = Update{Version: strings.TrimPrefix(r.Tag, "app/"), Tag: r.Tag, Notes: r.Body, Published: r.Published, Page: r.Page, url: a.URL}
	// hashes.txt of the same release is the official list; GitHub's own
	// digest is checked too when present.
	if h, has := r.Asset("hashes.txt"); has {
		if list, err := m.Client.Fetch(ctx, h.URL); err == nil {
			if s := release.SumFor(list, AssetName); s != "" {
				u.sha256 = append(u.sha256, s)
			}
		}
	}
	if d := a.SHA256(); d != "" {
		u.sha256 = append(u.sha256, d)
	}
	if len(u.sha256) == 0 {
		return u, false, errors.New("у релиза нет контрольных сумм (hashes.txt): обновление небезопасно")
	}
	return u, true, nil
}

// Install downloads, verifies and activates u. The new core must answer
// "hysteria version" with the expected version before it becomes current;
// the old one becomes the rollback target. Running Hysteria processes are
// not touched: profiles pick the new core when they start next time.
func (m *Manager) Install(ctx context.Context, u Update, progress func(done, total int64)) error {
	if len(u.sha256) == 0 {
		return errors.New("нет контрольной суммы")
	}
	if err := ProtectDir(m.Dir); err != nil {
		return fmt.Errorf("папка ядра: %w", err)
	}
	dir := filepath.Join(m.Dir, u.Version)
	dst := filepath.Join(dir, "hysteria.exe")
	sum, err := m.Client.Download(ctx, u.url, dst, 200<<20, progress, u.sha256...)
	if err != nil {
		os.RemoveAll(dir)
		return err
	}
	got, err := m.Version(dst)
	if err != nil || release.Compare(got, u.Version) != 0 {
		os.RemoveAll(dir)
		if err == nil {
			err = fmt.Errorf("сообщает версию %s", got)
		}
		return fmt.Errorf("новое ядро не запускается, обновление отменено: %v", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	old := m.st
	m.st.Previous, m.st.Current = old.Current, &entry{Version: u.Version, SHA256: sum}
	if err := m.save(); err != nil {
		// core.json is unchanged: so is the state, and the new core's
		// folder goes unless it is one of the kept ones.
		m.st = old
		if (old.Current == nil || old.Current.Version != u.Version) && (old.Previous == nil || old.Previous.Version != u.Version) {
			os.RemoveAll(dir)
		}
		return err
	}
	m.prune()
	return nil
}

// Rollback returns to the previous core (or the bundled one).
func (m *Manager) Rollback() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.load()
	if m.st.Current == nil {
		return errors.New("используется встроенное ядро, откатываться некуда")
	}
	old := m.st
	if m.st.Previous != nil && !m.verified(m.st.Previous) {
		m.st.Previous = nil
	}
	m.st.Current, m.st.Previous = m.st.Previous, m.st.Current
	if err := m.save(); err != nil {
		m.st = old // core.json is unchanged
		return err
	}
	return nil
}

// prune removes version directories other than current and previous.
func (m *Manager) prune() {
	keep := map[string]bool{}
	for _, e := range []*entry{m.st.Current, m.st.Previous} {
		if e != nil {
			keep[e.Version] = true
		}
	}
	ents, _ := os.ReadDir(m.Dir)
	for _, e := range ents {
		if e.IsDir() && !keep[e.Name()] {
			os.RemoveAll(filepath.Join(m.Dir, e.Name()))
		}
	}
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
