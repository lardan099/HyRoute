package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/store"
)

// logFiles holds the on-disk logs; all writes are no-ops while logs stay
// in memory only.
type logFiles struct {
	mu     sync.Mutex
	dir    string
	on     bool
	max    int64
	keep   int
	engine *logx.RotatingFile
	hy     map[string]*logx.RotatingFile
	out    logx.Switch // the engine log handler writes here
}

// EngineWriter is the engine log's file output (switchable at runtime).
func (c *Controller) EngineWriter() io.Writer { return &c.files.out }

// LogDir is where log files go (empty = no files).
func (c *Controller) LogDir() string {
	c.files.mu.Lock()
	defer c.files.mu.Unlock()
	return c.files.dir
}

// SetLogDir enables file logging into dir according to the preferences.
// A folder an elevated HyRoute must not write to (see store.Guard) keeps
// logs in memory only.
func (c *Controller) SetLogDir(dir string) {
	if dir != "" {
		if err := store.Guard(dir); err != nil {
			c.Log.Warn("log files are off", "err", err)
			dir = ""
		}
	}
	c.files.mu.Lock()
	c.files.dir = dir
	c.files.mu.Unlock()
	c.applyLogPrefs()
}

func (c *Controller) applyLogPrefs() {
	c.mu.Lock()
	p := c.prefs
	c.mu.Unlock()
	f := &c.files
	f.mu.Lock()
	defer f.mu.Unlock()
	f.on, f.max, f.keep = p.ToDisk() && f.dir != "", p.MaxBytes(), p.Keep()
	if !f.on {
		f.out.Set(nil)
		f.closeLocked()
		return
	}
	if f.engine == nil {
		f.engine = &logx.RotatingFile{Path: filepath.Join(f.dir, "hyroute.log"), Header: "# HyRoute engine log"}
	}
	// The files may be written right now (under their own lock).
	f.engine.SetLimits(f.max, f.keep)
	for _, h := range f.hy {
		h.SetLimits(f.max, f.keep)
	}
	f.out.Set(f.engine)
}

func (f *logFiles) closeLocked() {
	if f.engine != nil {
		f.engine.Close()
		f.engine = nil
	}
	for _, h := range f.hy {
		h.Close()
	}
	f.hy = nil
}

// hysteriaFile returns the profile's log file, or nil when logs stay in
// memory.
func (c *Controller) hysteriaFile(id, name string) io.Writer {
	f := &c.files
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.on {
		return nil
	}
	if f.hy == nil {
		f.hy = map[string]*logx.RotatingFile{}
	}
	h := f.hy[id]
	if h == nil {
		h = &logx.RotatingFile{Path: filepath.Join(f.dir, "hysteria-"+safeName(id)+".log"),
			MaxBytes: f.max, Keep: f.keep, Header: "# Hysteria log, profile " + name}
		f.hy[id] = h
	}
	return h
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 128 && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return r
		}
		return '_'
	}, s)
}

// ---- preferences ----

func (c *Controller) Prefs() store.Prefs {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prefs
}

// SavePrefs replaces the prefs (UpdatePrefs, so under prefsMu).
func (c *Controller) SavePrefs(p store.Prefs) error {
	return c.UpdatePrefs(func(q *store.Prefs) error { *q = p; return nil })
}

// savePrefs checks and saves p (c.prefsMu held).
func (c *Controller) savePrefs(p store.Prefs) error {
	if p.UpdateCheck != "" && p.UpdateCheck != "auto" && p.UpdateCheck != "manual" {
		return fmt.Errorf("неизвестный режим проверки обновлений %q", p.UpdateCheck)
	}
	c.mu.Lock()
	broken := c.prefsBroken
	c.mu.Unlock()
	if broken != nil {
		return fmt.Errorf("prefs.json не загружен, изменения не сохраняются, чтобы не потерять настройки: %v", broken)
	}
	if err := c.Store.SavePrefs(p); err != nil {
		return err
	}
	c.mu.Lock()
	c.prefs = p
	c.mu.Unlock()
	c.applyLogPrefs()
	c.changed()
	return nil
}

// clearLogsHook, set by tests, runs in ClearLogs between closing the
// files and deleting them.
var clearLogsHook func()

// ClearLogs empties the in-memory logs and deletes the log files.
func (c *Controller) ClearLogs() error {
	c.EngineLog.Clear()
	c.HysteriaLog.Clear()
	c.hyMu.Lock()
	for _, j := range c.hyLogs {
		j.Clear()
	}
	c.hyMu.Unlock()
	f := &c.files
	// f.mu is held until the files are gone: a Hysteria line arriving
	// meanwhile would open its file again (hysteriaFile), and an open log
	// cannot be deleted.
	f.mu.Lock()
	dir := f.dir
	f.out.Set(nil)
	f.closeLocked()
	if clearLogsHook != nil {
		clearLogsHook()
	}
	var errs []error
	if dir != "" {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.log*"))
		for _, m := range matches {
			// dir is held by store.Guard: the names cannot lead elsewhere.
			if filepath.Base(m) == "crash.log" {
				// Held open by the runtime for crash reports: emptied,
				// not deleted (and never through a link).
				if err := logx.Truncate(m); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
				continue
			}
			if err := os.Remove(m); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	f.mu.Unlock()
	c.applyLogPrefs()
	c.Log.Info("logs cleared")
	return errors.Join(errs...)
}

// ExportLog formats a whole journal for saving (the UI polls only the
// newest entries). sanitized applies Privacy mode (secrets are always
// redacted already).
func (c *Controller) ExportLog(kind string, sanitized bool) string {
	var b strings.Builder
	for _, e := range c.journal(kind).Since(0, 0) {
		fmt.Fprintf(&b, "%s %-5s %s\r\n", e.Time.Format("2006-01-02 15:04:05.000"), strings.ToUpper(e.Level), e.Msg)
	}
	if sanitized {
		return c.Sanitize(b.String())
	}
	return b.String()
}

// Sanitize applies Privacy mode: public IPs, server hosts and URLs.
func (c *Controller) Sanitize(s string) string { return c.SanitizeFunc()(s) }
