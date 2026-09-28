package app

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/store"
)

// What the command line (hyroutectl, see internal/ctl) needs from the
// controller besides the calls the window makes: the tray's connect, the
// exit guard, one lock for every prefs.json change, the effective access
// mode, the newest log lines and a sanitizer for many strings.

// cliState is the controller state of this file.
type cliState struct {
	// prefsMu is held across the read and the write of every prefs.json
	// change (UpdatePrefs; RestoreBackup holds it around its writes).
	// Order: prefsMu → lifeMu → saveMu → mu; nothing holding lifeMu,
	// saveMu or mu takes it.
	prefsMu sync.Mutex
	// closing: HyRoute is exiting (BeginExit); Connect and Reconnect
	// refuse. shutDown: Shutdown ran, undo no longer clears closing. Both
	// guarded by lifeMu.
	closing, shutDown bool
}

// errClosing is what a connect gets once HyRoute is exiting.
var errClosing = errors.New("HyRoute завершает работу")

// BeginExit makes every later Connect/Reconnect fail with errClosing. Called
// by Shutdown and by the exit paths that disconnect before quitting
// (ApplyAppUpdate, «Перенести в Program Files»), so a CLI / tray / network
// connect in their 200 ms window does not start a session that Shutdown
// tears down again (and that races the updater's reconnect). undo clears
// the flag again for a path that fails before it quits (no effect once
// Shutdown has run).
func (c *Controller) BeginExit() (undo func()) {
	c.lifeMu.Lock()
	c.closing = true
	c.lifeMu.Unlock()
	return func() {
		c.lifeMu.Lock()
		if !c.shutDown {
			c.closing = false
		}
		c.lifeMu.Unlock()
	}
}

// beginShutdown is BeginExit for Shutdown: for good.
func (c *Controller) beginShutdown() {
	c.lifeMu.Lock()
	c.closing, c.shutDown = true, true
	c.lifeMu.Unlock()
}

// closingLocked: c.lifeMu is held.
func (c *Controller) closingLocked() error {
	if c.closing {
		return errClosing
	}
	return nil
}

// ConnectOrResume does what «Подключить» in the tray does: a session whose
// engine failed is reconnected (Connect would do nothing), a running one
// is left alone, otherwise routing starts.
func (c *Controller) ConnectOrResume() (already bool, err error) {
	st := c.Status()
	switch {
	case st.State == "error" && st.Stats != nil:
		return false, c.Reconnect()
	case st.State != "disconnected" && st.State != "error":
		return true, nil
	}
	return false, c.Connect()
}

// resolveByName finds q among names: exact (case-insensitive, trimmed),
// else a unique part of one. what is the noun for the texts, in the
// nominative («подписка»).
func resolveByName(names []string, q, what string) (int, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return -1, fmt.Errorf("укажите имя: %s", what)
	}
	for i, n := range names {
		if strings.EqualFold(strings.TrimSpace(n), q) {
			return i, nil
		}
	}
	lq := strings.ToLower(q)
	var hits []int
	for i, n := range names {
		if strings.Contains(strings.ToLower(n), lq) {
			hits = append(hits, i)
		}
	}
	switch len(hits) {
	case 0:
		return -1, fmt.Errorf("не найдено: %s «%s»", what, q)
	case 1:
		return hits[0], nil
	}
	quoted := make([]string, len(hits))
	for i, h := range hits {
		quoted[i] = "«" + names[h] + "»"
	}
	return -1, fmt.Errorf("«%s» подходит к нескольким (%s): %s — уточните", q, what, strings.Join(quoted, ", "))
}

// ResolveSubscription finds a subscription by name (exact, else a unique
// part of one) for the command line.
func (c *Controller) ResolveSubscription(q string) (string, error) {
	c.mu.Lock()
	names := make([]string, len(c.subs))
	ids := make([]string, len(c.subs))
	for i, s := range c.subs {
		names[i], ids[i] = s.Name, s.ID
	}
	c.mu.Unlock()
	i, err := resolveByName(names, q, "подписка")
	if err != nil {
		return "", err
	}
	return ids[i], nil
}

// UpdatePrefs applies fn to the current prefs and saves the result, under
// prefsMu (held across read and write; lock order prefsMu → mu). The
// prefsBroken refusal of SavePrefs applies.
func (c *Controller) UpdatePrefs(fn func(*store.Prefs) error) error {
	c.prefsMu.Lock()
	defer c.prefsMu.Unlock()
	p := c.Prefs()
	if err := fn(&p); err != nil {
		return err
	}
	return c.savePrefs(p)
}

// CLIMode is the effective hyroutectl access ("full", "read" or "off"):
// "off" while prefs.json is broken (the user may have chosen «Выключено»;
// saving is refused then, so the choice could not even be changed back).
// err is the load error.
func (c *Controller) CLIMode() (mode string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.prefsBroken != nil {
		return "off", c.prefsBroken
	}
	return c.prefs.CLIMode(), nil
}

// SanitizeFunc is Sanitize with the server hosts read once (c.mu held
// once), for masking many strings.
func (c *Controller) SanitizeFunc() func(string) string {
	c.mu.Lock()
	var hosts []string
	for _, p := range c.profiles.List {
		hosts = append(hosts, p.Host, p.TLS.SNI)
	}
	c.mu.Unlock()
	return func(s string) string { return logx.Sanitize(c.Redactor.Redact(s), hosts) }
}

// maxLogsTail is the most entries LogsTail returns (the size of the engine
// and Hysteria journals).
const maxLogsTail = 10000

// LogsTail returns the newest n entries of a journal (kinds as Logs),
// oldest first; n is capped at 10000.
func (c *Controller) LogsTail(kind string, n int) []logx.Entry {
	return c.journal(kind).Tail(max(0, min(n, maxLogsTail)))
}
