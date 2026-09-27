package app

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// Connect turns routing on: filters, relay, and a Hysteria for every
// profile the rules use. A Disconnect meanwhile waits for it, then stops
// what it started.
func (c *Controller) Connect() error {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	return c.connectLocked()
}

// connectLocked is Connect with c.lifeMu held.
func (c *Controller) connectLocked() error { return c.startLocked(false) }

// startLocked starts a session; recovering: the automatic reconnect after
// an engine failure. c.lifeMu must be held.
func (c *Controller) startLocked(recovering bool) error {
	c.mu.Lock()
	if c.sess != nil {
		c.mu.Unlock()
		return nil
	}
	// The rules in memory are the defaults, not the user's.
	if err := c.settingsBroken; err != nil {
		c.mu.Unlock()
		return fmt.Errorf("settings.json не загружен: с правилами по умолчанию весь трафик пошёл бы напрямую. Исправьте или удалите файл и перезапустите HyRoute. Ошибка: %v", err)
	}
	cfg := c.Base
	set, want := c.routingLocked()
	st := *c.settings
	cfg.Settings, cfg.Rules, cfg.Profiles = &st, set, want
	// SaveSettings compares engine options with what is starting.
	c.sessSet = &st
	c.starting, c.startErr = true, ""
	c.mu.Unlock()
	gen := c.newRecoverGen() // an engine failure of this session reconnects
	c.changed()

	// Connections the tunnel may have carried and nothing reset (the
	// resets of a failed engine may not have got through; a block from a
	// crash, an update or a reconnect kept the applications from seeing
	// them) are reset when their route depends on a domain the new engine
	// does not know yet, rather than sent on direct without it.
	ks, _ := c.killSwitchStatus()
	cfg.ResetUnknownDomain = recovering || ks == "blocking"

	cfg.Log = c.Log
	cfg.Redactor = c.Redactor
	cfg.OnEngineFail = func() { c.engineFailed(gen) }
	cfg.HysteriaLog = c.hysteriaLine
	cfg.OnStatus = func(id string, s hysteria.Status) {
		c.Log.Info("hysteria status", "profile", c.profileName(id), "state", s.State.String(), "msg", s.Message, "udp", s.UDPEnabled, "socks", s.SOCKS, "serverIPs", s.ServerIPs)
		c.changed()
	}
	names := make([]string, len(want))
	for i, p := range want {
		names[i] = p.Name
	}
	if len(want) == 0 {
		c.Log.Warn("connecting: no rule and not the default route uses a tunnel, all traffic stays direct")
	} else {
		c.Log.Info("connecting", "profiles", strings.Join(names, ", "))
	}
	sess, err := c.Start(cfg)

	c.mu.Lock()
	c.starting = false
	if err != nil {
		c.startErr = err.Error()
		c.mu.Unlock()
		c.Log.Error("connect failed", "err", err)
		c.changed()
		return err
	}
	c.sess, c.lastFlows, c.since = sess, sess.Flows(), time.Now()
	// Rules, profiles and servers saved while it started.
	c.applyRoutingLocked()
	c.mu.Unlock()
	c.Log.Info("connected: filters active")
	c.armKillSwitch(sess)
	c.syncProxies()
	c.changed()
	return nil
}

// profileName does not take c.mu: Hysteria status and log callbacks call
// it while c.mu may be held by code that waits for a Hysteria to stop.
func (c *Controller) profileName(id string) string {
	if m := c.names.Load(); m != nil {
		if n, ok := (*m)[id]; ok {
			return n
		}
	}
	return id
}

// Disconnect removes the filters and stops every Hysteria. The kill
// switch opens the internet too.
func (c *Controller) Disconnect() { c.disconnect(true) }

// Shutdown stops routing when HyRoute exits. Only Disconnect opens the
// internet: the kill switch block stays over an exit (not over the end of
// the Windows session, see EndSession).
func (c *Controller) Shutdown() { c.disconnect(false) }

// disconnect: with release unset the kill switch keeps the internet
// closed (reconnect). The relayed connections are reset first; then its
// pass filters go before the engine does, so no packet slips out in
// between.
func (c *Controller) disconnect(release bool) {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	c.disconnectLocked(release)
}

// disconnectLocked is disconnect with c.lifeMu held. It cancels an
// automatic reconnect not yet under way.
func (c *Controller) disconnectLocked(release bool) {
	c.newRecoverGen()
	c.mu.Lock()
	s := c.sess
	c.sess, c.startErr = nil, ""
	c.mu.Unlock()
	if s != nil {
		// While the kill switch's pass still lets the resets in.
		s.ResetConnections()
	}
	c.routingStopped(release)
	c.stopProxies()
	if s != nil {
		s.Stop()
		c.Log.Info("disconnected: filters removed")
	}
	c.changed()
}

// Reconnect applies engine options. The kill switch stays closed while
// routing restarts, and a Disconnect meanwhile comes after the new start.
func (c *Controller) Reconnect() error {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	c.disconnectLocked(false)
	return c.connectLocked()
}

// ---- status ----

type Status struct {
	// State: disconnected | starting | connecting | connected | tunnel-down | error
	State   string `json:"state"`
	Message string `json:"message"`
	// Main is the main profile (rules without an explicit profile).
	Main     string           `json:"main"`
	MainID   string           `json:"mainId"`
	Since    time.Time        `json:"since"`
	Tunnels  []tunnels.Status `json:"tunnels"`
	Stats    *session.Stats   `json:"stats,omitempty"`
	Warnings []RuleWarning    `json:"warnings"`
	// LoadError: profiles.json or settings.json could not be read.
	LoadError string `json:"loadError,omitempty"`
	// NoTunnel: routing is on but no rule (nor the default route) uses a
	// tunnel, so everything goes direct.
	NoTunnel bool `json:"noTunnel"`
	// KillSwitch: "" (off), "armed" or "blocking" (the internet is closed).
	KillSwitch      string `json:"killSwitch"`
	KillSwitchError string `json:"killSwitchError,omitempty"`
}

// down reports a profile that cannot carry traffic now: failed, or
// reconnecting after it already worked or refused connections.
func down(t tunnels.Status) bool {
	switch t.State {
	case "connected":
		return false
	case "connecting":
		return t.Restarts > 0 || t.Rejected > 0
	}
	return true
}

func (c *Controller) Status() Status {
	c.mu.Lock()
	s := c.sess
	st := Status{State: "disconnected", LoadError: c.loadErr, Tunnels: []tunnels.Status{}, Warnings: c.ruleWarningsLocked()}
	if p := c.profiles.Find(c.profiles.Active); p != nil {
		st.Main, st.MainID = p.Name, p.ID
	}
	if s != nil {
		st.Since = c.since
	}
	switch {
	case c.starting:
		st.State = "starting"
	case s == nil && c.startErr != "":
		st.State, st.Message = "error", c.startErr
	}
	c.mu.Unlock()
	st.KillSwitch, st.KillSwitchError = c.killSwitchStatus()
	if s == nil {
		if st.State == "error" {
			st.Message += c.startFailedNote()
		}
		return st
	}
	stats := s.Stats()
	st.Stats = &stats
	if s.EngineFailed() {
		st.State, st.Message = "error", c.engineFailedMessage(st.KillSwitch == "blocking")
		return st
	}
	for _, t := range s.Tunnels() {
		if !t.Test {
			st.Tunnels = append(st.Tunnels, t)
		}
	}
	st.State = "connected"
	var downMsgs []string
	for _, t := range st.Tunnels {
		switch {
		case down(t):
			st.State = "tunnel-down"
			m := fmt.Sprintf("%s недоступен, %d соединений отклонено", t.Name, t.Rejected)
			if t.Message != "" {
				m += ": " + t.Message
			}
			downMsgs = append(downMsgs, m)
		case t.State == "connecting" && st.State == "connected":
			st.State = "connecting"
		}
	}
	if len(downMsgs) > 0 {
		st.Message = strings.Join(downMsgs, "; ")
	} else if len(st.Tunnels) == 0 && len(st.Warnings) == 0 {
		st.NoTunnel = true
		st.Message = "Туннель не используется: ни одно правило не ведёт в туннель, всё идёт напрямую"
	}
	return st
}

// ---- connections ----

type Connections struct {
	Active []flows.View `json:"active"`
	Closed []flows.View `json:"closed"`
}

// Connections returns live flows and the newest closed ones (limit).
// After a disconnect only the closed ones remain: the engine does not
// close its direct flows when it stops.
func (c *Controller) Connections(limit int) Connections {
	c.mu.Lock()
	reg, live := c.lastFlows, c.sess != nil
	c.mu.Unlock()
	out := Connections{Active: []flows.View{}, Closed: []flows.View{}}
	if reg == nil {
		return out
	}
	// Closed first: a flow leaves the active list before it joins the
	// closed one, so one closing in between is in neither list this time,
	// never in both (the UI keys rows by ID).
	closed := reg.Closed()
	if live {
		out.Active = reg.Active(time.Now())
	}
	sort.Slice(out.Active, func(i, j int) bool { return out.Active[i].ID > out.Active[j].ID })
	if limit > 0 && len(closed) > limit {
		closed = closed[len(closed)-limit:]
	}
	for i, j := 0, len(closed)-1; i < j; i, j = i+1, j-1 {
		closed[i], closed[j] = closed[j], closed[i]
	}
	if closed != nil { // none closed yet: [] rather than null
		out.Closed = closed
	}
	return out
}
