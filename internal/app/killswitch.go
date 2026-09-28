package app

import "errors"

// KillSwitch closes the internet while routing is down without a
// Disconnect (see package killswitch).
type KillSwitch interface {
	// Arm: the engine is up. Routing decides; the block waits underneath.
	// relayPort is the port the session's relay listens on: the block
	// keeps it closed to other hosts. On an error part of it may be
	// installed (the pass goes first).
	Arm(relayPort uint16) error
	// Close: the engine is gone. The block takes effect.
	Close() error
	// Release removes everything.
	Release() error
	// Engaged: the block is installed (maybe left by a crashed run). An
	// error with true: it is installed, but another HyRoute looks after it.
	Engaged() (bool, error)
}

type ksState struct {
	blocks bool   // block filters installed
	armed  bool   // pass filters on (engine up)
	hold   bool   // keep the block over the coming exit (update)
	ending bool   // Windows is ending the session: nothing arms (EndSession)
	resume bool   // EndSession removed a block: SessionResumed puts it back
	relay  uint16 // the relay port of the last Arm (see restoreBlock)
	err    string // last failure, shown in the status
}

// InitKillSwitch finds a block left by a run that ended without a
// Disconnect. It stays until the user connects or unblocks.
func (c *Controller) InitKillSwitch() {
	if c.KillSwitch == nil {
		return
	}
	on, err := c.KillSwitch.Engaged()
	if err != nil {
		c.Log.Error("kill switch state unknown", "err", err)
		// Another HyRoute (another Windows user's) owns an installed
		// block: the internet may be closed for this user too, whatever
		// the setting. Otherwise it matters only with the kill switch on.
		if set, known := c.killSwitchSetting(); on || set || !known {
			c.ksMu.Lock()
			c.ks.err = err.Error()
			c.ksMu.Unlock()
		}
		return
	}
	if on {
		c.ksMu.Lock()
		c.ks.blocks = true
		c.ksMu.Unlock()
		c.Log.Warn("kill switch: the internet is blocked, the previous run ended without disconnecting; connect or unblock")
		// The block may be another copy's (the one this copy was moved or
		// updated from): its exception lets that copy's program through,
		// not this one's.
		c.refreshKillSwitchApps()
	}
}

// killSwitchSetting reads the setting. known is false while settings.json
// is not loaded: "off" is then the default, not the user's choice, and
// must not open a block a previous run left.
func (c *Controller) killSwitchSetting() (on, known bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.settings.KillSwitchOn(), c.settingsBroken == nil
}

// armKillSwitch runs after the engine of s came up.
func (c *Controller) armKillSwitch(s Session) {
	if c.KillSwitch == nil {
		return
	}
	on, known := c.killSwitchSetting()
	relayPort := uint16(s.Stats().RelayPort)
	c.ksMu.Lock()
	defer c.ksMu.Unlock()
	if c.ks.ending {
		return // a Connect racing the end of the session sets no block
	}
	if !on {
		if c.ks.blocks && known {
			c.releaseLocked()
		}
		return
	}
	if err := c.KillSwitch.Arm(relayPort); err != nil {
		c.Log.Error("kill switch not armed", "err", err)
		c.undoArmLocked(err)
		return
	}
	c.ks.blocks, c.ks.armed, c.ks.err, c.ks.relay = true, true, "", relayPort
	// The engine may have failed before the pass went in: engineFailed
	// then found nothing armed to close. The engine marks itself failed
	// before it reports, so either this sees it or engineFailed sees armed.
	if s.EngineFailed() {
		c.closePassLocked()
		return
	}
	c.Log.Info("kill switch armed: if routing stops without Disconnect, the internet stays closed")
}

// undoArmLocked removes what a failed Arm installed: its pass would let
// everything through with nothing to close it when the engine fails, while
// the status said "blocking". Routing works without the kill switch; the
// status shows why.
func (c *Controller) undoArmLocked(err error) {
	c.ks.armed, c.ks.err = false, err.Error()
	rerr := c.KillSwitch.Release()
	if rerr == nil {
		c.ks.blocks = false
		return
	}
	c.Log.Error("kill switch: filters of the failed arm not removed", "err", rerr)
	// Without the pass whatever stayed blocks, as the status then says.
	c.KillSwitch.Close()
	if on, eerr := c.KillSwitch.Engaged(); eerr == nil {
		c.ks.blocks = on
	} // else the filter service is unreachable and Arm installed nothing
}

// closePassLocked makes an armed block take effect.
func (c *Controller) closePassLocked() {
	if err := c.KillSwitch.Close(); err != nil {
		c.Log.Error("kill switch: pass filters not removed", "err", err)
	}
	c.ks.armed = false
	c.Log.Warn("kill switch: the engine failed, the internet is closed until routing is back or you unblock")
}

// engineFailed is called by the engine of the session gen started, on
// the engine's goroutine, before it removes its filters. It must not
// wait for lifeMu or c.mu: the reconnect runs later on its own goroutine.
func (c *Controller) engineFailed(gen uint64) {
	c.stats.EngineFailed(c.statsNow()) // stats (a leaf lock)
	if c.KillSwitch != nil {
		c.ksMu.Lock()
		if c.ks.armed {
			c.closePassLocked()
		}
		c.ksMu.Unlock()
	}
	c.scheduleRecover(gen)
	c.changed()
}

// routingStopped: the session ended. A Disconnect opens the internet;
// a reconnect, an exit or an update keeps it closed.
func (c *Controller) routingStopped(release bool) {
	if c.KillSwitch == nil {
		return
	}
	c.ksMu.Lock()
	defer c.ksMu.Unlock()
	if release && !c.ks.hold {
		c.ks.resume = false // a Disconnect while Windows ends the session
	}
	if !c.ks.blocks {
		return
	}
	if release && !c.ks.hold {
		c.releaseLocked()
		return
	}
	if c.ks.armed {
		if err := c.KillSwitch.Close(); err != nil {
			c.Log.Error("kill switch: pass filters not removed", "err", err)
		}
		c.ks.armed = false
	}
}

func (c *Controller) releaseLocked() error {
	if err := c.KillSwitch.Release(); err != nil {
		c.ks.err = err.Error()
		c.Log.Error("kill switch not released", "err", err)
		return err
	}
	c.ks.blocks, c.ks.armed, c.ks.err, c.ks.resume = false, false, "", false
	c.Log.Info("kill switch released: the internet is open")
	return nil
}

// blockLocked installs the block without the pass while routing is down:
// the internet closes.
func (c *Controller) blockLocked(relayPort uint16) {
	err := c.KillSwitch.Arm(relayPort)
	if cerr := c.KillSwitch.Close(); cerr != nil {
		c.Log.Error("kill switch: pass filters not removed", "err", cerr)
	}
	c.ks.armed = false
	if err != nil {
		c.ks.err = err.Error()
		c.Log.Error("kill switch: the block not installed", "err", err)
		if on, eerr := c.KillSwitch.Engaged(); eerr == nil {
			c.ks.blocks = on
		}
		return
	}
	c.ks.blocks, c.ks.err = true, ""
	c.Log.Warn("kill switch: routing is down, the internet is closed until routing is back or you unblock")
}

// ReleaseKillSwitch opens the internet (the user's "unblock"). Once
// routing is back (an automatic reconnect armed the kill switch again
// while the button was still shown) the internet is open already: the
// kill switch keeps guarding the session rather than go until the next
// Connect.
func (c *Controller) ReleaseKillSwitch() error {
	if c.KillSwitch == nil {
		return errors.New("kill switch недоступен")
	}
	c.netManual() // netmodes: the user's choice wins until the network changes
	c.ksMu.Lock()
	var err error
	if c.ks.armed {
		c.Log.Info("unblock: routing is back already, the kill switch stays armed")
	} else {
		err = c.releaseLocked()
	}
	c.ksMu.Unlock()
	c.changed()
	return err
}

// HoldKillSwitch keeps the block over the exit before an update: the new
// version arms it again once it reconnects.
func (c *Controller) HoldKillSwitch() {
	c.ksMu.Lock()
	c.ks.hold = true
	c.ksMu.Unlock()
}

// EndSession: Windows is shutting down, restarting or signing out. The
// block goes as on Disconnect: it is meant to last until Windows
// restarts, and a shutdown with Fast Startup keeps the filter engine
// (hibernated with the block), so the next boot would have no internet
// and no HyRoute to say why. The engine stops with the process. Until
// SessionResumed nothing arms the block again (a Connect or reconnect
// under way); lifeMu is not taken: the tray's window procedure must not
// wait for a Connect. The statistics are saved last, without a Controller
// lock and with a bounded wait (statsSessionEnd).
func (c *Controller) EndSession() {
	if c.KillSwitch != nil {
		c.ksMu.Lock()
		c.ks.ending = true
		if c.ks.blocks {
			c.Log.Info("Windows is ending the session: removing the kill switch block")
			c.releaseLocked()
			c.ks.resume = true
		}
		c.ksMu.Unlock()
	}
	c.statsSessionEnd() // stats: no Controller lock, a bounded wait
}

// SessionResumed: the end of the session was cancelled (another program
// refused it) and HyRoute goes on. The kill switch follows the setting
// again: a working session is armed, and a block EndSession removed
// closes the internet again while routing is down (the engine failed, a
// block a crash left, a reconnect that failed).
func (c *Controller) SessionResumed() {
	if c.KillSwitch == nil {
		return
	}
	c.ksMu.Lock()
	was := c.ks.ending
	c.ks.ending = false
	c.ksMu.Unlock()
	if !was {
		return
	}
	c.Log.Info("the end of the Windows session was cancelled: the kill switch follows the setting again")
	c.applyKillSwitch()
	c.restoreBlock()
	c.changed()
}

// restoreBlock puts back the block EndSession removed, unless routing
// works, the user opened the internet meanwhile (Disconnect, unblock,
// the setting turned off) or something installed it again.
func (c *Controller) restoreBlock() {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	on, known := c.killSwitchSetting()
	c.mu.Lock()
	s := c.sess
	c.mu.Unlock()
	c.ksMu.Lock()
	defer c.ksMu.Unlock()
	if c.ks.ending {
		return // Windows is ending the session again: resume stays for its SessionResumed
	}
	resume := c.ks.resume
	c.ks.resume = false
	switch {
	case !resume || c.ks.blocks:
		return
	case !on && known:
		return
	case s != nil && !s.EngineFailed():
		return // armed by applyKillSwitch, or its Arm failed and said so
	}
	// The failed session's relay port as its Arm left it: s.Stats would
	// take the engine's locks, which a packet loop the watchdog gave up on
	// may hold for good (lifeMu and ksMu are held here).
	var relayPort uint16
	if s != nil {
		relayPort = c.ks.relay
	}
	c.blockLocked(relayPort)
}

// applyKillSwitch follows a settings change while connected.
func (c *Controller) applyKillSwitch() {
	if c.KillSwitch == nil {
		return
	}
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	on, known := c.killSwitchSetting()
	c.mu.Lock()
	s := c.sess
	c.mu.Unlock()
	switch {
	case on && s != nil && !s.EngineFailed():
		c.armKillSwitch(s)
	case !on && known:
		c.ksMu.Lock()
		c.ks.resume = false
		if c.ks.blocks {
			c.releaseLocked()
		}
		c.ksMu.Unlock()
	}
}

// killSwitchStatus: "" (off), "armed" (routing up, the block waits) or
// "blocking" (the internet is closed).
func (c *Controller) killSwitchStatus() (state, errText string) {
	c.ksMu.Lock()
	defer c.ksMu.Unlock()
	switch {
	case c.ks.armed:
		state = "armed"
	case c.ks.blocks:
		state = "blocking"
	}
	return state, c.ks.err
}
