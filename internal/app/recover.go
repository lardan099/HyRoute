package app

import (
	"fmt"
	"time"
)

// An engine that failed (watchdog, panic, Recv error) removed its filters:
// traffic goes direct, or with the kill switch nowhere. The controller
// reconnects on its own: the new session has a new engine, so a packet
// loop stuck in the old one does not hold routing, and the kill switch
// block stays while it restarts (as on Reconnect). An engine that keeps
// failing is left to the user.
const (
	engineRecoverDelay  = 5 * time.Second
	engineRecoverMax    = 3                // automatic reconnects...
	engineRecoverWindow = 10 * time.Minute // ...within this time
)

type recoverState struct {
	// gen names the session started last; every start and stop changes
	// it. A failure of an older session, and an attempt scheduled before a
	// Connect, Disconnect or Reconnect, see another gen and do nothing.
	gen      uint64
	timer    *time.Timer // the attempt waiting for its delay
	attempts []time.Time // automatic reconnects, the last engineRecoverWindow
	gaveUp   bool        // the engine of gen failed after engineRecoverMax attempts
}

// newRecoverGen cancels a pending attempt; the session starting or
// stopping gets a new gen. c.lifeMu must be held.
func (c *Controller) newRecoverGen() uint64 {
	c.recMu.Lock()
	defer c.recMu.Unlock()
	c.rec.gen++
	if c.rec.timer != nil {
		c.rec.timer.Stop()
		c.rec.timer = nil
	}
	c.rec.gaveUp = false
	return c.rec.gen
}

// scheduleRecover plans a reconnect after the engine of gen failed, or
// after an automatic reconnect did not start. It runs in the engine's
// failure callback, so it only starts a timer.
func (c *Controller) scheduleRecover(gen uint64) {
	c.recMu.Lock()
	if gen != c.rec.gen || c.rec.timer != nil {
		c.recMu.Unlock()
		return // an older session's engine, or already planned
	}
	now := time.Now()
	recent := c.rec.attempts[:0]
	for _, t := range c.rec.attempts {
		if now.Sub(t) < engineRecoverWindow {
			recent = append(recent, t)
		}
	}
	c.rec.attempts = recent
	n := len(recent)
	c.rec.gaveUp = n >= engineRecoverMax
	if !c.rec.gaveUp {
		c.rec.timer = time.AfterFunc(c.recoverDelay, func() { c.recoverEngine(gen) })
	}
	c.recMu.Unlock()
	if n >= engineRecoverMax {
		c.Log.Error("engine failed again: no more automatic reconnects, reconnect manually", "attempts", n, "within", engineRecoverWindow)
		if c.OnGiveUp != nil {
			go c.OnGiveUp()
		}
		return
	}
	c.Log.Warn("engine failed: reconnecting automatically", "in", c.recoverDelay, "attempt", n+1, "of", engineRecoverMax)
}

// recoverEngine is the planned attempt, on the timer's goroutine. It
// waits for a Connect or Disconnect under way; one that got there first
// changed the gen and cancelled it.
func (c *Controller) recoverEngine(gen uint64) {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	c.recMu.Lock()
	current := gen == c.rec.gen
	if current {
		c.rec.timer = nil
	}
	c.recMu.Unlock()
	if !current {
		return
	}
	c.mu.Lock()
	s := c.sess
	c.mu.Unlock()
	// No session: the last automatic reconnect did not start (a Connect
	// or Disconnect since would have changed the gen).
	if s != nil && !s.EngineFailed() {
		return
	}
	c.recMu.Lock()
	c.rec.attempts = append(c.rec.attempts, time.Now())
	n := len(c.rec.attempts)
	c.recMu.Unlock()
	c.Log.Warn("reconnecting after the engine failure", "attempt", n, "of", engineRecoverMax)
	c.disconnectLocked(false) // the kill switch block stays
	if c.startLocked(true) != nil {
		// Logged and shown in the status. It counts as an attempt: the
		// next one follows, or the user is told.
		c.recMu.Lock()
		gen := c.rec.gen // startLocked's; lifeMu keeps it
		c.recMu.Unlock()
		c.scheduleRecover(gen)
		c.changed()
	}
}

// startFailedNote follows the error of a start that failed: whether
// HyRoute tries again by itself.
func (c *Controller) startFailedNote() string {
	c.recMu.Lock()
	pending, gaveUp := c.rec.timer != nil, c.rec.gaveUp
	c.recMu.Unlock()
	switch {
	case pending:
		return " HyRoute попробует подключиться ещё раз через несколько секунд."
	case gaveUp:
		return fmt.Sprintf(" Автоматические переподключения после отказа движка (%d за %d минут) не помогли: подключитесь вручную.", engineRecoverMax, int(engineRecoverWindow/time.Minute))
	}
	return ""
}

// engineFailedMessage is the status of a session whose engine failed.
func (c *Controller) engineFailedMessage(blocking bool) string {
	c.recMu.Lock()
	pending, gaveUp := c.rec.timer != nil, c.rec.gaveUp
	c.recMu.Unlock()
	switch {
	case pending && blocking:
		return "Движок перехвата остановлен из-за ошибки. Kill switch закрыл интернет; HyRoute переподключится сам через несколько секунд."
	case pending:
		return "Движок перехвата остановлен из-за ошибки, фильтры сняты (трафик идёт напрямую). HyRoute переподключится сам через несколько секунд."
	case gaveUp:
		msg := fmt.Sprintf("Движок перехвата снова отказал: %d автоматических переподключения за %d минут не помогли. ", engineRecoverMax, int(engineRecoverWindow/time.Minute))
		if blocking {
			return msg + "Kill switch закрыл интернет: переподключитесь вручную или разблокируйте."
		}
		return msg + "Фильтры сняты (трафик идёт напрямую): переподключитесь вручную."
	case blocking:
		return "Движок перехвата остановлен из-за ошибки. Kill switch закрыл интернет: переподключитесь или разблокируйте."
	}
	return "Движок перехвата остановлен из-за ошибки, фильтры сняты (трафик идёт напрямую). Переподключитесь."
}
