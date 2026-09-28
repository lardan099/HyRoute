package app

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/session"
)

// recoverCtl is connected; the automatic reconnect waits delay. setup runs
// before the Connect.
func recoverCtl(t *testing.T, delay time.Duration, setup func(*Controller)) (*Controller, func() []*fakeSession) {
	t.Helper()
	c, gate, started := gatedCtl(t)
	close(gate)
	c.recoverDelay = delay
	if setup != nil {
		setup(c)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	// Disconnect waits for an attempt under way.
	t.Cleanup(c.Disconnect)
	return c, started
}

// waitSessions waits until n sessions started and the last one runs.
func waitSessions(t *testing.T, c *Controller, started func() []*fakeSession, n int) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		if s := c.Status(); len(started()) == n && s.State == "connected" {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("%d sessions, state %q; want %d", len(started()), c.Status().State, n)
		}
	}
}

// The engine failed (L40): one reconnect after the delay brings routing
// back, and the kill switch block stays over it.
func TestEngineRecoverAfterDelay(t *testing.T) {
	const delay = 50 * time.Millisecond
	ks := &fakeKS{}
	c, started := recoverCtl(t, delay, func(c *Controller) {
		c.KillSwitch = ks
		setKillSwitch(t, c, true)
	})
	failed := time.Now()
	started()[0].fail()
	waitSessions(t, c, started, 2)
	if d := time.Since(failed); d < delay {
		t.Fatalf("reconnected after %v, before the delay", d)
	}
	for end := time.Now().Add(5 * time.Second); c.Status().KillSwitch != "armed"; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("kill switch %q after the reconnect", c.Status().KillSwitch)
		}
	}
	// Never released: the block held while the engine was down.
	if ops := strings.Join(ks.ops, ","); ops != "arm,close,arm" {
		t.Fatalf("kill switch ops %s", ops)
	}
	time.Sleep(3 * delay)
	if n := len(started()); n != 2 {
		t.Fatalf("%d sessions: one reconnect per failure", n)
	}
}

// An engine that keeps failing gets 3 automatic reconnects within 10
// minutes, then the status asks the user.
func TestEngineRecoverLimit(t *testing.T) {
	var changes atomic.Int32
	c, started := recoverCtl(t, time.Millisecond, func(c *Controller) {
		c.OnChange = func() { changes.Add(1) }
	})
	for i := range engineRecoverMax {
		started()[i].fail()
		waitSessions(t, c, started, i+2)
	}
	before := changes.Load()
	started()[engineRecoverMax].fail()
	time.Sleep(50 * time.Millisecond)
	st := c.Status()
	if n := len(started()); n != engineRecoverMax+1 {
		t.Fatalf("%d sessions after the limit", n)
	}
	if st.State != "error" || !strings.Contains(st.Message, "переподключитесь вручную") || changes.Load() == before {
		t.Fatalf("after the limit: %q %q, %d changes", st.State, st.Message, changes.Load()-before)
	}
	// A manual reconnect does not renew the limit...
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	started()[engineRecoverMax+1].fail()
	time.Sleep(50 * time.Millisecond)
	if n := len(started()); n != engineRecoverMax+2 {
		t.Fatalf("%d sessions: reconnected over the limit", n)
	}
	// ...time does.
	c.recMu.Lock()
	for i := range c.rec.attempts {
		c.rec.attempts[i] = c.rec.attempts[i].Add(-engineRecoverWindow)
	}
	c.recMu.Unlock()
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	started()[engineRecoverMax+2].fail()
	waitSessions(t, c, started, engineRecoverMax+4)
}

// The status says a reconnect is coming. Disconnect and exit cancel it,
// also when its timer already fired and waits for them to finish.
func TestEngineRecoverCancelled(t *testing.T) {
	for name, stop := range map[string]func(*Controller){
		"disconnect": (*Controller).Disconnect,
		"exit":       (*Controller).Shutdown,
	} {
		t.Run(name, func(t *testing.T) {
			var changes atomic.Int32
			c, started := recoverCtl(t, time.Hour, func(c *Controller) {
				c.OnChange = func() { changes.Add(1) }
			})
			before := changes.Load()
			started()[0].fail()
			st := c.Status()
			if st.State != "error" || !strings.Contains(st.Message, "переподключится сам") || changes.Load() == before {
				t.Fatalf("after the failure: %q %q, %d changes", st.State, st.Message, changes.Load()-before)
			}
			c.recMu.Lock()
			gen := c.rec.gen
			c.recMu.Unlock()
			stop(c)
			c.recMu.Lock()
			pending := c.rec.timer != nil
			c.recMu.Unlock()
			if pending {
				t.Fatal("reconnect still planned")
			}
			c.recoverEngine(gen) // the timer fired meanwhile
			if n, st := len(started()), c.Status().State; n != 1 || st != "disconnected" {
				t.Fatalf("%d sessions, state %q", n, st)
			}
		})
	}
}

// While HyRoute is exiting (BeginExit) the planned attempt starts nothing:
// the Disconnect or Shutdown that follows would only stop it again.
func TestEngineRecoverNotWhileExiting(t *testing.T) {
	c, started := recoverCtl(t, time.Hour, nil)
	started()[0].fail()
	c.recMu.Lock()
	gen := c.rec.gen
	c.recMu.Unlock()
	undo := c.BeginExit()
	c.recoverEngine(gen) // the timer fired
	undo()
	if n := len(started()); n != 1 {
		t.Fatalf("%d sessions", n)
	}
}

// After the user reconnected nothing reconnects again: not the planned
// attempt, nor a late failure report of the session replaced.
func TestEngineRecoverNotAfterManualReconnect(t *testing.T) {
	const delay = 20 * time.Millisecond
	c, started := recoverCtl(t, delay, nil)
	started()[0].fail()
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	old := started()[1]
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	old.fail()
	time.Sleep(5 * delay)
	if n, st := len(started()), c.Status().State; n != 3 || st != "connected" {
		t.Fatalf("%d sessions, state %q", n, st)
	}
}

// failingStarts makes the next n starts fail, as WinDivert still
// unavailable after the engine's Recv error would.
func failingStarts(c *Controller, n *atomic.Int32) {
	inner := c.Start
	c.Start = func(cfg session.Config) (Session, error) {
		if n.Add(-1) >= 0 {
			return nil, errors.New("WinDivert недоступен")
		}
		return inner(cfg)
	}
}

// An automatic reconnect that does not start counts as an attempt: the
// next one follows. It resets connections of domains it does not know.
func TestEngineRecoverStartFails(t *testing.T) {
	var fails atomic.Int32
	c, started := recoverCtl(t, time.Millisecond, func(c *Controller) { failingStarts(c, &fails) })
	fails.Store(1)
	started()[0].fail()
	waitSessions(t, c, started, 2)
	c.recMu.Lock()
	attempts := len(c.rec.attempts)
	c.recMu.Unlock()
	if attempts != 2 {
		t.Fatalf("%d attempts", attempts)
	}
	if started()[0].cfg.ResetUnknownDomain || !started()[1].cfg.ResetUnknownDomain {
		t.Fatal("only an automatic reconnect resets connections of unknown domains")
	}
}

// When no automatic reconnect starts, HyRoute stops after the limit, says
// so and shows its window (OnGiveUp).
func TestEngineRecoverStartFailsGivesUp(t *testing.T) {
	var fails atomic.Int32
	gaveUp := make(chan struct{}, engineRecoverMax+1)
	c, started := recoverCtl(t, time.Millisecond, func(c *Controller) {
		failingStarts(c, &fails)
		c.OnGiveUp = func() { gaveUp <- struct{}{} }
	})
	fails.Store(100)
	started()[0].fail()
	select {
	case <-gaveUp:
	case <-time.After(5 * time.Second):
		t.Fatal("OnGiveUp not called")
	}
	st := c.Status()
	if st.State != "error" || !strings.Contains(st.Message, "WinDivert недоступен") || !strings.Contains(st.Message, "не помогли") {
		t.Fatalf("%q %q", st.State, st.Message)
	}
	time.Sleep(20 * time.Millisecond)
	c.recMu.Lock()
	attempts, pending := len(c.rec.attempts), c.rec.timer != nil
	c.recMu.Unlock()
	if attempts != engineRecoverMax || pending || len(gaveUp) != 0 || len(started()) != 1 {
		t.Fatalf("%d attempts, pending %v, %d more give-ups, %d sessions", attempts, pending, len(gaveUp), len(started()))
	}
	// The user's Connect clears it.
	fails.Store(0)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); st.State != "connected" {
		t.Fatalf("%q %q", st.State, st.Message)
	}
}
