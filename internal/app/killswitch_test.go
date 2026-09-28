package app

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/settings"
)

// fakeKS models the filters: blocks and pass. A failing Arm leaves both
// installed, as the real one can after its pass went in.
type fakeKS struct {
	blocks, pass       bool
	relay              uint16 // the relay's port at the last Arm
	ops                []string
	onClose            func()
	armErr, releaseErr error
}

func (k *fakeKS) Arm(relayPort uint16) error {
	k.ops = append(k.ops, "arm")
	k.blocks, k.pass, k.relay = true, true, relayPort
	return k.armErr
}
func (k *fakeKS) Close() error {
	k.ops = append(k.ops, "close")
	if k.onClose != nil {
		k.onClose()
	}
	k.pass = false
	return nil
}
func (k *fakeKS) Release() error {
	k.ops = append(k.ops, "release")
	if k.releaseErr != nil {
		return k.releaseErr
	}
	k.blocks, k.pass = false, false
	return nil
}
func (k *fakeKS) Engaged() (bool, error) { return k.blocks, nil }

func setKillSwitch(t *testing.T, c *Controller, on bool) {
	t.Helper()
	st := c.Settings()
	st.KillSwitch = &on
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
}

func TestKillSwitchOffByDefault(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.Disconnect()
	if len(ks.ops) != 0 || c.Status().KillSwitch != "" {
		t.Fatalf("%v %q", ks.ops, c.Status().KillSwitch)
	}
}

func TestKillSwitchLifecycle(t *testing.T) {
	c, started := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if !ks.blocks || !ks.pass || c.Status().KillSwitch != "armed" {
		t.Fatalf("%+v %q", ks, c.Status().KillSwitch)
	}
	// The engine fails: the block takes over.
	(*started)[0].cfg.OnEngineFail()
	if !ks.blocks || ks.pass || c.Status().KillSwitch != "blocking" {
		t.Fatalf("after engine failure: %+v", ks)
	}
	// Reconnect keeps the internet closed, then arms again. The pass
	// filters close before the old engine stops.
	(*started)[0].cfg.OnEngineFail() // a second report is harmless
	ks.ops = nil
	old := (*started)[0]
	ks.onClose = func() {
		if old.stopped {
			t.Error("pass closed after the engine stopped")
		}
	}
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ks.ops, ",") != "arm" || !ks.pass {
		t.Fatalf("reconnect: %v", ks.ops)
	}
	if (*started)[0].cfg.ResetUnknownDomain || !(*started)[1].cfg.ResetUnknownDomain {
		t.Fatal("connections of unknown domains are reset only over a block")
	}
	ks.ops = nil
	old = (*started)[1]
	old.onReset = func() {
		if !ks.pass {
			t.Error("relayed connections reset after the pass closed: the block may drop the resets")
		}
	}
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ks.ops, ",") != "close,arm" {
		t.Fatalf("reconnect while armed: %v", ks.ops)
	}
	if old.resets != 1 {
		t.Fatalf("%d resets before the pass closed", old.resets)
	}
	// Disconnect opens the internet.
	c.Disconnect()
	if ks.blocks || c.Status().KillSwitch != "" {
		t.Fatalf("after disconnect: %+v", ks)
	}
}

func TestKillSwitchLeftoverAndUnblock(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{blocks: true} // a crashed run left the block
	c.KillSwitch = ks
	c.InitKillSwitch()
	if c.Status().KillSwitch != "blocking" {
		t.Fatal(c.Status().KillSwitch)
	}
	if err := c.ReleaseKillSwitch(); err != nil || ks.blocks || c.Status().KillSwitch != "" {
		t.Fatalf("%v %+v", err, ks)
	}
	// Connecting with the setting off also removes a left block.
	ks.blocks = true
	c.InitKillSwitch()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if ks.blocks {
		t.Fatal("left block kept with the kill switch off")
	}
}

func TestKillSwitchHeldOverExit(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.Shutdown() // window closed, or "End task" in Task Manager
	if !ks.blocks || ks.pass {
		t.Fatalf("exit: %+v", ks)
	}
	// Without the kill switch an exit changes nothing.
	c2, _ := newCtl(t)
	ks2 := &fakeKS{}
	c2.KillSwitch = ks2
	c2.Connect()
	c2.Shutdown()
	if len(ks2.ops) != 0 {
		t.Fatal(ks2.ops)
	}
}

// Arm learns the port of the session's relay, whose connections have the
// real remote hosts for peers: the block keeps it closed to them.
func TestKillSwitchRelayPort(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	port := 50123
	c.Start = func(cfg session.Config) (Session, error) {
		return &fakeSession{reg: flows.NewRegistry(10), cfg: cfg, stats: session.Stats{RelayPort: port}}, nil
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if ks.relay != 50123 {
		t.Fatalf("armed with relay port %d", ks.relay)
	}
	// A new session listens elsewhere.
	port = 50124
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	if ks.relay != 50124 {
		t.Fatalf("after reconnect: relay port %d", ks.relay)
	}
}

func TestKillSwitchHeldForUpdate(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.HoldKillSwitch()
	c.Disconnect()
	if !ks.blocks || ks.pass {
		t.Fatalf("update exit: %+v", ks)
	}
}

func TestKillSwitchToggle(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	setKillSwitch(t, c, true)
	if !ks.pass || !ks.blocks {
		t.Fatalf("turned on while connected: %+v", ks)
	}
	setKillSwitch(t, c, false)
	if ks.blocks {
		t.Fatalf("turned off: %+v", ks)
	}
	var s settings.Settings
	if s.KillSwitchOn() {
		t.Fatal("kill switch on by default")
	}
}

// A failed Arm may leave its pass on: with nothing to close it the kill
// switch never works, while "blocking" said the internet was closed.
func TestKillSwitchArmFailure(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{armErr: errors.New("BFE unavailable")}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	st := c.Status()
	if st.State != "connected" || st.KillSwitch != "" || !strings.Contains(st.KillSwitchError, "BFE unavailable") {
		t.Fatalf("%q %q %q", st.State, st.KillSwitch, st.KillSwitchError)
	}
	if ks.pass || ks.blocks {
		t.Fatalf("filters of the failed arm left: %+v", ks)
	}
	c.Disconnect()

	// They cannot be removed either: the pass goes, so what stays blocks,
	// as the status says.
	c2, _ := newCtl(t)
	ks2 := &fakeKS{armErr: errors.New("AddRule failed"), releaseErr: errors.New("busy")}
	c2.KillSwitch = ks2
	setKillSwitch(t, c2, true)
	if err := c2.Connect(); err != nil {
		t.Fatal(err)
	}
	if st := c2.Status(); ks2.pass || !ks2.blocks || st.KillSwitch != "blocking" || st.KillSwitchError == "" {
		t.Fatalf("%+v %q %q", ks2, st.KillSwitch, st.KillSwitchError)
	}
}

// failedSession: the engine failed before the kill switch was armed.
type failedSession struct{ fakeSession }

func (f *failedSession) EngineFailed() bool { return true }

func TestKillSwitchEngineFailedBeforeArm(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	c.Start = func(cfg session.Config) (Session, error) {
		// The engine reports its failure right after it came up, while
		// Hysteria starts: nothing is armed yet.
		cfg.OnEngineFail()
		return &failedSession{fakeSession{reg: flows.NewRegistry(10), cfg: cfg}}, nil
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); ks.pass || !ks.blocks || st.KillSwitch != "blocking" {
		t.Fatalf("pass left on a failed engine: %+v %q", ks, st.KillSwitch)
	}
}

// With Fast Startup a shutdown keeps the filter engine: the block would
// greet the next boot without HyRoute.
func TestKillSwitchEndSession(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	c.EndSession()
	if len(ks.ops) != 0 {
		t.Fatalf("nothing to remove: %v", ks.ops)
	}
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.EndSession()
	if ks.blocks || ks.pass || c.Status().KillSwitch != "" {
		t.Fatalf("block kept over the end of the session: %+v", ks)
	}
	// A block a crashed run left goes too, also when held for an update.
	c2, _ := newCtl(t)
	ks2 := &fakeKS{blocks: true}
	c2.KillSwitch = ks2
	c2.InitKillSwitch()
	c2.HoldKillSwitch()
	c2.EndSession()
	if ks2.blocks {
		t.Fatal("left block kept over the end of the session")
	}
}

// A Connect racing the end of the session installs no block; when the end
// is cancelled, the kill switch comes back for the running session.
func TestKillSwitchEndSessionCancelled(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	c.EndSession()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if ks.blocks || ks.pass {
		t.Fatalf("armed while the session ends: %+v", ks)
	}
	c.SessionResumed()
	if !ks.blocks || !ks.pass || c.Status().KillSwitch != "armed" {
		t.Fatalf("not armed again after the end was cancelled: %+v %q", ks, c.Status().KillSwitch)
	}
	n := len(ks.ops)
	c.SessionResumed() // nothing was ending
	if len(ks.ops) != n {
		t.Fatalf("%v", ks.ops)
	}
}

// settings.json did not load: "kill switch off" is the default, not the
// user's choice, so nothing opens a block a previous run left.
func TestKillSwitchKeptWithUnloadedSettings(t *testing.T) {
	c, started := brokenSettingsCtl(t)
	ks := &fakeKS{blocks: true}
	c.KillSwitch = ks
	c.InitKillSwitch()
	c.Connect() // refused
	c.armKillSwitch(&fakeSession{})
	c.applyKillSwitch()
	if !ks.blocks || len(ks.ops) != 0 || c.Status().KillSwitch != "blocking" || *started != 0 {
		t.Fatalf("%+v %d", ks, *started)
	}
	// The user's "unblock" still works.
	if err := c.ReleaseKillSwitch(); err != nil || ks.blocks {
		t.Fatalf("%v %+v", err, ks)
	}
}

// A cancelled end of the session puts back a block that closed the
// internet: routing is not there to arm it again.
func TestKillSwitchEndSessionCancelledWhileBlocking(t *testing.T) {
	// The engine failed and HyRoute stopped reconnecting by itself.
	c, started := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	(*started)[0].fail()
	c.EndSession()
	if ks.blocks {
		t.Fatal("block kept over the end of the session")
	}
	c.SessionResumed()
	if st := c.Status(); !ks.blocks || ks.pass || st.KillSwitch != "blocking" {
		t.Fatalf("failed engine: %+v %q", ks, st.KillSwitch)
	}

	// A block a crashed run left, no session.
	c2, _ := newCtl(t)
	ks2 := &fakeKS{blocks: true}
	c2.KillSwitch = ks2
	c2.InitKillSwitch()
	setKillSwitch(t, c2, true)
	c2.EndSession()
	c2.SessionResumed()
	if st := c2.Status(); !ks2.blocks || ks2.pass || st.KillSwitch != "blocking" {
		t.Fatalf("left block: %+v %q", ks2, st.KillSwitch)
	}

	// The user opened the internet meanwhile: it stays open.
	for name, open := range map[string]func(*Controller){
		"disconnect": (*Controller).Disconnect,
		"unblock":    func(c *Controller) { c.ReleaseKillSwitch() },
		"setting":    func(c *Controller) { setKillSwitch(t, c, false) },
	} {
		c3, _ := newCtl(t)
		ks3 := &fakeKS{blocks: true}
		c3.KillSwitch = ks3
		c3.InitKillSwitch()
		setKillSwitch(t, c3, true)
		c3.EndSession()
		open(c3)
		c3.SessionResumed()
		if ks3.blocks || c3.Status().KillSwitch != "" {
			t.Fatalf("%s: %+v", name, ks3)
		}
	}
}

// failedStatsSession counts Stats once its engine failed: they take the
// engine's locks, which a packet loop the watchdog gave up on may hold for
// good.
type failedStatsSession struct {
	*fakeSession
	calls atomic.Int32
}

func (s *failedStatsSession) Stats() session.Stats {
	if s.failed.Load() {
		s.calls.Add(1)
	}
	return s.fakeSession.Stats()
}

// Putting the block back after the engine failed does not ask the failed
// session for its relay port (lifeMu and ksMu are held): the port of the
// last Arm is used.
func TestKillSwitchRestoreBlockNoStats(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	var s *failedStatsSession
	c.Start = func(cfg session.Config) (Session, error) {
		s = &failedStatsSession{fakeSession: &fakeSession{reg: flows.NewRegistry(10), cfg: cfg, stats: session.Stats{RelayPort: 50123}}}
		return s, nil
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	s.fail()
	c.EndSession()
	ks.relay = 0
	c.SessionResumed()
	if n := s.calls.Load(); n != 0 {
		t.Fatalf("Stats of the failed session called %d times", n)
	}
	if !ks.blocks || ks.pass || ks.relay != 50123 {
		t.Fatalf("%+v", ks)
	}
}

// A second end of the session before the first cancel is done: its
// SessionResumed still puts the block back.
func TestKillSwitchEndSessionTwice(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{blocks: true}
	c.KillSwitch = ks
	c.InitKillSwitch()
	setKillSwitch(t, c, true)
	c.EndSession()
	// SessionResumed up to applyKillSwitch, then Windows ends it again.
	c.ksMu.Lock()
	c.ks.ending = false
	c.ksMu.Unlock()
	c.applyKillSwitch()
	c.EndSession()
	c.restoreBlock()
	if ks.blocks {
		t.Fatal("block put back while Windows ends the session")
	}
	c.SessionResumed()
	if !ks.blocks || c.Status().KillSwitch != "blocking" {
		t.Fatalf("resume lost: %+v", ks)
	}
}

// "Open the internet" clicked just after an automatic reconnect armed the
// kill switch again: the internet is open, the kill switch stays.
func TestKillSwitchUnblockWhileArmed(t *testing.T) {
	c, _ := newCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := c.ReleaseKillSwitch(); err != nil {
		t.Fatal(err)
	}
	if st := c.Status(); !ks.blocks || !ks.pass || st.KillSwitch != "armed" {
		t.Fatalf("%+v %q", ks, st.KillSwitch)
	}
}

// A block found at start may be another copy's (moved to Program Files,
// updated): its exceptions are renewed for this copy's programs.
func TestKillSwitchLeftoverRefreshesApps(t *testing.T) {
	c, _ := newCtl(t)
	ks := &refreshKS{}
	c.KillSwitch = ks
	c.InitKillSwitch()
	if ks.refreshed != 0 {
		t.Fatal("refreshed without a block")
	}
	ks.blocks = true
	c.InitKillSwitch()
	if ks.refreshed != 1 {
		t.Fatalf("refreshed %d times", ks.refreshed)
	}
	// Hysteria resolves its servers before the Arm: the DNS servers the
	// block lets through are renewed before the start (the network may
	// have changed).
	setKillSwitch(t, c, true)
	c.Start = func(session.Config) (Session, error) {
		if ks.refreshed != 2 {
			t.Errorf("started with the exceptions refreshed %d times", ks.refreshed)
		}
		return &fakeSession{reg: flows.NewRegistry(10)}, nil
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
}

// engagedErrKS cannot tell whether the block is installed, or (blocks)
// another HyRoute owns the installed one.
type engagedErrKS struct{ fakeKS }

func (k *engagedErrKS) Engaged() (bool, error) {
	return k.blocks, errors.New("занят другим HyRoute")
}

// Whether the block is there is unknown (another HyRoute owns it): the
// status says so while the kill switch is on.
func TestKillSwitchStateUnknown(t *testing.T) {
	c, _ := newCtl(t)
	c.KillSwitch = &engagedErrKS{}
	c.InitKillSwitch()
	if st := c.Status(); st.KillSwitchError != "" {
		t.Fatalf("kill switch off: %q", st.KillSwitchError)
	}
	setKillSwitch(t, c, true)
	c.InitKillSwitch()
	if st := c.Status(); !strings.Contains(st.KillSwitchError, "занят") {
		t.Fatalf("%q", st.KillSwitchError)
	}
}

// Another HyRoute (another Windows user's) owns an installed block: the
// internet may be closed for this user too, and the status says why even
// with the kill switch off.
func TestKillSwitchOwnedByAnother(t *testing.T) {
	c, _ := newCtl(t)
	c.KillSwitch = &engagedErrKS{fakeKS{blocks: true}}
	c.InitKillSwitch()
	if st := c.Status(); !strings.Contains(st.KillSwitchError, "занят") || st.KillSwitch != "" {
		t.Fatalf("%q %q", st.KillSwitch, st.KillSwitchError)
	}
}
