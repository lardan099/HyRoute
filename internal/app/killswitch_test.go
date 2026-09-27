package app

import (
	"errors"
	"strings"
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
