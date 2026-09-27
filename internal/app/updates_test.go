package app

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/lardan099/hyroute/internal/core"
)

// coreUpdated is a core manager with an installed update (v2.99.0) over
// the bundled core (v2.12.3). Fake binaries contain their version.
func coreUpdated(t *testing.T) *core.Manager {
	t.Helper()
	dir := t.TempDir()
	bundled := filepath.Join(dir, "hysteria.exe")
	coreDir := filepath.Join(dir, "core")
	bin := []byte("v2.99.0")
	if err := os.MkdirAll(filepath.Join(coreDir, "v2.99.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(bundled, []byte("v2.12.3"), 0o755)
	os.WriteFile(filepath.Join(coreDir, "v2.99.0", "hysteria.exe"), bin, 0o755)
	s := sha256.Sum256(bin)
	os.WriteFile(filepath.Join(coreDir, "core.json"), []byte(`{"current":{"version":"v2.99.0","sha256":"`+hex.EncodeToString(s[:])+`"}}`), 0o644)
	return &core.Manager{Dir: coreDir, Bundled: bundled, Version: func(p string) (string, error) {
		b, err := os.ReadFile(p)
		return string(b), err
	}}
}

// "Ядро обновлено, переподключитесь" lasts only while the session that
// ran during the core change does.
func TestCoreReconnectNoticeClears(t *testing.T) {
	c, _ := newCtl(t)
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := c.RollbackCore(); err != nil {
		t.Fatal(err)
	}
	if !c.Updates().CoreNeedsReconn {
		t.Fatal("connected during the core change: a reconnect is needed")
	}
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	if c.Updates().CoreNeedsReconn {
		t.Fatal("still asks for a reconnect after it")
	}
	c.Disconnect()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if c.Updates().CoreNeedsReconn {
		t.Fatal("the notice came back with the next connection")
	}

	// A disconnect ends it as well.
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.RollbackCore(); err != nil || !c.Updates().CoreNeedsReconn {
		t.Fatalf("%v %+v", err, c.Updates())
	}
	c.Disconnect()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if c.Updates().CoreNeedsReconn {
		t.Fatal("notice kept after a disconnect")
	}
}

// refreshKS is a kill switch that can renew its program exceptions.
type refreshKS struct {
	fakeKS
	refreshed int
}

func (k *refreshKS) RefreshApps() error { k.refreshed++; return nil }

// A core update or rollback moves hysteria.exe: an installed block lets
// the new path through at once.
func TestCoreChangeRefreshesKillSwitch(t *testing.T) {
	c, _ := newCtl(t)
	ks := &refreshKS{}
	c.KillSwitch = ks
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.RollbackCore(); err != nil {
		t.Fatal(err)
	}
	if ks.refreshed != 0 {
		t.Fatal("refreshed without a block")
	}
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.RollbackCore(); err != nil {
		t.Fatal(err)
	}
	if ks.refreshed != 1 {
		t.Fatalf("refreshed %d times", ks.refreshed)
	}
	// Routing stopped without a Disconnect: the internet is closed, and a
	// server check must still reach the server through the new core.
	c.Shutdown()
	if c.Status().KillSwitch != "blocking" {
		t.Fatalf("kill switch %q", c.Status().KillSwitch)
	}
	c.Updater = &Updater{Core: coreUpdated(t)}
	if err := c.RollbackCore(); err != nil {
		t.Fatal(err)
	}
	if ks.refreshed != 2 {
		t.Fatalf("refreshed %d times while blocking", ks.refreshed)
	}
}
