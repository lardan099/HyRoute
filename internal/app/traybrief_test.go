package app

import (
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/zapret"
)

// The tray's reads: the servers with the main one, and the DPI bypass,
// switched with its settings as they are.
func TestServersBrief(t *testing.T) {
	c, _ := newCtl(t)
	if b := c.ServersBrief(); b.Main != "" || len(b.List) != 0 {
		t.Fatalf("%+v", b)
	}
	add, err := c.ImportURIs("hysteria2://p1@a.example:443#NL\nhysteria2://p2@b.example:443#NL\nhysteria2://p3@c.example:443#DE")
	if err != nil || len(add.Added) != 3 {
		t.Fatalf("%+v %v", add, err)
	}
	g, err := c.SaveGroup(groups.Group{Name: "Быстрые", Strategy: groups.Failover, Members: []string{add.Added[0].ID, add.Added[2].ID}})
	if err != nil {
		t.Fatal(err)
	}
	b := c.ServersBrief()
	if len(b.List) != 4 || b.Main != add.Added[0].ID {
		t.Fatalf("%+v", b)
	}
	// Servers of one name are told apart as everywhere else; the group is
	// last and says it is one.
	if b.List[0].Name != b.List[1].Name || !strings.Contains(b.List[0].Name, "NL") || b.List[2].Name != "DE" || !b.List[3].Group || b.List[3].Name != "Быстрые" || b.List[3].ID != g.ID {
		t.Fatalf("%+v", b.List)
	}
	if err := c.SetMain(g.ID); err != nil {
		t.Fatal(err)
	}
	if b = c.ServersBrief(); b.Main != g.ID {
		t.Fatalf("%+v", b)
	}
	if err := c.SetMain(add.Added[2].ID); err != nil {
		t.Fatal(err)
	}
	if b = c.ServersBrief(); b.Main != add.Added[2].ID {
		t.Fatalf("%+v", b)
	}
}

func TestZapretBriefAndSwitch(t *testing.T) {
	c, _ := zapFixture(t)
	changed := make(chan struct{}, 64)
	c.OnChange = func() { // before anything runs that reports changes
		select {
		case changed <- struct{}{}:
		default:
		}
	}
	if b := c.ZapretBrief(); b.Shown || b.Enabled {
		t.Fatalf("%+v", b)
	}
	if err := c.SaveZapret(ZapretInput{Enabled: true, Targets: []zapret.Target{zapret.Discord, zapret.YouTube}}); err != nil {
		t.Fatal(err)
	}
	b := c.ZapretBrief()
	if !b.Shown || !b.Enabled || strings.Join(b.Targets, ",") != "YouTube,Discord" {
		t.Fatalf("%+v", b)
	}
	before := c.ZapretInfo()
	if err := c.SetZapretEnabled(false); err != nil {
		t.Fatal(err)
	}
	// Off, with everything else as it was: the services stay chosen.
	after := c.ZapretInfo()
	if b = c.ZapretBrief(); !b.Shown || b.Enabled || len(b.Targets) != 2 || after.Settings.Enabled || len(after.Settings.Targets) != len(before.Settings.Targets) {
		t.Fatalf("%+v %+v", b, after)
	}
	if err := c.SetZapretEnabled(true); err != nil || !c.ZapretBrief().Enabled {
		t.Fatalf("%v", err)
	}
	// An apply or a pick under way: the last answer, at once; and once it
	// is over the controller says so, for the tray to ask again.
	c.zapretMu.Lock()
	for len(changed) > 0 {
		<-changed
	}
	b = c.ZapretBrief()
	c.zapretCfg.Enabled = false // what the holder of the lock did meanwhile
	c.zapretMu.Unlock()
	if !b.Shown || !b.Enabled {
		t.Fatalf("%+v", b)
	}
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("no change reported after the lock was free")
	}
	if c.ZapretBrief().Enabled {
		t.Fatal("the old answer after the lock was free")
	}
	c.zapretMu.Lock()
	c.zapretCfg.Enabled = true
	c.zapretMu.Unlock()
	// Nowhere to run it (no winws2 here): nothing to switch.
	c.ZapretPrepare = nil
	if c.ZapretBrief().Shown {
		t.Fatal("shown without the bypass")
	}
}
