package app

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// downRunner is a server that never connects.
type downRunner struct{ ctlRunner }

func (r *downRunner) Start() error { return nil }

func waitPing(t *testing.T, c *Controller) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); c.PingState().Running; {
		if time.Now().After(end) {
			t.Fatal("the run did not end")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func pingOf(t *testing.T, c *Controller, id string) ProfileSummary {
	t.Helper()
	for _, p := range c.Profiles() {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("no server %s", id)
	return ProfileSummary{}
}

// «Проверить все»: every server through a temporary core of its own, a
// routing one in place; a server that does not connect has its reason, a
// server changed since has no result.
func TestPingServers(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, de2, nl1 := servers(t, c)
	var events atomic.Int32
	c.OnChange = func() { events.Add(1) }
	live := c.Runners
	c.Runners = func(p hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
		if p.ID == nl1 {
			r.temp.Add(1)
			return &downRunner{}
		}
		return live(p, h)
	}
	if st := c.PingServers(nil); !st.Running || st.Total != 3 {
		t.Fatalf("%+v", st)
	}
	waitPing(t, c)
	if n := r.temp.Load(); n != 3 {
		t.Fatalf("%d temporary cores, want 3", n)
	}
	if events.Load() == 0 {
		t.Fatal("the page was not told")
	}
	for _, id := range []string{de1, de2} {
		if p := pingOf(t, c, id); p.PingMs <= 0 || p.PingErr != "" || p.PingAt == 0 || p.Pinging {
			t.Fatalf("%+v", p)
		}
	}
	if p := pingOf(t, c, nl1); p.PingMs != 0 || p.PingErr != "down" || p.PingAt == 0 || p.Pinging {
		t.Fatalf("%+v", p)
	}

	// Another port: not the server that was measured.
	p, err := c.Profile(de1)
	if err != nil {
		t.Fatal(err)
	}
	p.Ports = "8443"
	if _, err := c.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	if p := pingOf(t, c, de1); p.PingAt != 0 || p.PingMs != 0 {
		t.Fatalf("a changed server kept its result: %+v", p)
	}

	// One server by name.
	r.temp.Store(0)
	if st := c.PingServers([]string{de1}); !st.Running || st.Total != 1 {
		t.Fatalf("%+v", st)
	}
	waitPing(t, c)
	if n := r.temp.Load(); n != 1 {
		t.Fatalf("%d temporary cores, want 1", n)
	}
	if p := pingOf(t, c, de1); p.PingMs <= 0 {
		t.Fatalf("%+v", p)
	}

	// Connected, de1 routing (a rule names it): measured in place.
	setRules(t, c, rules.Direct, "", curlRule(de1))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	r.temp.Store(0)
	c.PingServers(nil)
	waitPing(t, c)
	if n := r.temp.Load(); n != 2 {
		t.Fatalf("%d temporary cores, want 2 (de1 runs)", n)
	}
	if p := pingOf(t, c, de1); p.PingMs <= 0 || p.PingErr != "" {
		t.Fatalf("%+v", p)
	}
	// No room for the addresses of one more server.
	r.sess.room = 3
	c.PingServers([]string{de1, de2})
	waitPing(t, c)
	if p := pingOf(t, c, de2); p.PingErr != "не проверен: запущено слишком много серверов" {
		t.Fatalf("%+v", p)
	}
	if p := pingOf(t, c, de1); p.PingMs <= 0 {
		t.Fatalf("%+v", p)
	}
}

// A run under way is the only one, and «Остановить» ends it without
// results.
func TestPingStop(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	de1, _, _ := servers(t, c)
	r.holdTemp, r.tempHeld = make(chan struct{}), make(chan struct{}, 1)
	c.PingServers(nil)
	<-r.tempHeld
	if p := pingOf(t, c, de1); !p.Pinging {
		t.Fatalf("%+v", p)
	}
	if st := c.PingServers([]string{de1}); !st.Running || st.Total != 3 || st.Done != 0 {
		t.Fatalf("a second run: %+v", st)
	}
	c.PingStop()
	close(r.holdTemp)
	waitPing(t, c)
	for _, p := range c.Profiles() {
		if p.PingAt != 0 || p.Pinging {
			t.Fatalf("%+v", p)
		}
	}
	// The exit with no run under way returns at once.
	c.stopPing()
}
