package tunnels

import (
	"testing"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
)

type tcpOnlyRunner struct{ Runner }

func (tcpOnlyRunner) UDPAvailable() bool { return false }

func TestVPNChainGroupSwitchesIngress(t *testing.T) {
	r := newRig()
	rt := groups.NewRuntime(nil)
	r.m.Groups = rt
	tcp := prof("tcp", "198.51.100.1")
	first, second := prof("first", "198.51.100.2"), prof("second", "198.51.100.3")
	chained, exit := prof("chained", "198.51.100.4"), prof("exit", "198.51.100.5")
	g := groups.Group{ID: groups.NewID("aaaaaaaa0001"), Strategy: groups.Failover,
		Members: []string{exit.ID, chained.ID, tcp.ID, first.ID, second.ID}}
	chained.Via, exit.Via = first.ID, g.ID
	rt.SetGroups([]groups.Group{g})
	newRunner := r.m.New
	r.m.New = func(p hysteria.Profile, h Hooks) Runner {
		runner := newRunner(p, h)
		if p.ID == tcp.ID {
			return tcpOnlyRunner{runner}
		}
		return runner
	}
	r.m.Sync([]hysteria.Profile{tcp, first, second, chained, exit})
	defer r.m.StopAll()
	pick := r.runs["profile:"+exit.ID].h.Via
	check := func(want string) hysteria.Upstream {
		t.Helper()
		up, ok := pick().(chainUpstream)
		if !ok || up.ID != want {
			t.Fatalf("expected upstream %s, got %v", want, up.ID)
		}
		return up
	}
	active := check(first.ID)
	retry := check(second.ID)
	if !active.Available() || !retry.Available() {
		t.Fatal("a new attempt should choose a different ingress without invalidating the active endpoint")
	}
	r.m.Sync([]hysteria.Profile{tcp, second, chained, exit})
	if active.Available() {
		t.Fatal("removed endpoint still carries the chain")
	}
	active = check(second.ID)
	g.Members = []string{tcp.ID, chained.ID, exit.ID}
	rt.SetGroups([]groups.Group{g})
	if active.Available() || pick() != nil {
		t.Fatal("the chain kept a removed member or fell back to an ineligible server")
	}
}
