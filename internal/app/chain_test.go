package app

import (
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/vless"
)

func TestVPNChainGroupRunsOnlyEligibleIngress(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	first, second, exit := servers(t, c)
	nested := srv("", "Nested", "nested.example")
	nested.Via = first
	chained, err := c.SaveProfile(nested)
	if err != nil {
		t.Fatal(err)
	}
	gid := saveGroup(t, c, "Вход", groups.Failover, exit, chained.ID, first, second)
	onlyExit := saveGroup(t, c, "Только выход", groups.Failover, exit)
	p, err := c.Profile(exit)
	if err != nil {
		t.Fatal(err)
	}
	p.Via = onlyExit
	if _, err := c.SaveProfile(p); err == nil {
		t.Fatal("an exit-only group may not be its own ingress")
	}
	p.Via = gid
	if _, err := c.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteGroup(gid); err == nil {
		t.Fatal("deleted a group used as the first VPN")
	}

	// The standalone check takes temporary endpoints for the eligible members.
	ep, release := c.acquire(p)
	release()
	if ep == nil || r.temp.Load() != 3 {
		t.Fatalf("expected two temporary ingress members and the exit, started %d", r.temp.Load())
	}
	if status := c.checkMgr.Statuses(); len(status) != 0 {
		t.Fatalf("temporary endpoints survived the check: %+v", status)
	}

	if err := c.SetMain(exit); err != nil {
		t.Fatal(err)
	}
	set, err := rules.Compile(rules.Config{DefaultAction: rules.Tunnel})
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.set = set
	_, wanted, used := c.routingLocked()
	c.mu.Unlock()
	var ids []string
	for _, w := range wanted {
		ids = append(ids, w.ID)
	}
	slices.Sort(ids)
	sorted := []string{first, second, exit}
	slices.Sort(sorted)
	if !slices.Equal(ids, sorted) || !slices.Equal(used, []string{gid}) {
		t.Fatalf("wrong chain routing: %v, groups %v", ids, used)
	}
}

func TestVPNChainProfile(t *testing.T) {
	c, _ := newCtl(t)
	ingress, err := c.SaveProfile(srv("", "First", "first.example"))
	if err != nil {
		t.Fatal(err)
	}
	p := srv("", "Exit", "exit.example")
	p.Via = ingress.ID
	egress, err := c.SaveProfile(p)
	if err != nil || egress.Via != ingress.ID {
		t.Fatalf("save: via=%q, %v", egress.Via, err)
	}
	if err := c.SetMain(egress.ID); err != nil {
		t.Fatal(err)
	}
	set, err := rules.Compile(rules.Config{DefaultAction: rules.Tunnel})
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.set = set
	_, wanted, _ := c.routingLocked()
	c.mu.Unlock()
	for _, id := range []string{ingress.ID, egress.ID} {
		if !slices.ContainsFunc(wanted, func(p hysteria.Profile) bool { return p.ID == id }) {
			t.Fatalf("profile %s did not start with the chain", id)
		}
	}
	first, err := c.Profile(ingress.ID)
	if err != nil {
		t.Fatal(err)
	}
	first.Via = egress.ID
	if _, err := c.SaveProfile(first); err == nil {
		t.Fatal("accepted a cycle")
	}
	p.ID = egress.ID
	for _, via := range []string{egress.ID, "missing"} {
		p.Via = via
		if _, err := c.SaveProfile(p); err == nil {
			t.Fatalf("accepted invalid ingress %q", via)
		}
	}
	if err := c.DeleteProfile(ingress.ID); err == nil {
		t.Fatal("deleted the first VPN of a saved chain")
	}
}

func TestVPNChainSubscriptionRefresh(t *testing.T) {
	exit := srv("exit", "Exit", "exit.example")
	exit.Source, exit.Via = "sub:s", "first"
	fresh := exit
	fresh.ID, fresh.Source, fresh.Via, fresh.Name = "", "", "", "Renamed"
	profiles, _ := mergeSubscription([]hysteria.Profile{exit}, exit.Source, []hysteria.Profile{fresh},
		func(string) bool { return false }, func() string { return "new" })
	if len(profiles) != 1 || profiles[0].ID != exit.ID || profiles[0].Via != exit.Via || profiles[0].Name != fresh.Name {
		t.Fatal("subscription update lost the existing chain")
	}
}

func TestVPNChainBalanceEditorKeepsProviderNodes(t *testing.T) {
	c, _ := newCtl(t)
	ingress, err := c.SaveProfile(srv("", "First", "first.example"))
	if err != nil {
		t.Fatal(err)
	}
	balance := hysteria.Profile{ID: "balance", Name: "Автовыбор", Protocol: hysteria.ProtoVLESS,
		Balance: &vless.Balance{Nodes: []vless.Node{{Host: "exit.example", Port: 443, Settings: vless.Settings{ID: "test", Security: "tls"}}}}}
	c.mu.Lock()
	c.profiles.List = append(c.profiles.List, balance)
	c.mu.Unlock()
	edit := balance
	edit.Via, edit.Balance = ingress.ID, &vless.Balance{}
	if got, err := c.SaveProfile(edit); err != nil || got.Via != ingress.ID || !got.Balance {
		t.Fatalf("save balance chain: via=%q, balance=%v, %v", got.Via, got.Balance, err)
	}
	balance.Via = ingress.ID
	if got, err := c.Profile(balance.ID); err != nil || !hysteria.SameConnection(got, balance) {
		t.Fatalf("balance nodes changed: %v", err)
	}
}

func TestVPNChainRestoreRemapsIngress(t *testing.T) {
	first := srv("aaaaaaaa0001", "First", "first.example")
	exit := srv("aaaaaaaa0002", "Exit", "exit.example")
	exit.Via = first.ID
	unrelated := srv(first.ID, "Other", "other.example")
	cur := baseState(unrelated)

	restore := func(profiles ...hysteria.Profile) *restorePlan {
		file := payload(true).put("servers", bkServers{List: profiles})
		return plan(cur, file.p, map[string]string{"servers": "add"})
	}
	pl := restore(exit, first)
	if pl.err != "" {
		t.Fatal(pl.err)
	}
	p := pl.next.Profiles.Find(exit.ID)
	if p == nil || p.Via == first.ID {
		t.Fatal("restored chain points to an unrelated server")
	}
	if got := pl.next.Profiles.Find(p.Via); got == nil || got.Host != first.Host {
		t.Fatal("restored chain lost the ingress")
	}
	pl = restore(exit)
	p = pl.next.Profiles.Find(exit.ID)
	if pl.err != "" || p == nil || p.Via == "" || pl.next.Profiles.Find(p.Via) != nil ||
		!strings.Contains(texts(pl), "цепочка «Exit»") {
		t.Fatal("partial restore must keep and report an unavailable ingress", texts(pl))
	}
}

func TestVPNChainRestoreRemapsIngressGroup(t *testing.T) {
	gid := groups.NewID("aaaaaaaa0003")
	ingress := srv("aaaaaaaa0001", "First", "first.example")
	exit := srv("aaaaaaaa0002", "Exit", "exit.example")
	exit.Via = gid
	other := srv("aaaaaaaa0004", "Other", "other.example")
	cur := baseState(other)
	cur.Groups.Groups = []groups.Group{{ID: gid, Name: "Other", Strategy: groups.Failover, Members: []string{other.ID}}}
	file := payload(true).
		put("servers", bkServers{List: []hysteria.Profile{ingress, exit}}).
		put("groups", groups.File{Version: 1, Groups: []groups.Group{
			{ID: gid, Name: "First VPN", Strategy: groups.Latency, Members: []string{ingress.ID}},
		}})
	pl := plan(cur, file.p, map[string]string{"servers": "add", "groups": "add"})
	if pl.err != "" {
		t.Fatal(pl.err)
	}
	p := pl.next.Profiles.Find(exit.ID)
	g := pl.next.Groups.Find(p.Via)
	if p.Via == gid || g == nil || !slices.Equal(g.Members, []string{ingress.ID}) {
		t.Fatal("restored chain points to the wrong group")
	}
}
