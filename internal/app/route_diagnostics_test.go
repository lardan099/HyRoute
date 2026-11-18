package app

import (
	"context"
	"slices"
	"testing"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

func TestConnectionRouteUsesCurrentRulesAndRecordedAddress(t *testing.T) {
	c, _ := newCtl(t)
	a, b, _ := servers(t, c)
	r := rules.Rule{Name: "Сеть", Domains: []string{"192.0.2.0/24"}, Action: rules.Tunnel, Profile: a, Fallback: []string{b}}
	facts := ConnFacts{Process: "client.exe", Dst: "192.0.2.4:443", Proto: "tcp", Domain: "site.example", DomainSrc: "sni"}
	setRules(t, c, rules.Direct, "", r)
	route, err := c.ConnectionRoute(facts)
	if err != nil || route.Profile != a || route.Rule != r.Name || !slices.Equal(route.Fallback, []string{b}) {
		t.Fatalf("initial route: %+v, %v", route, err)
	}
	setRules(t, c, rules.Block, "")
	route, err = c.ConnectionRoute(facts)
	if err != nil || route.Action != "block" || route.Rule != "default" || route.Profile != "" {
		t.Fatalf("after rule change: %+v, %v", route, err)
	}
	facts.Excluded = "system-dns"
	route, err = c.ConnectionRoute(facts)
	if err != nil || route.Action != "" || route.Note == "" {
		t.Fatalf("service exclusion: %+v, %v", route, err)
	}
	setRules(t, c, rules.Direct, "", rules.Rule{Name: "Сайт", Domains: []string{"site.example"}, Action: rules.Tunnel, Profile: a})
	facts = ConnFacts{Dst: "192.0.2.4:443", Proto: "udp", DomainSrc: "dns", Domain: "site.example"}
	route, err = c.ConnectionRoute(facts)
	if err != nil || route.Action != "block" || route.Profile != "" {
		t.Fatalf("unknown QUIC name: %+v, %v", route, err)
	}
}

func TestTunnelReasonsFollowActiveAssignments(t *testing.T) {
	c, _ := newCtl(t)
	a, b, d := servers(t, c)
	g := saveGroup(t, c, "Работа", groups.Failover, b, d)
	if err := c.SetMain(a); err != nil {
		t.Fatal(err)
	}
	off := false
	disabled := curlRule(b)
	disabled.Name, disabled.Enabled = "Отключено", &off
	setRules(t, c, rules.Tunnel, g, curlRule("", b, b), disabled)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	if got := c.TunnelReasons(a); !slices.Equal(got, []string{"curl"}) {
		t.Fatalf("main: %v", got)
	}
	if got := c.TunnelReasons(b); !slices.Equal(got, []string{"curl (запасной)", "Группа «Работа» · по умолчанию"}) {
		t.Fatalf("group and fallback: %v", got)
	}
	c.mu.Lock()
	c.proxies = []store.LocalProxy{{ID: "work", Name: "Рабочий", Profile: d, Enabled: true}, {ID: "unused", Name: "Второй", Profile: d, Enabled: true}}
	c.mu.Unlock()
	if got := c.TunnelReasons(d); len(got) != 1 {
		t.Fatalf("sleeping proxy: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the fake session has no endpoint to wait for
	release := c.proxyWake(ctx, c.sess, d, "work")
	if got := c.TunnelReasons(d); !slices.Contains(got, "Локальный прокси · Рабочий") {
		t.Fatalf("awake proxy: %v", got)
	}
	release()
	if got := c.TunnelReasons(d); !slices.Contains(got, "Локальный прокси · Рабочий (ожидание простоя)") {
		t.Fatalf("proxy idle window: %v", got)
	}
	setRules(t, c, rules.Direct, "")
	if got := c.TunnelReasons(b); len(got) != 0 {
		t.Fatalf("after removing rule and default: %v", got)
	}
}
