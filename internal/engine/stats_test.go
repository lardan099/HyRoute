package engine

import (
	"net/netip"
	"testing"

	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
)

// stats: a tunnel pick the IPv6 block turns into a block keeps no group
// and no failover (statistics count failovers of tunnel flows only).
func TestIPv6BlockClearsPick(t *testing.T) {
	g := newGroupRig(t, curlTo(grp1, "us"), Options{NoDefaultExclusions: true, BlockIPv6Tunnel: true}, []string{"de", "nl", "us"},
		groups.Group{ID: grp1, Name: "F", Strategy: groups.Failover, Members: []string{"de", "nl"}})
	g.tuns["de"].up.Store(false)
	// Over IPv4 the pick is a failover to the second member.
	if e := g.syn(t, "192.168.1.5:41002", R, 100); e == nil || e.Profile != "nl" {
		t.Fatalf("%+v", e)
	}
	if v := lastRecord(t, g.c); !v.Failover || v.Group != grp1 {
		t.Fatalf("%+v", v)
	}
	// The same pick for an IPv6 SYN is refused as a block.
	if e := g.syn(t, L6, R6, 100); e != nil {
		t.Fatalf("%+v", e)
	}
	if v := lastRecord(t, g.c); v.Route != "block" || v.Failover || v.Group != "" {
		t.Fatalf("IPv6 SYN: %+v", v)
	}
	// An IPv6 datagram.
	g.own(17, "[2a00::5]:40001", "[2606:4700::1111]:3478", 100)
	g.sendUDP("[2a00::5]:40001", "[2606:4700::1111]:3478", []byte("x"))
	if v := lastRecord(t, g.c); v.Route != "block" || v.Outcome != "dropped: IPv6 blocked for tunnel" || v.Failover || v.Group != "" {
		t.Fatalf("IPv6 UDP: %+v", v)
	}
	// A sniffed IPv6 flow.
	e6 := &nat.Entry{Flow: nat.FlowKey{Dst: netip.MustParseAddrPort(R6)}, Meta: &procinfo.Info{Name: "curl.exe", Path: `C:\Tools\curl.exe`}}
	if r := g.c.RelayDecide(e6, "a.test", rules.SrcSNI); r.Action != rules.Block || r.Failover || r.Group != "" {
		t.Fatalf("RelayDecide: %+v", r)
	}
}
