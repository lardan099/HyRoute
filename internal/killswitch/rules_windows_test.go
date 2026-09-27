//go:build windows

package killswitch

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// conn is what the filters see of a connection.
type conn struct {
	app      string
	proto    wf.IPProto
	local    uint16
	remote   netip.AddrPort
	loopback bool
}

// matches applies a rule the way WFP does: conditions on one field are
// ORed, conditions on different fields ANDed.
func matches(r *wf.Rule, c conn) bool {
	fields := map[wf.FieldID]bool{}
	for _, m := range r.Conditions {
		if m.Field != wf.FieldFlags && m.Op != wf.MatchTypeEqual {
			panic(fmt.Sprintf("%s: operator not modeled", m))
		}
		var ok bool
		switch m.Field {
		case wf.FieldALEAppID:
			ok = m.Value.(string) == c.app
		case wf.FieldIPProtocol:
			ok = m.Value.(wf.IPProto) == c.proto
		case wf.FieldIPLocalPort:
			ok = m.Value.(uint16) == c.local
		case wf.FieldIPRemotePort:
			ok = m.Value.(uint16) == c.remote.Port()
		case wf.FieldIPRemoteAddress:
			switch v := m.Value.(type) {
			case netip.Addr:
				ok = v == c.remote.Addr()
			case netip.Prefix:
				ok = v.Contains(c.remote.Addr())
			default:
				panic(fmt.Sprintf("%s: value not modeled", m))
			}
		case wf.FieldFlags:
			if m.Value != wf.ConditionFlagIsLoopback {
				panic(fmt.Sprintf("%s: flag not modeled", m))
			}
			switch m.Op {
			case wf.MatchTypeFlagsAllSet:
				ok = c.loopback
			case wf.MatchTypeFlagsNoneSet:
				ok = !c.loopback
			default:
				panic(fmt.Sprintf("%s: operator not modeled", m))
			}
		default:
			panic(fmt.Sprintf("%s: field not modeled", m))
		}
		fields[m.Field] = fields[m.Field] || ok
	}
	for _, ok := range fields {
		if !ok {
			return false
		}
	}
	return true
}

// decide is the action of the highest-weighted rule that matches: the
// sublayer's verdict.
func decide(t *testing.T, rs []*wf.Rule, c conn) wf.Action {
	t.Helper()
	var top *wf.Rule
	for _, r := range rs {
		if !matches(r, c) {
			continue
		}
		switch {
		case top == nil || r.Weight > top.Weight:
			top = r
		case r.Weight == top.Weight && r.Action != top.Action:
			t.Fatalf("%+v: %q and %q decide differently at the same weight", c, r.Name, top.Name)
		}
	}
	if top == nil {
		t.Fatalf("%+v: no rule matches", c)
	}
	return top.Action
}

func find(rs []*wf.Rule, i int, kind byte) *wf.Rule {
	for _, r := range rs {
		if r.ID == ruleID(i, kind) {
			return r
		}
	}
	return nil
}

// TestRules checks what Arm installs on every layer: what gets through
// the block and what does not, with and without the pass filters.
func TestRules(t *testing.T) {
	const relay = 50123
	e := exceptions{
		apps:  []string{"hyroute", "hysteria"},
		svc:   "svchost",
		dns:   []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
		self:  "hyroute",
		relay: relay,
	}
	for i, l := range layers {
		// Arm deletes what it replaces before adding it again.
		for _, r := range e.rules(i) {
			if kind := windows.GUID(r.ID).Data4[7]; !slices.Contains(refreshedKinds, kind) {
				t.Fatalf("%s: a second Arm would find it in place", r.Name)
			}
		}
		block := append(fixedRules(i), e.rules(i)...)
		seen := map[wf.RuleID]bool{}
		for _, r := range block {
			if r.Layer != l.id || r.Sublayer != sublayerID {
				t.Fatalf("%s: layer %v, sublayer %v", r.Name, r.Layer, r.Sublayer)
			}
			if seen[r.ID] {
				t.Fatalf("%s: ID used twice on the layer", r.Name)
			}
			seen[r.ID] = true
			if kind := windows.GUID(r.ID).Data4[7]; !slices.Contains(blockKinds, kind) {
				t.Fatalf("%s: Release does not remove kind %d", r.Name, kind)
			}
		}
		for _, kind := range []byte{kindSecureDNS, kindRelay} {
			if find(block, i, kind) == nil {
				t.Fatalf("layer %d: no filter of kind %d", i, kind)
			}
		}

		// The layer's address family: a DNS server, a remote host and a
		// host of the local network.
		dns, host, lan := "1.1.1.1", "93.184.216.34", "192.168.1.20"
		if l.v6 {
			dns, host, lan = "2606:4700:4700::1111", "2001:db8::34", "fe80::20"
		}
		at := func(a string, port uint16) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr(a), port) }
		otherDNS := at("9.9.9.9", 443)
		if l.v6 {
			otherDNS = at("2620:fe::fe", 443)
		}
		tcp, udp := wf.IPProtoTCP, wf.IPProtoUDP
		cases := []struct {
			what string
			c    conn
			want wf.Action
		}{
			{"a browser", conn{app: "browser", proto: tcp, local: 50000, remote: at(host, 443)}, wf.ActionBlock},
			{"a browser to the DNS server's DoH port", conn{app: "browser", proto: tcp, local: 50000, remote: at(dns, 443)}, wf.ActionBlock},
			{"the local network", conn{app: "browser", proto: tcp, local: 50000, remote: at(lan, 445)}, wf.ActionPermit},
			{"loopback", conn{app: "browser", proto: tcp, local: 50000, remote: at(host, 80), loopback: true}, wf.ActionPermit},
			{"DNS", conn{app: "svchost", proto: udp, local: 50000, remote: at(host, 53)}, wf.ActionPermit},
			{"DNS of another program", conn{app: "browser", proto: udp, local: 50000, remote: at(host, 53)}, wf.ActionBlock},
			{"DoH to the DNS server", conn{app: "svchost", proto: tcp, local: 50000, remote: at(dns, 443)}, wf.ActionPermit},
			{"DoT to the DNS server", conn{app: "svchost", proto: tcp, local: 50000, remote: at(dns, 853)}, wf.ActionPermit},
			{"DoH to another server", conn{app: "svchost", proto: tcp, local: 50000, remote: otherDNS}, wf.ActionBlock},
			{"QUIC to the DNS server", conn{app: "svchost", proto: udp, local: 50000, remote: at(dns, 443)}, wf.ActionBlock},
			{"a service to the DNS server's web port", conn{app: "svchost", proto: tcp, local: 50000, remote: at(dns, 80)}, wf.ActionBlock},
			{"Hysteria", conn{app: "hysteria", proto: udp, local: 50000, remote: at(host, 443)}, wf.ActionPermit},
			{"HyRoute", conn{app: "hyroute", proto: tcp, local: 50000, remote: at(host, 443)}, wf.ActionPermit},
			{"the relay", conn{app: "hyroute", proto: tcp, local: relay, remote: at(host, 51000)}, wf.ActionBlock},
			{"the relay on the local network", conn{app: "hyroute", proto: tcp, local: relay, remote: at(lan, 51000)}, wf.ActionBlock},
			{"the relay over loopback", conn{app: "hyroute", proto: tcp, local: relay, remote: at(host, 51000), loopback: true}, wf.ActionPermit},
			{"another program on the relay's port", conn{app: "browser", proto: tcp, local: relay, remote: at(lan, 51000)}, wf.ActionPermit},
		}
		for _, tc := range cases {
			if got := decide(t, block, tc.c); got != tc.want {
				t.Errorf("layer %d, %s: %v, want %v", i, tc.what, got, tc.want)
			}
			// While routing works the pass filters let everything through.
			if got := decide(t, append(block, passRule(i)), tc.c); got != wf.ActionPermit {
				t.Errorf("layer %d, %s under the pass: %v", i, tc.what, got)
			}
		}
	}

	// Unknown pieces leave their filters out; without svchost's app ID the
	// DNS ports stay open to every program, as before.
	for i := range layers {
		rs := exceptions{dns: e.dns}.rules(i)
		if len(rs) != 1 || rs[0].ID != ruleID(i, kindPorts) || len(rs[0].Conditions) != len(Ports) {
			t.Fatalf("layer %d without app IDs, relay: %v", i, rs)
		}
	}
	// Only the family's DNS servers: no IPv6 server, no IPv6 filter.
	v4 := exceptions{svc: "svchost", dns: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	for i, l := range layers {
		if got := find(v4.rules(i), i, kindSecureDNS) != nil; got == l.v6 {
			t.Fatalf("layer %d (IPv6 %v): encrypted DNS filter %v", i, l.v6, got)
		}
	}
}
