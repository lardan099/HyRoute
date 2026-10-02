package routing

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func TestChainBuiltins(t *testing.T) {
	for _, c := range ChainBuiltins() {
		if err := c.Link.Validate(); err != nil || c.Format != ChainFormat || c.Version != ChainVersion || !c.Builtin || c.Name == "" {
			t.Errorf("%+v %v", c, err)
		}
		if c.Entry == nil {
			continue
		}
		for _, p := range acl.Check(c.Entry.ACL, acl.Env{Entry: true, Resolver: hyconfig.Resolver{Type: c.Entry.Resolver.Type}, GeoIPPath: "/g", GeoSitePath: "/s"}) {
			t.Errorf("%s: %+v", c.ID, p)
		}
		// Domain rules come before geoip ones.
		last := -1
		for i, r := range c.Entry.ACL.Rules {
			if k := acl.KindOf(r.Address); k == acl.KindSuffix || k == acl.KindDomain || k == acl.KindGeoSite {
				last = i
			}
		}
		if first := slices.IndexFunc(c.Entry.ACL.Rules, func(r acl.Rule) bool { return acl.KindOf(r.Address) == acl.KindGeoIP }); first >= 0 && first < last {
			t.Errorf("%s: geoip at %d before domains up to %d", c.ID, first, last)
		}
	}
}

// A cascade's template carries no server, local port or secret, and reads
// back as it was.
func TestChainExport(t *testing.T) {
	e := newEnv(t, config, true)
	v, err := e.svc.Open(context.Background(), e.server)
	if err != nil {
		t.Fatal(err)
	}
	p := cascade.Params{LocalPort: 40001, Up: "100 mbps", Down: "200 mbps", NoUDP: true, CheckTarget: "www.example.com:443"}
	c := model.Chain{ID: 7, Name: "RU→NL", Notes: "мой каскад", Nodes: []int64{e.server, 99}, Links: []model.ChainLink{{Params: p.Raw(), State: model.LinkActive}}}
	tp, err := ChainOf(c, v)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tp)
	for _, s := range []string{"fake-", "localPort", "127.0.0.1", "192.0.2.", "203.0.113.", redactMask()} {
		if strings.Contains(string(b), s) {
			t.Errorf("%q in %s", s, b)
		}
	}
	if tp.Link.Up != "100 mbps" || !tp.Link.NoUDP || tp.Entry == nil || len(tp.Entry.ACL.Rules) != 3 || tp.Entry.Resolver.Type != "udp" || tp.Description != "мой каскад" {
		t.Fatalf("%+v", tp)
	}
	back, err := ImportChain(b)
	if err != nil {
		t.Fatal(err)
	}
	if b2, _ := json.Marshal(back); string(b2) != string(b) {
		t.Fatalf("import changed it:\n%s\n%s", b, b2)
	}

	var fe *model.FieldError
	for _, bad := range []string{
		`{"format":"hyroute-routing","version":1}`,
		`{"format":"hyroute-chain","version":9}`,
		`{"format":"hyroute-chain","version":1,"link":{"up":"100 mbps"}}`,
		`{"format":`,
	} {
		if _, err := ImportChain([]byte(bad)); !errors.As(err, &fe) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	// A local port in a file is not taken: it is the entry's.
	if tp, err := ImportChain([]byte(`{"format":"hyroute-chain","version":1,"name":"x","link":{"localPort":40002},"id":"builtin:all","builtin":true}`)); err != nil || tp.Link.LocalPort != 0 || tp.Builtin || tp.ID != "" {
		t.Fatalf("%v %+v", err, tp)
	}
}

func redactMask() string { return "[REDACTED]" }

// A cascade from a template gets the link client's config a cascade made
// by hand with the same settings gets.
func TestChainSameConfig(t *testing.T) {
	exitCfg, err := hyconfig.ParseServer([]byte("listen: :443\nacme:\n  domains: [exit.example.com]\nauth:\n  type: password\n  password: fake-exit-pass\n"))
	if err != nil {
		t.Fatal(err)
	}
	exit := model.Server{ID: 2, Name: "nl", Host: "exit.example.com"}
	s := cascade.Secrets{SOCKSUser: "link-1-0", SOCKSPassword: "fake-socks-pass"}
	manual := cascade.Params{Up: "50 mbps", Down: "300 mbps", NoUDP: true}
	for _, tp := range append(ChainBuiltins(), ChainTemplate{Format: ChainFormat, Version: ChainVersion, Name: "x", Link: manual}) {
		// The template's settings as the create API stores them.
		var stored cascade.Params
		json.Unmarshal(tp.Link.Raw(), &stored)
		hand := tp.Link
		stored.LocalPort, hand.LocalPort = 41000, 41000
		a, err1 := cascade.ClientConfig(exit, exitCfg, model.ConfigMeta{}, 1, 0, stored, s)
		b, err2 := cascade.ClientConfig(exit, exitCfg, model.ConfigMeta{}, 1, 0, hand, s)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		ya, _ := a.Marshal()
		yb, _ := b.Marshal()
		if string(ya) != string(yb) {
			t.Fatalf("%s:\n%s\n%s", tp.Name, ya, yb)
		}
	}
}
