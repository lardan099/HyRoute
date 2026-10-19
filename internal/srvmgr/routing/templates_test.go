package routing

import (
	"slices"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// The built-in templates pass Hysteria's compiler; the local one quiets
// the open-networks lint and leaves nothing for it to add.
func TestBuiltins(t *testing.T) {
	for _, tp := range Builtins() {
		ps := acl.Check(tp.ACL, acl.Env{})
		for _, p := range ps {
			if p.Level == acl.Error {
				t.Errorf("%s: %+v", tp.ID, p)
			}
		}
		if tp.ID == "builtin:local" && slices.ContainsFunc(ps, func(p acl.Problem) bool { return p.Code == "private" }) {
			t.Errorf("local: %+v", ps)
		}
		if tp.Name == "" || tp.Description == "" || len(tp.ACL.Rules) == 0 || !tp.Builtin {
			t.Errorf("%+v", tp)
		}
		for _, r := range tp.ACL.Rules {
			if r.Group == "" {
				t.Errorf("%s: no group", tp.ID)
			}
		}
	}
}

func TestFromPreset(t *testing.T) {
	p := model.Preset{ID: 4, Name: "Мой набор", Config: "acl:\n  inline:\n    - reject(geoip:private)\n    - nl(all)\noutbounds:\n  - name: nl\n    type: socks5\n    socks5:\n      addr: 203.0.113.5:1080\n"}
	tp, ok := FromPreset(p)
	if !ok || tp.ID != "preset:4" || tp.Name != "Мой набор" || len(tp.ACL.Rules) != 2 || len(tp.Outbounds) != 1 || tp.Outbounds[0].From != "" {
		t.Fatalf("%v %+v", ok, tp)
	}
	if _, ok := FromPreset(model.Preset{Config: "speedTest: true\n"}); ok {
		t.Fatal("a preset without rules")
	}
	// The cascade's outbound (in a preset made on an entry before) is not
	// offered: the link makes it.
	p.Config += "  - name: cascade\n    type: socks5\n    socks5:\n      addr: 127.0.0.1:41000\n"
	if tp, _ := FromPreset(p); len(tp.Outbounds) != 1 || tp.Outbounds[0].Name != "nl" {
		t.Fatalf("%+v", tp.Outbounds)
	}
}

// A template goes into a server's routing as the rule templates dialog
// puts it: its rules at the top, at the end or instead, the outbounds the
// server lacks, its resolver when asked.
func TestMerged(t *testing.T) {
	own := acl.Rule{Outbound: "direct", Address: "all", Text: "direct(all)"}
	v := View{Revision: 7, ACL: acl.Document{Rules: []acl.Rule{own}, Tail: []string{"# end"}},
		Outbounds: []Outbound{{Name: "NL", From: "NL", Type: "socks5", SOCKS5: &SOCKS5{Addr: "198.51.100.1:1080"}}}, Resolver: Resolver{Type: "system"}}
	tp := Template{ACL: acl.Document{Rules: []acl.Rule{{Outbound: "reject", Address: "geoip:private"}}},
		Outbounds: []Outbound{{Name: "nl", Type: "socks5", SOCKS5: &SOCKS5{Addr: "203.0.113.5:1080"}}, {Name: "us", From: "us", Type: "direct", Locked: true}},
		Resolver:  &Resolver{Type: "https", Addr: "1.1.1.1:443"}}
	addr := func(in Input) []string {
		var out []string
		for _, r := range in.ACL.Rules {
			out = append(out, r.Address)
		}
		return out
	}
	top := Merged(v, tp, PlaceTop, true, false)
	if top.Base != 7 || !slices.Equal(addr(top), []string{"geoip:private", "all"}) || !slices.Equal(top.ACL.Tail, v.ACL.Tail) || top.Resolver.Type != "system" {
		t.Fatalf("top %+v", top)
	}
	if len(top.Outbounds) != 2 || top.Outbounds[0].From != "NL" || top.Outbounds[1].Name != "us" || top.Outbounds[1].From != "" || top.Outbounds[1].Locked {
		t.Fatalf("outbounds %+v", top.Outbounds)
	}
	if b := Merged(v, tp, PlaceBottom, false, true); !slices.Equal(addr(b), []string{"all", "geoip:private"}) || len(b.Outbounds) != 1 || b.Resolver.Type != "https" {
		t.Fatalf("bottom %+v", b)
	}
	if r := Merged(v, tp, PlaceReplace, false, false); !slices.Equal(addr(r), []string{"geoip:private"}) {
		t.Fatalf("replace %+v", r)
	}
	if len(v.ACL.Rules) != 1 || len(v.Outbounds) != 1 || len(tp.ACL.Rules) != 1 {
		t.Fatal("the view or the template changed")
	}
	if got := Templates([]model.Preset{{ID: 2, Name: "x", Config: "acl:\n  inline:\n    - reject(all)\n"}}); len(got) != len(Builtins())+1 || got[len(got)-1].ID != "preset:2" {
		t.Fatalf("templates %+v", got)
	}
}
