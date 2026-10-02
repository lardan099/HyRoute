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
}
