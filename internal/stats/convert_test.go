package stats

import (
	"testing"

	"github.com/lardan099/hyroute/internal/flows"
)

func TestFlowOf(t *testing.T) {
	base := func(set func(v *flows.View)) flows.View {
		v := flows.View{Process: "Chrome.exe", Path: `C:\Program Files\Chrome.EXE`,
			Fields: flows.Fields{Route: "tunnel", Profile: "de", Group: "grp-1", Failover: true, Outcome: "relayed", Domain: "a.com,b.com"}}
		if set != nil {
			set(&v)
		}
		return v
	}
	for _, kind := range []string{"self", "hysteria", "system-dns"} {
		if _, _, ok := flowOf(base(func(v *flows.View) { v.Excluded = kind })); ok {
			t.Errorf("%s counted", kind)
		}
	}
	if _, _, ok := flowOf(base(func(v *flows.View) { v.Stage = flows.StageDNS })); ok {
		t.Error("DNS row counted")
	}
	// Rule names are never parsed.
	f, settled, ok := flowOf(base(func(v *flows.View) { v.Rule = "exclusion: self" }))
	if !ok || !settled || f.App != `c:\program files\chrome.exe` || f.AppName != "Chrome.exe" ||
		f.Server != "de" || f.Group != "grp-1" || !f.Failover || f.Route != Tunnel {
		t.Fatalf("%+v", f)
	}
	if f, _, _ := flowOf(base(func(v *flows.View) { v.Path = "proxy:AbC" })); f.App != "proxy:AbC" {
		t.Fatalf("%q", f.App)
	}
	if f, _, _ := flowOf(base(func(v *flows.View) { v.Path = "" })); f.App != "chrome.exe" {
		t.Fatalf("%q", f.App)
	}
	if f, _, _ := flowOf(base(func(v *flows.View) { v.Path, v.Process = "", "" })); f.App != "" {
		t.Fatalf("%q", f.App)
	}
	for _, route := range []string{"direct", "block"} {
		f, _, _ := flowOf(base(func(v *flows.View) { v.Route = route }))
		if f.Server != "" || f.Group != "" || f.Failover {
			t.Errorf("%s keeps the pick: %+v", route, f)
		}
	}
	if _, settled, ok := flowOf(base(func(v *flows.View) { v.Route = "odd" })); settled || !ok {
		t.Error("unknown route settled")
	}
	if f, _, _ := flowOf(base(func(v *flows.View) { v.Outcome = "rst: socks5 connect failed" })); !f.Failed {
		t.Error("failed")
	}
}
