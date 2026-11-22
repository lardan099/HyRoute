package engine

import (
	"testing"

	"github.com/lardan099/hyroute/internal/procinfo"
)

// The cores HyRoute started are its own traffic: hysteria.exe and
// xray.exe, and the copies of HyRoute that run AmneziaWG servers.
func TestOwnHysteria(t *testing.T) {
	c := &Core{SelfPID: 10, SelfName: "hyroute.exe"}
	self := &procinfo.Info{PID: 10, Name: "hyroute.exe"}
	other := &procinfo.Info{PID: 20, Name: "explorer.exe"}
	for _, tc := range []struct {
		proc *procinfo.Info
		want bool
	}{
		{&procinfo.Info{PID: 11, Name: "hysteria.exe", Parent: self}, true},
		{&procinfo.Info{PID: 12, Name: "xray.exe", Parent: self}, true},
		{&procinfo.Info{PID: 13, Name: "hyroute.exe", Parent: self}, true},
		{&procinfo.Info{PID: 14, Name: "hyroute.exe", Parent: other}, false},
		{&procinfo.Info{PID: 15, Name: "hysteria.exe", Parent: other}, false},
		{&procinfo.Info{PID: 16, Name: "curl.exe", Parent: self}, false},
		{&procinfo.Info{PID: 17, Name: "hyroute.exe"}, false},
		{nil, false},
	} {
		if got := c.ownHysteria(tc.proc); got != tc.want {
			t.Errorf("%+v: %v", tc.proc, got)
		}
	}
	if (&Core{SelfPID: 10}).ownHysteria(&procinfo.Info{Name: "", Parent: self}) {
		t.Error("an unknown name counts as HyRoute's")
	}
}
