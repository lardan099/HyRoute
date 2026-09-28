//go:build windows

package session

import (
	"testing"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// The stub runner reports its status through its hooks like a Hysteria:
// server groups follow the uptime of stub members too.
func TestStubRunnerReportsStatus(t *testing.T) {
	var got []hysteria.State
	r := &stubRunner{c: socks5.Client{Server: "127.0.0.1:1"}, h: tunnels.Hooks{OnStatus: func(st hysteria.Status) {
		got = append(got, st.State)
	}}}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if !r.Available() || len(got) != 1 || got[0] != hysteria.Connected {
		t.Fatalf("after Start: %v", got)
	}
	r.Stop()
	if r.Available() || len(got) != 2 || got[1] != hysteria.Stopped {
		t.Fatalf("after Stop: %v", got)
	}
	// Without hooks (a check outside a session) it still works.
	(&stubRunner{}).Start()
}
