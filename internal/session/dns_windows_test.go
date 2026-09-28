//go:build windows

package session

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// dialStub is a connected runner whose dials fail or succeed on request.
type dialStub struct {
	stubRunner
	err error
}

func (r *dialStub) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	if r.err != nil {
		return nil, r.err
	}
	c1, c2 := net.Pipe()
	c2.Close()
	return c1, nil
}

// The resolver's dials through a routing endpoint (DoH/DoT to the tunnel
// server) are quiet: neither a failed nor a successful lookup changes a
// server group member's error streak.
func TestResolverDialsAreQuiet(t *testing.T) {
	for _, fail := range []bool{true, false} {
		var mu sync.Mutex
		var dials []string
		var dialErr error
		if fail {
			dialErr = errors.New("socks5: host unreachable")
		}
		m := &tunnels.Manager{
			New: func(_ hysteria.Profile, h tunnels.Hooks) tunnels.Runner {
				return &dialStub{stubRunner: stubRunner{h: h}, err: dialErr}
			},
			SetServerIPs: func([]netip.Addr) error { return nil },
			OnDial: func(id, dst string, err error) {
				mu.Lock()
				dials = append(dials, dst)
				mu.Unlock()
			},
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		m.Sync([]hysteria.Profile{{ID: "de", Name: "de", Host: "198.51.100.1", Ports: "443"}})
		e := m.Get("de")
		if e == nil || !e.Available() {
			t.Fatal("endpoint not running")
		}
		d := socksDialer(e)
		for _, host := range []string{"1.1.1.1", "2606:4700:4700::1111", "cloudflare-dns.com"} {
			c, err := d(t.Context(), host, 443)
			if (err != nil) != fail {
				t.Fatalf("fail=%v: %s: %v", fail, host, err)
			}
			if c != nil {
				c.Close()
			}
		}
		mu.Lock()
		if len(dials) != 0 {
			t.Fatalf("fail=%v: resolver dials reported to the groups: %v", fail, dials)
		}
		mu.Unlock()
		// A flow's dial through the same endpoint still reports.
		if c, _ := e.Dial(t.Context(), socks5.Addr{Host: "example.com", Port: 443}); c != nil {
			c.Close()
		}
		mu.Lock()
		if len(dials) != 1 {
			t.Fatalf("fail=%v: flow dial not reported: %v", fail, dials)
		}
		mu.Unlock()
		m.StopAll()
	}
}
