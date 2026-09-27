//go:build windows

package engine

import (
	"net/netip"
	"testing"

	"github.com/lardan099/hyroute/internal/sysdns"
)

func TestAdapterDNSServers(t *testing.T) {
	l, err := sysdns.Servers()
	if err != nil {
		t.Fatal(err)
	}
	s := &systemDNS{}
	for a := range l {
		if !s.Has(a) {
			t.Fatalf("%s listed but not found", a)
		}
	}
	if s.Has(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("TEST-NET address reported as a DNS server")
	}
}
