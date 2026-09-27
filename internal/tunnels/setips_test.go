package tunnels

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
)

// A list the engine could not apply leaves the union: its profile retries
// with it, and the other profiles' changes must not fail on it meanwhile.
func TestSetIPsFailureKeepsAppliedUnion(t *testing.T) {
	bad := netip.MustParseAddr("203.0.113.99")
	var applied []netip.Addr
	fail := false
	m := &Manager{SetServerIPs: func(ips []netip.Addr) error {
		if fail || slices.Contains(ips, bad) {
			return errors.New("filter not opened")
		}
		applied = ips
		return nil
	}}
	step := func(key string, ips []netip.Addr, wantErr bool, want []netip.Addr) {
		t.Helper()
		if err := m.setIPs(key, ips); (err != nil) != wantErr {
			t.Fatalf("setIPs(%s, %v): %v", key, ips, err)
		}
		if !slices.Equal(applied, want) {
			t.Fatalf("after setIPs(%s, %v): applied %v, want %v", key, ips, applied, want)
		}
	}
	step("a", ipList("203.0.113.1"), false, ipList("203.0.113.1"))
	step("b", ipList("203.0.113.2"), false, ipList("203.0.113.1", "203.0.113.2"))
	// A replacement and a new profile that fail keep what was there.
	step("a", ipList("203.0.113.99"), true, ipList("203.0.113.1", "203.0.113.2"))
	step("c", ipList("203.0.113.99"), true, ipList("203.0.113.1", "203.0.113.2"))
	step("d", ipList("203.0.113.4"), false, ipList("203.0.113.1", "203.0.113.2", "203.0.113.4"))
	// A failed removal stays done: the next change drops the address.
	fail = true
	step("b", nil, true, ipList("203.0.113.1", "203.0.113.2", "203.0.113.4"))
	fail = false
	step("d", nil, false, ipList("203.0.113.1"))
}
