//go:build windows

package sysdns

import "testing"

func TestServers(t *testing.T) {
	l, err := Servers()
	if err != nil {
		t.Fatal(err)
	}
	for a := range l {
		if !a.IsValid() || a.Is4In6() {
			t.Fatalf("%s: not a plain IPv4 or IPv6 address", a)
		}
	}
}
