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

// dns: the adapter walk needs no elevation; FlushCache is resolvable but
// never called by tests (it would empty this machine's DNS cache), and
// neither is the registry reader.
func TestAdapters(t *testing.T) {
	info, suffixes, err := adapters()
	if err != nil {
		t.Fatal(err)
	}
	if info.All == nil || info.Primary == nil {
		t.Fatal("nil maps")
	}
	for a := range info.Primary {
		if !info.All[a] {
			t.Fatalf("%s primary but not in All", a)
		}
	}
	_ = ParseNames(suffixes)
	if err := procFlush.Find(); err != nil {
		t.Fatal(err)
	}
}
