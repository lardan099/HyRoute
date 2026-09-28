package netwatch

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/lardan099/hyroute/internal/netmode"
)

func TestAdapterKind(t *testing.T) {
	for in, want := range map[uint32]string{6: netmode.Ethernet, 71: netmode.WiFi, 243: netmode.Mobile, 244: netmode.Mobile, 131: netmode.Other, 53: netmode.Other} {
		if got := adapterKind(in); got != want {
			t.Errorf("%d: %s, want %s", in, got, want)
		}
	}
}

func TestCategoryName(t *testing.T) {
	for in, want := range map[uint32]string{0: netmode.Public, 1: netmode.Private, 2: netmode.Domain, 99: ""} {
		if got := categoryName(in); got != want {
			t.Errorf("%d: %q, want %q", in, got, want)
		}
	}
}

func attrs(n uint32, ssid string, size int) []byte {
	b := make([]byte, size)
	if size >= ssidOffset+4 {
		binary.LittleEndian.PutUint32(b[ssidOffset:], n)
		copy(b[ssidOffset+4:], ssid)
	}
	return b
}

func TestParseConnectionAttributes(t *testing.T) {
	full := ssidOffset + 4 + 32 + 64
	if s, ok := parseConnectionAttributes(attrs(4, "Home", full)); !ok || string(s) != "Home" {
		t.Fatal(string(s), ok)
	}
	if s, ok := parseConnectionAttributes(attrs(0, "", full)); !ok || len(s) != 0 {
		t.Fatal("length 0")
	}
	if _, ok := parseConnectionAttributes(attrs(33, "x", full)); ok {
		t.Fatal("length 33 accepted")
	}
	if _, ok := parseConnectionAttributes(attrs(4, "Home", ssidOffset+10)); ok {
		t.Fatal("short buffer accepted")
	}
	if _, ok := parseConnectionAttributes(nil); ok {
		t.Fatal("nil accepted")
	}
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, x := range s {
		out = append(out, netip.MustParseAddr(x))
	}
	return out
}

func TestPickGateway(t *testing.T) {
	if g := pickGateway(addrs("192.168.1.254", "192.168.1.1"), addrs("fe80::1")); g != "192.168.1.1" {
		t.Fatal(g)
	}
	if g := pickGateway(nil, addrs("fe80::2%12", "fe80::1%12")); g != "fe80::1" {
		t.Fatal(g)
	}
	if g := pickGateway(nil, nil); g != "" {
		t.Fatal(g)
	}
	v4, v6 := splitGateways(addrs("::ffff:10.0.0.1", "fe80::1", "::"))
	if len(v4) != 1 || v4[0].String() != "10.0.0.1" || len(v6) != 1 {
		t.Fatal(v4, v6)
	}
}

func TestMacString(t *testing.T) {
	if s := macString([]byte{0xaa, 0xbb, 0xcc, 1, 2, 0xff}); s != "aa-bb-cc-01-02-ff" {
		t.Fatal(s)
	}
	for _, b := range [][]byte{nil, {1, 2, 3}, make([]byte, 8)} {
		if macString(b) != "" {
			t.Fatal(b)
		}
	}
}

func TestGuidString(t *testing.T) {
	s := guidString(0x5e1b9c0a, 0x3c7d, 0x4f0e, [8]byte{0x9a, 0x51, 0x0d, 0x2b, 0x6b, 0x1c, 0x7e, 0x11})
	if s != "{5E1B9C0A-3C7D-4F0E-9A51-0D2B6B1C7E11}" || netmode.CanonGUID(s) != s {
		t.Fatal(s)
	}
}

func TestBestNetwork(t *testing.T) {
	ads := []adapter{
		{ifIndex: 1, ifType: ifTypeLoopback},
		{ifIndex: 7, ipv6IfIndex: 7, ifType: ifTypeEthernet, guid: "{E}"},
		{ifIndex: 12, ipv6IfIndex: 13, ifType: ifTypeWiFi, guid: "{W}"},
	}
	if a := bestNetwork(ads, 12); a == nil || a.guid != "{W}" {
		t.Fatal("IPv4 index")
	}
	if a := bestNetwork(ads, 13); a == nil || a.guid != "{W}" {
		t.Fatal("IPv6 index")
	}
	if bestNetwork(ads, 99) != nil || bestNetwork(ads, 0) != nil || bestNetwork(ads, 1) != nil {
		t.Fatal("no match / loopback")
	}
}
