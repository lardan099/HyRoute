package divert

import (
	"encoding/hex"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/packet"
)

// These tests run the filters through WinDivert's own compiler and
// evaluator (tools/wdfilter, built from the WinDivert 2.2.2 sources). They
// are skipped unless HYROUTE_WDFILTER points at the binary:
//
//	./tools/wdfilter/build.sh
//	HYROUTE_WDFILTER=$PWD/tools/wdfilter/wdfilter go test ./internal/divert/
func wdfilter(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("HYROUTE_WDFILTER")
	if bin == "" {
		t.Skip("HYROUTE_WDFILTER not set (see tools/wdfilter/build.sh)")
	}
	return bin
}

func run(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, _ := exec.Command(bin, args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func TestFiltersCompileWithWinDivert(t *testing.T) {
	bin := wdfilter(t)
	servers := []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("2001:db8::10")}
	for _, c := range []struct {
		name, filter string
		layer        Layer
	}{
		{"main", MainFilter(FilterOptions{RelayPort: 50123, ServerIPs: servers}), LayerNetwork},
		{"main tcp", MainFilter(FilterOptions{RelayPort: 50123, ServerIPs: servers, TCPOnly: true}), LayerNetwork},
		{"main no servers", MainFilter(FilterOptions{RelayPort: 50123}), LayerNetwork},
		{"socket", SocketFilter, LayerSocket},
		{"dns", DNSFilter, LayerNetwork},
		{"flow", FlowFilter, LayerFlow},
	} {
		if got := run(t, bin, "compile", c.filter, string('0'+rune(c.layer))); got != "OK" {
			t.Errorf("%s: %s\n%s", c.name, got, c.filter)
		}
	}
}

func TestMainFilterSemantics(t *testing.T) {
	bin := wdfilter(t)
	const relay = 50123
	opts := FilterOptions{RelayPort: relay, ServerIPs: []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")}}
	tcp := func(src, dst string) []byte {
		return packet.BuildTCP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), packet.FlagSYN, 1, 0, nil)
	}
	udp := func(src, dst string) []byte {
		return packet.BuildUDP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), []byte("x"))
	}
	const L4, L6 = "192.168.1.5:50000", "[2a00:1450::5]:50000"
	// frag4 turns a UDP packet into an IPv4 fragment at offset off.
	frag4 := func(b []byte, off int, more bool) []byte {
		b = append([]byte(nil), b...)
		fl := uint16(off / 8)
		if more {
			fl |= 0x2000
		}
		b[6], b[7] = byte(fl>>8), byte(fl)
		if off > 0 { // no UDP header in later fragments
			b = append(b[:20], []byte("payload-continues")...)
			b[2], b[3] = 0, byte(len(b))
		}
		return b
	}
	cases := []struct {
		name     string
		opts     FilterOptions
		pkt      []byte
		outbound bool
		loopback bool
		want     string
	}{
		{"public v4", opts, tcp(L4, "93.184.216.34:443"), true, false, "1"},
		{"public v6", opts, tcp(L6, "[2606:4700::1111]:443"), true, false, "1"},
		{"udp v4", opts, udp(L4, "8.8.8.8:53"), true, false, "1"},
		{"udp excluded in tcp-only", FilterOptions{RelayPort: relay, TCPOnly: true}, udp(L4, "8.8.8.8:53"), true, false, "0"},
		{"10/8", opts, tcp(L4, "10.1.2.3:443"), true, false, "0"},
		{"172.16/12", opts, tcp(L4, "172.31.255.255:443"), true, false, "0"},
		{"172.32 is public", opts, tcp(L4, "172.32.0.1:443"), true, false, "1"},
		{"192.168/16", opts, tcp(L4, "192.168.1.1:80"), true, false, "0"},
		{"127/8", opts, tcp(L4, "127.0.0.1:80"), true, false, "0"},
		{"0/8", opts, tcp(L4, "0.1.2.3:80"), true, false, "0"},
		{"link-local v4", opts, tcp(L4, "169.254.1.1:80"), true, false, "0"},
		{"multicast v4", opts, udp(L4, "224.0.0.251:5353"), true, false, "0"},
		{"broadcast", opts, udp(L4, "255.255.255.255:67"), true, false, "0"},
		{"cgnat captured", opts, tcp(L4, "100.64.1.1:443"), true, false, "1"},
		{"server v4", opts, udp(L4, "203.0.113.10:30000"), true, false, "0"},
		{"server v4 neighbour", opts, udp(L4, "203.0.113.9:30000"), true, false, "1"},
		{"server v6", opts, udp(L6, "[2001:db8::10]:30000"), true, false, "0"},
		{"::1", opts, tcp("[::1]:5000", "[::1]:80"), true, false, "0"},
		{"fe80::/10", opts, tcp(L6, "[fe80::1]:80"), true, false, "0"},
		{"fc00::/7", opts, tcp(L6, "[fd12::1]:80"), true, false, "0"},
		{"ff00::/8", opts, udp(L6, "[ff02::fb]:5353"), true, false, "0"},
		{"loopback flag", opts, tcp(L4, "93.184.216.34:443"), true, true, "0"},
		{"inbound to relay", opts, tcp("93.184.216.34:443", "192.168.1.5:50123"), false, false, "1"},
		{"inbound other", opts, tcp("93.184.216.34:443", "192.168.1.5:50000"), false, false, "0"},
		{"relay reply", opts, tcp("192.168.1.5:50123", "93.184.216.34:50000"), true, false, "1"},
		{"udp first fragment", opts, frag4(udp(L4, "93.184.216.34:443"), 0, true), true, false, "1"},
		{"udp later fragment", opts, frag4(udp(L4, "93.184.216.34:443"), 1480, false), true, false, "1"},
		{"fragment to LAN", opts, frag4(udp(L4, "192.168.1.1:443"), 1480, false), true, false, "0"},
		{"fragment to server", opts, frag4(udp(L4, "203.0.113.10:30000"), 1480, false), true, false, "0"},
	}
	for _, c := range cases {
		ob, lb := "0", "0"
		if c.outbound {
			ob = "1"
		}
		if c.loopback {
			lb = "1"
		}
		if got := run(t, bin, "eval", MainFilter(c.opts), hex.EncodeToString(c.pkt), ob, lb); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

// dns: the DNS capture filter compiles, with maxServerIPs addresses too,
// and captures DNS and fragments to private destinations.
func TestMainFilterDNSWinDivert(t *testing.T) {
	bin := wdfilter(t)
	const relay = 50123
	servers := []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")}
	opts := FilterOptions{RelayPort: relay, ServerIPs: servers, DNS: true}
	many := FilterOptions{RelayPort: relay, DNS: true}
	for i := range 100 {
		if i%2 == 0 {
			many.ServerIPs = append(many.ServerIPs, netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}))
		} else {
			many.ServerIPs = append(many.ServerIPs, netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i)}))
		}
	}
	for _, o := range []FilterOptions{opts, many, {RelayPort: relay, DNS: true, TCPOnly: true, ServerIPs: many.ServerIPs}} {
		if got := run(t, bin, "compile", MainFilter(o), "0"); got != "OK" {
			t.Fatalf("%s\n%s", got, MainFilter(o))
		}
	}
	tcp := func(src, dst string) []byte {
		return packet.BuildTCP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), packet.FlagSYN, 1, 0, nil)
	}
	udp := func(src, dst string) []byte {
		return packet.BuildUDP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), []byte("x"))
	}
	later := func(b []byte) []byte { // an IPv4 fragment at offset 1480, no UDP header
		b = append([]byte(nil), b[:20]...)
		b = append(b, []byte("payload-continues")...)
		b[2], b[3] = 0, byte(len(b))
		b[6], b[7] = 0, 185
		return b
	}
	const L4, L6 = "192.168.1.5:50000", "[fe80::5]:50000"
	for _, c := range []struct {
		name string
		pkt  []byte
		want string
	}{
		{"udp 53 to the router", udp(L4, "192.168.1.1:53"), "1"},
		{"tcp 53 to the router", tcp(L4, "192.168.1.1:53"), "1"},
		{"udp 53 link-local v6", udp(L6, "[fe80::1]:53"), "1"},
		{"tcp 53 link-local v6", tcp(L6, "[fe80::1]:53"), "1"},
		{"router 443", tcp(L4, "192.168.1.1:443"), "0"},
		{"router 443 udp", udp(L4, "192.168.1.1:443"), "0"},
		{"server 53", udp(L4, "203.0.113.10:53"), "0"},
		{"server v6 53", tcp("[2a00::5]:50000", "[2001:db8::10]:53"), "0"},
		{"relay reply to the router", tcp("192.168.1.5:50123", "192.168.1.1:50000"), "1"},
		{"later fragment to the router", later(udp(L4, "192.168.1.1:53")), "1"},
		{"public stays", tcp(L4, "93.184.216.34:443"), "1"},
	} {
		if got := run(t, bin, "eval", MainFilter(opts), hex.EncodeToString(c.pkt), "1", "0"); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
	if got := run(t, bin, "eval", MainFilter(opts), hex.EncodeToString(udp(L4, "192.168.1.1:53")), "1", "1"); got != "0" {
		t.Errorf("loopback captured")
	}
}
