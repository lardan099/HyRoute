package divert

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/lardan099/hyroute/internal/packet"
)

func TestAddressLayout(t *testing.T) {
	if unsafe.Sizeof(Address{}) != AddressSize {
		t.Fatalf("sizeof(Address) = %d", unsafe.Sizeof(Address{}))
	}
	var a Address
	// Layer=SOCKET(3), Event=CONNECT(4), Outbound, IPv6.
	a.bits = 3 | 4<<8 | bitOutbound | bitIPv6
	if a.Layer() != LayerSocket || a.Event() != EventSocketConnect || !a.Outbound() || !a.IPv6() || a.Loopback() {
		t.Fatal("bitfield decode")
	}
	a.SetOutbound(false)
	if a.Outbound() || a.Layer() != LayerSocket {
		t.Fatal("SetOutbound")
	}
	a.SetChecksumsValid()
	if a.bits&(bitIPChecksum|bitTCPChecksum|bitUDPChecksum) != bitIPChecksum|bitTCPChecksum|bitUDPChecksum {
		t.Fatal("checksum bits")
	}
}

func TestSocketDataDecode(t *testing.T) {
	var a Address
	u := a.union[:]
	binary.LittleEndian.PutUint64(u[0:], 0x1122)
	binary.LittleEndian.PutUint64(u[8:], 0x33)
	binary.LittleEndian.PutUint32(u[16:], 4242)
	// 192.168.1.10 as WinDivert stores it: UINT32[0]=0xC0A8010A (host
	// order), UINT32[1]=0x0000FFFF, rest 0.
	binary.LittleEndian.PutUint32(u[20:], 0xC0A8010A)
	binary.LittleEndian.PutUint32(u[24:], 0x0000FFFF)
	raw := RawFromAddr(netip.MustParseAddr("2001:db8::1"))
	copy(u[36:52], raw[:])
	binary.LittleEndian.PutUint16(u[52:], 51000)
	binary.LittleEndian.PutUint16(u[54:], 443)
	u[56] = 6
	s := a.Socket()
	want := SocketData{
		EndpointID: 0x1122, ParentEndpointID: 0x33, ProcessID: 4242,
		LocalAddr:  netip.MustParseAddr("192.168.1.10"),
		RemoteAddr: netip.MustParseAddr("2001:db8::1"),
		LocalPort:  51000, RemotePort: 443, Protocol: 6,
	}
	if s != want {
		t.Fatalf("got %+v", s)
	}
	// The IPv6 raw form: UINT32[3] holds the most significant word.
	if binary.LittleEndian.Uint32(raw[12:]) != 0x20010db8 || binary.LittleEndian.Uint32(raw[0:]) != 1 {
		t.Fatalf("raw ipv6 layout %x", raw)
	}
}

func TestSplitBatch(t *testing.T) {
	a := packet.BuildUDP(netip.MustParseAddrPort("1.1.1.1:53"), netip.MustParseAddrPort("10.0.0.1:5000"), []byte("abc"))
	b := packet.BuildUDP(netip.MustParseAddrPort("[2001:db8::1]:53"), netip.MustParseAddrPort("[2001:db8::2]:5000"), []byte("hello"))
	buf := append(append([]byte(nil), a...), b...)
	got := SplitBatch(buf)
	if len(got) != 2 || len(got[0]) != len(a) || len(got[1]) != len(b) {
		t.Fatalf("split: %d parts", len(got))
	}
	if len(SplitBatch(buf[:len(buf)-1])) != 1 {
		t.Fatal("truncated tail must be dropped")
	}
}

func TestMainFilter(t *testing.T) {
	f := MainFilter(FilterOptions{
		RelayPort: 50123,
		ServerIPs: []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")},
	})
	for _, want := range []string{
		"outbound and !loopback and (tcp or udp or fragment)",
		"(ipv6 or ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255)",
		"(ipv6 or ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255)",
		"(ipv6 or ip.DstAddr < 240.0.0.0 or ip.DstAddr > 255.255.255.255)",
		"(ipv6 or ip.DstAddr > 0.255.255.255)",
		"(ip or ipv6.DstAddr < fe80:: or ipv6.DstAddr > febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff)",
		"(ip or ipv6.DstAddr > ::1)",
		"(ipv6 or ip.DstAddr != 203.0.113.10)",
		"(ip or ipv6.DstAddr != 2001:db8::10)",
		"or (inbound and tcp.DstPort == 50123)",
	} {
		if !strings.Contains(f, want) {
			t.Fatalf("filter lacks %q:\n%s", want, f)
		}
	}
	// WinDivert rejects negation of a parenthesized expression.
	if strings.Contains(f, "not (") || strings.Contains(f, "!(") {
		t.Fatal("negated group is a WinDivert parse error")
	}
	// CGNAT (Tailscale) is captured: the template «Локальная сеть» sends
	// it direct by the rules.
	if strings.Contains(f, "100.64.0.0") {
		t.Fatal("CGNAT excluded in the filter")
	}
	f = MainFilter(FilterOptions{RelayPort: 1, TCPOnly: true})
	if !strings.Contains(f, "!loopback and tcp and") {
		t.Fatal(f)
	}
}

func TestExplain(t *testing.T) {
	d := &DriverInfo{Exists: true, ImagePath: `C:\zapret\binaries\win64\WinDivert64.sys`}
	if m := Explain(654, d); !strings.Contains(m, "несовместимая") || !strings.Contains(m, `C:\zapret`) {
		t.Fatal(m)
	}
	if m := Explain(2, d); !strings.Contains(m, "sc delete WinDivert") {
		t.Fatal(m)
	}
	if m := Explain(2, nil); !strings.Contains(m, "WinDivert64.sys") {
		t.Fatal(m)
	}
	// An older driver of another program may reject our parameters before
	// the version check: the message names it.
	if m := Explain(87, d); !strings.Contains(m, `C:\zapret`) {
		t.Fatal(m)
	}
	if err := CheckVersion(2, 2, nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckVersion(2, 1, d); err == nil || !strings.Contains(err.Error(), "2.1") {
		t.Fatal(err)
	}
}

// dns: without DNS capture the filter is exactly the one before it;
// with it, DNS and fragments to private destinations and the relay's
// replies are captured, never a server IP's.
func TestMainFilterDNS(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("2001:db8::10")}
	base := FilterOptions{RelayPort: 50123, ServerIPs: servers}
	const before = "(outbound and !loopback and (tcp or udp or fragment) and (ipv6 or ip.DstAddr > 0.255.255.255) and " +
		"(ipv6 or ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and (ipv6 or ip.DstAddr < 127.0.0.0 or ip.DstAddr > 127.255.255.255) and " +
		"(ipv6 or ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255) and (ipv6 or ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and " +
		"(ipv6 or ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and (ipv6 or ip.DstAddr < 224.0.0.0 or ip.DstAddr > 239.255.255.255) and " +
		"(ipv6 or ip.DstAddr < 240.0.0.0 or ip.DstAddr > 255.255.255.255) and (ip or ipv6.DstAddr > ::1) and " +
		"(ip or ipv6.DstAddr < fe80:: or ipv6.DstAddr > febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff) and " +
		"(ip or ipv6.DstAddr < fc00:: or ipv6.DstAddr > fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) and " +
		"(ip or ipv6.DstAddr < ff00:: or ipv6.DstAddr > ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff) and " +
		"(ipv6 or ip.DstAddr != 203.0.113.10) and (ip or ipv6.DstAddr != 2001:db8::10)) or (inbound and tcp.DstPort == 50123)"
	if got := MainFilter(base); got != before {
		t.Fatalf("DNS off changed the filter:\n%s", got)
	}
	o := base
	o.DNS = true
	f := MainFilter(o)
	for _, want := range []string{
		"(outbound and !loopback and (tcp or udp or fragment) and (ipv6 or ip.DstAddr != 203.0.113.10) and (ip or ipv6.DstAddr != 2001:db8::10) and (((ipv6 or ip.DstAddr > 0.255.255.255) and ",
		" or udp.DstPort == 53 or fragment or tcp.DstPort == 53 or tcp.SrcPort == 50123)) or (inbound and tcp.DstPort == 50123)",
	} {
		if !strings.Contains(f, want) {
			t.Fatalf("filter lacks %q:\n%s", want, f)
		}
	}
	o.TCPOnly = true
	if f := MainFilter(o); strings.Contains(f, "udp.DstPort") || strings.Contains(f, "or fragment") || !strings.Contains(f, "!loopback and tcp and") {
		t.Fatalf("TCP only: %s", f)
	}
	// WinDivert compiles at most 256 tests: MaxServerIPs addresses fit in
	// every mode (filter_wdfilter_test.go checks filterTests against
	// WinDivert's own count).
	for _, o := range maxFilters() {
		if n := filterTests(MainFilter(o)); n > 256 {
			t.Fatalf("tcpOnly=%v dns=%v: %d tests", o.TCPOnly, o.DNS, n)
		}
	}
}

// maxFilters are the main filter's options in every mode with
// MaxServerIPs server addresses, IPv4 and IPv6.
func maxFilters() []FilterOptions {
	ips := make([]netip.Addr, MaxServerIPs)
	for i := range ips {
		if i%2 == 0 {
			ips[i] = netip.AddrFrom4([4]byte{203, 0, 113, byte(i)})
		} else {
			ips[i] = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(i)})
		}
	}
	var out []FilterOptions
	for _, tcpOnly := range []bool{false, true} {
		for _, dns := range []bool{false, true} {
			out = append(out, FilterOptions{RelayPort: 50123, ServerIPs: ips, TCPOnly: tcpOnly, DNS: dns})
		}
	}
	return out
}

// filterTests counts the tests WinDivert compiles a filter into: every
// comparison and every bare field (outbound, !loopback, ip, tcp,
// fragment...).
func filterTests(f string) int {
	toks := strings.Fields(strings.NewReplacer("(", " ", ")", " ").Replace(f))
	n := 0
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "and", "or", "not", "&&", "||":
			continue
		}
		n++
		if i+1 < len(toks) && slices.Contains([]string{"==", "!=", "<", ">", "<=", ">="}, toks[i+1]) {
			i += 2
		}
	}
	return n
}
