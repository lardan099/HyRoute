package socks5

import (
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// The payload limit mirrors both of Hysteria's 4096-byte buffers: the
// SOCKS5 datagram and the QUIC UDP message.
func TestMaxUDPPayload(t *testing.T) {
	ip := func(s string) Addr { return AddrFromAddrPort(netip.MustParseAddrPort(s)) }
	for _, c := range []struct {
		dst  Addr
		want int
	}{
		{ip("1.1.1.1:53"), 4077},
		{ip("93.184.216.34:443"), 4070},
		{ip("255.255.255.255:65535"), 4066},
		{ip("[::1]:1"), 4074},
		{ip("[2606:4700:4700::1111]:443"), 4061},
		{ip("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"), 4040},
		{Addr{Host: "example.com", Port: 443}, 4072},
		// A 100-character name: "host:port" is longer than 63, so its
		// length takes a 2-byte varint.
		{Addr{Host: strings.Repeat("a", 100), Port: 443}, 4096 - (8 + 2 + 104)},
		{Addr{Host: strings.Repeat("a", 256), Port: 443}, 0},
		{Addr{}, 0},
	} {
		if got := MaxUDPPayload(c.dst); got != c.want {
			t.Errorf("%v: %d, want %d", c.dst, got, c.want)
		}
	}
}

// wireLimit computes the limit from what actually goes to Hysteria: the
// bytes AppendAddr writes, and the "host:port" Hysteria prints of them
// (txthinking/socks5 Datagram.Address: net.IP(b).String()).
func wireLimit(t *testing.T, dst Addr) int {
	t.Helper()
	b, err := AppendAddr([]byte{0, 0, 0}, dst)
	if err != nil {
		t.Fatal(err)
	}
	var host string
	switch b[3] {
	case atypIPv4:
		host = net.IP(b[4:8]).String()
	case atypIPv6:
		host = net.IP(b[4:20]).String()
	default:
		t.Fatalf("ATYP %d", b[3])
	}
	hp := net.JoinHostPort(host, strconv.Itoa(int(dst.Port)))
	v := 1
	if len(hp) > 63 {
		v = 2
	}
	return min(4096-len(b), 4096-(8+v+len(hp)))
}

func randAddr(r *rand.Rand, v6 bool) netip.Addr {
	if !v6 {
		var a [4]byte
		for i := range a {
			a[i] = byte(r.IntN(256))
		}
		return netip.AddrFrom4(a)
	}
	var a [16]byte
	for i := range a {
		// Zero runs make "::" compression paths likely.
		if r.IntN(3) > 0 {
			a[i] = byte(r.IntN(256))
		}
	}
	return netip.AddrFrom16(a)
}

// The result never exceeds what fits on the wire: an IPv4-mapped or zoned
// address counts like its plain form, which is what AppendAddr sends.
func TestMaxUDPPayloadConservative(t *testing.T) {
	v4 := netip.MustParseAddr("93.184.216.34")
	mapped := netip.AddrFrom16(v4.As16())
	if got, want := MaxUDPPayload(Addr{IP: mapped, Port: 443}), MaxUDPPayload(Addr{IP: v4, Port: 443}); got != want {
		t.Fatalf("IPv4-mapped %d, plain %d", got, want)
	}
	zoned, plain := netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("fe80::1")
	if got, want := MaxUDPPayload(Addr{IP: zoned, Port: 443}), MaxUDPPayload(Addr{IP: plain, Port: 443}); got != want {
		t.Fatalf("zoned %d, plain %d", got, want)
	}
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 5000 {
		dst := Addr{IP: randAddr(r, i%2 == 1), Port: uint16(r.IntN(65536))}
		if i%7 == 0 && dst.IP.Is4() {
			dst.IP = netip.AddrFrom16(dst.IP.As16())
		}
		if got, want := MaxUDPPayload(dst), wireLimit(t, dst); got != want {
			t.Fatalf("%v: %d, on the wire %d", dst, got, want)
		}
	}
}

// Every IP destination carries UDPPayloadAlways, IPv4 ones at least 4066.
func TestMaxUDPPayloadFloor(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for i := range 5000 {
		v6 := i%2 == 1
		dst := Addr{IP: randAddr(r, v6), Port: uint16(r.IntN(65536))}
		got := MaxUDPPayload(dst)
		if got < UDPPayloadAlways || (!v6 && got < 4066) {
			t.Fatalf("%v: %d", dst, got)
		}
	}
}

// socks-udp: the SOCKS5 UDP header round-trips for every address type and
// rejects fragments, short input and a bad ATYP.
func TestUDPHeader(t *testing.T) {
	for _, dst := range []Addr{
		{IP: netip.MustParseAddr("1.2.3.4"), Port: 53},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
		{Host: "example.com", Port: 3478},
	} {
		b, err := AppendUDPHeader(nil, dst)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, "data"...)
		got, payload, err := ParseUDPHeader(b)
		if err != nil || got != dst || string(payload) != "data" {
			t.Fatalf("%v: %v %q %v", dst, got, payload, err)
		}
		b[0], b[1] = 7, 9 // RSV is not checked
		if _, _, err := ParseUDPHeader(b); err != nil {
			t.Fatalf("RSV: %v", err)
		}
		b[2] = 1
		if _, _, err := ParseUDPHeader(b); !errors.Is(err, ErrFragmented) {
			t.Fatalf("FRAG: %v", err)
		}
	}
	for _, b := range [][]byte{nil, {0, 0, 0}, {0, 0, 0, 1, 1, 2}, {0, 0, 0, 3, 10, 'a'}} {
		if _, _, err := ParseUDPHeader(b); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%v: %v", b, err)
		}
	}
	if _, _, err := ParseUDPHeader([]byte{0, 0, 0, 9, 1, 2, 3, 4, 0, 53}); err == nil {
		t.Fatal("bad ATYP accepted")
	}
	if _, err := AppendUDPHeader(nil, Addr{}); err == nil {
		t.Fatal("empty address accepted")
	}
}
