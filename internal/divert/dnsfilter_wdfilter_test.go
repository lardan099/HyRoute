package divert

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/lardan099/hyroute/internal/packet"
)

func TestDNSFilterSemantics(t *testing.T) {
	bin := wdfilter(t)
	udp := func(src, dst string) []byte {
		return packet.BuildUDP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), []byte("dns"))
	}
	tcp := func(src, dst, payload string) []byte {
		return packet.BuildTCP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), packet.FlagACK, 1, 1, []byte(payload))
	}
	const L, R = "192.168.1.5:50000", "8.8.8.8:53"
	cases := []struct {
		name     string
		pkt      []byte
		outbound bool
		loopback bool
		want     string
	}{
		{"udp query", udp(L, R), true, false, "1"},
		{"udp answer", udp(R, L), false, false, "1"},
		{"udp query v6", udp("[2a00:1450::5]:50000", "[2001:4860:4860::8888]:53"), true, false, "1"},
		{"tcp query", tcp(L, R, "dns"), true, false, "1"},
		{"tcp answer", tcp(R, L, "dns"), false, false, "1"},
		{"tcp ack", tcp(R, L, ""), false, false, "0"},
		{"query to us", udp(R, L), true, false, "0"},
		{"inbound query", udp(L, R), false, false, "0"},
		{"other port", udp(L, "8.8.8.8:443"), true, false, "0"},
		{"loopback", udp("127.0.0.1:50000", "127.0.0.1:53"), true, true, "0"},
	}
	for _, c := range cases {
		ob, lb := "0", "0"
		if c.outbound {
			ob = "1"
		}
		if c.loopback {
			lb = "1"
		}
		if got := run(t, bin, "eval", DNSFilter, hex.EncodeToString(c.pkt), ob, lb); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}
