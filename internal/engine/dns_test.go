package engine

import (
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

// cnameResponse answers name with a CNAME to target and target's address.
func cnameResponse(t *testing.T, name, target, ip string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	b.CNAMEResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET, TTL: 300},
		dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)})
	b.AResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(target), Class: dnsmessage.ClassINET, TTL: 300},
		dnsmessage.AResource{A: netip.MustParseAddr(ip).As4()})
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A rule on the queried name applies to an address reached through a CNAME
// to a CDN name that no rule mentions: both names are one site. Only
// another site on the address leaves the route open.
func TestCNAMEChainIsOneSite(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	h.c.DNS.AddResponse(cnameResponse(t, "www.youtube.com.", "youtube-ui.l.google.com.", "142.250.1.2"))
	flow := func(src string) *nat.Entry {
		h.own(6, src, "142.250.1.2:7777", 200)
		h.sendTCP(src, "142.250.1.2:7777", packet.FlagSYN, "")
		if i := h.next(t); i.pkt.DstPort() != relayPort {
			t.Fatal("not reflected to the relay")
		}
		return h.c.NAT.LookupFlow(nat.FlowKey{Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort("142.250.1.2:7777")})
	}
	if e := flow("192.168.1.5:42000"); e == nil || e.Mode != nat.NoSniff || e.Profile != "" {
		t.Fatalf("CNAME site must tunnel by the rule on its queried name: %+v", e)
	}
	if v := lastRecord(t, h.c); v.Rule != "yt" || v.DomainSrc != "dns" {
		t.Fatalf("%+v", v)
	}
	// A neighbour with another route: the name is needed.
	h.c.DNS.AddResponse(dnsResponse(t, "other.example.", "142.250.1.2"))
	if e := flow("192.168.1.5:42001"); e == nil || e.Mode != nat.Sniff {
		t.Fatalf("neighbours with different routes must be sniffed: %+v", e)
	}
}

// The outer SNI of an ECH hello is the site (GREASE ECH, which Chrome and
// Firefox send to every site without an ECH config) unless it is a known
// ECH public name: then the DNS cache names the site, or the domain is
// unknown. A rule on the public name never decides for the hidden site.
func TestRelayDecideECH(t *testing.T) {
	cfg := appRules
	cfg.Rules = append(slices.Clone(appRules.Rules),
		rules.Rule{Name: "cf", Domain: &rules.DomainMatch{Pattern: "cloudflare-ech.com"}, Action: rules.Tunnel})
	h := newHarness(t, cfg, Options{})
	decide := func(dst, outer string) rules.Result {
		e := &nat.Entry{Flow: nat.FlowKey{Src: netip.MustParseAddrPort(L), Dst: netip.MustParseAddrPort(dst)}}
		return h.c.RelayDecide(e, outer, rules.SrcECH)
	}
	// Nothing cached (DoH): the outer name is the site.
	if r := decide("198.51.100.50:443", "www.youtube.com"); r.Action != rules.Tunnel || r.Domain != "www.youtube.com" || r.DomainSrc != rules.SrcSNI {
		t.Fatalf("empty cache: %+v", r)
	}
	// The cache names only another site of the same servers (Google's
	// frontends serve both): the outer name still decides.
	h.c.DNS.AddResponse(dnsResponse(t, "www.google.com.", "198.51.100.51"))
	if r := decide("198.51.100.51:443", "www.youtube.com"); r.Action != rules.Tunnel || r.DomainSrc != rules.SrcSNI {
		t.Fatalf("GREASE next to a cached neighbour: %+v", r)
	}
	// Real ECH: the public name hides the site, which the cache names.
	h.c.DNS.AddResponse(dnsResponse(t, "www.blocked.test.", "198.51.100.52"))
	if r := decide("198.51.100.52:443", "cloudflare-ech.com"); r.Action != rules.Block || r.DomainSrc != rules.SrcDNS {
		t.Fatalf("real ECH: %+v", r)
	}
	// Nothing cached, or cached neighbours that disagree: the domain is
	// unknown, as README promises for DoH with ECH; the rule on the public
	// name does not apply.
	h.c.DNS.AddResponse(dnsResponse(t, "a.blocked.test.", "198.51.100.53"))
	h.c.DNS.AddResponse(dnsResponse(t, "b.example.", "198.51.100.53"))
	for _, dst := range []string{"198.51.100.50:443", "198.51.100.53:443"} {
		if r := decide(dst, "cloudflare-ech.com"); r.Action != rules.Direct || r.Domain != "" || r.DomainSrc != rules.SrcNone || !strings.HasSuffix(r.Rule, "(domain unknown)") {
			t.Fatalf("%s: unsettled real ECH: %+v", dst, r)
		}
	}
	// The application asked for the public name itself: it is the site.
	h.c.DNS.AddResponse(dnsResponse(t, "cloudflare-ech.com.", "198.51.100.54"))
	if r := decide("198.51.100.54:443", "cloudflare-ech.com"); r.Rule != "cf" || r.DomainSrc != rules.SrcSNI {
		t.Fatalf("public name asked for: %+v", r)
	}
}

// fakeUDPRelay is a loopback SOCKS5 server whose UDP associations answer
// every datagram themselves, as if from its destination: answer returns
// the reply payload.
func fakeUDPRelay(t *testing.T, answer func(dst socks5.Addr, payload []byte) []byte) *socks5.Client {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 512)
				// Greeting (no authentication), then UDP ASSOCIATE.
				if _, err := io.ReadFull(c, b[:3]); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				if _, err := c.Read(b); err != nil {
					return
				}
				pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					return
				}
				defer pc.Close()
				r, _ := socks5.AppendAddr([]byte{5, 0, 0}, socks5.AddrFromAddrPort(pc.LocalAddr().(*net.UDPAddr).AddrPort()))
				c.Write(r)
				go func() {
					buf := make([]byte, 4096)
					for {
						n, from, err := pc.ReadFromUDP(buf)
						if err != nil || n < 4 {
							return
						}
						dst, hl, err := socks5.ParseAddr(buf[3:n])
						if err != nil {
							continue
						}
						hdr, _ := socks5.AppendAddr([]byte{0, 0, 0}, dst)
						pc.WriteToUDP(append(hdr, answer(dst, buf[3+hl:n])...), from)
					}
				}()
				c.Read(b) // the association lives as long as the connection
			}()
		}
	}()
	return &socks5.Client{Server: ln.Addr().String()}
}

// A datagram from port 53 that comes back through the tunnel reaches the
// DNS cache only when it answers a query the socket sent there: any peer
// of a tunneled UDP application could otherwise write name -> IP pairs.
func TestTunneledDNSAnswerNeedsQuery(t *testing.T) {
	forged := dnsResponse(t, "evil.test.", "203.0.113.9")
	answer := func(_ socks5.Addr, q []byte) []byte {
		var p dnsmessage.Parser
		h, err := p.Start(q)
		var qq dnsmessage.Question
		if err == nil {
			qq, err = p.Question()
		}
		if err != nil || h.Response {
			return forged // not a query: a forged "answer" all the same
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true})
		b.StartQuestions()
		b.Question(qq)
		b.StartAnswers()
		b.AResource(dnsmessage.ResourceHeader{Name: qq.Name, Class: dnsmessage.ClassINET, TTL: 300},
			dnsmessage.AResource{A: [4]byte{203, 0, 113, 10}})
		m, _ := b.Finish()
		return m
	}
	h := newHarness(t, appRules, Options{NoDefaultExclusions: true})
	h.tun.client = fakeUDPRelay(t, answer)
	app, dst := "10.0.0.2:5000", "198.51.100.53:53"
	h.own(17, app, dst, 400) // game.exe, UDP tunnel rule
	h.sendUDP(app, dst, []byte("stun-binding"))
	if i := h.next(t); i.pkt.Src() != netip.MustParseAddrPort(dst) {
		t.Fatalf("reply from %v", i.pkt.Src())
	}
	h.sendUDP(app, dst, dnsQuery(t, "good.test."))
	if i := h.next(t); i.pkt.Src() != netip.MustParseAddrPort(dst) {
		t.Fatalf("reply from %v", i.pkt.Src())
	}
	// The cache is fed before the reply reaches the application, which
	// may connect to the address at once.
	if len(h.c.DNS.Names(netip.MustParseAddr("203.0.113.10"))) == 0 {
		t.Fatal("the answer to a tunneled query was not cached before it was delivered")
	}
	if got := h.c.DNS.Names(netip.MustParseAddr("203.0.113.9")); len(got) != 0 {
		t.Fatalf("unsolicited tunneled answer cached: %v", got)
	}
}
