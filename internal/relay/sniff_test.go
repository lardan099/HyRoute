package relay

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go tls.Client(c1, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	hdr := make([]byte, 5)
	io.ReadFull(c2, hdr)
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	io.ReadFull(c2, body)
	return append(hdr, body...)
}

type decision struct {
	domain string
	src    rules.DomainSource
}

func sniffFixture(t *testing.T, action rules.Action) (*fixture, chan decision) {
	f := newFixture(t)
	ch := make(chan decision, 4)
	f.relay.Decide = func(e *nat.Entry, domain string, src rules.DomainSource) rules.Result {
		ch <- decision{domain, src}
		return rules.Result{Action: action, Rule: "r", Domain: domain, DomainSrc: src}
	}
	return f, ch
}

func echoRoundTrip(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(payload) {
		t.Fatalf("echo mismatch: %v", err)
	}
}

func TestSniffTLSTunnelRemoteDNS(t *testing.T) {
	f, ch := sniffFixture(t, rules.Tunnel)
	f.relay.PreferRemoteDNS = true
	rec := &flows.Record{}
	c := f.dialEntry(t, &nat.Entry{Mode: nat.Sniff, Rec: rec})
	defer c.Close()
	hello := clientHello(t, "Sni.Example.com")
	// Deliver the hello in two segments.
	c.Write(hello[:7])
	time.Sleep(20 * time.Millisecond)
	c.Write(hello[7:])
	d := <-ch
	if d.domain != "sni.example.com" || d.src != rules.SrcSNI {
		t.Fatalf("decision input %+v", d)
	}
	// The stub resolves the domain itself; it must see the name, not the IP.
	if a := <-f.seen; a.Host != "sni.example.com" {
		t.Fatalf("socks target %+v", a)
	}
}

func TestSniffHTTPDirectForwardsBufferUnchanged(t *testing.T) {
	f, ch := sniffFixture(t, rules.Direct)
	rec := &flows.Record{}
	c := f.dialEntry(t, &nat.Entry{Mode: nat.Sniff, Rec: rec})
	defer c.Close()
	req := []byte("GET / HTTP/1.1\r\nHost: plain.example.org\r\n\r\n")
	echoRoundTrip(t, c, req) // echo server returns exactly the buffered head
	if d := <-ch; d.domain != "plain.example.org" || d.src != rules.SrcHost {
		t.Fatalf("%+v", d)
	}
	echoRoundTrip(t, c, []byte("more"))
	c.Close()
	r := <-f.done
	if r.Route != "direct" || r.Stage != "sniff" || f.relay.Direct.Load() != 1 {
		t.Fatalf("%+v", r)
	}
	if rec.Sent.Load() != int64(len(req)+4) {
		t.Fatalf("sent %d", rec.Sent.Load())
	}
	select {
	case a := <-f.seen:
		t.Fatalf("direct flow went through socks: %v", a)
	default:
	}
}

func TestSniffTimeoutAndServerFirst(t *testing.T) {
	f, ch := sniffFixture(t, rules.Direct)
	f.relay.SniffTimeout = 300 * time.Millisecond
	f.relay.ServerFirstTimeout = 30 * time.Millisecond
	// Silent client on a normal port: waits SniffTimeout.
	start := time.Now()
	c := f.dialEntry(t, &nat.Entry{Mode: nat.Sniff})
	defer c.Close()
	if d := <-ch; d.domain != "" || d.src != rules.SrcNone {
		t.Fatalf("%+v", d)
	}
	if el := time.Since(start); el < 250*time.Millisecond {
		t.Fatalf("gave up too early: %v", el)
	}
	// Server-first port (22): gives up fast.
	f.relay.ServerFirstPorts = map[uint16]bool{uint16(f.echo.Addr().(*net.TCPAddr).Port): true}
	start = time.Now()
	c2 := f.dialEntry(t, &nat.Entry{Mode: nat.Sniff})
	defer c2.Close()
	<-ch
	if el := time.Since(start); el > 200*time.Millisecond {
		t.Fatalf("server-first port waited %v", el)
	}
	// Non-TLS/HTTP bytes decide immediately without a name.
	c3 := f.dialEntry(t, &nat.Entry{Mode: nat.Sniff})
	defer c3.Close()
	echoRoundTrip(t, c3, []byte("SSH-2.0-client\r\n"))
	if d := <-ch; d.domain != "" {
		t.Fatalf("%+v", d)
	}
}

func TestSniffBlockAndTunnelDown(t *testing.T) {
	f, _ := sniffFixture(t, rules.Block)
	c := f.dialEntry(t, &nat.Entry{Mode: nat.Sniff})
	defer c.Close()
	c.Write(clientHello(t, "blocked.example"))
	expectReset(t, c)
	if f.relay.Blocked.Load() != 1 {
		t.Fatal("blocked counter")
	}

	f2, _ := sniffFixture(t, rules.Tunnel)
	f2.tunnel.up.Store(false)
	c2 := f2.dialEntry(t, &nat.Entry{Mode: nat.Sniff})
	defer c2.Close()
	c2.Write(clientHello(t, "down.example"))
	expectReset(t, c2)
	if r := <-f2.done; r.Route != "rejected" || r.Reason != "tunnel unavailable" {
		t.Fatalf("%+v", r)
	}
}

func TestNoSniffUsesIPEvenWithRemoteDNS(t *testing.T) {
	f := newFixture(t)
	f.relay.PreferRemoteDNS = true
	c := f.dial(t, true)
	defer c.Close()
	echoRoundTrip(t, c, []byte("x"))
	if a := <-f.seen; a.Host != "" || a != socks5.AddrFromAddrPort(f.echo.Addr().(*net.TCPAddr).AddrPort()) {
		t.Fatalf("%+v", a)
	}
}

// A request to a forward proxy names the proxied site in Host: the name
// decides the route, but the tunnel still connects to the proxy's address.
func TestProxyRequestKeepsProxyAddress(t *testing.T) {
	// localhost resolves at once: the stub does not dial out.
	for _, tc := range []struct {
		req    string
		byName bool
	}{
		{"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n", false},
		{"GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\n\r\n", false},
		{"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", true},
	} {
		f, ch := sniffFixture(t, rules.Tunnel)
		f.relay.PreferRemoteDNS = true
		c := f.dialEntry(t, &nat.Entry{Mode: nat.Sniff})
		c.Write([]byte(tc.req))
		if d := <-ch; d.domain != "localhost" || d.src != rules.SrcHost {
			t.Fatalf("%q: decision input %+v", tc.req, d)
		}
		a := <-f.seen
		if tc.byName && a.Host != "localhost" {
			t.Fatalf("%q: socks target %+v, want the name", tc.req, a)
		}
		if !tc.byName && a != socks5.AddrFromAddrPort(f.echo.Addr().(*net.TCPAddr).AddrPort()) {
			t.Fatalf("%q: socks target %+v, want the proxy's address", tc.req, a)
		}
		c.Close()
	}
}

func TestProxyRequest(t *testing.T) {
	for req, want := range map[string]bool{
		"CONNECT example.com:443 HTTP/1.1\r\n":    true,
		"GET http://example.com/ HTTP/1.1\r\n":    true,
		"POST https://example.com/x HTTP/1.1\r\n": true,
		"GET / HTTP/1.1\r\n":                      false,
		"GET /?u=http://x HTTP/1.1\r\n":           false,
		"OPTIONS * HTTP/1.1\r\n":                  false,
	} {
		if got := proxyRequest([]byte(req + "Host: example.com\r\n\r\n")); got != want {
			t.Errorf("%q: %v", req, got)
		}
	}
}
