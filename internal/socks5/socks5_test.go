package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func TestAddrRoundTrip(t *testing.T) {
	for _, a := range []Addr{
		{IP: netip.MustParseAddr("1.2.3.4"), Port: 443},
		{IP: netip.MustParseAddr("::ffff:1.2.3.4"), Port: 443},
		{IP: netip.MustParseAddr("2001:db8::1"), Port: 53},
		{Host: "example.com", Port: 80},
	} {
		b, err := AppendAddr(nil, a)
		if err != nil {
			t.Fatal(err)
		}
		got, n, err := ParseAddr(b)
		if err != nil || n != len(b) {
			t.Fatalf("%v: n=%d err=%v", a, n, err)
		}
		want := a
		want.IP = a.IP.Unmap()
		if got != want {
			t.Fatalf("got %v want %v", got, want)
		}
		if _, _, err := ParseAddr(b[:len(b)-1]); err == nil {
			t.Fatal("truncated address must fail")
		}
	}
}

func TestConnectWithAuth(t *testing.T) {
	echo := echoServer(t)
	var seen Addr
	s := &Server{Username: "u", Password: "p", OnConnect: func(a Addr) { seen = a }}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	dst := AddrFromAddrPort(echo.Addr().(*net.TCPAddr).AddrPort())
	c := &Client{Server: s.Addr(), Username: "u", Password: "p"}
	conn, err := c.Connect(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if seen != dst {
		t.Fatalf("server saw %v, want %v", seen, dst)
	}
	msg := bytes.Repeat([]byte("hyroute"), 1000)
	go conn.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %v", err)
	}

	bad := &Client{Server: s.Addr(), Username: "u", Password: "wrong"}
	if _, err := bad.Connect(context.Background(), dst); !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	none := &Client{Server: s.Addr()}
	if _, err := none.Connect(context.Background(), dst); !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth without creds, got %v", err)
	}
}

func TestConnectRefusedAndDomain(t *testing.T) {
	var seen Addr
	s := &Server{OnConnect: func(a Addr) { seen = a }}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Grab a free port and close it so the dial is refused.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	c := &Client{Server: s.Addr()}
	_, err := c.Connect(context.Background(), Addr{Host: "localhost", Port: port})
	var re ReplyError
	if !errors.As(err, &re) || re != 5 {
		t.Fatalf("want connection refused reply, got %v", err)
	}
	if seen.Host != "localhost" {
		t.Fatalf("domain not passed through: %+v", seen)
	}
}

func TestConnectContextCancel(t *testing.T) {
	// A server that accepts and never answers.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(2 * time.Second)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := (&Client{Server: ln.Addr().String()}).Connect(ctx, Addr{Host: "x", Port: 1})
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("cancel not honoured: %v after %v", err, time.Since(start))
	}
}

func TestUDPAssociate(t *testing.T) {
	// UDP echo.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := pc.ReadFromUDP(b)
			if err != nil {
				return
			}
			pc.WriteToUDP(b[:n], a)
		}
	}()
	s := &Server{}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := (&Client{Server: s.Addr()}).UDPAssociate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	dst := AddrFromAddrPort(pc.LocalAddr().(*net.UDPAddr).AddrPort())
	if err := a.WriteTo([]byte("ping"), dst); err != nil {
		t.Fatal(err)
	}
	a.pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	n, from, err := a.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ping" || from != dst {
		t.Fatalf("udp echo: %q from %v err %v", buf[:n], from, err)
	}
}

// isReset reports a connection reset. On Windows it is WSAECONNRESET
// (10054) or WSAECONNABORTED (10053), which syscall.ECONNRESET does not
// match.
func isReset(err error) bool {
	var errno syscall.Errno
	return errors.Is(err, syscall.ECONNRESET) || (errors.As(err, &errno) && (errno == 10054 || errno == 10053))
}

// wrapped hides the *net.TCPConn like a counting wrapper does.
type wrapped struct{ net.Conn }

func (w wrapped) NetConn() net.Conn { return w.Conn }

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// A reset on either side reaches the other side as a reset, not as a clean
// end of stream (which would make truncated data look complete).
func TestPipePropagatesReset(t *testing.T) {
	for _, upstreamFails := range []bool{true, false} {
		app, proxyApp := tcpPair(t)
		proxyUp, upstream := tcpPair(t)
		done := make(chan struct{})
		go func() { Pipe(wrapped{proxyApp}, proxyUp); close(done) }()
		broken, other := upstream, app
		if !upstreamFails {
			broken, other = app, upstream
		}
		broken.Write([]byte("partial"))
		time.Sleep(50 * time.Millisecond)
		Abort(broken)
		other.SetReadDeadline(time.Now().Add(3 * time.Second))
		got, err := io.ReadAll(other)
		if !isReset(err) {
			t.Fatalf("upstream fails %v: read %q, err %v: want connection reset", upstreamFails, got, err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Pipe did not return")
		}
	}
}

// A clean end of stream still half-closes.
func TestPipeHalfClose(t *testing.T) {
	app, proxyApp := tcpPair(t)
	proxyUp, upstream := tcpPair(t)
	go Pipe(proxyApp, proxyUp)
	app.Write([]byte("req"))
	app.(*net.TCPConn).CloseWrite()
	upstream.SetReadDeadline(time.Now().Add(3 * time.Second))
	if got, err := io.ReadAll(upstream); err != nil || string(got) != "req" {
		t.Fatalf("upstream read %q %v", got, err)
	}
	upstream.Write([]byte("resp"))
	upstream.Close()
	app.SetReadDeadline(time.Now().Add(3 * time.Second))
	if got, err := io.ReadAll(app); err != nil || string(got) != "resp" {
		t.Fatalf("app read %q %v", got, err)
	}
}
