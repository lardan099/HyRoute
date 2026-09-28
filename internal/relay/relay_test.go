package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

type socksTunnel struct {
	c  *socks5.Client
	up atomic.Bool
}

func (t *socksTunnel) Available() bool { return t.up.Load() }
func (t *socksTunnel) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	return t.c.Connect(ctx, dst)
}

type fixture struct {
	relay  *Server
	tunnel *socksTunnel
	echo   net.Listener
	seen   chan socks5.Addr
	mu     sync.Mutex
	byPeer map[netip.AddrPort]*nat.Entry
	// appAddr, when set, is the application's address in the entries
	// Lookup returns (it differs from the test's dialing peer).
	appAddr netip.Addr
	done    chan Result
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{byPeer: map[netip.AddrPort]*nat.Entry{}, seen: make(chan socks5.Addr, 4), done: make(chan Result, 4)}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	f.echo = echo
	stub := &socks5.Server{Username: "u", Password: "p", OnConnect: func(a socks5.Addr) { f.seen <- a }}
	if err := stub.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	f.tunnel = &socksTunnel{c: &socks5.Client{Server: stub.Addr(), Username: "u", Password: "p"}}
	f.tunnel.up.Store(true)
	f.relay = &Server{
		Lookup: func(p netip.AddrPort) *nat.Entry {
			f.mu.Lock()
			defer f.mu.Unlock()
			e := f.byPeer[p]
			if e != nil && f.appAddr.IsValid() {
				e.Flow.Src = netip.AddrPortFrom(f.appAddr, e.Flow.Src.Port())
			}
			return e
		},
		Tunnel: func(profile string) Tunnel {
			if profile == "gone" {
				return nil // profile not running
			}
			return f.tunnel
		},
		OnDone:    func(r Result) { f.done <- r },
		ListenIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}
	if err := f.relay.Start(0); err != nil {
		t.Fatal(err)
	}
	if p := f.relay.Port(); p < PortMin {
		t.Fatalf("port %d outside dynamic range", p)
	}
	t.Cleanup(func() { f.relay.Close(); stub.Close(); echo.Close() })
	return f
}

// dial connects to the relay from a fixed local port and registers the NAT
// entry for that peer first, like the engine does before injecting the SYN.
func (f *fixture) dial(t *testing.T, register bool) net.Conn {
	t.Helper()
	var e *nat.Entry
	if register {
		e = &nat.Entry{Mode: nat.NoSniff}
	}
	return f.dialEntry(t, e)
}

// dialEntry registers e (Flow filled in; Dst defaults to the echo server).
func (f *fixture) dialEntry(t *testing.T, e *nat.Entry) net.Conn {
	t.Helper()
	register := e != nil
	// Reserve a local port.
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	lp := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()
	if register {
		peer := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(lp))
		f.mu.Lock()
		e.Flow.Src = peer
		if !e.Flow.Dst.IsValid() {
			e.Flow.Dst = f.echo.Addr().(*net.TCPAddr).AddrPort()
		}
		f.byPeer[peer] = e
		f.mu.Unlock()
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: lp}}
	c, err := d.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.relay.Port()))))
	if isReset(err) {
		// The relay reset the connection before connect() returned.
		return resetConn{}
	}
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// isReset reports a connection reset. On Windows it is WSAECONNRESET
// (10054) or WSAECONNABORTED (10053), which syscall.ECONNRESET does not
// match.
func isReset(err error) bool {
	var errno syscall.Errno
	return errors.Is(err, syscall.ECONNRESET) || (errors.As(err, &errno) && (errno == 10054 || errno == 10053))
}

// resetConn stands for a connection that was reset while dialing.
type resetConn struct{ net.Conn }

func (resetConn) Read([]byte) (int, error)        { return 0, syscall.ECONNRESET }
func (resetConn) Write(b []byte) (int, error)     { return 0, syscall.ECONNRESET }
func (resetConn) SetReadDeadline(time.Time) error { return nil }
func (resetConn) Close() error                    { return nil }

func expectReset(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := c.Read(make([]byte, 1))
	if !isReset(err) {
		t.Fatalf("want connection reset, got %v", err)
	}
}

func TestTunnelRoundTrip(t *testing.T) {
	f := newFixture(t)
	c := f.dial(t, true)
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	// The SOCKS5 request carries the original destination IP:port.
	if got := <-f.seen; got != socks5.AddrFromAddrPort(f.echo.Addr().(*net.TCPAddr).AddrPort()) {
		t.Fatalf("socks target %v", got)
	}
	c.(*net.TCPConn).CloseWrite()
	if _, err := c.Read(buf); err != io.EOF {
		t.Fatalf("half-close: want EOF, got %v", err)
	}
	r := <-f.done
	if r.Route != "tunnel" || r.Sent != 5 || r.Recv != 5 {
		t.Fatalf("result %+v", r)
	}
	if f.relay.Tunneled.Load() != 1 {
		t.Fatal("counter")
	}
}

func TestRejectWhenTunnelDown(t *testing.T) {
	f := newFixture(t)
	f.tunnel.up.Store(false)
	c := f.dial(t, true)
	defer c.Close()
	expectReset(t, c)
	if r := <-f.done; r.Route != "rejected" || r.Reason != "tunnel unavailable" {
		t.Fatalf("result %+v", r)
	}
	if f.relay.Rejected.Load() != 1 {
		t.Fatal("rejected counter")
	}
	select {
	case a := <-f.seen:
		t.Fatalf("nothing may reach the upstream when the tunnel is down, saw %v", a)
	default:
	}
}

func TestRejectOnSocksFailure(t *testing.T) {
	f := newFixture(t)
	f.echo.Close() // CONNECT will be refused
	time.Sleep(20 * time.Millisecond)
	c := f.dial(t, true)
	defer c.Close()
	expectReset(t, c)
	if r := <-f.done; r.Route != "rejected" || r.Err == nil {
		t.Fatalf("result %+v", r)
	}
}

func TestStrayConnectionReset(t *testing.T) {
	f := newFixture(t)
	c := f.dial(t, false)
	defer c.Close()
	expectReset(t, c)
	if f.relay.Stray.Load() != 1 {
		t.Fatal("stray counter")
	}
}

func TestCloseAbortsActive(t *testing.T) {
	f := newFixture(t)
	c := f.dial(t, true)
	defer c.Close()
	c.Write([]byte("x"))
	io.ReadFull(c, make([]byte, 1))
	done := make(chan struct{})
	go func() { f.relay.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung with an active connection")
	}
	// A reset, not a FIN: once the filters are gone a FIN (and queued data)
	// would go to the real remote.
	expectReset(t, c)
}

// A profile that is not running refuses the connection; it never falls
// back to another profile.
func TestRejectWhenProfileNotRunning(t *testing.T) {
	f := newFixture(t)
	c := f.dialEntry(t, &nat.Entry{Mode: nat.NoSniff, Profile: "gone"})
	defer c.Close()
	expectReset(t, c)
	if r := <-f.done; r.Route != "rejected" || r.Profile != "gone" {
		t.Fatalf("result %+v", r)
	}
	select {
	case a := <-f.seen:
		t.Fatalf("reached the upstream: %v", a)
	default:
	}
}

// hangTunnel accepts CONNECT requests that never complete (an unreachable
// destination behind Hysteria).
type hangTunnel struct{ dialing chan struct{} }

func (hangTunnel) Available() bool { return true }
func (h hangTunnel) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	h.dialing <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

// Close cancels pending dials instead of waiting for DialTimeout.
func TestCloseCancelsPendingDial(t *testing.T) {
	f := newFixture(t)
	h := hangTunnel{dialing: make(chan struct{}, 1)}
	f.relay.Tunnel = func(string) Tunnel { return h }
	c := f.dial(t, true)
	defer c.Close()
	select {
	case <-h.dialing:
	case <-time.After(3 * time.Second):
		t.Fatal("no dial")
	}
	start := time.Now()
	done := make(chan struct{})
	go func() { f.relay.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close waited for the pending dial")
	}
	if el := time.Since(start); el > time.Second {
		t.Fatalf("Close took %v", el)
	}
	if r := <-f.done; r.Route != "rejected" {
		t.Fatalf("result %+v", r)
	}
	expectReset(t, c)
}

// An upstream that breaks mid-stream reaches the application as a reset,
// not as a clean end of stream: truncated data must not look complete, and
// the application's socket must not stay half-open after the NAT entry is
// gone.
func TestUpstreamResetReachesApp(t *testing.T) {
	f := newFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("partial"))
		time.Sleep(50 * time.Millisecond)
		Reset(c)
	}()
	// Rec set: the relay wraps the application side in countingConn.
	c := f.dialEntry(t, &nat.Entry{Mode: nat.NoSniff, Rec: &flows.Record{},
		Flow: nat.FlowKey{Dst: ln.Addr().(*net.TCPAddr).AddrPort()}})
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(c)
	if !isReset(err) {
		t.Fatalf("read %q, err %v: want connection reset", got, err)
	}
}

// A Direct upstream leaves from the application's own address, as the
// packet-level Direct does; if the address is gone, the connection is
// reset rather than sent from another one.
func TestDirectDialsFromAppAddress(t *testing.T) {
	f, _ := sniffFixture(t, rules.Direct)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	from := make(chan netip.Addr, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			from <- c.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	// The application's address differs from the test's peer. It is set
	// through the fixture's Lookup: the relay reads its own Lookup field
	// without a lock, so the field is never replaced after Start.
	setApp := func(a string) {
		f.mu.Lock()
		f.appAddr = netip.MustParseAddr(a)
		f.mu.Unlock()
	}
	req := []byte("GET / HTTP/1.1\r\nHost: plain.example.org\r\n\r\n")
	dst := ln.Addr().(*net.TCPAddr).AddrPort()

	setApp("127.0.0.2")
	c := f.dialEntry(t, &nat.Entry{Mode: nat.Sniff, Flow: nat.FlowKey{Dst: dst}})
	defer c.Close()
	echoRoundTrip(t, c, req)
	if a := <-from; a != netip.MustParseAddr("127.0.0.2") {
		t.Fatalf("direct upstream came from %v", a)
	}
	c.Close()
	if r := <-f.done; r.Route != "direct" || r.Err != nil {
		t.Fatalf("%+v", r)
	}

	setApp("192.0.2.1") // not ours
	c2 := f.dialEntry(t, &nat.Entry{Mode: nat.Sniff, Flow: nat.FlowKey{Dst: dst}})
	defer c2.Close()
	c2.Write(req)
	expectReset(t, c2)
	if r := <-f.done; r.Route != "direct" || r.Err == nil {
		t.Fatalf("%+v", r)
	}
	select {
	case a := <-from:
		t.Fatalf("dialed from %v instead of resetting", a)
	default:
	}
}

// CloseWait does not hang on a handler that cannot finish (OnDone waiting
// for a lock a stuck packet loop holds): the session must still stop.
func TestCloseWaitBounded(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	s := &Server{
		Lookup: func(netip.AddrPort) *nat.Entry { return &nat.Entry{Mode: nat.NoSniff} },
		OnDone: func(Result) {
			entered <- struct{}{}
			<-release
		},
		ListenIPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
	}
	if err := s.Start(0); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(s.Port()))))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no OnDone")
	}
	begin := time.Now()
	if s.CloseWait(200 * time.Millisecond) {
		t.Fatal("reported finished with a handler stuck")
	}
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("CloseWait took %v", d)
	}
	// A second call (Stop after ResetConnections) does not wait again.
	begin = time.Now()
	if s.CloseWait(2 * time.Second) {
		t.Fatal("reported finished with a handler stuck")
	}
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("second CloseWait took %v", d)
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for !s.CloseWait(0) {
		if time.Now().After(deadline) {
			t.Fatal("handler not finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
