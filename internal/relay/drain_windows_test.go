//go:build windows

package relay

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/engine/nat"
)

// SIO_TCP_INFO works: bytes the peer has not taken are not acknowledged
// and its window is closed; once it reads them, they are and it is open.
func TestSendProgress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	b, err := smallBufDialer(0).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	a, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	const n = 16 << 10
	go a.Write(make([]byte, n))
	time.Sleep(300 * time.Millisecond)
	if p, ok := sendProgress(a); !ok || p.acked >= n || p.window != 0 {
		t.Fatalf("stalled peer: %+v %v", p, ok)
	}
	b.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(b, make([]byte, n)); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		p, ok := sendProgress(a)
		if ok && p.acked == n && p.inFlight == 0 && p.window > 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("read by the peer: %+v %v", p, ok)
		}
	}
	a.Close()
	if _, ok := sendProgress(a); ok {
		t.Fatal("progress of a closed connection")
	}
}

// smallBufDialer dials from port lp (0: any) with a receive buffer too
// small for what the tests send.
func smallBufDialer(lp int) *net.Dialer {
	return &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: lp},
		Control: func(_, _ string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) {
				syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1024)
			})
		},
	}
}

// stalledApp opens a relayed connection whose application half-closes and
// does not read, with a receive buffer too small for the size bytes the
// upstream sends before closing: when the upstream is done, the tail is
// still unacknowledged.
func stalledApp(t *testing.T, f *fixture, size int) net.Conn {
	t.Helper()
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { up.Close() })
	finished := make(chan struct{})
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.Write(make([]byte, size))
		c.(*net.TCPConn).CloseWrite()
		io.Copy(io.Discard, c) // the application's FIN
		close(finished)
	}()
	tmp, _ := net.Listen("tcp", "127.0.0.1:0")
	lp := tmp.Addr().(*net.TCPAddr).Port
	tmp.Close()
	peer := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(lp))
	f.mu.Lock()
	f.byPeer[peer] = &nat.Entry{Mode: nat.NoSniff, Flow: nat.FlowKey{Src: peer, Dst: up.Addr().(*net.TCPAddr).AddrPort()}}
	f.mu.Unlock()
	d := smallBufDialer(lp)
	c, err := d.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(f.relay.Port()))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.(*net.TCPConn).CloseWrite()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("the upstream did not finish")
	}
	time.Sleep(200 * time.Millisecond) // the relay has written what it could
	return c
}

// readReset reads c to the end and fails unless the connection is reset
// before the application has everything.
func readReset(t *testing.T, c net.Conn, size int) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("read %d of %d bytes: %v, want a reset", len(got), size, err)
	}
}

// A connection whose tail the application has not acknowledged is not
// shut down on the relay's side yet: on Windows a reset no longer stops a
// queued FIN and the data before it, which would go on to the real remote
// once the filters are gone. Close resets it at once, before the
// application has the tail.
func TestCloseResetsDrainingConnection(t *testing.T) {
	f := newFixture(t)
	c := stalledApp(t, f, 48<<10)
	select {
	case r := <-f.done:
		t.Fatalf("closed with its tail unacknowledged: %+v", r)
	default:
	}
	begin := time.Now()
	f.relay.Close()
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("Close took %v", d)
	}
	select {
	case r := <-f.done:
		if r.Route != "tunnel" {
			t.Fatalf("%+v", r)
		}
	default:
		t.Fatal("no result after Close")
	}
	readReset(t, c, 48<<10)
}

// An application that pauses reading (a pager, a paused download) is
// waited for however long the pause, like an idle connection: when it
// resumes it gets the tail and a clean end, not a reset.
func TestPausedReaderGetsTail(t *testing.T) {
	old := drainTimeout
	drainTimeout = 300 * time.Millisecond
	t.Cleanup(func() { drainTimeout = old })
	f := newFixture(t)
	const size = 48 << 10
	c := stalledApp(t, f, size)
	select {
	case r := <-f.done:
		t.Fatalf("finished while the application paused: %+v", r)
	case <-time.After(time.Second):
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil || len(got) != size {
		t.Fatalf("read %d of %d bytes: %v", len(got), size, err)
	}
	select {
	case r := <-f.done:
		if r.Route != "tunnel" || r.Recv != size {
			t.Fatalf("%+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no result")
	}
}

// An application that resets its socket while the relay waits for it to
// take the tail ends the wait at once: nothing more can reach it.
func TestAppResetEndsSettle(t *testing.T) {
	f := newFixture(t)
	c := stalledApp(t, f, 48<<10)
	c.(*net.TCPConn).SetLinger(0)
	c.Close()
	select {
	case r := <-f.done:
		if r.Route != "tunnel" {
			t.Fatalf("%+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the relay still waits for a reset application")
	}
}

// An application that reads slowly but steadily gets everything and a
// clean end, however long that takes past drainTimeout.
func TestSlowReaderNotReset(t *testing.T) {
	old := drainTimeout
	drainTimeout = 300 * time.Millisecond
	t.Cleanup(func() { drainTimeout = old })
	f := newFixture(t)
	const size = 24 << 10
	c := stalledApp(t, f, size)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 512)
	total := 0
	for {
		n, err := c.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("after %d of %d bytes: %v", total, size, err)
		}
		time.Sleep(40 * time.Millisecond)
	}
	if total != size {
		t.Fatalf("read %d of %d bytes", total, size)
	}
	select {
	case r := <-f.done:
		if r.Route != "tunnel" || r.Recv != size {
			t.Fatalf("%+v", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no result")
	}
}
