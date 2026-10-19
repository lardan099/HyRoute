package sshexec

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
)

// proxy forwards TCP connections on 127.0.0.1 to a server until frozen;
// then it drops whatever arrives in either direction but keeps the
// connections open, as a dead route or a frozen VPS does.
type proxy struct {
	ln     net.Listener
	frozen atomic.Bool
	mu     sync.Mutex
	conns  []net.Conn
}

func startProxy(t *testing.T, to string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", to)
			if err != nil {
				c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, s)
			p.mu.Unlock()
			go p.pipe(c, s)
			go p.pipe(s, c)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		p.mu.Lock()
		for _, c := range p.conns {
			c.Close()
		}
		p.mu.Unlock()
	})
	return p
}

func (p *proxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 && !p.frozen.Load() {
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (p *proxy) port() int { return p.ln.Addr().(*net.TCPAddr).Port }

// deadLink connects through a proxy, checks that a command runs, then
// freezes the proxy. The server's exec handler needs no shell.
func deadLink(t *testing.T, keepalive time.Duration) *Client {
	t.Helper()
	srv := sshtest.Start(t, "tester", fakePass)
	srv.SetExec(func(ctx context.Context, line string, _ io.Reader, stdout, _ io.Writer) int {
		io.WriteString(stdout, "ok")
		return 0
	})
	p := startProxy(t, net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port)))
	c, err := Dial(context.Background(), Target{Host: "127.0.0.1", Port: p.port(), User: srv.User}, Auth{Password: fakePass},
		Options{HostKey: trust(srv.HostKey()), Timeout: 5 * time.Second, Keepalive: keepalive})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if res, err := c.Run(context.Background(), remote.Cmd{Args: []string{"true"}}); err != nil || string(res.Stdout) != "ok" {
		t.Fatalf("before freezing: %q %v", res.Stdout, err)
	}
	p.frozen.Store(true)
	return c
}

// within fails the test when f takes longer than d.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
		t.Logf("%s: %v", what, time.Since(start).Round(time.Millisecond))
	case <-time.After(d):
		t.Fatalf("%s still waiting after %v", what, d)
	}
}

// A cancelled command on a silent server returns soon after the context
// ends, and the connection is closed: later calls fail at once.
func TestRunOnDeadLink(t *testing.T) {
	c := deadLink(t, time.Hour)
	within(t, time.Second+cancelGrace+3*time.Second, "run with a 1 s context", func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := c.Run(ctx, remote.Cmd{Args: []string{"true"}}); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("run: %v", err)
		}
	})
	within(t, time.Second, "run on the closed connection", func() {
		var ue *remote.UnreachableError
		if _, err := c.Run(context.Background(), remote.Cmd{Args: []string{"true"}}); !errors.As(err, &ue) {
			t.Errorf("after the abort: %v", err)
		}
	})
	within(t, time.Second, "close", func() { c.Close() })
}

// Streams and SFTP reads end the same way.
func TestStreamAndReadOnDeadLink(t *testing.T) {
	c := deadLink(t, time.Hour)
	within(t, time.Second+cancelGrace+3*time.Second, "stream with a 1 s context", func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		c.Stream(ctx, remote.Cmd{Args: []string{"journalctl", "-f"}}, func(string) {})
	})
	c = deadLink(t, time.Hour)
	within(t, time.Second+cancelGrace+3*time.Second, "read with a 1 s context", func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := c.ReadFile(ctx, "/etc/hostname", false); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("read: %v", err)
		}
	})
}

// Keepalives without answers close the connection even when no context
// ends: a call without a deadline does not hang.
func TestKeepaliveFindsDeadLink(t *testing.T) {
	c := deadLink(t, 100*time.Millisecond)
	within(t, 3*time.Second, "run without a deadline", func() {
		var ue *remote.UnreachableError
		if _, err := c.Run(context.Background(), remote.Cmd{Args: []string{"true"}}); !errors.As(err, &ue) {
			t.Errorf("run: %v", err)
		}
	})
}

// Close does not wait for an SFTP session that is still opening on a
// silent server, and the opening call returns once the connection closes.
func TestCloseWhileSFTPOpens(t *testing.T) {
	c := deadLink(t, time.Hour)
	read := make(chan error, 1)
	go func() {
		_, err := c.ReadFile(context.Background(), "/etc/hostname", false)
		read <- err
	}()
	time.Sleep(200 * time.Millisecond) // the read is waiting for the server
	within(t, time.Second, "close", func() { c.Close() })
	within(t, 2*time.Second, "read after close", func() {
		var ue *remote.UnreachableError
		if err := <-read; !errors.As(err, &ue) {
			t.Errorf("read: %v", err)
		}
	})
}
