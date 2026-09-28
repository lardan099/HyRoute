package groups

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// dialTo ignores the SOCKS destination and dials the test server (the
// probe URL names a public host that is never contacted).
func dialTo(addr string) func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	return func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

func TestProbeOnceStatus(t *testing.T) {
	var gotHost, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.RequestURI()
		if r.URL.Path == "/fail" {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	dial := dialTo(srv.Listener.Addr().String())
	rtt, err := ProbeOnce(t.Context(), dial, "http://cp.example.com/generate_204?x=1", nil)
	if err != nil || rtt < 0 { // Windows timers may read 0 on loopback
		t.Fatal(rtt, err)
	}
	if gotHost != "cp.example.com" || gotPath != "/generate_204?x=1" {
		t.Fatal(gotHost, gotPath)
	}
	if _, err := ProbeOnce(t.Context(), dial, "http://cp.example.com/fail", nil); err == nil || err.Error() != "HTTP 500" {
		t.Fatal(err)
	}
}

// fakeServer answers every connection with handle.
func fakeServer(t *testing.T, handle func(net.Conn)) string {
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
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// readRequest reads the request head: a socket closed with unread data
// resets the connection on Windows.
func readRequest(c net.Conn) {
	b := make([]byte, 1)
	var got []byte
	for !strings.HasSuffix(string(got), "\r\n\r\n") {
		if _, err := c.Read(b); err != nil {
			return
		}
		got = append(got, b[0])
	}
}

func TestProbeOnceBadAnswers(t *testing.T) {
	old := probeTimeout
	probeTimeout = 300 * time.Millisecond
	defer func() { probeTimeout = old }()
	slow := fakeServer(t, func(c net.Conn) { time.Sleep(time.Second) })
	if _, err := ProbeOnce(t.Context(), dialTo(slow), "http://x.example/", nil); err == nil || err.Error() != "нет ответа за 5 с" {
		t.Fatal(err)
	}
	garbage := fakeServer(t, func(c net.Conn) { readRequest(c); io.WriteString(c, "SSH-2.0-OpenSSH\r\n") })
	if _, err := ProbeOnce(t.Context(), dialTo(garbage), "http://x.example/", nil); err == nil || err.Error() != "неверный ответ" {
		t.Fatal(err)
	}
	// A status line longer than 1 KiB: the read is bounded.
	long := fakeServer(t, func(c net.Conn) {
		readRequest(c)
		io.WriteString(c, "HTTP/1.1 200 "+strings.Repeat("x", 4096)+"\r\n")
	})
	if _, err := ProbeOnce(t.Context(), dialTo(long), "http://x.example/", nil); err == nil || err.Error() != "неверный ответ" {
		t.Fatal(err)
	}
	// The parent context ends mid-read: canceled, not a failure.
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := ProbeOnce(ctx, dialTo(slow), "http://x.example/", nil); err != ErrCanceled {
		t.Fatal(err)
	}
}

func TestProbeOnceTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	dial := dialTo(srv.Listener.Addr().String())
	// httptest's certificate is for example.com.
	if _, err := ProbeOnce(t.Context(), dial, "https://example.com/generate_204", &tls.Config{RootCAs: pool}); err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeOnce(t.Context(), dial, "https://other.test/", &tls.Config{RootCAs: pool}); err == nil || !strings.HasPrefix(err.Error(), "TLS:") {
		t.Fatalf("wrong name accepted: %v", err)
	}
	if _, err := ProbeOnce(t.Context(), dial, "https://example.com/", &tls.Config{RootCAs: x509.NewCertPool()}); err == nil {
		t.Fatal("unknown CA accepted")
	}
}

func TestProberRun(t *testing.T) {
	oldTick := probeTick
	probeTick = 20 * time.Millisecond
	defer func() { probeTick = oldTick }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Latency, Members: []string{"a", "b", "c"}})
	g.set(true, "a", "b", "c")
	g.NoteProbe("c", 7*time.Millisecond, nil) // c is not due

	var active, peak atomic.Int32
	var mu sync.Mutex
	dialled := map[string]int{}
	block := make(chan struct{})
	p := &Prober{RT: g.Runtime, Workers: 1, Log: slog.Default(),
		Targets: func() ([]string, Probe) { return []string{"a", "b", "c"}, Probe{} },
		Dial: func(ctx context.Context, member string, dst socks5.Addr) (net.Conn, error) {
			n := active.Add(1)
			defer active.Add(-1)
			if n > peak.Load() {
				peak.Store(n)
			}
			mu.Lock()
			dialled[member]++
			mu.Unlock()
			if member == "b" {
				<-block
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
		}}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for g.Snapshot(gid, g.usable).Members[0].ProbeAt.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("a never probed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// b blocks in its dial (the single worker); cancel: its result is not
	// noted.
	time.Sleep(50 * time.Millisecond)
	cancel()
	close(block)
	<-done
	h := g.Snapshot(gid, g.usable)
	mu.Lock()
	defer mu.Unlock()
	if dialled["c"] != 0 || dialled["a"] != 1 || dialled["b"] != 1 || peak.Load() != 1 {
		t.Fatalf("dials %v peak %d", dialled, peak.Load())
	}
	if !h.Members[1].ProbeAt.IsZero() || h.Members[1].ProbeError != "" {
		t.Fatalf("a canceled probe was noted: %+v", h.Members[1])
	}
}
