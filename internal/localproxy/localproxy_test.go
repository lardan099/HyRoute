package localproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// direct dials without a tunnel and records destinations.
func direct(seen *[]string) Dialer {
	return func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		*seen = append(*seen, dst.String())
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dst.String())
	}
}

func start(t *testing.T, s *Server) string {
	t.Helper()
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s.Addr()
}

func origin(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s via=%q auth=%q", r.URL.Path, r.Header.Get("Proxy-Connection"), r.Header.Get("Proxy-Authorization"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPProxy(t *testing.T) {
	o := origin(t)
	var seen []string
	s := &Server{Username: "u", Password: "p", Dial: direct(&seen)}
	addr := start(t, s)

	// Without credentials: 407.
	pu, _ := url.Parse("http://" + addr)
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := cl.Get(o.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("no auth: %d", resp.StatusCode)
	}

	// Plain requests, kept alive, proxy headers stripped.
	pu, _ = url.Parse("http://u:p@" + addr)
	cl = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	for _, path := range []string{"/a", "/b"} {
		resp, err := cl.Get(o.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != fmt.Sprintf(`hello %s via="" auth=""`, path) {
			t.Fatalf("%s: %s", path, b)
		}
	}
	if s.Recv.Load() == 0 || s.Sent.Load() == 0 {
		t.Fatal("bytes not counted")
	}

	// CONNECT (as for HTTPS).
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	host := strings.TrimPrefix(o.URL, "http://")
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic dTpw\r\n\r\n", host, host)
	br := bufio.NewReader(c)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT: %q", line)
	}
	br.ReadString('\n')
	fmt.Fprintf(c, "GET /tunnel HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	body, _ := io.ReadAll(br)
	if !strings.Contains(string(body), "hello /tunnel") {
		t.Fatalf("through CONNECT: %s", body)
	}
	if len(seen) < 2 || seen[len(seen)-1] != host {
		t.Fatalf("dialed %v", seen)
	}
}

func TestSOCKS5(t *testing.T) {
	o := origin(t)
	var seen []string
	s := &Server{Username: "u", Password: "p", Dial: direct(&seen)}
	addr := start(t, s)
	host := strings.TrimPrefix(o.URL, "http://")
	dst, _ := socks5.ParseHostPort(host)

	bad := socks5.Client{Server: addr, Username: "u", Password: "wrong"}
	if c, err := bad.Connect(context.Background(), dst); err == nil {
		c.Close()
		t.Fatal("wrong password accepted")
	}
	good := socks5.Client{Server: addr, Username: "u", Password: "p"}
	c, err := good.Connect(context.Background(), socks5.Addr{Host: "localhost", Port: dst.Port})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET /s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	body, _ := io.ReadAll(c)
	if !strings.Contains(string(body), "hello /s") {
		t.Fatalf("%s", body)
	}
	if seen[len(seen)-1] != fmt.Sprintf("localhost:%d", dst.Port) {
		t.Fatalf("the name must reach the tunnel unresolved: %v", seen)
	}
	if s.AuthFailures.Load() != 1 {
		t.Fatal(s.AuthFailures.Load())
	}
}

func TestNoAuthAndFailures(t *testing.T) {
	s := &Server{Dial: func(context.Context, socks5.Addr) (net.Conn, error) { return nil, socks5.ReplyError(5) }}
	addr := start(t, s)
	cl := socks5.Client{Server: addr}
	_, err := cl.Connect(context.Background(), socks5.Addr{Host: "example.com", Port: 443})
	var re socks5.ReplyError
	if err == nil || !errorsAs(err, &re) || re != 5 {
		t.Fatalf("tunnel refusal not passed on: %v", err)
	}
	pu, _ := url.Parse("http://" + addr)
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := hc.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatal(resp.StatusCode)
	}
	// Opening the port in a browser is not a proxy request.
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", addr)
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(line, "400") {
		t.Fatal(line)
	}
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }

// dialer dials without a tunnel and counts the connections.
func dialer(n *atomic.Int32) Dialer {
	return func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		n.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dst.String())
	}
}

// shortTimeouts makes the handshake and response header timeouts d. Call
// it before start: the old values come back after the server closes.
func shortTimeouts(t *testing.T, d time.Duration) {
	hs, hd := handshakeTimeout, headerTimeout
	handshakeTimeout, headerTimeout = d, d
	t.Cleanup(func() { handshakeTimeout, headerTimeout = hs, hd })
}

func client(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	return c, bufio.NewReader(c)
}

// send writes a raw request and reads the response.
func send(t *testing.T, c net.Conn, br *bufio.Reader, raw string) (*http.Response, string) {
	t.Helper()
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("%q: %v", raw, err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("%q: %v", raw, err)
	}
	return resp, string(b)
}

// Only waits are timed: a kept-alive client and a download outlive the
// handshake and response header timeouts.
func TestPlainHTTPTimeouts(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			for i := range 6 {
				fmt.Fprint(w, i)
				w.(http.Flusher).Flush()
				time.Sleep(100 * time.Millisecond)
			}
			return
		}
		io.WriteString(w, "ok")
	}))
	t.Cleanup(o.Close)
	shortTimeouts(t, 200*time.Millisecond)
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	c, br := client(t, addr)
	if _, b := send(t, c, br, "GET "+o.URL+"/a HTTP/1.1\r\nHost: x\r\n\r\n"); b != "ok" {
		t.Fatal(b)
	}
	time.Sleep(400 * time.Millisecond)
	if _, b := send(t, c, br, "GET "+o.URL+"/b HTTP/1.1\r\nHost: x\r\n\r\n"); b != "ok" {
		t.Fatal(b)
	}
	if _, b := send(t, c, br, "GET "+o.URL+"/slow HTTP/1.1\r\nHost: x\r\n\r\n"); b != "012345" {
		t.Fatal(b)
	}
	if dials.Load() != 1 {
		t.Fatalf("%d connections to the server, want 1 kept alive", dials.Load())
	}
}

// A connection upgraded through a plain request (WebSocket) is not timed.
func TestUpgrade(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "no upgrade", http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw.Reader)
	}))
	t.Cleanup(o.Close)
	shortTimeouts(t, 200*time.Millisecond)
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	// Connection is a list: browsers send "keep-alive, Upgrade".
	for _, conn := range []string{"Upgrade", "keep-alive, Upgrade"} {
		c, br := client(t, addr)
		fmt.Fprintf(c, "GET %s/ws HTTP/1.1\r\nHost: x\r\nConnection: %s\r\nUpgrade: echo\r\n\r\n", o.URL, conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatal(conn, resp, err)
		}
		time.Sleep(400 * time.Millisecond)
		io.WriteString(c, "ping")
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil || string(b) != "ping" {
			t.Fatalf("%s: %q %v", conn, b, err)
		}
	}
}

// Headers that Connection lists are hop-by-hop, both ways.
func TestConnectionListedHeaders(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "X-Resp")
		w.Header().Set("X-Resp", "1")
		fmt.Fprintf(w, "hop=%q", r.Header.Get("X-Hop"))
	}))
	t.Cleanup(o.Close)
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	c, br := client(t, addr)
	resp, b := send(t, c, br, "GET "+o.URL+"/h HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\n\r\n")
	if b != `hop=""` || resp.Header.Get("X-Resp") != "" {
		t.Fatalf("%q, X-Resp %q", b, resp.Header.Get("X-Resp"))
	}
}

// 100 Continue is passed on and the final response follows it.
func TestExpectContinue(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "got %s", b)
	}))
	t.Cleanup(o.Close)
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	c, br := client(t, addr)
	for i := range 2 { // twice: the responses stay in step
		body := fmt.Sprint("body", i)
		resp, _ := send(t, c, br, fmt.Sprintf("POST %s/p HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: %d\r\n\r\n%s", o.URL, len(body), body))
		if resp.StatusCode != http.StatusContinue {
			t.Fatalf("interim: %d", resp.StatusCode)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(b) != "got "+body {
			t.Fatalf("final: %d %q", resp.StatusCode, b)
		}
	}
}

// A client that waits for 100 Continue before sending the body gets it
// from the proxy: the proxy does not wait for the body first.
func TestExpectContinueWaits(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "got %s", b)
	}))
	t.Cleanup(o.Close)
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	c, br := client(t, addr)
	fmt.Fprintf(c, "POST %s/p HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n", o.URL)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusContinue {
		t.Fatalf("interim: %v %v", resp, err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "body")
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "got body" {
		t.Fatalf("final: %d %q", resp.StatusCode, b)
	}
}

// An HTTP/1.0 client does not get a chunked body: it would take the chunk
// sizes for data.
func TestHTTP10NotChunked(t *testing.T) {
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "part1")
		w.(http.Flusher).Flush()
		io.WriteString(w, "part2")
	}))
	t.Cleanup(o.Close)
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	c, _ := client(t, addr)
	fmt.Fprintf(c, "GET %s/f HTTP/1.0\r\n\r\n", o.URL)
	raw, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	head, body, _ := strings.Cut(string(raw), "\r\n\r\n")
	if body != "part1part2" || strings.Contains(strings.ToLower(head), "transfer-encoding") {
		t.Fatalf("%q", raw)
	}
}

// A kept-alive connection the server has closed (keep-alive timeout) is
// not used again.
func TestUpstreamIdleClosed(t *testing.T) {
	o := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, "ok "+r.Method)
	}))
	o.Config.IdleTimeout = 100 * time.Millisecond
	o.Start()
	t.Cleanup(o.Close)
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	c, br := client(t, addr)
	for _, m := range []string{"GET", "GET", "POST"} {
		resp, b := send(t, c, br, fmt.Sprintf("%s %s/ HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx", m, o.URL))
		if resp.StatusCode != http.StatusOK || b != "ok "+m {
			t.Fatalf("%s: %d %q", m, resp.StatusCode, b)
		}
		time.Sleep(400 * time.Millisecond)
	}
	if dials.Load() != 3 {
		t.Fatalf("%d connections to the server, want 3", dials.Load())
	}
}

// A server that drops a kept-alive connection just as a request arrives:
// a GET goes again on a new connection, a POST gets 502 and is not
// repeated.
func TestUpstreamClosedOnRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var posts atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				br := bufio.NewReader(conn)
				for i := 0; ; i++ {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					io.Copy(io.Discard, req.Body)
					if req.Method == "POST" {
						posts.Add(1)
					}
					if i == 1 { // the second request goes unanswered
						return
					}
					io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				}
			}()
		}
	}()
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	c, br := client(t, addr)
	url := "http://" + ln.Addr().String()
	for i := range 2 {
		resp, b := send(t, c, br, "GET "+url+"/ HTTP/1.1\r\nHost: x\r\n\r\n")
		if resp.StatusCode != http.StatusOK || b != "ok" {
			t.Fatalf("GET %d: %d %q", i, resp.StatusCode, b)
		}
	}
	if dials.Load() != 2 {
		t.Fatalf("GET: %d connections, want 2", dials.Load())
	}
	resp, _ := send(t, c, br, "POST "+url+"/ HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\n\r\nx")
	if resp.StatusCode != http.StatusBadGateway || posts.Load() != 1 || dials.Load() != 2 {
		t.Fatalf("POST: %d, sent %d times, %d connections", resp.StatusCode, posts.Load(), dials.Load())
	}
}

// Close drops a dial in progress and a request waiting for its response
// instead of waiting for them.
func TestCloseDoesNotWait(t *testing.T) {
	asked := make(chan struct{}, 1)
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked <- struct{}{}
		<-r.Context().Done()
	}))
	t.Cleanup(o.Close)
	dialing := make(chan struct{}, 1)
	s := &Server{Dial: func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		if dst.Host == "hang.example" {
			dialing <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dst.String())
	}}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	c1, _ := client(t, s.Addr())
	fmt.Fprintf(c1, "GET %s/poll HTTP/1.1\r\nHost: x\r\n\r\n", o.URL)
	c2, _ := client(t, s.Addr())
	fmt.Fprint(c2, "CONNECT hang.example:443 HTTP/1.1\r\nHost: hang.example:443\r\n\r\n")
	<-asked
	<-dialing
	begin := time.Now()
	s.Close()
	if d := time.Since(begin); d > 2*time.Second {
		t.Fatalf("Close took %v", d)
	}
}

// An endless header is cut off (before the password is checked) instead
// of filling the memory; a big but sane one passes.
func TestHeaderLimit(t *testing.T) {
	o := origin(t)
	var dials atomic.Int32
	addr := start(t, &Server{Username: "u", Password: "p", Dial: dialer(&dials)})
	c, br := client(t, addr)
	resp, b := send(t, c, br, fmt.Sprintf("GET %s/big HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic dTpw\r\nCookie: %s\r\n\r\n", o.URL, strings.Repeat("a", 32<<10)))
	if resp.StatusCode != http.StatusOK || !strings.Contains(b, "hello /big") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}

	c, br = client(t, addr)
	go func() {
		io.WriteString(c, "GET http://x/ HTTP/1.1\r\nX-A: ")
		chunk := strings.Repeat("a", 16<<10)
		for range 64 { // 1 MB
			if _, err := io.WriteString(c, chunk); err != nil {
				return
			}
		}
	}()
	line, err := br.ReadString('\n')
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the proxy is still reading the header")
	}
	if err == nil && !strings.Contains(line, "431") {
		t.Fatal(line)
	}
}

// Half-close passes through: the client may still send after the server
// is done sending.
func TestSOCKSHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "hello")
		conn.(*net.TCPConn).CloseWrite()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, _ := io.ReadAll(conn)
		got <- string(b)
	}()
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	dst, _ := socks5.ParseHostPort(ln.Addr().String())
	cl := socks5.Client{Server: addr}
	c, err := cl.Connect(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(c); err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
	io.WriteString(c, "after-eof")
	c.(interface{ CloseWrite() error }).CloseWrite()
	if b := <-got; b != "after-eof" {
		t.Fatalf("server got %q", b)
	}
}

// An IPv4 address listens on IPv4 only: "0.0.0.0" must not open IPv6.
func TestListenNetwork(t *testing.T) {
	for addr, want := range map[string]string{
		"0.0.0.0:1080": "tcp4", "127.0.0.1:1080": "tcp4", "[::]:1080": "tcp", "[::1]:1080": "tcp", "localhost:1080": "tcp",
	} {
		if got := network(addr); got != want {
			t.Errorf("%s: %s, want %s", addr, got, want)
		}
	}
}

// Over MaxConns a new connection is closed at once and reported once (the
// report is rate-limited); a freed slot takes connections again.
func TestConnectionLimit(t *testing.T) {
	o := origin(t)
	var dials atomic.Int32
	reports := make(chan int64, 10)
	s := &Server{Dial: dialer(&dials), MaxConns: 2, OnLimit: func(n int64) { reports <- n }}
	addr := start(t, s)
	waitActive := func(n int64) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); s.Active.Load() != n; {
			if time.Now().After(end) {
				t.Fatalf("active %d, want %d", s.Active.Load(), n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	// Two clients that say nothing hold both slots.
	idle1, _ := client(t, addr)
	client(t, addr)
	waitActive(2)

	refused := func() {
		t.Helper()
		c, _ := client(t, addr)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, err := c.Read(make([]byte, 1))
		var ne net.Error
		if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
			t.Fatalf("connection over the cap is served: %v", err)
		}
	}
	refused()
	select {
	case n := <-reports:
		if n != 1 {
			t.Fatalf("reported %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not reported")
	}
	refused()
	if s.Refused.Load() != 2 || s.Active.Load() != 2 {
		t.Fatalf("refused %d, active %d", s.Refused.Load(), s.Active.Load())
	}
	select {
	case n := <-reports:
		t.Fatalf("reported again at once: %d", n)
	default:
	}

	idle1.Close()
	waitActive(1)
	c, br := client(t, addr)
	if resp, b := send(t, c, br, fmt.Sprintf("GET %s/free HTTP/1.1\r\nHost: x\r\n\r\n", o.URL)); resp.StatusCode != http.StatusOK || !strings.Contains(b, "hello /free") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
}

// A tunnel connection that breaks mid-stream reaches the program as a
// reset, not as a clean end of stream (a truncated download must not look
// complete), over SOCKS5 and HTTP CONNECT alike.
func TestTunnelResetReachesClient(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.WriteString(conn, "partial")
				time.Sleep(50 * time.Millisecond)
				socks5.Abort(conn)
			}()
		}
	}()
	var dials atomic.Int32
	addr := start(t, &Server{Dial: dialer(&dials)})
	dst, _ := socks5.ParseHostPort(ln.Addr().String())

	cl := socks5.Client{Server: addr}
	c, err := cl.Connect(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(c); !isReset(err) {
		t.Fatalf("SOCKS5: read %q, err %v: want a reset", b, err)
	}

	hc, br := client(t, addr)
	fmt.Fprintf(hc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", ln.Addr(), ln.Addr())
	if b, err := io.ReadAll(br); !isReset(err) {
		t.Fatalf("CONNECT: read %q, err %v: want a reset", b, err)
	}
}

// A plain HTTP client that breaks off a response resets the tunnel side
// too: the server must not see a clean close, as with CONNECT.
func TestClientResetReachesUpstream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	more, got := make(chan struct{}), make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- err
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		if _, err := http.ReadRequest(br); err != nil {
			got <- err
			return
		}
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nfirst")
		<-more
		// The proxy learns of the reset when it writes to the client.
		for i := 0; i < 10; i++ {
			if _, err := io.WriteString(conn, "more"); err != nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = br.ReadByte()
		got <- err
	}()
	var dials atomic.Int32
	c, br := client(t, start(t, &Server{Dial: dialer(&dials)}))
	fmt.Fprintf(c, "GET http://%s/ HTTP/1.1\r\nHost: x\r\n\r\n", ln.Addr())
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(resp.Body, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	socks5.Abort(c)
	time.Sleep(100 * time.Millisecond)
	close(more)
	if err := <-got; !isReset(err) {
		t.Fatalf("the server saw %v: want a reset", err)
	}
}

// isReset: the connection failed, as opposed to a clean end of stream or
// the test's own deadline.
func isReset(err error) bool {
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

// Close resets the connections it drops (Disconnect, a changed proxy).
func TestCloseResetsClients(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	held := make(chan net.Conn, 1) // the server side stays open, silent
	t.Cleanup(func() {
		select {
		case conn := <-held:
			conn.Close()
		default:
		}
	})
	go func() {
		if conn, err := ln.Accept(); err == nil {
			held <- conn
		}
	}()
	var dials atomic.Int32
	s := &Server{Dial: dialer(&dials)}
	addr := start(t, s)
	dst, _ := socks5.ParseHostPort(ln.Addr().String())
	cl := socks5.Client{Server: addr}
	c, err := cl.Connect(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(c); !isReset(err) {
		t.Fatalf("read %q, err %v: want a reset", b, err)
	}
}

// A SOCKS5 CONNECT answered after the handshake deadline still gets its
// reply: the deadline covers the handshake, not the dial.
func TestSOCKSSlowDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		io.WriteString(conn, "hello")
		conn.Close()
	}()
	shortTimeouts(t, 200*time.Millisecond)
	addr := start(t, &Server{Dial: func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		time.Sleep(400 * time.Millisecond)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", dst.String())
	}})
	dst, _ := socks5.ParseHostPort(ln.Addr().String())
	cl := socks5.Client{Server: addr}
	c, err := cl.Connect(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(c); err != nil || string(b) != "hello" {
		t.Fatalf("%q %v", b, err)
	}
}

// failingListener fails its first fail Accepts with an error that is not
// a timeout (out of sockets, say).
type failingListener struct {
	net.Listener
	fail  int32
	calls atomic.Int32
}

func (l *failingListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) <= l.fail {
		return nil, errors.New("accept: out of buffer space")
	}
	return l.Listener.Accept()
}

// A failed Accept is reported, once however often it fails in a row, and
// the port goes on serving: only Close stops it.
func TestAcceptErrorRetried(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := origin(t)
	var dials atomic.Int32
	reported := make(chan error, 10)
	s := &Server{Dial: dialer(&dials), OnAcceptError: func(err error) { reported <- err }}
	s.start(&failingListener{Listener: ln, fail: 3})
	t.Cleanup(func() { s.Close() })
	c, br := client(t, ln.Addr().String())
	if resp, b := send(t, c, br, fmt.Sprintf("GET %s/after HTTP/1.1\r\nHost: x\r\n\r\n", o.URL)); resp.StatusCode != http.StatusOK || !strings.Contains(b, "hello /after") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	if n := len(reported); n != 1 {
		t.Fatalf("accept error reported %d times", n)
	}
}
