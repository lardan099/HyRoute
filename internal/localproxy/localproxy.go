// Package localproxy serves a local proxy for programs that take a proxy
// setting (trading terminals, browsers, bots): one port speaks both SOCKS5
// and HTTP (CONNECT and plain requests), told apart by the first byte.
// Every connection goes out through Dial, i.e. through one Hysteria
// profile. UDP is not offered: SOCKS5 UDP ASSOCIATE is refused.
package localproxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// Dialer opens a connection to dst through the tunnel.
type Dialer func(ctx context.Context, dst socks5.Addr) (net.Conn, error)

// Timeouts (variables for tests). Only waits are timed: a tunnel, a body
// or a response takes as long as it takes.
var (
	// handshakeTimeout bounds the first bytes and the SOCKS5 handshake.
	handshakeTimeout = 30 * time.Second
	// idleTimeout: waiting for the next plain HTTP request.
	idleTimeout = 2 * time.Minute
	// headerTimeout: waiting for the server's response header.
	headerTimeout = 2 * time.Minute
)

// http.ReadRequest and http.ReadResponse read a header of any size, and a
// request is read before its password is checked.
const (
	maxRequestHeader  = 64 << 10
	maxResponseHeader = 1 << 20
)

const (
	// DefaultMaxConns caps simultaneous client connections when
	// Server.MaxConns is 0.
	DefaultMaxConns = 1024
	// limitReport: OnLimit is called at most this often.
	limitReport = time.Minute
)

type Server struct {
	// Username and Password are required from clients when Username is
	// set (SOCKS5 user/password, HTTP Proxy-Authorization: Basic).
	Username, Password string
	Dial               Dialer
	// OnError reports failed dials (logging); may be nil.
	OnError func(dst string, err error)
	// MaxConns caps simultaneous client connections (0: DefaultMaxConns).
	// Each one costs the elevated process a goroutine and buffers, and
	// anyone who can reach the port may open them, before the password:
	// over the cap a new connection is closed at once.
	MaxConns int
	// OnLimit reports connections closed over MaxConns (logging), at most
	// once a minute: refused counts them since the last report. It runs on
	// the accept loop and must not block; may be nil.
	OnLimit func(refused int64)

	Active       atomic.Int64 // open client connections
	Total        atomic.Int64 // connections served
	Sent, Recv   atomic.Int64 // bytes to / from the internet
	AuthFailures atomic.Int64
	Refused      atomic.Int64 // connections closed over MaxConns

	ln     net.Listener
	ctx    context.Context // cancelled by Close: stops dials
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool
	conn   map[net.Conn]struct{} // clients and their tunnel connections
	// Refusals not reported yet and the last report (serve only).
	unreported int64
	reportedAt time.Time
}

// Listen starts serving on addr ("127.0.0.1:1080", "0.0.0.0:1080"). An
// IPv4 address listens on IPv4 only: "0.0.0.0" over "tcp" would take
// every IPv6 address too, global ones included.
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen(network(addr), addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.conn = map[net.Conn]struct{}{}
	s.wg.Add(1)
	go s.serve()
	return nil
}

func network(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
		return "tcp4"
	}
	return "tcp"
}

func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops listening and drops every connection, tunnel side included,
// and every dial in progress, so it does not wait for slow servers.
func (s *Server) Close() error {
	err := s.ln.Close()
	s.cancel()
	s.mu.Lock()
	s.closed = true
	for c := range s.conn {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

// track registers a connection for Close; false once closed.
func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conn[c] = struct{}{}
	return true
}

// drop closes a tracked connection.
func (s *Server) drop(c net.Conn) {
	s.mu.Lock()
	delete(s.conn, c)
	s.mu.Unlock()
	c.Close()
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		// Only this loop adds to Active, so the cap holds.
		if s.Active.Load() >= int64(s.maxConns()) {
			s.refuse()
			c.Close()
			continue
		}
		if !s.track(c) { // accepted while Close ran
			c.Close()
			return
		}
		s.Active.Add(1)
		s.Total.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.drop(c)
				s.Active.Add(-1)
			}()
			s.handle(c)
		}()
	}
}

func (s *Server) maxConns() int {
	if s.MaxConns > 0 {
		return s.MaxConns
	}
	return DefaultMaxConns
}

// refuse counts a connection over the cap and reports the ones not
// reported yet, at most once per limitReport.
func (s *Server) refuse() {
	s.Refused.Add(1)
	s.unreported++
	if s.OnLimit == nil || (!s.reportedAt.IsZero() && time.Since(s.reportedAt) < limitReport) {
		return
	}
	s.OnLimit(s.unreported)
	s.unreported, s.reportedAt = 0, time.Now()
}

// bufConn reads through the bufio.Reader that already holds the first
// bytes.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// CloseWrite keeps half-close working through the wrapper: socks5.Pipe
// would otherwise close the whole connection when the other side is done
// sending.
func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return b.Conn.Close()
}

// limitReader caps what a header read may take from a connection (left <
// 0: no cap) and notes when the cap was reached.
type limitReader struct {
	r    io.Reader
	left int64
	hit  bool
}

func (l *limitReader) Read(p []byte) (int, error) {
	if l.left == 0 {
		l.hit = true
		return 0, io.EOF
	}
	if l.left > 0 && int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	if l.left > 0 {
		l.left -= int64(n)
	}
	return n, err
}

func (s *Server) handle(c net.Conn) {
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	lim := &limitReader{r: c, left: -1}
	br := bufio.NewReader(lim)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	bc := &bufConn{Conn: c, r: br}
	if first[0] == 5 {
		s.socks(bc)
	} else {
		s.http(bc, br, lim)
	}
}

func (s *Server) okCreds(user, pass string) bool {
	if s.Username == "" {
		return true
	}
	u := subtle.ConstantTimeCompare([]byte(user), []byte(s.Username))
	p := subtle.ConstantTimeCompare([]byte(pass), []byte(s.Password))
	if u&p == 1 {
		return true
	}
	s.AuthFailures.Add(1)
	return false
}

// dial opens a tracked connection; the caller drops it.
func (s *Server) dial(dst socks5.Addr) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
	defer cancel()
	up, err := s.Dial(ctx, dst)
	if err != nil {
		if s.OnError != nil {
			s.OnError(dst.String(), err)
		}
		return nil, err
	}
	if !s.track(up) {
		up.Close()
		return nil, net.ErrClosed
	}
	return up, nil
}

// pipe relays until both sides are done and counts the bytes.
func (s *Server) pipe(client, up net.Conn) {
	client.SetDeadline(time.Time{})
	up.SetDeadline(time.Time{})
	sent, recv := socks5.Pipe(client, up)
	s.Sent.Add(sent)
	s.Recv.Add(recv)
}

// ---- SOCKS5 ----

func (s *Server) socks(c net.Conn) {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	want := byte(0) // no auth
	if s.Username != "" {
		want = 2 // username/password
	}
	ok := false
	for _, m := range methods {
		ok = ok || m == want
	}
	if !ok {
		c.Write([]byte{5, 0xff})
		return
	}
	c.Write([]byte{5, want})
	if want == 2 {
		var v [2]byte
		if _, err := io.ReadFull(c, v[:]); err != nil {
			return
		}
		u := make([]byte, v[1])
		if _, err := io.ReadFull(c, u); err != nil {
			return
		}
		if _, err := io.ReadFull(c, v[:1]); err != nil {
			return
		}
		p := make([]byte, v[0])
		if _, err := io.ReadFull(c, p); err != nil {
			return
		}
		if !s.okCreds(string(u), string(p)) {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	}
	var r [3]byte
	if _, err := io.ReadFull(c, r[:]); err != nil || r[0] != 5 {
		return
	}
	dst, err := socks5.ReadAddr(c)
	if err != nil {
		return
	}
	if r[1] != socks5.CmdConnect {
		socksReply(c, 7) // command not supported (UDP ASSOCIATE, BIND)
		return
	}
	up, err := s.dial(dst)
	if err != nil {
		socksReply(c, replyCode(err))
		return
	}
	defer s.drop(up)
	socksReply(c, 0)
	s.pipe(c, up)
}

func socksReply(c net.Conn, code byte) {
	c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

// replyCode keeps the tunnel's SOCKS5 answer (host unreachable, refused…).
func replyCode(err error) byte {
	var re socks5.ReplyError
	if errors.As(err, &re) {
		return byte(re)
	}
	return 1 // general failure
}

// ---- HTTP ----

var hopHeaders = []string{"Proxy-Authorization", "Proxy-Connection", "Proxy-Authenticate", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"}

func (s *Server) httpAuth(req *http.Request) bool {
	if s.Username == "" {
		return true
	}
	h := req.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return false
	}
	u, p, _ := strings.Cut(string(raw), ":")
	return s.okCreds(u, p)
}

func respond(c net.Conn, code int, headers string) {
	io.WriteString(c, "HTTP/1.1 "+itoa(code)+" "+http.StatusText(code)+"\r\n"+headers+"Content-Length: 0\r\n\r\n")
}

func itoa(n int) string {
	var b [8]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			return string(b[i:])
		}
	}
}

func hostPort(req *http.Request) string {
	h := req.URL.Host
	if h == "" {
		h = req.Host
	}
	if _, _, err := net.SplitHostPort(h); err != nil {
		port := "80"
		if req.URL.Scheme == "https" {
			port = "443"
		}
		h = net.JoinHostPort(strings.Trim(h, "[]"), port)
	}
	return h
}

// upstream is the tunnel connection plain requests to one host reuse.
type upstream struct {
	net.Conn
	host string
	lim  *limitReader
	r    *bufio.Reader
}

func (s *Server) dialUpstream(dst socks5.Addr, host string) (*upstream, error) {
	conn, err := s.dial(dst)
	if err != nil {
		return nil, err
	}
	lim := &limitReader{r: conn, left: -1}
	return &upstream{Conn: conn, host: host, lim: lim, r: bufio.NewReader(lim)}, nil
}

// stale reports whether the server has closed the kept-alive connection
// while it waited (keep-alive timeout) or said something unasked.
func (u *upstream) stale() bool {
	if u.r.Buffered() > 0 {
		return true
	}
	u.SetReadDeadline(time.Now().Add(time.Millisecond))
	_, err := u.r.Peek(1)
	u.SetReadDeadline(time.Time{})
	var ne net.Error
	return !errors.As(err, &ne) || !ne.Timeout()
}

// errNoResponse: the connection failed before the server answered
// anything, so a request that is safe to repeat may go again.
var errNoResponse = errors.New("no response")

// exchange sends req and reads the response header.
func (s *Server) exchange(u *upstream, req *http.Request) (*http.Response, error) {
	cw := &countWriter{w: u}
	err := req.Write(cw)
	s.Sent.Add(cw.n)
	if err != nil {
		return nil, errNoResponse
	}
	u.SetReadDeadline(time.Now().Add(headerTimeout))
	if _, err := u.r.Peek(1); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, err
		}
		return nil, errNoResponse
	}
	return u.response(req)
}

// response reads a response header within the read deadline set by the
// caller and lifts it: the body that follows is not timed.
func (u *upstream) response(req *http.Request) (*http.Response, error) {
	u.lim.left = maxResponseHeader
	resp, err := http.ReadResponse(u.r, req)
	u.lim.left = -1
	u.SetReadDeadline(time.Time{})
	return resp, err
}

// replayable: a request net/http's Transport would repeat on a new
// connection (no body, idempotent method).
func replayable(req *http.Request) bool {
	if req.Body != nil && req.Body != http.NoBody {
		return false
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}

// interim passes on a 1xx response (100 Continue, 103 Early Hints): the
// final one follows. Response.Write would add a Content-Length.
func interim(w io.Writer, resp *http.Response) error {
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode) + "\r\n")
	resp.Header.Write(&b)
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func (s *Server) http(c net.Conn, br *bufio.Reader, lim *limitReader) {
	var up *upstream
	defer func() {
		if up != nil {
			s.drop(up.Conn)
		}
	}()
	for {
		c.SetReadDeadline(time.Now().Add(idleTimeout))
		lim.left = maxRequestHeader
		req, err := http.ReadRequest(br)
		lim.left = -1
		if err != nil {
			if lim.hit {
				respond(c, http.StatusRequestHeaderFieldsTooLarge, "")
			}
			return
		}
		// Only the wait for a request is timed (both ways: the handshake
		// deadline covers writes too).
		c.SetDeadline(time.Time{})
		if !s.httpAuth(req) {
			respond(c, http.StatusProxyAuthRequired, "Proxy-Authenticate: Basic realm=\"HyRoute\"\r\n")
			return
		}
		target := hostPort(req)
		dst, err := socks5.ParseHostPort(target)
		if err != nil {
			respond(c, http.StatusBadRequest, "")
			return
		}
		if req.Method == http.MethodConnect {
			conn, err := s.dial(dst)
			if err != nil {
				respond(c, http.StatusBadGateway, "")
				return
			}
			defer s.drop(conn)
			io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
			s.pipe(c, conn)
			return
		}
		if req.URL.Scheme != "http" || req.URL.Host == "" {
			// Not a proxy request (someone opened the port in a browser).
			respond(c, http.StatusBadRequest, "")
			return
		}
		upgrade := strings.EqualFold(req.Header.Get("Connection"), "upgrade")
		for _, h := range hopHeaders {
			if h == "Connection" || h == "Upgrade" {
				if upgrade {
					continue
				}
			}
			req.Header.Del(h)
		}
		req.RequestURI = ""
		if up != nil && (up.host != target || up.stale()) {
			s.drop(up.Conn)
			up = nil
		}
		// The server may close a kept-alive connection just as the
		// request arrives: one more try on a new one.
		retry := up != nil && replayable(req)
		var resp *http.Response
		for {
			if up == nil {
				if up, err = s.dialUpstream(dst, target); err != nil {
					respond(c, http.StatusBadGateway, "")
					return
				}
			}
			if resp, err = s.exchange(up, req); err == nil {
				break
			}
			s.drop(up.Conn)
			up = nil
			if !retry || err != errNoResponse {
				respond(c, http.StatusBadGateway, "")
				return
			}
			retry = false
		}
		rw := &countWriter{w: c}
		for resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
			// HTTP/1.0 clients get no 1xx (RFC 9110, 15.2).
			if req.ProtoAtLeast(1, 1) {
				if err := interim(rw, resp); err != nil {
					s.Recv.Add(rw.n)
					return
				}
			}
			up.SetReadDeadline(time.Now().Add(headerTimeout))
			if resp, err = up.response(req); err != nil {
				s.Recv.Add(rw.n)
				respond(c, http.StatusBadGateway, "")
				return
			}
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			resp.Write(rw)
			s.Recv.Add(rw.n)
			s.pipe(&bufConn{Conn: c, r: br}, &bufConn{Conn: up.Conn, r: up.r})
			return
		}
		closeAfter := resp.Close || req.Close
		for _, h := range hopHeaders {
			resp.Header.Del(h)
		}
		err = resp.Write(rw)
		resp.Body.Close()
		s.Recv.Add(rw.n)
		if err != nil || closeAfter {
			return
		}
	}
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
