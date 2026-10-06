// Package localproxy serves a local proxy for programs that take a proxy
// setting (trading terminals, browsers, bots): one port speaks both SOCKS5
// and HTTP (CONNECT and plain requests), told apart by the first byte.
// Every connection goes out through Dial, i.e. through one Hysteria
// profile. SOCKS5 UDP ASSOCIATE is served when AssociateUDP is set: on one
// shared UDP socket on the TCP port number (SharedUDP, LAN proxies) or on a
// socket per association (see udp.go); HTTP is TCP only.
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
	// acceptRetry: the first pause after a failed Accept; it doubles up to
	// acceptRetryMax while Accept keeps failing.
	acceptRetry    = 50 * time.Millisecond
	acceptRetryMax = time.Second
)

type Server struct {
	// Username and Password are required from clients when Username is
	// set (SOCKS5 user/password, HTTP Proxy-Authorization: Basic).
	Username, Password string
	Dial               Dialer
	// OnError reports failed dials (logging); may be nil.
	OnError func(dst string, err error)
	// OnAcceptError reports a failed Accept (logging), at most once per
	// limitReport; the server goes on accepting after a pause. May be nil.
	OnAcceptError func(err error)
	// MaxConns caps simultaneous client connections (0: DefaultMaxConns).
	// Each one costs the elevated process a goroutine and buffers, and
	// anyone who can reach the port may open them, before the password:
	// over the cap a new connection is closed at once.
	MaxConns int
	// OnLimit reports connections closed over MaxConns (logging), at most
	// once a minute: refused counts them since the last report. It runs on
	// the accept loop and must not block; may be nil.
	OnLimit func(refused int64)

	// AssociateUDP serves SOCKS5 UDP ASSOCIATE (nil: refused with reply 7,
	// no UDP socket is opened).
	AssociateUDP UDPDialer
	// SharedUDP: one UDP socket on the TCP port number (same host) serves
	// every association (LAN proxies: the firewall rule stays exact).
	// false: each association gets its own socket on <TCP host>:0.
	SharedUDP bool
	// Owners, when set, makes every association whose control connection
	// comes from this computer "owner-checked": it pins only a UDP source
	// owned by the process that owns the control connection. Without
	// SharedUDP every peer is local (loopback proxies with a password);
	// with SharedUDP it applies to peers that are loopback or one of this
	// PC's addresses (a LAN proxy used locally), decided per association.
	// Peers on other devices are checked by IP only.
	Owners OwnerLookup
	// MaxUDP caps simultaneous associations (0: DefaultMaxUDP).
	MaxUDP int
	// OnUDPLimit reports associations refused over MaxUDP; OnUDPEvent
	// reports datagram drops and association events per kind with the
	// count since the last report and one example size; OnUDPPort reports
	// socket results only: the shared socket opening late (err == nil) or
	// a socket failing to bind. Each at most once per limitReport per key
	// (an opening at once); called without locks held; may be nil; must
	// not block.
	OnUDPLimit func(refused int64)
	OnUDPEvent func(ev UDPEvent, count int64, size int)
	OnUDPPort  func(err error)

	UDPActive  atomic.Int64 // open associations
	UDPTotal   atomic.Int64 // associations served
	UDPDropped atomic.Int64 // datagrams dropped (Drop* events only)
	// UDPCtlActive/UDPCtlTotal count UDP ASSOCIATE control connections,
	// refused ones included (Active/Total minus these = TCP connections).
	UDPCtlActive, UDPCtlTotal atomic.Int64

	Active       atomic.Int64 // open client connections (UDP control connections included)
	Total        atomic.Int64 // connections served
	Sent, Recv   atomic.Int64 // bytes to / from the internet (UDP payloads included)
	AuthFailures atomic.Int64
	Refused      atomic.Int64 // connections closed over MaxConns
	// OnAuthFail reports failed logins: one address that failed and the
	// failures since the last report, at most once per limitReport;
	// called without locks held; may be nil; must not block.
	OnAuthFail func(from netip.Addr, count int64)

	ln     net.Listener
	ctx    context.Context // cancelled by Close: stops dials
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool
	conn   map[net.Conn]struct{} // clients and their tunnel connections
	// UDP side (udp.go). udpMu guards shared, udpErr and nassoc; it is
	// never nested with mu or a port's mu.
	udpMu  sync.Mutex
	shared *udpPort // SharedUDP: nil while not bound
	udpErr error    // SharedUDP: why shared is nil
	nassoc int      // reserved + open associations (MaxUDP)
	udpRep reporter // rate limiting of the UDP callbacks
	// Refusals not reported yet and the last report (serve only).
	unreported int64
	reportedAt time.Time
	// Failed logins by address (see noteAuth). failMu is a leaf lock.
	failMu    sync.Mutex
	fails     map[netip.Addr]*authFails
	failUnrep int64
	failAt    time.Time
}

// Listen starts serving on addr ("127.0.0.1:1080", "0.0.0.0:1080"). An
// IPv4 address listens on IPv4 only: "0.0.0.0" over "tcp" would take
// every IPv6 address too, global ones included.
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen(network(addr), addr)
	if err != nil {
		return err
	}
	s.start(ln)
	return nil
}

// start serves on ln (tests pass their own listener).
func (s *Server) start(ln net.Listener) {
	s.ln = ln
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.conn = map[net.Conn]struct{}{}
	s.startUDP()
	s.wg.Add(1)
	go s.serve()
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
// and every dial in progress, so it does not wait for slow servers. The
// connections are reset, not closed with a FIN: a download cut short must
// not look complete to the program.
func (s *Server) Close() error {
	err := s.ln.Close()
	s.cancel()
	s.closeUDP()
	s.mu.Lock()
	s.closed = true
	for c := range s.conn {
		socks5.Abort(c)
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
	var retry time.Duration // 0: the last Accept succeeded
	var reported time.Time
	for {
		c, err := s.ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return // Close
			}
			// Out of sockets or memory for a moment: the port is still
			// open, so give up only on Close.
			if s.OnAcceptError != nil && (reported.IsZero() || time.Since(reported) >= limitReport) {
				reported = time.Now()
				s.OnAcceptError(err)
			}
			retry = min(max(2*retry, acceptRetry), acceptRetryMax)
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(retry):
			}
			continue
		}
		retry = 0
		if s.authBlocked(c) {
			c.Close() // waits after failed logins
			continue
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

// NetConn returns the wrapped connection (socks5.Abort resets through it).
func (b *bufConn) NetConn() net.Conn { return b.Conn }

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
			s.noteAuth(c, false)
			c.Write([]byte{1, 1})
			return
		}
		s.noteAuth(c, true)
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
	// The handshake is over: the dial has its own timeout, and the reply
	// must not fail on the handshake deadline (it covers writes too).
	c.SetDeadline(time.Time{})
	switch r[1] {
	case socks5.CmdConnect:
	case socks5.CmdUDPAssociate:
		s.UDPCtlActive.Add(1)
		s.UDPCtlTotal.Add(1)
		defer s.UDPCtlActive.Add(-1)
		s.associate(c, dst)
		return
	default:
		socksReply(c, 7) // command not supported (BIND)
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

// connectionTokens returns the options of every Connection header: each
// is a comma-separated list (RFC 9110, 7.6.1).
func connectionTokens(h http.Header) []string {
	var out []string
	for _, v := range h["Connection"] {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

// isUpgrade reports a request to switch protocols (WebSocket, h2c).
func isUpgrade(h http.Header) bool {
	for _, t := range connectionTokens(h) {
		if strings.EqualFold(t, "upgrade") {
			return true
		}
	}
	return false
}

// dropHop removes the hop-by-hop headers: the fixed ones and the ones
// Connection lists. With upgrade, Upgrade stays and Connection says
// "Upgrade" to the next hop.
func dropHop(h http.Header, upgrade bool) {
	for _, t := range connectionTokens(h) {
		if !(upgrade && strings.EqualFold(t, "upgrade")) {
			h.Del(t)
		}
	}
	for _, name := range hopHeaders {
		if !(upgrade && name == "Upgrade") {
			h.Del(name)
		}
	}
	if upgrade {
		h.Set("Connection", "Upgrade")
	}
}

// httpAuth checks the request's credentials; tried is false when it has
// none (a browser asks without them first and answers the 407).
func (s *Server) httpAuth(req *http.Request) (ok, tried bool) {
	if s.Username == "" {
		return true, false
	}
	h := req.Header.Get("Proxy-Authorization")
	if h == "" {
		return false, false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		return false, true
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return false, true
	}
	u, p, _ := strings.Cut(string(raw), ":")
	return s.okCreds(u, p), true
}

// authFails: an address's failed logins in a row, and until when it waits.
type authFails struct {
	n     int
	until time.Time
}

// authFree is how many failed logins in a row an address gets before it
// waits; the wait doubles with every further one up to authWaitMax.
// authTrack bounds the addresses remembered.
const (
	authFree    = 5
	authWaitMax = 5 * time.Minute
	authTrack   = 4096
)

func remoteIP(c net.Conn) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// authBlocked: c's address waits after failed logins (new connections
// from it are closed at once, so guesses cannot run in parallel).
func (s *Server) authBlocked(c net.Conn) bool {
	if s.Username == "" {
		return false
	}
	ip, ok := remoteIP(c)
	if !ok {
		return false
	}
	s.failMu.Lock()
	defer s.failMu.Unlock()
	f := s.fails[ip]
	return f != nil && time.Now().Before(f.until)
}

// noteAuth records a login on c: a success forgets the address's
// failures, a failure counts and from authFree on makes it wait.
func (s *Server) noteAuth(c net.Conn, ok bool) {
	ip, valid := remoteIP(c)
	if !valid {
		return
	}
	s.failMu.Lock()
	if ok {
		delete(s.fails, ip)
		s.failMu.Unlock()
		return
	}
	if s.fails == nil {
		s.fails = map[netip.Addr]*authFails{}
	}
	f := s.fails[ip]
	if f == nil {
		if len(s.fails) >= authTrack {
			for k, v := range s.fails { // forget one that no longer waits
				if time.Now().After(v.until) {
					delete(s.fails, k)
					break
				}
			}
		}
		f = &authFails{}
		s.fails[ip] = f
	}
	f.n++
	if f.n >= authFree {
		f.until = time.Now().Add(min(time.Second<<min(f.n-authFree, 20), authWaitMax))
	}
	s.failUnrep++
	report := s.OnAuthFail != nil && (s.failAt.IsZero() || time.Since(s.failAt) >= limitReport)
	var n int64
	if report {
		n, s.failUnrep, s.failAt = s.failUnrep, 0, time.Now()
	}
	s.failMu.Unlock()
	if report {
		s.OnAuthFail(ip, n)
	}
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
	dropHop(resp.Header, false)
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
		ok, tried := s.httpAuth(req)
		if tried {
			s.noteAuth(c, ok)
		}
		if !ok {
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
		dropHop(req.Header, isUpgrade(req.Header))
		// A client that expects 100 Continue holds the body back until it
		// comes, but req.Write sends the body at once instead of waiting
		// for the server's 100: the proxy answers the expectation itself
		// (HTTP/1.0 clients may not ask it, RFC 9110, 10.1.1).
		cont := req.ProtoAtLeast(1, 1) && req.Body != nil && req.Body != http.NoBody &&
			strings.EqualFold(strings.TrimSpace(req.Header.Get("Expect")), "100-continue")
		if cont {
			req.Header.Del("Expect")
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
			if cont {
				cont = false
				if _, err := io.WriteString(c, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
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
		// An HTTP/1.0 client cannot read chunked (RFC 9112, 6.1): the body
		// goes as it is, ended by closing the connection.
		if !req.ProtoAtLeast(1, 1) && len(resp.TransferEncoding) > 0 {
			resp.TransferEncoding = nil
			resp.ContentLength = -1
			resp.Close = true
		}
		closeAfter := resp.Close || req.Close
		dropHop(resp.Header, false)
		// A body cut short must not end like a complete one, on either
		// side (as in pipe). A client that breaks off resets the tunnel
		// at once: resp.Write then closes the body, which would first
		// read the rest of it from the server.
		reset := func() {
			socks5.Abort(c)
			socks5.Abort(up.Conn)
		}
		rw.fail = reset
		err = resp.Write(rw)
		resp.Body.Close()
		s.Recv.Add(rw.n)
		if err != nil {
			reset() // the server's side broke
			return
		}
		if closeAfter {
			return
		}
	}
}

type countWriter struct {
	w io.Writer
	n int64
	// fail, if set, runs on the first failed write.
	fail func()
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	if err != nil && c.fail != nil {
		c.fail()
		c.fail = nil
	}
	return n, err
}
