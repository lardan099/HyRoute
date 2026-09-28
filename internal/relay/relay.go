// Package relay is the transparent TCP listener that reflected flows land
// in. It recovers the original destination from the NAT table and forwards
// the connection according to the decision stored in the entry.
package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/sniff"
	"github.com/lardan099/hyroute/internal/socks5"
)

// Tunnel is the upstream for Tunnel-routed connections (one Hysteria
// SOCKS5 per profile).
type Tunnel interface {
	// Available reports whether Hysteria is connected. When it is not,
	// Tunnel connections are rejected, never sent direct.
	Available() bool
	Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error)
}

// Counting is implemented by tunnels that keep per-profile counters.
type Counting interface {
	NoteRejected()
	NoteTraffic(sent, recv int64)
}

// Result describes a finished relayed connection.
type Result struct {
	Entry      *nat.Entry
	Route      string // "tunnel", "direct", "block", "rejected"
	Reason     string
	Err        error
	Rule       string
	Profile    string
	Domain     string
	DomainSrc  rules.DomainSource
	Stage      string // "relay", "sniff", "sniff-timeout"
	Sent, Recv int64
	Start, End time.Time
	// groups
	// Group is the server group Profile was chosen through; Failover: the
	// connection could not use its preferred server. Sniffed connections
	// only (a NoSniff one's record already has both).
	Group    string
	Failover bool
}

// Counters are exposed to the UI.
type Counters struct {
	Accepted atomic.Int64
	Tunneled atomic.Int64
	Direct   atomic.Int64
	Blocked  atomic.Int64
	// Rejected counts Tunnel connections reset because the tunnel was down
	// or the SOCKS5 request failed.
	Rejected atomic.Int64
	// Stray counts accepted connections without a NAT entry.
	Stray atomic.Int64
}

// DefaultServerFirstPorts are protocols where the client waits for the
// server's banner, so sniffing gives up quickly.
var DefaultServerFirstPorts = map[uint16]bool{
	21: true, 22: true, 25: true, 110: true, 143: true, 587: true, 3306: true, 5432: true,
}

type Server struct {
	// Lookup maps the accepted peer (R, lp) to the NAT entry.
	Lookup func(peer netip.AddrPort) *nat.Entry
	// Tunnel returns the profile's tunnel, or nil when the profile is not
	// running (the connection is then refused).
	Tunnel func(profile string) Tunnel
	Log    *slog.Logger
	// OnDone is called once per connection that had a NAT entry.
	OnDone func(Result)
	// ListenIPs defaults to 0.0.0.0 and [::].
	ListenIPs []netip.Addr
	// DialTimeout bounds the SOCKS5 CONNECT and direct dials (default 10s).
	DialTimeout time.Duration

	// Decide is called for SNIFF entries with the name found (or "") and
	// must return a final result.
	Decide func(e *nat.Entry, domain string, src rules.DomainSource) rules.Result
	// DialDirect opens Direct upstreams from the application's source
	// address src, so the connection leaves through the interface the
	// application chose, as a packet-level Direct would (default net.Dialer
	// bound to src). HyRoute's own connections are excluded from
	// interception by PID.
	DialDirect func(ctx context.Context, src netip.Addr, dst netip.AddrPort) (net.Conn, error)
	// PreferRemoteDNS sends the SNI/Host name (never a DNS-cache name, nor
	// the Host of a request to a forward proxy) to SOCKS5 as ATYP=DOMAIN.
	PreferRemoteDNS bool
	// SniffTimeout bounds waiting for the first bytes (default 800ms);
	// ServerFirstPorts use ServerFirstTimeout (default 150ms).
	SniffTimeout       time.Duration
	ServerFirstTimeout time.Duration
	ServerFirstPorts   map[uint16]bool
	// dns
	// ServeDNS serves a DNS entry's connection (nat.DNS): length-prefixed
	// queries in, answers out. pass opens the connection that queries
	// passed on unchanged go to (the original server, by the route res):
	// Direct dials like a relayed Direct connection, Tunnel through
	// res.Profile's tunnel (unavailable: an error, never direct), Block is
	// an error. The connection is tracked (reset by Abort) until ServeDNS
	// returns. nil: DNS entries are reset.
	ServeDNS func(ctx context.Context, e *nat.Entry, client net.Conn,
		pass func(ctx context.Context, res rules.Result) (net.Conn, error))

	Counters

	port   uint16
	lns    []net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]*nat.Entry // the entry of a client or upstream connection; nil before the NAT lookup
	wg     sync.WaitGroup
	done   chan struct{}
	ctx    context.Context // canceled by Abort: interrupts pending dials
	cancel context.CancelFunc
	// idle is closed once the handlers are done (see CloseWait); stuck
	// records that a CloseWait gave up on them.
	idleOnce sync.Once
	idle     chan struct{}
	stuck    atomic.Bool
}

// Dynamic port range used for the relay (the firewall rule covers it).
const (
	PortMin = 49152
	PortMax = 65535
)

// Start listens on port on every ListenIP. Port 0 picks a random free port
// from the dynamic range that is free on all families.
func (s *Server) Start(port uint16) error {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	if len(s.ListenIPs) == 0 {
		s.ListenIPs = []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()}
	}
	s.conns = make(map[net.Conn]*nat.Entry)
	s.done = make(chan struct{})
	s.ctx, s.cancel = context.WithCancel(context.Background())
	tries := 1
	if port == 0 {
		tries = 32
	}
	var err error
	for i := 0; i < tries; i++ {
		p := port
		if p == 0 {
			p = uint16(PortMin + rand.IntN(PortMax-PortMin+1))
		}
		if err = s.listenAll(p); err == nil {
			s.port = p
			for _, ln := range s.lns {
				s.wg.Add(1)
				go s.serve(ln)
			}
			return nil
		}
	}
	return fmt.Errorf("relay: listen: %w", err)
}

func (s *Server) listenAll(port uint16) error {
	var lns []net.Listener
	for _, ip := range s.ListenIPs {
		network := "tcp4"
		if ip.Is6() {
			network = "tcp6" // Go sets IPV6_V6ONLY for tcp6
		}
		ln, err := net.Listen(network, netip.AddrPortFrom(ip, port).String())
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return err
		}
		lns = append(lns, ln)
	}
	s.lns = lns
	return nil
}

func (s *Server) Port() uint16 { return s.port }

// Close aborts the server (see Abort) and waits for the connection
// handlers to finish.
func (s *Server) Close() error {
	s.Abort()
	s.wg.Wait()
	return nil
}

// CloseWait is Close that waits at most d for the handlers and reports
// whether they finished. A handler ends with OnDone, which may need a lock
// held by a packet loop that never returns: whoever stops the session must
// not hang on it. One goroutine waits for the handlers however often it
// is called, and once a call gave up the later ones do not wait again.
func (s *Server) CloseWait(d time.Duration) bool {
	s.Abort()
	s.idleOnce.Do(func() {
		s.idle = make(chan struct{})
		go func() {
			s.wg.Wait()
			close(s.idle)
		}()
	})
	select {
	case <-s.idle:
		return true
	default:
	}
	if s.stuck.Load() {
		return false
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.idle:
		return true
	case <-t.C:
		if !s.stuck.Swap(true) {
			s.Log.Error("relay: connection handlers still running after close", "waited", d)
		}
		return false
	}
}

// Abort stops listening, cancels pending upstream dials and resets every
// connection, application and upstream side, without waiting. A reset
// sends no FIN, queued data or keepalives later: an accepted socket's peer
// is the real remote address (R, lp), so once the filters are gone those
// would leave for R directly, outside the kill switch that exempts
// HyRoute. Call it while the filters still reflect the resets to the
// applications.
func (s *Server) Abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done == nil {
		return // never started
	}
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
	s.cancel()
	for _, ln := range s.lns {
		ln.Close()
	}
	for c := range s.conns {
		Reset(c)
	}
}

func (s *Server) serve(ln net.Listener) {
	defer s.wg.Done()
	var retry time.Duration // 0: the last Accept succeeded
	var logged time.Time
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// A lasting failure is logged once a minute, not per retry.
			if logged.IsZero() || time.Since(logged) >= time.Minute {
				logged = time.Now()
				s.Log.Error("relay accept failed", "err", err)
			}
			retry = min(max(2*retry, 50*time.Millisecond), time.Second)
			select {
			case <-s.done:
				return
			case <-time.After(retry):
			}
			continue
		}
		retry = 0
		if !s.track(c, true) {
			Reset(c)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(c, false)
			defer func() {
				if r := recover(); r != nil {
					s.Log.Error("relay: panic in connection handler", "panic", r)
					Reset(c)
				}
			}()
			s.handle(c)
		}()
	}
}

func (s *Server) track(c net.Conn, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		select {
		case <-s.done:
			return false
		default:
		}
		s.conns[c] = nil
	} else {
		delete(s.conns, c)
	}
	return true
}

// setEntry records the NAT entry of a tracked connection (AbortWhere).
func (s *Server) setEntry(c net.Conn, e *nat.Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.conns[c]; ok {
		s.conns[c] = e
	}
}

// AbortWhere resets every tracked connection, application and upstream
// side, whose entry pred matches (dns: the DNS-mode connections when DNS
// capture goes, the browsers' DoH connections). Call it while the filters
// still reflect the resets to the applications.
func (s *Server) AbortWhere(pred func(*nat.Entry) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c, e := range s.conns {
		if e != nil && pred(e) {
			Reset(c)
		}
	}
}

func (s *Server) handle(c net.Conn) {
	s.Accepted.Add(1)
	peer := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	e := s.Lookup(peer)
	if e == nil {
		// Not one of ours: someone connected to the relay port directly.
		s.Stray.Add(1)
		s.Log.Warn("relay: connection without NAT entry, reset", "peer", peer)
		Reset(c)
		return
	}
	res := Result{Entry: e, Start: time.Now(), Stage: "relay"}
	defer func() {
		res.End = time.Now()
		if s.OnDone != nil {
			s.OnDone(res)
		}
	}()
	s.setEntry(c, e)
	if e.Mode == nat.DNS { // dns
		s.serveDNS(c, e, &res)
		return
	}

	client := &appConn{Conn: c, s: s, rec: e.Rec}
	action, profile := rules.Tunnel, e.Profile
	var head []byte
	host := ""       // name the route is decided by
	remoteName := "" // name the tunnel may resolve instead of the IP
	if e.Mode == nat.Sniff {
		var src rules.DomainSource
		head, host, src, res.Stage = s.sniff(client, e)
		remoteName = host
		if src == rules.SrcHost && proxyRequest(head) {
			// A request to a forward proxy: Host names the proxied site,
			// not the proxy this connection goes to. It still decides the
			// route, but the connection keeps the proxy's address.
			remoteName = ""
		}
		if s.Decide == nil {
			s.reject(c, &res, "no decider for sniff mode", nil)
			return
		}
		d := s.Decide(e, host, src)
		if src == rules.SrcECH && d.DomainSrc != rules.SrcSNI {
			// Unless the decider took the outer SNI of the ECH hello for
			// the site itself (GREASE ECH), it is a provider's public
			// name: its address need not lead to the server that holds
			// the site, so the tunnel connects to the address the
			// application chose.
			remoteName = ""
		}
		action, profile, res.Rule, res.Domain, res.DomainSrc = d.Action, d.Profile, d.Rule, d.Domain, d.DomainSrc
		res.Group, res.Failover = d.Group, d.Failover
		if e.Rec != nil {
			e.Rec.Set(func(f *flows.Fields) {
				f.Rule, f.Route, f.Profile, f.Stage = d.Rule, d.Action.String(), d.Profile, res.Stage
				f.Group, f.Failover = d.Group, d.Failover
				if d.Domain != "" {
					f.Domain, f.DomainSrc = d.Domain, d.DomainSrc.String()
				}
			})
		}
	}

	if action == rules.Block {
		s.Blocked.Add(1)
		res.Route = "block"
		s.setOutcome(e, "rst: blocked")
		Reset(c)
		return
	}
	if action != rules.Direct {
		res.Profile = profile
	}
	up, tun, fail, err := s.dialRoute(s.ctx, e, action, profile, remoteName)
	switch {
	case err != nil && action == rules.Direct:
		res.Route, res.Err = "direct", err
		s.setOutcome(e, "rst: "+fail)
		Reset(c)
		return
	case errors.Is(err, errTunnelUnavailable):
		s.reject(c, &res, fail, nil)
		return
	case err != nil:
		s.reject(c, &res, fail, err)
		return
	case action == rules.Direct:
		res.Route = "direct"
	default:
		res.Route = "tunnel"
		if cnt, ok := tun.(Counting); ok {
			defer func() { cnt.NoteTraffic(res.Sent, res.Recv) }()
		}
	}
	if !s.track(up, true) {
		Reset(up)
		Reset(c)
		return
	}
	defer s.track(up, false)
	s.setEntry(up, e)
	s.setOutcome(e, "relayed")
	if len(head) > 0 {
		if _, err := up.Write(head); err != nil {
			up.Close()
			Reset(c)
			return
		}
	}
	// Pipe resets both sides when either breaks: the application must not
	// take a broken upstream for a clean end of stream, nor keep a
	// half-closed socket that outlives the NAT entry. The application side
	// is shut down only once it has taken what it was sent (see settle).
	res.Sent, res.Recv = socks5.Pipe(client, up)
	res.Sent += int64(len(head))
	c.Close()
	up.Close()
}

// drainTimeout: send counters that show room, nothing in flight and bytes
// still unacknowledged for this long without change do not add up; settle
// stops waiting on them (a variable for tests).
var drainTimeout = 10 * time.Second

// TCP states (TCPSTATE, mstcpip.h) in which the application may still
// acknowledge what it was sent.
const (
	tcpEstablished = 4
	tcpCloseWait   = 7
)

// progress is the send side of a socket as the kernel sees it.
type progress struct {
	state    uint32 // TCPSTATE
	acked    int64  // bytes the peer has acknowledged
	inFlight uint32 // bytes sent, not acknowledged
	window   uint32 // the peer's receive window
}

// settle waits until the application has acknowledged the written bytes
// sent to c and has room for a FIN, and reports whether c may now be shut
// down. Not before: on Windows, once shutdown(SD_SEND) has queued a FIN,
// closing with SO_LINGER 0 no longer resets the connection, and the socket
// goes on sending its tail (retransmits, window probes, the FIN) after
// Abort, once the filters are gone: to the real remote. While settle
// waits, c stays tracked and Abort still resets it; after it, only a FIN
// is outstanding, which the application acknowledges at once. An
// application that pauses reading is waited for as long as the connection
// lives, like an idle one: it gets the tail and the end of stream when it
// resumes. One that closes or resets its socket ends the wait.
func (s *Server) settle(c net.Conn, written int64) bool {
	last, ok := sendProgress(c)
	stalled := time.Now() // since the counters last changed
	wait := time.Millisecond
	for ok && (last.acked < written || last.window == 0) {
		if last.state != tcpEstablished && last.state != tcpCloseWait {
			return true // the application is gone: nothing more reaches it
		}
		if last.window > 0 && last.inFlight == 0 && time.Since(stalled) > drainTimeout {
			// Room and nothing in flight with bytes outstanding: the
			// counters do not add up, not a paused application.
			s.Log.Warn("relay: send counters inconsistent", "written", written, "acked", last.acked)
			return true
		}
		t := time.NewTimer(wait)
		select {
		case <-s.done:
			t.Stop()
			Reset(c)
			return false
		case <-t.C:
		}
		wait = min(2*wait, 100*time.Millisecond)
		var p progress
		if p, ok = sendProgress(c); ok && p != last {
			stalled = time.Now()
		}
		last = p
	}
	return true
}

// dialFrom is the default DialDirect. Binding to the application's source
// address keeps the interface it chose (strong host model; the port is
// picked by the system). If the address is gone, the dial fails and the
// connection is reset rather than sent from another address.
func dialFrom(ctx context.Context, src netip.Addr, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	if src.IsValid() && !src.IsUnspecified() {
		d.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(src, 0))
	}
	return d.DialContext(ctx, "tcp", dst.String())
}

// proxyRequest reports an HTTP request to a forward proxy: CONNECT, or an
// absolute-form target such as "GET http://site/ HTTP/1.1".
func proxyRequest(head []byte) bool {
	line, _, _ := bytes.Cut(head, []byte("\r\n"))
	method, rest, _ := bytes.Cut(line, []byte(" "))
	target, _, _ := bytes.Cut(rest, []byte(" "))
	if string(method) == "CONNECT" {
		return true
	}
	return len(target) > 0 && target[0] != '/' && bytes.Contains(target, []byte("://"))
}

// sniff reads the first bytes until a name is found, the protocol is
// clearly not TLS/HTTP, or the timeout expires.
func (s *Server) sniff(c net.Conn, e *nat.Entry) (head []byte, host string, src rules.DomainSource, stage string) {
	timeout := s.SniffTimeout
	if timeout == 0 {
		timeout = 800 * time.Millisecond
	}
	sf := s.ServerFirstPorts
	if sf == nil {
		sf = DefaultServerFirstPorts
	}
	if sf[e.Flow.Dst.Port()] {
		timeout = s.ServerFirstTimeout
		if timeout == 0 {
			timeout = 150 * time.Millisecond
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	stage = "sniff"
	for len(buf) < sniff.MaxTLS {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		r := sniff.Parse(buf)
		if r.Done {
			switch {
			case r.Host == "":
			case r.Kind == sniff.TLS && r.ECH:
				host, src = r.Host, rules.SrcECH
			case r.Kind == sniff.TLS:
				host, src = r.Host, rules.SrcSNI
			case r.Kind == sniff.HTTP:
				host, src = r.Host, rules.SrcHost
			}
			return buf, host, src, stage
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				stage = "sniff-timeout"
			}
			return buf, "", rules.SrcNone, stage
		}
	}
	return buf, "", rules.SrcNone, stage
}

func (s *Server) setOutcome(e *nat.Entry, o string) {
	if e.Rec != nil {
		e.Rec.Set(func(f *flows.Fields) { f.Outcome = o })
	}
}

func (s *Server) reject(c net.Conn, res *Result, reason string, err error) {
	s.Rejected.Add(1)
	res.Route, res.Reason, res.Err = "rejected", reason, err
	s.setOutcome(res.Entry, "rst: "+reason)
	s.Log.Info("relay: tunnel connection rejected", "dst", res.Entry.Flow.Dst, "profile", res.Profile, "reason", reason, "err", err)
	Reset(c)
}

// Reset closes c with RST instead of FIN so the application fails fast.
func Reset(c net.Conn) { socks5.Abort(c) }

// appConn is the application side of a relayed connection. It counts
// application bytes into the flow record as they pass (reads from the app
// are "sent", writes to the app are "received") and delays its shutdown
// until the application has acknowledged them (see settle).
type appConn struct {
	net.Conn
	s       *Server
	rec     *flows.Record // nil: not recorded
	written int64         // by the one goroutine that writes
}

func (c *appConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.rec != nil {
		c.rec.Sent.Add(int64(n))
	}
	return n, err
}

func (c *appConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.written += int64(n)
	if c.rec != nil {
		c.rec.Recv.Add(int64(n))
	}
	return n, err
}

func (c *appConn) CloseWrite() error {
	if !c.s.settle(c.Conn, c.written) {
		return net.ErrClosed
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// NetConn returns the wrapped connection (socks5.Abort resets through it).
func (c *appConn) NetConn() net.Conn { return c.Conn }

// dialRoute opens the upstream of e for action (Direct or Tunnel; Block is
// the caller's): Direct from the application's address, Tunnel through
// profile's Hysteria (remoteName: the name the tunnel may resolve instead
// of the address), never direct. The dial is bounded by DialTimeout and
// canceled by Abort. The Direct and Tunnel counters are kept here; fail
// says why a dial failed ("direct dial failed", "tunnel unavailable",
// "socks5 connect failed").
func (s *Server) dialRoute(parent context.Context, e *nat.Entry, action rules.Action, profile, remoteName string) (up net.Conn, tun Tunnel, fail string, err error) {
	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	// Abort cancels the dial: Close must not wait for a dead upstream.
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if action == rules.Direct {
		dial := s.DialDirect
		if dial == nil {
			dial = dialFrom
		}
		up, err = dial(ctx, e.Flow.Src.Addr(), e.Flow.Dst)
		if err != nil {
			return nil, nil, "direct dial failed", err
		}
		s.Direct.Add(1)
		return up, nil, "", nil
	}
	if s.Tunnel != nil {
		tun = s.Tunnel(profile)
	}
	if tun == nil || !tun.Available() {
		if cnt, ok := tun.(Counting); ok {
			cnt.NoteRejected()
		}
		return nil, tun, "tunnel unavailable", errTunnelUnavailable
	}
	dst := socks5.AddrFromAddrPort(e.Flow.Dst)
	if remoteName != "" && s.PreferRemoteDNS {
		dst.Host = remoteName // name from SNI/Host only
	}
	up, err = tun.Dial(ctx, dst)
	if err != nil {
		if cnt, ok := tun.(Counting); ok {
			cnt.NoteRejected()
		}
		return nil, tun, "socks5 connect failed", err
	}
	s.Tunneled.Add(1)
	return up, tun, "", nil
}

var (
	errTunnelUnavailable = errors.New("relay: tunnel unavailable")
	errPassBlocked       = errors.New("relay: blocked")
)

// serveDNS hands a DNS entry's connection to ServeDNS (dns) with the dial
// for queries passed on unchanged. Upstreams it opened are tracked (Abort
// and AbortWhere reset them) and closed when it returns; res.Route is the
// last route used ("" when nothing was passed on).
func (s *Server) serveDNS(c net.Conn, e *nat.Entry, res *Result) {
	res.Stage = "dns"
	if s.ServeDNS == nil {
		Reset(c)
		return
	}
	var ups []net.Conn
	defer func() {
		for _, up := range ups {
			s.track(up, false)
			up.Close()
		}
	}()
	pass := func(ctx context.Context, r rules.Result) (net.Conn, error) {
		if r.Action == rules.Block {
			return nil, errPassBlocked
		}
		up, _, fail, err := s.dialRoute(ctx, e, r.Action, r.Profile, "")
		if err != nil {
			if r.Action != rules.Direct {
				s.Rejected.Add(1)
			}
			s.Log.Debug("relay: DNS pass-through dial failed", "route", r.Action.String(), "reason", fail, "err", err)
			return nil, err
		}
		if !s.track(up, true) {
			Reset(up)
			return nil, net.ErrClosed
		}
		s.setEntry(up, e)
		ups = append(ups, up)
		res.Route, res.Profile = r.Action.String(), r.Profile
		return up, nil
	}
	s.ServeDNS(s.ctx, e, c, pass)
	c.Close()
}
