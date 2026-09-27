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

	Counters

	port   uint16
	lns    []net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
	done   chan struct{}
	ctx    context.Context // canceled by Abort: interrupts pending dials
	cancel context.CancelFunc
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
	s.conns = make(map[net.Conn]struct{})
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
			s.Log.Error("relay accept failed", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
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
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	return true
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

	var client net.Conn = c
	if e.Rec != nil {
		client = &countingConn{Conn: c, rec: e.Rec}
	}
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
		action, profile, res.Rule, res.Domain, res.DomainSrc = d.Action, d.Profile, d.Rule, d.Domain, d.DomainSrc
		if e.Rec != nil {
			e.Rec.Set(func(f *flows.Fields) {
				f.Rule, f.Route, f.Profile, f.Stage = d.Rule, d.Action.String(), d.Profile, res.Stage
				if d.Domain != "" {
					f.Domain, f.DomainSrc = d.Domain, d.DomainSrc.String()
				}
			})
		}
	}

	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	// Abort cancels the dial: Close must not wait for a dead upstream.
	ctx, cancel := context.WithTimeout(s.ctx, timeout)
	var up net.Conn
	var err error
	switch action {
	case rules.Block:
		cancel()
		s.Blocked.Add(1)
		res.Route = "block"
		s.setOutcome(e, "rst: blocked")
		Reset(c)
		return
	case rules.Direct:
		dial := s.DialDirect
		if dial == nil {
			dial = dialFrom
		}
		up, err = dial(ctx, e.Flow.Src.Addr(), e.Flow.Dst)
		cancel()
		if err != nil {
			res.Route, res.Err = "direct", err
			s.setOutcome(e, "rst: direct dial failed")
			Reset(c)
			return
		}
		s.Direct.Add(1)
		res.Route = "direct"
	default:
		res.Profile = profile
		var tun Tunnel
		if s.Tunnel != nil {
			tun = s.Tunnel(profile)
		}
		if tun == nil || !tun.Available() {
			cancel()
			if cnt, ok := tun.(Counting); ok {
				cnt.NoteRejected()
			}
			s.reject(c, &res, "tunnel unavailable", nil)
			return
		}
		dst := socks5.AddrFromAddrPort(e.Flow.Dst)
		if remoteName != "" && s.PreferRemoteDNS {
			dst.Host = remoteName // name from SNI/Host only
		}
		up, err = tun.Dial(ctx, dst)
		cancel()
		if err != nil {
			if cnt, ok := tun.(Counting); ok {
				cnt.NoteRejected()
			}
			s.reject(c, &res, "socks5 connect failed", err)
			return
		}
		s.Tunneled.Add(1)
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
	// half-closed socket that outlives the NAT entry.
	res.Sent, res.Recv = socks5.Pipe(client, up)
	res.Sent += int64(len(head))
	c.Close()
	up.Close()
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

// countingConn counts application bytes into the flow record as they pass:
// reads from the app are "sent", writes to the app are "received".
type countingConn struct {
	net.Conn
	rec *flows.Record
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.rec.Sent.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.rec.Recv.Add(int64(n))
	return n, err
}

func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// NetConn returns the wrapped connection (socks5.Abort resets through it).
func (c *countingConn) NetConn() net.Conn { return c.Conn }
