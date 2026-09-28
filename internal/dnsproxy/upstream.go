package dnsproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/dnspolicy"
)

// Dialer opens a TCP connection to host:port. A tunnel dialer sends host
// as a SOCKS5 domain when it is not an IP.
type Dialer func(ctx context.Context, host string, port uint16) (net.Conn, error)

// Client exchanges one DNS message with an upstream server.
type Client interface {
	Exchange(ctx context.Context, q []byte) ([]byte, error)
	Close()
}

const (
	exchangeTimeout  = 5 * time.Second
	bootstrapTimeout = 2 * time.Second
	maxDoHBody       = 64 << 10
	streamIdle       = 30 * time.Second
	streamPool       = 2
)

// httpError: the DoH server answered, but not with a DNS message.
type httpError struct{ code int }

func (e *httpError) Error() string { return fmt.Sprintf("dns: DoH server answered HTTP %d", e.code) }

// NewClient returns the client for s. roots nil = the system roots (tests
// pass their own).
func NewClient(s dnspolicy.Spec, dial Dialer, roots *x509.CertPool) Client {
	d := bootstrapDialer(s, dial)
	tc := &tls.Config{ServerName: s.Host, RootCAs: roots, MinVersion: tls.VersionTLS12}
	switch s.Scheme {
	case "https":
		return newDoH(s, d, tc)
	case "tls":
		return &streamClient{dial: d, tls: tc}
	}
	return &streamClient{dial: d}
}

// bootstrapDialer dials s's bootstrap addresses in order (2 s each), or
// its host when it has none.
func bootstrapDialer(s dnspolicy.Spec, dial Dialer) func(ctx context.Context) (net.Conn, error) {
	return func(ctx context.Context) (net.Conn, error) {
		if len(s.Bootstrap) == 0 {
			return dial(ctx, s.Host, s.Port)
		}
		var last error
		for _, a := range s.Bootstrap {
			c, cancel := context.WithTimeout(ctx, bootstrapTimeout)
			conn, err := dial(c, a.String(), s.Port)
			cancel()
			if err == nil {
				return conn, nil
			}
			last = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, last
	}
}

// ---- DoH ----

type dohClient struct {
	url string
	tr  *http.Transport
	cl  *http.Client
}

func newDoH(s dnspolicy.Spec, dial func(context.Context) (net.Conn, error), tc *tls.Config) *dohClient {
	tr := &http.Transport{
		Proxy: nil, // never the environment's proxy
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx)
		},
		TLSClientConfig:       tc,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		TLSHandshakeTimeout:   4 * time.Second,
		DisableCompression:    true,
	}
	host := s.Host
	if a, err := netip.ParseAddr(s.Host); err == nil && a.Is6() {
		host = "[" + s.Host + "]"
	}
	u := "https://" + host
	if s.Port != 443 {
		u += ":" + strconv.Itoa(int(s.Port))
	}
	return &dohClient{
		url: u + s.Path,
		tr:  tr,
		cl: &http.Client{Transport: tr, Timeout: exchangeTimeout, Jar: nil,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (d *dohClient) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	b, err := d.once(ctx, q)
	if err != nil && retryable(ctx, err) {
		// A pooled HTTP/2 connection through a restarted Hysteria: once more
		// on a new one.
		d.tr.CloseIdleConnections()
		b, err = d.once(ctx, q)
	}
	return b, err
}

func (d *dohClient) once(ctx context.Context, q []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header["User-Agent"] = []string{""} // no User-Agent at all
	resp, err := d.cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxDoHBody))
		return nil, &httpError{resp.StatusCode}
	}
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt != "application/dns-message" {
		return nil, &httpError{resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDoHBody {
		return nil, errAnswer
	}
	return body, nil
}

func (d *dohClient) Close() { d.tr.CloseIdleConnections() }

// retryable: a connection-level failure the caller's context did not
// cause (not an HTTP status, not a bad answer, not the deadline).
func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	kind, _, counts := errKind(ctx, err)
	return counts && kind == "connect"
}

// ---- DoT and plain TCP ----

// streamClient speaks length-prefixed DNS over TLS (tls set) or plain TCP:
// one query at a time per connection, at most streamPool idle ones.
type streamClient struct {
	dial func(context.Context) (net.Conn, error)
	tls  *tls.Config // nil: plain TCP

	mu     sync.Mutex
	idle   []idleConn
	closed bool
}

type idleConn struct {
	c    net.Conn
	used time.Time
}

func (s *streamClient) get() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.idle) > 0 {
		ic := s.idle[len(s.idle)-1]
		s.idle = s.idle[:len(s.idle)-1]
		if time.Since(ic.used) < streamIdle {
			return ic.c
		}
		ic.c.Close()
	}
	return nil
}

func (s *streamClient) put(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.idle) >= streamPool {
		c.Close()
		return
	}
	s.idle = append(s.idle, idleConn{c, time.Now()})
}

func (s *streamClient) open(ctx context.Context) (net.Conn, error) {
	c, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	if s.tls == nil {
		return c, nil
	}
	tc := tls.Client(c, s.tls)
	hctx, cancel := context.WithTimeout(ctx, exchangeTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

func (s *streamClient) Exchange(ctx context.Context, q []byte) ([]byte, error) {
	if len(q) > maxMessage {
		return nil, errAnswer
	}
	if c := s.get(); c != nil {
		if b, err := s.roundTrip(ctx, c, q); err == nil {
			s.put(c)
			return b, nil
		} else if !retryable(ctx, err) {
			c.Close()
			return nil, err
		}
		c.Close() // a stale pooled connection: once more on a new one
	}
	c, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	b, err := s.roundTrip(ctx, c, q)
	if err != nil {
		c.Close()
		return nil, err
	}
	s.put(c)
	return b, nil
}

func (s *streamClient) roundTrip(ctx context.Context, c net.Conn, q []byte) ([]byte, error) {
	dl := time.Now().Add(exchangeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = c.SetDeadline(dl)
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	buf := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(buf, uint16(len(q)))
	copy(buf[2:], q)
	if _, err := c.Write(buf); err != nil {
		return nil, err
	}
	var n [2]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return b, nil
}

func (s *streamClient) Close() {
	s.mu.Lock()
	idle := s.idle
	s.idle, s.closed = nil, true
	s.mu.Unlock()
	for _, ic := range idle {
		ic.c.Close()
	}
}
