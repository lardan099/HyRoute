package groups

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// Dialer opens a connection to dst through member's SOCKS5 only (never
// direct, and not through the routing endpoint's Dial: probes must not
// feed error streaks).
type Dialer func(ctx context.Context, member string, dst socks5.Addr) (net.Conn, error)

// ErrCanceled: the probe was cut by its caller (a disconnect, the budget of
// a group check). It is never noted: a probe cut short is no failure.
var ErrCanceled = errors.New("проверка прервана")

// ErrNotRunning: the member does not run or is not connected now (a
// Dialer's answer). Nothing was sent, so it is no result either: a server
// outage must not read as a broken probe address.
var ErrNotRunning = errors.New("сервер не подключён")

// Test hooks.
var (
	probeTimeout = ProbeTimeout
	probeTick    = 5 * time.Second
)

// Prober measures the latency of the running members of the used groups.
type Prober struct {
	RT   *Runtime
	Dial Dialer
	// Targets are the members to probe (members of used groups that run
	// now) and the probe settings.
	Targets func() ([]string, Probe)
	TLS     *tls.Config // nil = system roots (tests inject)
	Workers int         // default 8
	Log     *slog.Logger
}

// Run probes every probeTick whatever is due (DueProbes), at most Workers
// at once, until ctx ends; then it waits for the probes in flight, whose
// results are dropped.
func (p *Prober) Run(ctx context.Context) {
	workers := p.Workers
	if workers <= 0 {
		workers = 8
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	inflight := map[string]bool{}
	defer wg.Wait()
	t := time.NewTicker(probeTick)
	defer t.Stop()
	for {
		members, probe := p.Targets()
		rawURL, every := probe.Effective()
		for _, m := range p.RT.DueProbes(members, every) {
			mu.Lock()
			busy := inflight[m]
			inflight[m] = true
			mu.Unlock()
			if busy {
				continue
			}
			// select picks at random among ready cases: a free slot must
			// not start a probe after Run was cancelled.
			select {
			case sem <- struct{}{}:
				if ctx.Err() != nil {
					<-sem
					return
				}
			case <-ctx.Done():
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					<-sem
					mu.Lock()
					delete(inflight, m)
					mu.Unlock()
				}()
				defer func() {
					// A probe must never take the engine down.
					if r := recover(); r != nil && p.Log != nil {
						p.Log.Error("server group probe panicked", "panic", r)
					}
				}()
				rtt, err := ProbeOnce(ctx, func(c context.Context, dst socks5.Addr) (net.Conn, error) {
					return p.Dial(c, m, dst)
				}, rawURL, p.TLS)
				if ctx.Err() != nil || errors.Is(err, ErrCanceled) || errors.Is(err, ErrNotRunning) {
					return
				}
				p.RT.NoteProbe(m, rtt, err)
			}()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ProbeOnce requests rawURL (already validated) through dial and returns
// the time from the start of the dial to the first byte of the answer.
// A status 200–399 passes. The answer read is bounded to its 1 KiB status
// line; the whole probe to ProbeTimeout. No redirect is followed, no
// cookie kept, TLS is verified normally. When ctx ends first the result is
// ErrCanceled, whatever the dial or read said.
func ProbeOnce(ctx context.Context, dial func(ctx context.Context, dst socks5.Addr) (net.Conn, error),
	rawURL string, tlsConf *tls.Config) (time.Duration, error) {
	rtt, err := probeOnce(ctx, dial, rawURL, tlsConf)
	if err != nil && ctx.Err() != nil {
		return 0, ErrCanceled
	}
	return rtt, err
}

var errNoAnswer = errors.New("нет ответа за 5 с")

func probeOnce(ctx context.Context, dial func(ctx context.Context, dst socks5.Addr) (net.Conn, error),
	rawURL string, tlsConf *tls.Config) (time.Duration, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return 0, errors.New("неверный адрес проверки")
	}
	host := u.Hostname()
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if ps := u.Port(); ps != "" {
		if port, err = strconv.Atoi(ps); err != nil || port < 1 || port > 65535 {
			return 0, errors.New("неверный порт адреса проверки")
		}
	}
	dst := socks5.Addr{Host: host, Port: uint16(port)} // the name goes to the tunnel: remote DNS
	if a, err := netip.ParseAddr(host); err == nil {
		dst = socks5.Addr{IP: a.Unmap(), Port: uint16(port)}
	}
	t0 := time.Now()
	dctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := dial(dctx, dst)
	if err != nil {
		return 0, probeErr(dctx, err)
	}
	defer conn.Close()
	conn.SetDeadline(t0.Add(probeTimeout))
	stop := context.AfterFunc(dctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	var rw io.ReadWriter = conn
	if u.Scheme == "https" {
		cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if tlsConf != nil {
			cfg.RootCAs = tlsConf.RootCAs
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			return 0, probeErr(dctx, fmt.Errorf("TLS: %w", err))
		}
		rw = tc
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\nHost: " + u.Host + "\r\nUser-Agent: HyRoute\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(rw, req); err != nil {
		return 0, probeErr(dctx, err)
	}
	br := bufio.NewReaderSize(io.LimitReader(rw, 1024), 1024)
	first, err := br.ReadByte()
	if err != nil {
		return 0, probeErr(dctx, err)
	}
	rtt := time.Since(t0)
	line, err := br.ReadString('\n')
	if err != nil {
		if e := probeErr(dctx, err); e == errNoAnswer {
			return 0, e
		}
		return 0, errors.New("неверный ответ")
	}
	code, ok := statusCode(string(first) + line)
	switch {
	case !ok:
		return 0, errors.New("неверный ответ")
	case code < 200 || code > 399:
		return 0, fmt.Errorf("HTTP %d", code)
	}
	return rtt, nil
}

// probeErr turns a timeout into «нет ответа за 5 с».
func probeErr(ctx context.Context, err error) error {
	var ne net.Error
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return errNoAnswer
	}
	return err
}

// statusCode reads "HTTP/1.x NNN reason".
func statusCode(line string) (int, bool) {
	proto, rest, ok := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
	if !ok || !strings.HasPrefix(proto, "HTTP/") {
		return 0, false
	}
	c, _, _ := strings.Cut(rest, " ")
	n, err := strconv.Atoi(c)
	if err != nil || len(c) != 3 {
		return 0, false
	}
	return n, true
}
