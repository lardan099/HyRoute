package dnsproxy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/dnspolicy"
)

// fakeClient answers from reply (nil: a good answer) and counts calls.
type fakeClient struct {
	t      *testing.T
	calls  atomic.Int32
	closed atomic.Bool
	mu     sync.Mutex
	err    error
	rcode  dnsmessage.RCode // answer with this rcode (and no records) when not 0
	block  chan struct{}
}

func (f *fakeClient) Exchange(ctx context.Context, b []byte) ([]byte, error) {
	f.calls.Add(1)
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	err, rcode := f.err, f.rcode
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if rcode != 0 {
		q, _ := ParseQuery(b)
		return answer(f.t, q, rcode, nil, nil, 0, false), nil
	}
	return upAnswer(f.t, b), nil
}

func (f *fakeClient) Close() { f.closed.Store(true) }

func (f *fakeClient) fail(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

type rig struct {
	r       *Resolver
	mu      sync.Mutex
	clients map[string]*fakeClient // by spec host
	up      map[string]bool        // tunnels up
	now     time.Time
	logs    *strings.Builder
}

func newRig(t *testing.T) *rig {
	g := &rig{clients: map[string]*fakeClient{}, up: map[string]bool{"de": true, "nl": true}, now: time.Unix(1000, 0), logs: &strings.Builder{}}
	g.r = &Resolver{
		TunnelDial: func(p string) Dialer {
			g.mu.Lock()
			defer g.mu.Unlock()
			if !g.up[p] {
				return nil
			}
			return func(context.Context, string, uint16) (net.Conn, error) { return nil, errors.New("not used") }
		},
		Now: func() time.Time { g.mu.Lock(); defer g.mu.Unlock(); return g.now },
		NewClient: func(s dnspolicy.Spec, _ Dialer) Client {
			g.mu.Lock()
			defer g.mu.Unlock()
			c := &fakeClient{t: t}
			g.clients[s.Host+"#"+string(rune('0'+len(g.clients)))] = c
			return c
		},
		Log:  slog.New(slog.NewTextHandler(g.logs, nil)),
		Name: func(p string) string { return "Server " + strings.ToUpper(p) },
	}
	return g
}

func (g *rig) advance(d time.Duration) { g.mu.Lock(); g.now = g.now.Add(d); g.mu.Unlock() }

func (g *rig) all() []*fakeClient {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []*fakeClient
	for _, c := range g.clients {
		out = append(out, c)
	}
	return out
}

var (
	tunSpec = dnspolicy.Spec{Scheme: "https", Host: "cloudflare-dns.com", Port: 443, Path: "/dns-query"}
	dirSpec = dnspolicy.Spec{Scheme: "tls", Host: "dns.quad9.net", Port: 853}
)

func TestResolver(t *testing.T) {
	g := newRig(t)
	r := g.r
	q := mustQuery(t, query(t, "a.example.", dnsmessage.TypeA, 0, false))
	ctx := context.Background()
	if _, _, err := r.Exchange(ctx, dnspolicy.ViaTunnel, "de", q); !errors.Is(err, errNoUpstream) {
		t.Fatalf("unconfigured: %v", err)
	}
	r.Configure(tunSpec, &dirSpec)
	if _, _, err := r.Exchange(ctx, dnspolicy.ViaTunnel, "de", q); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Exchange(ctx, dnspolicy.ViaTunnel, "nl", q); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Exchange(ctx, dnspolicy.ViaDirect, "ignored", q); err != nil {
		t.Fatal(err)
	}
	if n := len(g.all()); n != 3 {
		t.Fatalf("%d clients, want one per tunnel profile and one direct", n)
	}
	// Cached: no new call, age grows.
	g.advance(5 * time.Second)
	calls := func() (n int32) {
		for _, c := range g.all() {
			n += c.calls.Load()
		}
		return
	}
	before := calls()
	if _, age, err := r.Exchange(ctx, dnspolicy.ViaTunnel, "de", q); err != nil || age != 5*time.Second {
		t.Fatalf("cache: %v %v", age, err)
	}
	if calls() != before {
		t.Fatal("cache missed")
	}
	// A tunnel that does not run: ErrTunnelDown without I/O.
	g.mu.Lock()
	g.up["de"] = false
	g.mu.Unlock()
	q2 := mustQuery(t, query(t, "b.example.", dnsmessage.TypeA, 0, false))
	if _, _, err := r.Exchange(ctx, dnspolicy.ViaTunnel, "de", q2); !errors.Is(err, ErrTunnelDown) {
		t.Fatalf("tunnel down: %v", err)
	}
	if calls() != before {
		t.Fatal("I/O for a tunnel that is down")
	}
	// Configure: the same specs keep clients and cache; a change closes
	// the old clients and clears the cache.
	r.Configure(tunSpec, &dirSpec)
	if r.cache.len() == 0 {
		t.Fatal("unchanged Configure cleared the cache")
	}
	other := dirSpec
	other.Host = "dns.google"
	r.Configure(tunSpec, &other)
	if r.cache.len() != 0 {
		t.Fatal("cache kept over a change")
	}
	closed := 0
	for _, c := range g.all() {
		if c.closed.Load() {
			closed++
		}
	}
	if closed != 1 {
		t.Fatalf("%d clients closed, want the direct one", closed)
	}
	// Retain closes the clients of profiles that stopped.
	r.Retain([]string{"de"})
	r.mu.Lock()
	_, nl := r.clients[tunnelKeyOf+"nl"]
	_, de := r.clients[tunnelKeyOf+"de"]
	r.mu.Unlock()
	if nl || !de {
		t.Fatalf("retain: nl %v de %v", nl, de)
	}
	// Off.
	r.Configure(dnspolicy.Spec{}, nil)
	if _, _, err := r.Exchange(ctx, dnspolicy.ViaDirect, "", q); !errors.Is(err, errNoUpstream) {
		t.Fatalf("off: %v", err)
	}
	r.Close()
}

func TestHealth(t *testing.T) {
	g := newRig(t)
	r := g.r
	r.Configure(tunSpec, &dirSpec)
	ctx := context.Background()
	names := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	n := 0
	ask := func(via dnspolicy.Via) error {
		n++
		q := mustQuery(t, query(t, names[n%len(names)]+string(rune('a'+n/len(names)))+".example.", dnsmessage.TypeA, 0, false))
		_, _, err := r.Exchange(ctx, via, "de", q)
		return err
	}
	if err := ask(dnspolicy.ViaTunnel); err != nil {
		t.Fatal(err)
	}
	cl := g.all()[0]
	cl.fail(&httpError{503})
	for i := range 3 {
		if err := ask(dnspolicy.ViaTunnel); err == nil || errors.Is(err, ErrUpstreamDown) {
			t.Fatalf("failure %d: %v", i, err)
		}
	}
	hs := r.Health(g.now)
	if len(hs) != 1 || hs[0].Key != "tunnel:de" || hs[0].Profile != "de" || hs[0].Via != dnspolicy.ViaTunnel || hs[0].Kind != "http" || hs[0].Code != 503 ||
		hs[0].RetryAt.Sub(g.now) != 30*time.Second {
		t.Fatalf("health %+v", hs)
	}
	if !strings.Contains(g.logs.String(), "DNS upstream down") || !strings.Contains(g.logs.String(), "Server DE") {
		t.Fatalf("log: %s", g.logs)
	}
	// Down: refused without calling the client.
	before := cl.calls.Load()
	if err := ask(dnspolicy.ViaTunnel); !errors.Is(err, ErrUpstreamDown) {
		t.Fatal(err)
	}
	if cl.calls.Load() != before {
		t.Fatal("client called while down")
	}
	// After RetryAt one trial; concurrent callers are still refused.
	g.advance(30 * time.Second)
	cl.block = make(chan struct{})
	done := make(chan error)
	go func() { done <- ask(dnspolicy.ViaTunnel) }()
	for cl.calls.Load() == before {
		time.Sleep(time.Millisecond)
	}
	if err := ask(dnspolicy.ViaTunnel); !errors.Is(err, ErrUpstreamDown) {
		t.Fatalf("during the trial: %v", err)
	}
	close(cl.block)
	if err := <-done; err == nil {
		t.Fatal("trial succeeded")
	}
	cl.block = nil
	if hs := r.Health(g.now); len(hs) != 1 || hs[0].RetryAt.Sub(g.now) != 60*time.Second {
		t.Fatalf("backoff doubled: %+v", hs)
	}
	g.advance(60 * time.Second)
	ask(dnspolicy.ViaTunnel)
	g.advance(120 * time.Second)
	ask(dnspolicy.ViaTunnel)
	if hs := r.Health(g.now); len(hs) != 1 || hs[0].RetryAt.Sub(g.now) != 120*time.Second {
		t.Fatalf("backoff capped at 120 s: %+v", hs)
	}
	// Success resets.
	g.advance(120 * time.Second)
	cl.fail(nil)
	if err := ask(dnspolicy.ViaTunnel); err != nil {
		t.Fatal(err)
	}
	if hs := r.Health(g.now); len(hs) != 0 {
		t.Fatalf("still down: %+v", hs)
	}
	if !strings.Contains(g.logs.String(), "DNS upstream up") {
		t.Fatal("recovery not logged")
	}
	// ErrTunnelDown and the caller's cancellation do not count.
	cl.fail(ErrTunnelDown)
	for range 5 {
		ask(dnspolicy.ViaTunnel)
	}
	cl.fail(context.Canceled)
	for range 5 {
		ask(dnspolicy.ViaTunnel)
	}
	if hs := r.Health(g.now); len(hs) != 0 {
		t.Fatalf("counted: %+v", hs)
	}
	// The direct client has its own health; the URL is never logged.
	cl.fail(nil)
	ask(dnspolicy.ViaDirect)
	var dc *fakeClient
	for _, c := range g.all() {
		if c != cl {
			dc = c
		}
	}
	dc.fail(io.ErrUnexpectedEOF)
	for range 3 {
		ask(dnspolicy.ViaDirect)
	}
	if hs := r.Health(g.now); len(hs) != 1 || hs[0].Key != "direct" || hs[0].Via != dnspolicy.ViaDirect || hs[0].Kind != "connect" {
		t.Fatalf("direct: %+v", hs)
	}
	if strings.Contains(g.logs.String(), "quad9") || strings.Contains(g.logs.String(), "example") {
		t.Fatalf("names or URLs in the log: %s", g.logs)
	}
}

// An upstream's own error (SERVFAIL, REFUSED, …) fails the query: never
// cached, never given as an answer, for the direct and the tunnel client
// alike. It does not count toward the health: the server answered.
// NXDOMAIN is an answer.
func TestServerRcode(t *testing.T) {
	g := newRig(t)
	r := g.r
	r.Configure(tunSpec, &dirSpec)
	ctx := context.Background()
	n := 0
	ask := func(via dnspolicy.Via) error {
		n++
		q := mustQuery(t, query(t, "n"+string(rune('a'+n))+".example.", dnsmessage.TypeA, 0, false))
		_, _, err := r.Exchange(ctx, via, "de", q)
		return err
	}
	for _, via := range []dnspolicy.Via{dnspolicy.ViaDirect, dnspolicy.ViaTunnel} {
		if err := ask(via); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range g.all() {
		c.mu.Lock()
		c.rcode = dnsmessage.RCodeNameError
		c.mu.Unlock()
	}
	if err := ask(dnspolicy.ViaDirect); err != nil {
		t.Fatalf("NXDOMAIN is an answer: %v", err)
	}
	for i, rc := range []dnsmessage.RCode{dnsmessage.RCodeRefused, dnsmessage.RCodeServerFailure, dnsmessage.RCodeNotImplemented} {
		for _, c := range g.all() {
			c.mu.Lock()
			c.rcode = rc
			c.mu.Unlock()
		}
		for _, via := range []dnspolicy.Via{dnspolicy.ViaDirect, dnspolicy.ViaTunnel} {
			if err := ask(via); !errors.Is(err, errAnswer) {
				t.Fatalf("%v %v #%d: %v", via, rc, i, err)
			}
		}
	}
	if r.cache.len() != 2 {
		t.Fatalf("%d cached, want the 2 good answers (the NXDOMAIN has no SOA: no TTL)", r.cache.len())
	}
	if hs := r.Health(g.now); len(hs) != 0 {
		t.Fatalf("health %+v", hs)
	}
	// Nor do they reset it: two timeouts, a SERVFAIL, a timeout = down.
	cl := g.all()[0]
	var dc *fakeClient
	for _, c := range g.all() {
		c.mu.Lock()
		c.rcode = 0
		c.mu.Unlock()
		if c != cl {
			dc = c
		}
	}
	// Find the direct client: the one a direct query reaches.
	before := cl.calls.Load()
	if err := ask(dnspolicy.ViaDirect); err != nil {
		t.Fatal(err)
	}
	if cl.calls.Load() != before {
		dc = cl
	}
	dc.fail(context.DeadlineExceeded)
	ask(dnspolicy.ViaDirect)
	ask(dnspolicy.ViaDirect)
	dc.fail(nil)
	dc.mu.Lock()
	dc.rcode = dnsmessage.RCodeServerFailure
	dc.mu.Unlock()
	ask(dnspolicy.ViaDirect)
	dc.fail(context.DeadlineExceeded)
	ask(dnspolicy.ViaDirect)
	if hs := r.Health(g.now); len(hs) != 1 || hs[0].Key != "direct" || hs[0].Kind != "timeout" {
		t.Fatalf("health %+v", hs)
	}
}

// brokenNameClient answers SERVFAIL for broken.* and well for the rest.
type brokenNameClient struct{ t *testing.T }

func (b *brokenNameClient) Exchange(ctx context.Context, m []byte) ([]byte, error) {
	q, _ := ParseQuery(m)
	if strings.HasPrefix(q.Name, "broken.") {
		return answer(b.t, q, dnsmessage.RCodeServerFailure, nil, nil, 0, false), nil
	}
	return upAnswer(b.t, m), nil
}

func (b *brokenNameClient) Close() {}

// One name whose name servers are dead: SERVFAIL for the A, AAAA and HTTPS
// queries that Windows sends at once, and for their retransmits. The
// server stays up and other names resolve.
func TestServerRcodeOneName(t *testing.T) {
	g := newRig(t)
	r := g.r
	r.NewClient = func(dnspolicy.Spec, Dialer) Client { return &brokenNameClient{t: t} }
	r.Configure(tunSpec, &dirSpec)
	ctx := context.Background()
	for _, via := range []dnspolicy.Via{dnspolicy.ViaDirect, dnspolicy.ViaTunnel} {
		for range 3 {
			for _, ty := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, 65} {
				q := mustQuery(t, query(t, "broken.example.", ty, 0, false))
				if _, _, err := r.Exchange(ctx, via, "de", q); !errors.Is(err, errServerRcode) {
					t.Fatalf("%v %v: %v", via, ty, err)
				}
			}
		}
		if hs := r.Health(g.now); len(hs) != 0 {
			t.Fatalf("%v: health %+v", via, hs)
		}
		q := mustQuery(t, query(t, "good.example.", dnsmessage.TypeA, 0, false))
		if _, _, err := r.Exchange(ctx, via, "de", q); err != nil {
			t.Fatalf("%v: a good name: %v", via, err)
		}
	}
}

// slowClient holds every query until release is closed, then fails the
// names that start with "fail" (timeout) and answers the rest.
type slowClient struct {
	t       *testing.T
	release chan struct{}
	calls   atomic.Int32
}

func (c *slowClient) Exchange(ctx context.Context, m []byte) ([]byte, error) {
	c.calls.Add(1)
	<-c.release
	q, _ := ParseQuery(m)
	if strings.HasPrefix(q.Name, "fail") {
		return nil, context.DeadlineExceeded
	}
	return upAnswer(c.t, m), nil
}

func (c *slowClient) Close() {}

// Configure while queries are in the client: their results must not panic,
// land in the new cache or count toward the new health, and a query after
// the change does not join a round trip to the old server.
func TestConfigureDuringExchange(t *testing.T) {
	g := newRig(t)
	r := g.r
	old := &slowClient{t: t, release: make(chan struct{})}
	var made atomic.Int32
	r.NewClient = func(dnspolicy.Spec, Dialer) Client {
		if made.Add(1) == 1 {
			return old
		}
		return &fakeClient{t: t}
	}
	r.Configure(tunSpec, &dirSpec)
	ctx := context.Background()
	names := []string{"ok.example.", "fail1.example.", "fail2.example.", "fail3.example."}
	done := make(chan error, len(names))
	for _, n := range names {
		q := mustQuery(t, query(t, n, dnsmessage.TypeA, 0, false))
		go func() {
			defer func() {
				if p := recover(); p != nil {
					done <- fmt.Errorf("panic: %v", p)
				}
			}()
			_, _, err := r.Exchange(ctx, dnspolicy.ViaDirect, "", q)
			if err != nil && !errors.Is(err, context.DeadlineExceeded) {
				err = fmt.Errorf("unexpected: %w", err)
			} else {
				err = nil
			}
			done <- err
		}()
	}
	for old.calls.Load() != int32(len(names)) {
		time.Sleep(5 * time.Millisecond)
	}
	other := dirSpec
	other.Host = "dns.google"
	r.Configure(tunSpec, &other)
	// The new server answers at once, on its own round trip.
	now := make(chan error, 1)
	go func() {
		q := mustQuery(t, query(t, "ok.example.", dnsmessage.TypeA, 0, false))
		_, _, err := r.Exchange(ctx, dnspolicy.ViaDirect, "", q)
		now <- err
	}()
	select {
	case err := <-now:
		if err != nil {
			t.Fatalf("after the change: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the query after the change joined the old round trip")
	}
	r.cache.clear()
	close(old.release)
	for range names {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if hs := r.Health(g.now); len(hs) != 0 {
		t.Fatalf("the old server's failures counted: %+v", hs)
	}
	if n := r.cache.len(); n != 0 {
		t.Fatalf("the old server's answer cached (%d)", n)
	}
	// Turning DNS off with a query in flight.
	old2 := &slowClient{t: t, release: make(chan struct{})}
	made.Store(0)
	old = old2
	r.Configure(dnspolicy.Spec{}, &dirSpec)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- fmt.Errorf("panic: %v", p)
			}
		}()
		q := mustQuery(t, query(t, "fail9.example.", dnsmessage.TypeA, 0, false))
		_, _, err := r.Exchange(ctx, dnspolicy.ViaDirect, "", q)
		if !errors.Is(err, context.DeadlineExceeded) {
			done <- fmt.Errorf("unexpected: %v", err)
			return
		}
		done <- nil
	}()
	for old2.calls.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	r.Configure(dnspolicy.Spec{}, nil)
	close(old2.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestErrKind(t *testing.T) {
	ctx := context.Background()
	dctx, cancel := context.WithTimeout(ctx, -time.Second)
	defer cancel()
	for _, c := range []struct {
		err    error
		ctx    context.Context
		kind   string
		counts bool
	}{
		{ErrTunnelDown, ctx, "", false},
		{&net.OpError{Op: "dial", Err: ErrTunnelDown}, ctx, "", false},
		{context.Canceled, ctx, "", false},
		{context.DeadlineExceeded, dctx, "timeout", true},
		{&net.OpError{Op: "dial", Err: errors.New("refused")}, ctx, "connect", true},
		{&httpError{404}, ctx, "http", true},
		{errAnswer, ctx, "answer", true},
		{errServerRcode, ctx, "", false},
		{x509.UnknownAuthorityError{}, ctx, "tls", true},
		{errors.New("socks5: connect failed"), ctx, "connect", true},
	} {
		kind, _, counts := errKind(c.ctx, c.err)
		if kind != c.kind || counts != c.counts {
			t.Errorf("%v: %s %v", c.err, kind, counts)
		}
	}
}
