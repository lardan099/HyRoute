package dnsproxy

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/dnspolicy"
)

var (
	// ErrTunnelDown: the profile cannot carry the query (not running, not
	// connected). Never passed direct.
	ErrTunnelDown = errors.New("dns: tunnel unavailable")
	// ErrUpstreamDown: the client failed failLimit times in a row and is
	// not asked until its next trial.
	ErrUpstreamDown = errors.New("dns: upstream marked down")
	// errNoUpstream: no server is configured for that way.
	errNoUpstream = errors.New("dns: no upstream configured")
)

// Resolver sends queries to «DNS-сервер для VPN» through a profile's
// tunnel, or to the direct upstream from HyRoute itself, with a cache,
// singleflight and per-client health.
type Resolver struct {
	// TunnelDial returns a dialer through a profile's Hysteria, or nil when
	// the profile is not running or not connected. It is asked on every
	// dial, so a client follows the endpoint's restarts.
	TunnelDial func(profile string) Dialer
	// DirectDial dials from HyRoute (excluded from routing by PID); nil =
	// net.Dialer. A custom server's host name is resolved by Windows: it
	// is one of the names the policy always passes.
	DirectDial Dialer
	Log        *slog.Logger
	// Name is a profile's name for logs (nil: its ID).
	Name func(profile string) string
	// Roots verifies the servers' certificates (nil: the system roots;
	// tests set their own).
	Roots *x509.CertPool
	// Now is the clock (nil: time.Now; tests set their own).
	Now func() time.Time
	// NewClient overrides NewClient (tests).
	NewClient func(s dnspolicy.Spec, dial Dialer) Client

	mu      sync.Mutex // guards the specs, clients, health and gen; never held across I/O; before cache.mu
	tunnel  *dnspolicy.Spec
	direct  *dnspolicy.Spec
	clients map[string]Client // directKey | tunnelKeyOf+profile
	health  map[string]*health
	// gen counts the Configure calls that changed a server. A query records
	// it before its I/O; when it has changed by the time the answer comes,
	// the answer is neither cached nor reported to the (new) health.
	gen    uint64
	cache  cache
	flight flight
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func sameSpec(a, b *dnspolicy.Spec) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Scheme == b.Scheme && a.Host == b.Host && a.Port == b.Port && a.Path == b.Path && slices.Equal(a.Bootstrap, b.Bootstrap)
}

// Configure sets the servers: tunnel with Scheme "" = none (DNS by the
// rules off), direct nil = none. A changed server replaces its clients
// (the old ones are closed), and any change clears the cache and health.
func (r *Resolver) Configure(tunnel dnspolicy.Spec, direct *dnspolicy.Spec) {
	var t *dnspolicy.Spec
	if tunnel.Scheme != "" {
		t = &tunnel
	}
	if direct != nil {
		d := *direct
		direct = &d
	}
	r.mu.Lock()
	var old []Client
	changed := false
	if !sameSpec(r.tunnel, t) {
		for k, c := range r.clients {
			if _, ok := cutTunnel(k); ok {
				old = append(old, c)
				delete(r.clients, k)
			}
		}
		changed = true
	}
	if !sameSpec(r.direct, direct) {
		if c := r.clients[directKey]; c != nil {
			old = append(old, c)
			delete(r.clients, directKey)
		}
		changed = true
	}
	r.tunnel, r.direct = t, direct
	if changed {
		clear(r.health)
		r.gen++
	}
	r.mu.Unlock()
	if changed {
		r.cache.clear()
	}
	for _, c := range old {
		c.Close()
	}
}

// Retain closes the tunnel clients (and forgets the health) of profiles
// not in the list: they no longer run.
func (r *Resolver) Retain(profiles []string) {
	r.mu.Lock()
	var old []Client
	for k, c := range r.clients {
		if p, ok := cutTunnel(k); ok && !slices.Contains(profiles, p) {
			old = append(old, c)
			delete(r.clients, k)
		}
	}
	for k := range r.health {
		if p, ok := cutTunnel(k); ok && !slices.Contains(profiles, p) {
			delete(r.health, k)
		}
	}
	r.mu.Unlock()
	for _, c := range old {
		c.Close()
	}
}

// Close closes every client.
func (r *Resolver) Close() {
	r.mu.Lock()
	old := r.clients
	r.clients = nil
	r.mu.Unlock()
	for _, c := range old {
		c.Close()
	}
}

// Sweep drops expired cache entries.
func (r *Resolver) Sweep(now time.Time) { r.cache.sweep(now) }

// Exchange resolves q directly (via ViaDirect, profile "") or through the
// profile's tunnel. It returns the upstream's answer to UpstreamQuery(q)
// (ID 0; Reply makes it the client's) and how long it was cached. An
// answer with another rcode than NOERROR or NXDOMAIN is a failure of that
// query only (errServerRcode): not cached, and not held against the
// client's health.
func (r *Resolver) Exchange(ctx context.Context, via dnspolicy.Via, profile string, q Query) ([]byte, time.Duration, error) {
	if via == dnspolicy.ViaDirect {
		profile = ""
	}
	key := keyOf(via, profile, q)
	if msg, age, ok := r.cache.get(key, r.now()); ok {
		return msg, age, nil
	}
	ck := directKey
	if via == dnspolicy.ViaTunnel {
		ck = tunnelKeyOf + profile
		if r.TunnelDial == nil || r.TunnelDial(profile) == nil {
			return nil, 0, ErrTunnelDown
		}
	}
	r.mu.Lock()
	if r.health == nil {
		r.health = map[string]*health{}
	}
	spec := r.direct
	if via == dnspolicy.ViaTunnel {
		spec = r.tunnel
	}
	if spec == nil {
		r.mu.Unlock()
		return nil, 0, errNoUpstream
	}
	gen := r.gen
	trial, err := r.gateLocked(ck, r.now())
	cl := r.clientLocked(ck, *spec, via, profile)
	r.mu.Unlock()
	if err != nil {
		return nil, 0, err
	}
	msg, err := r.flight.do(flightKey{key, gen}, func() ([]byte, error) {
		msg, err := cl.Exchange(ctx, UpstreamQuery(q))
		if err == nil {
			if _, _, rerr := Reply(q, msg, ReplyOpts{Max: maxMessage}); rerr != nil {
				err = rerr
			} else if serverError(msg) {
				err = errServerRcode
			}
		}
		r.report(ctx, gen, ck, via, profile, err, trial)
		if err == nil {
			r.mu.Lock()
			if r.gen == gen { // else Configure has cleared the cache since
				r.cache.put(key, msg, r.now())
			}
			r.mu.Unlock()
		}
		return msg, err
	})
	if err != nil {
		return nil, 0, err
	}
	return msg, 0, nil
}

// clientLocked returns the client of key, created on first use.
func (r *Resolver) clientLocked(key string, s dnspolicy.Spec, via dnspolicy.Via, profile string) Client {
	if c := r.clients[key]; c != nil {
		return c
	}
	var dial Dialer
	if via == dnspolicy.ViaTunnel {
		dial = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			var d Dialer
			if r.TunnelDial != nil {
				d = r.TunnelDial(profile)
			}
			if d == nil {
				return nil, ErrTunnelDown
			}
			return d(ctx, host, port)
		}
	} else if r.DirectDial != nil {
		dial = r.DirectDial
	} else {
		dial = func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		}
	}
	var c Client
	if r.NewClient != nil {
		c = r.NewClient(s, dial)
	} else {
		c = NewClient(s, dial, r.Roots)
	}
	if r.clients == nil {
		r.clients = map[string]Client{}
	}
	r.clients[key] = c
	return c
}
