package dnsproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/dnspolicy"
)

// Health is an upstream client that is down: it failed failLimit times in
// a row. Queries then fail at once (ErrUpstreamDown) until RetryAt, when
// one query goes through as a trial.
type Health struct {
	Via     dnspolicy.Via `json:"-"`
	Key     string        `json:"key"`               // "direct" | "tunnel:<profile>"
	Profile string        `json:"profile,omitempty"` // tunnel only
	Kind    string        `json:"kind"`              // last failure: timeout | connect | tls | http | answer
	Code    int           `json:"code,omitempty"`    // HTTP status for kind "http"
	RetryAt time.Time     `json:"retryAt"`
}

const (
	failLimit   = 3
	backoffMin  = 30 * time.Second
	backoffMax  = 120 * time.Second
	directKey   = "direct"
	tunnelKeyOf = "tunnel:"
)

// health is one client's state (under Resolver.mu).
type health struct {
	fails   int
	down    bool
	trial   bool // a trial query is under way
	backoff time.Duration
	retryAt time.Time
	kind    string
	code    int
}

// errKind classifies a client failure; counts is false for failures that
// are not the upstream's (the tunnel is down, the caller gave up) and for
// the upstream's own error answers (errServerRcode): SERVFAIL is usually
// about one name (dead or lame name servers, DNSSEC-bogus) and REFUSED or
// NOTIMP about one query type, and Windows and browsers ask A, AAAA and
// HTTPS for a name at once, so counting them would mark a working server
// down for one broken name. The server answered, so they do not reset the
// count either.
func errKind(ctx context.Context, err error) (kind string, code int, counts bool) {
	if errors.Is(err, ErrTunnelDown) || errors.Is(err, errServerRcode) {
		return "", 0, false
	}
	if errors.Is(err, context.Canceled) && (ctx == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return "", 0, false
	}
	var he *httpError
	if errors.As(err, &he) {
		return "http", he.code, true
	}
	if errors.Is(err, errAnswer) {
		return "answer", 0, true
	}
	var (
		rh  tls.RecordHeaderError
		ae  tls.AlertError
		cv  *tls.CertificateVerificationError
		ua  x509.UnknownAuthorityError
		hn  x509.HostnameError
		ci  x509.CertificateInvalidError
		ne  net.Error
		ope *net.OpError
	)
	switch {
	case errors.As(err, &rh), errors.As(err, &ae), errors.As(err, &cv), errors.As(err, &ua), errors.As(err, &hn), errors.As(err, &ci):
		return "tls", 0, true
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout", 0, true
	case errors.As(err, &ope) && ope.Op == "dial":
		return "connect", 0, true
	}
	return "connect", 0, true
}

// gateLocked says whether a query may go to the client key now; trial:
// it is the one query let through after RetryAt.
func (r *Resolver) gateLocked(key string, now time.Time) (trial bool, err error) {
	h := r.health[key]
	if h == nil || !h.down {
		return false, nil
	}
	if now.Before(h.retryAt) || h.trial {
		return false, ErrUpstreamDown
	}
	h.trial = true
	return true, nil
}

// report records the result of a query to the client key, sent when the
// resolver's generation was gen (a later Configure has reset the health:
// the result is dropped).
func (r *Resolver) report(ctx context.Context, gen uint64, key string, via dnspolicy.Via, profile string, err error, trial bool) {
	now := r.now()
	r.mu.Lock()
	if r.gen != gen {
		r.mu.Unlock()
		return
	}
	h := r.health[key]
	if h == nil {
		h = &health{backoff: backoffMin}
		if r.health == nil {
			r.health = map[string]*health{}
		}
		r.health[key] = h
	}
	var up, down bool
	var retryIn time.Duration
	switch kind, code, counts := errKind(ctx, err); {
	case err == nil:
		up = h.down
		*h = health{backoff: backoffMin}
	case !counts:
		if trial {
			h.trial = false // another query may try
		}
	default:
		h.fails++
		h.kind, h.code = kind, code
		switch {
		case h.down && trial:
			h.backoff = min(2*h.backoff, backoffMax)
			h.retryAt, h.trial = now.Add(h.backoff), false
		case !h.down && h.fails >= failLimit:
			h.down, h.backoff = true, backoffMin
			h.retryAt = now.Add(h.backoff)
			down = true
		}
		retryIn = h.retryAt.Sub(now)
	}
	kind, code := h.kind, h.code
	r.mu.Unlock()
	name := profile
	if r.Name != nil && profile != "" {
		name = r.Name(profile)
	}
	if down && r.Log != nil {
		r.Log.Warn("DNS upstream down", "via", via.String(), "profile", name, "kind", kind, "code", code, "retryIn", retryIn.Round(time.Second))
	}
	if up && r.Log != nil {
		r.Log.Info("DNS upstream up", "via", via.String(), "profile", name)
	}
}

// Health lists the clients that are down, sorted by key. RetryAt may be
// in the past while a trial is under way.
func (r *Resolver) Health(now time.Time) []Health {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Health
	for key, h := range r.health {
		if !h.down {
			continue
		}
		v := Health{Via: dnspolicy.ViaDirect, Key: key, Kind: h.kind, Code: h.code, RetryAt: h.retryAt}
		if p, ok := cutTunnel(key); ok {
			v.Via, v.Profile = dnspolicy.ViaTunnel, p
		}
		out = append(out, v)
	}
	sortHealth(out)
	return out
}

func cutTunnel(key string) (string, bool) { return strings.CutPrefix(key, tunnelKeyOf) }

func sortHealth(hs []Health) {
	slices.SortFunc(hs, func(a, b Health) int { return strings.Compare(a.Key, b.Key) })
}
