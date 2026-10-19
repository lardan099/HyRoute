package auth

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Limiter counts attempts per key (a client address, a user name) in a
// sliding window: after Max of them within Window the key waits until the
// oldest of the last Max leaves the window.
type Limiter struct {
	Max    int
	Window time.Duration

	mu    sync.Mutex
	hits  map[string][]time.Time
	sweep int // key count that triggers the next sweep of idle keys
}

// maxKeys bounds memory: from this many keys on, keys with nothing in the
// window are dropped. A sweep that leaves most keys alive puts the next one
// off until the map doubles, so a flood of keys does not sweep on every
// attempt.
const maxKeys = 10000

// maxPerKey bounds the attempts kept for one key (the newest stay). Only a
// user name under attack collects more than Max of them, see guard.
const maxPerKey = 64

// Wait is how long key must wait before the next attempt; 0 = go ahead.
func (l *Limiter) Wait(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	hs := l.recent(key, now)
	if len(hs) < l.Max {
		return 0
	}
	return hs[len(hs)-l.Max].Add(l.Window).Sub(now)
}

// Fail records a failed attempt of key.
func (l *Limiter) Fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	if len(l.hits) >= max(maxKeys, l.sweep) {
		for k := range l.hits {
			l.recent(k, now)
		}
		l.sweep = 2 * len(l.hits)
	}
	hs := append(l.recent(key, now), now)
	if keep := max(l.Max, maxPerKey); len(hs) > keep {
		hs = hs[len(hs)-keep:]
	}
	l.hits[key] = hs
}

// Forgive drops one attempt of key recorded at at: a reserved attempt that
// had the right password or never checked one. Nothing happens when it
// has left the window or was pushed out by newer ones.
func (l *Limiter) Forgive(key string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	hs := l.hits[key]
	for i := len(hs) - 1; i >= 0; i-- {
		if hs[i].Equal(at) {
			hs = slices.Delete(hs, i, i+1)
			break
		}
	}
	if len(hs) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = hs
	}
}

// Reset forgets the failures of key.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.hits, key)
	l.mu.Unlock()
}

// recent drops the failures of key that left the window. l.mu is held.
func (l *Limiter) recent(key string, now time.Time) []time.Time {
	hs := l.hits[key]
	i := 0
	for i < len(hs) && !hs[i].Add(l.Window).After(now) {
		i++
	}
	hs = hs[i:]
	if len(hs) == 0 {
		delete(l.hits, key)
	} else {
		l.hits[key] = hs
	}
	return hs
}

// guard is the rate limit of logins and of the setup token.
//
// An attempt is recorded as failed before its password is hashed, and the
// check and the record happen under one lock: concurrent attempts see each
// other, so a burst cannot pass the check before any of them fails. The
// attempt is forgiven when the password was right or was not checked at
// all (no free hashing slot, a database error).
//
// Limits:
//   - an address (an IPv6 client: its /64, the usual size of one
//     subscriber's network) has 20 attempts in 15 minutes, for any names;
//   - 5 failures for a user name in 5 minutes put the name under attack.
//     It then stays open only to addresses without failures of their own
//     for it in that window, so a fresh address gets one attempt at a
//     time. A guesser who failed waits, while the owner logs in from an
//     address that has not failed. A plain block of the name would let
//     anybody lock the owner out with one wrong password a minute; the
//     price is that guessing from many addresses gets one more try per
//     fresh address and window, within the limit of each address.
type guard struct {
	mu       sync.Mutex
	addr     *Limiter
	name     *Limiter
	nameAddr *Limiter // Max 1: waits while the address has a failure for the name
}

func newGuard() *guard {
	return &guard{
		addr:     &Limiter{Max: 20, Window: 15 * time.Minute},
		name:     &Limiter{Max: 5, Window: 5 * time.Minute},
		nameAddr: &Limiter{Max: 1, Window: 5 * time.Minute},
	}
}

// attempt is a reserved attempt: it counts as failed until forgiven.
type attempt struct {
	at                   time.Time
	addr, name, nameAddr string
}

// reserve checks the limits of an attempt from addr (see addrKey) for name
// ("" for the setup token, limited by address only) and records it as
// failed; now is read under the lock, so the records stay in time order.
func (g *guard) reserve(now func() time.Time, name, addr string) (attempt, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := attempt{at: now(), addr: addr}
	wait := g.addr.Wait(addr, a.at)
	if name != "" {
		a.name, a.nameAddr = name, name+" "+addr
		if w := g.name.Wait(a.name, a.at); w > 0 {
			// Under attack: open to an address without its own failures.
			wait = max(wait, min(w, g.nameAddr.Wait(a.nameAddr, a.at)))
		}
	}
	if wait > 0 {
		return attempt{}, &RateLimitedError{wait}
	}
	g.addr.Fail(a.addr, a.at)
	if a.name != "" {
		g.name.Fail(a.name, a.at)
		g.nameAddr.Fail(a.nameAddr, a.at)
	}
	return a, nil
}

// cancel forgives an attempt that did not check a password.
func (g *guard) cancel(a attempt) { g.forgive(a, false) }

// succeeded forgives an attempt with the right password together with the
// earlier failures of its address for the name: the user's own typos must
// not keep them out once the name is under attack. Failures from other
// addresses stay: a login of the owner does not give a guesser new tries.
func (g *guard) succeeded(a attempt) { g.forgive(a, true) }

func (g *guard) forgive(a attempt, own bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.addr.Forgive(a.addr, a.at)
	if a.name == "" {
		return
	}
	g.name.Forgive(a.name, a.at)
	if own {
		g.nameAddr.Reset(a.nameAddr)
	} else {
		g.nameAddr.Forgive(a.nameAddr, a.at)
	}
}

// addrKey is the rate-limit key of a client address: an IPv4 address, or
// the /64 of an IPv6 one (a client gets a whole /64 and can use any address
// in it). Anything else is used as is.
func addrKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}
