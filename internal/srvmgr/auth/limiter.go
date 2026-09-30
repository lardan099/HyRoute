package auth

import (
	"sync"
	"time"
)

// Limiter counts failures per key (an IP address or a username) in a
// sliding window: after Max failures within Window the key waits until the
// oldest failure leaves the window.
type Limiter struct {
	Max    int
	Window time.Duration

	mu   sync.Mutex
	hits map[string][]time.Time
}

// maxKeys bounds memory: beyond it, keys with nothing in the window are
// dropped.
const maxKeys = 10000

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
	if len(l.hits) >= maxKeys {
		for k := range l.hits {
			if len(l.recent(k, now)) == 0 {
				delete(l.hits, k)
			}
		}
	}
	hs := append(l.recent(key, now), now)
	if len(hs) > l.Max {
		hs = hs[len(hs)-l.Max:]
	}
	l.hits[key] = hs
}

// Reset forgets the failures of key (after a successful login).
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
