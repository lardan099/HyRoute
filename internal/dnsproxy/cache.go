package dnsproxy

import (
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/dnspolicy"
)

// cacheKey is everything an upstream answer depends on.
type cacheKey struct {
	via     dnspolicy.Via
	profile string
	name    string
	qtype   dnsmessage.Type
	class   dnsmessage.Class
	do, cd  bool
}

func keyOf(via dnspolicy.Via, profile string, q Query) cacheKey {
	return cacheKey{via, profile, q.Name, q.Type, q.Class, q.DO, q.CD}
}

type cacheEntry struct {
	msg []byte
	at  time.Time
	ttl time.Duration
}

func (e *cacheEntry) expires() time.Time { return e.at.Add(e.ttl) }

const (
	cacheMax    = 4096 // entries
	sweepBudget = 1024 // entries one Sweep looks at
)

// cache holds upstream answers (ID 0, as the upstream sent them) for their
// TTL. Its mutex is a leaf.
type cache struct {
	mu sync.Mutex
	m  map[cacheKey]*cacheEntry
}

// get returns a copy of the answer and how long it has been cached.
func (c *cache) get(k cacheKey, now time.Time) ([]byte, time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[k]
	if e == nil {
		return nil, 0, false
	}
	if !now.Before(e.expires()) {
		delete(c.m, k)
		return nil, 0, false
	}
	return append([]byte(nil), e.msg...), now.Sub(e.at), true
}

// put stores msg for its TTL (ttlOf); an answer that may not be cached is
// ignored.
func (c *cache) put(k cacheKey, msg []byte, now time.Time) {
	ttl := ttlOf(msg)
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[cacheKey]*cacheEntry{}
	}
	if _, ok := c.m[k]; !ok && len(c.m) >= cacheMax {
		c.evictLocked(now)
	}
	c.m[k] = &cacheEntry{msg: append([]byte(nil), msg...), at: now, ttl: ttl}
}

// evictLocked makes room for one entry: expired ones among 16 arbitrary
// entries (map order is random), else the earliest-expiring of 8.
func (c *cache) evictLocked(now time.Time) {
	n, freed := 0, false
	for k, e := range c.m {
		if !now.Before(e.expires()) {
			delete(c.m, k)
			freed = true
		}
		if n++; n >= 16 {
			break
		}
	}
	if freed {
		return
	}
	var victim cacheKey
	var exp time.Time
	n = 0
	for k, e := range c.m {
		if n == 0 || e.expires().Before(exp) {
			victim, exp = k, e.expires()
		}
		if n++; n >= 8 {
			break
		}
	}
	delete(c.m, victim)
}

// sweep drops expired entries, looking at no more than sweepBudget.
func (c *cache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, e := range c.m {
		if !now.Before(e.expires()) {
			delete(c.m, k)
		}
		if n++; n >= sweepBudget {
			return
		}
	}
}

func (c *cache) clear() {
	c.mu.Lock()
	c.m = nil
	c.mu.Unlock()
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
