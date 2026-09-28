package dnspolicy

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/rules"
)

// ownNamesMax bounds OwnNames.
const ownNamesMax = 256

// OwnNames are the hosts HyRoute is about to contact itself (subscriptions,
// rule databases, updates): their lookups come from the Windows DNS client
// like anyone's and are passed on as before for a while (Env.Transient).
// The controller owns the set and writes it whether or not a session runs,
// and every session's engine reads it, so a fetch that starts while a
// session is starting is covered from its first packet. The zero value is
// ready; its mutex is a leaf.
type OwnNames struct {
	mu  sync.Mutex
	m   map[string]time.Time // name -> until
	Now func() time.Time     // nil: time.Now (tests set their own)
}

func (o *OwnNames) clock() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// Has reports a registered name (normalized). A nil set has none.
func (o *OwnNames) Has(name string) bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	until, ok := o.m[name]
	if ok && !o.clock().Before(until) {
		delete(o.m, name)
		return false
	}
	return ok
}

// Add registers host (a name, in any case, with or without a trailing dot)
// for ttl. IP literals are ignored. At the cap the expired names go first,
// then the one that expires soonest.
func (o *OwnNames) Add(host string, ttl time.Duration) {
	host = strings.Trim(host, "[]")
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	name := rules.NormalizeDomain(host)
	if name == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.clock()
	if o.m == nil {
		o.m = map[string]time.Time{}
	}
	if _, ok := o.m[name]; !ok && len(o.m) >= ownNamesMax {
		var oldest string
		var at time.Time
		for n, u := range o.m {
			if !now.Before(u) {
				delete(o.m, n)
				continue
			}
			if oldest == "" || u.Before(at) {
				oldest, at = n, u
			}
		}
		if len(o.m) >= ownNamesMax {
			delete(o.m, oldest)
		}
	}
	if u := now.Add(ttl); u.After(o.m[name]) {
		o.m[name] = u
	}
}

// Len is the number of names held, expired ones included (tests).
func (o *OwnNames) Len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.m)
}
