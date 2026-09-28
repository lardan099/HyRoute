package dnsproxy

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/dnspolicy"
)

func TestCache(t *testing.T) {
	var c cache
	t0 := time.Unix(1000, 0)
	q := mustQuery(t, query(t, "a.example.", dnsmessage.TypeA, 0, false))
	k := keyOf(dnspolicy.ViaTunnel, "de", q)
	if _, _, ok := c.get(k, t0); ok {
		t.Fatal("hit on an empty cache")
	}
	c.put(k, answer(t, q, dnsmessage.RCodeSuccess, []rr{{"a.example.", dnsmessage.TypeA, 3600, "1.2.3.4"}}, nil, 0, false), t0)
	msg, age, ok := c.get(k, t0.Add(10*time.Second))
	if !ok || age != 10*time.Second || len(msg) == 0 {
		t.Fatalf("hit %v age %v", ok, age)
	}
	msg[0] = 0xff // a copy
	if m, _, _ := c.get(k, t0); m[0] == 0xff {
		t.Fatal("get returned the cached slice")
	}
	if _, _, ok := c.get(k, t0.Add(MaxTunnelTTL*time.Second)); ok {
		t.Fatal("TTL not clamped to 300 s")
	}
	if _, _, ok := c.get(keyOf(dnspolicy.ViaDirect, "", q), t0); ok {
		t.Fatal("the direct key shares the tunnel answer")
	}
	// Negative: SOA min(TTL, MINIMUM) up to 60 s.
	soa := &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.com."), MBox: dnsmessage.MustNewName("h.example.com."), MinTTL: 30}
	c.put(k, answer(t, q, dnsmessage.RCodeNameError, nil, soa, 3600, false), t0)
	if _, _, ok := c.get(k, t0.Add(29*time.Second)); !ok {
		t.Fatal("negative not cached")
	}
	if _, _, ok := c.get(k, t0.Add(31*time.Second)); ok {
		t.Fatal("negative kept past MINIMUM")
	}
	// SERVFAIL and TTL 0 are not stored.
	k2 := keyOf(dnspolicy.ViaDirect, "", q)
	c.put(k2, answer(t, q, dnsmessage.RCodeServerFailure, nil, nil, 0, false), t0)
	c.put(k2, answer(t, q, dnsmessage.RCodeSuccess, []rr{{"a.example.", dnsmessage.TypeA, 0, "1.2.3.4"}}, nil, 0, false), t0)
	c.put(k2, answer(t, q, dnsmessage.RCodeNameError, nil, nil, 0, false), t0) // no SOA
	if _, _, ok := c.get(k2, t0); ok {
		t.Fatal("uncacheable answer stored")
	}
	// Capacity.
	c.clear()
	ans := answer(t, q, dnsmessage.RCodeSuccess, []rr{{"a.example.", dnsmessage.TypeA, 60, "1.2.3.4"}}, nil, 0, false)
	for i := range cacheMax + 100 {
		kk := k
		kk.name = fmt.Sprintf("n%d.example", i)
		c.put(kk, ans, t0.Add(time.Duration(i)*time.Millisecond))
	}
	if n := c.len(); n > cacheMax {
		t.Fatalf("%d entries", n)
	}
	// Sweep is bounded, and repeated sweeps empty an expired cache.
	later := t0.Add(time.Hour)
	c.sweep(later)
	if n := c.len(); n < cacheMax-sweepBudget {
		t.Fatalf("one sweep dropped %d entries", cacheMax-n)
	}
	for c.len() > 0 {
		c.sweep(later)
	}
}

func TestFlight(t *testing.T) {
	var f flight
	var calls atomic.Int32
	release := make(chan struct{})
	k := flightKey{cacheKey: cacheKey{name: "a.example"}}
	var wg sync.WaitGroup
	got := make([][]byte, 50)
	started := make(chan struct{}, 50)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started <- struct{}{}
			got[i], _ = f.do(k, func() ([]byte, error) {
				calls.Add(1)
				<-release
				return []byte("answer"), nil
			})
		}()
	}
	for range got {
		<-started
	}
	time.Sleep(200 * time.Millisecond) // let them all join the call
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d upstream calls", n)
	}
	for i, b := range got {
		if string(b) != "answer" {
			t.Fatalf("%d: %q", i, b)
		}
	}
	got[0][0] = 'X'
	if string(got[1]) != "answer" {
		t.Fatal("callers share one slice")
	}
}
