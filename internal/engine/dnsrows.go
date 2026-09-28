package engine

import (
	"container/list"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
)

// DNS rows (dns): every query HyRoute answers itself is shown in
// "Connections" as one row per requester, name, rule, route, server and
// outcome. Later queries with the same key count into the open row, so a
// page load (A, AAAA and HTTPS for each name, to every adapter's server)
// gives a row or three per name instead of dozens.

const (
	dnsRowsMax   = 1024             // open rows; the least recently used closes first
	dnsRowIdle   = 30 * time.Second // a row closes after this long without a query
	dnsRowMaxAge = 5 * time.Minute  // and at the latest this long after it opened
)

type dnsRowKey struct {
	pid                                 uint32
	proto                               uint8
	name, rule, route, profile, outcome string
}

type dnsRow struct {
	rec          *flows.Record
	opened, last time.Time
	key          dnsRowKey
	el           *list.Element // in dnsRows.lru
}

// dnsRows is the open rows; its mutex is a leaf (it calls only the flows
// registry, whose locks are leaves too). lru orders them most recently
// used first, so an eviction on the packet loop is O(1).
type dnsRows struct {
	mu  sync.Mutex
	m   map[dnsRowKey]*dnsRow
	lru list.List // of *dnsRow
}

// noteDNS records one answered query: a new row (build makes its record,
// OnDecision is called) or one more query in the open row of k.
func (c *Core) noteDNS(now time.Time, k dnsRowKey, sent, recv int, build func() *flows.Record) {
	c.dnsRows.mu.Lock()
	if row := c.dnsRows.m[k]; row != nil {
		row.last = now
		c.dnsRows.lru.MoveToFront(row.el)
		row.rec.Set(func(f *flows.Fields) { f.Count++ })
		row.rec.Sent.Add(int64(sent))
		row.rec.Recv.Add(int64(recv))
		c.dnsRows.mu.Unlock()
		return
	}
	var evicted *flows.Record
	if len(c.dnsRows.m) >= dnsRowsMax {
		lru := c.dnsRows.lru.Remove(c.dnsRows.lru.Back()).(*dnsRow)
		evicted = lru.rec
		delete(c.dnsRows.m, lru.key)
	}
	rec := build()
	rec.Start = now
	rec.Sent.Store(int64(sent))
	rec.Recv.Store(int64(recv))
	rec.Set(func(f *flows.Fields) { f.Count = 1 })
	c.Flows.Open(rec)
	if c.dnsRows.m == nil {
		c.dnsRows.m = map[dnsRowKey]*dnsRow{}
	}
	row := &dnsRow{rec: rec, opened: now, last: now, key: k}
	row.el = c.dnsRows.lru.PushFront(row)
	c.dnsRows.m[k] = row
	c.dnsRows.mu.Unlock()
	if evicted != nil {
		c.Flows.Close(evicted, now)
	}
	if c.OnDecision != nil {
		c.OnDecision(rec.View(now))
	}
}

// sweepDNSRows closes rows idle for dnsRowIdle or open for dnsRowMaxAge;
// all of them with all set (the core closes).
func (c *Core) sweepDNSRows(now time.Time, all bool) {
	var closed []*flows.Record
	c.dnsRows.mu.Lock()
	for k, row := range c.dnsRows.m {
		if all || now.Sub(row.last) >= dnsRowIdle || now.Sub(row.opened) >= dnsRowMaxAge {
			closed = append(closed, row.rec)
			delete(c.dnsRows.m, k)
			c.dnsRows.lru.Remove(row.el)
		}
	}
	c.dnsRows.mu.Unlock()
	for _, r := range closed {
		c.Flows.Close(r, now)
	}
}
