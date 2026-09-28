// Package attrib maps connections to process IDs using WinDivert SOCKET
// layer events, with IP Helper tables as a fallback.
package attrib

import (
	"net/netip"
	"sync"
	"time"
)

// maxRecords caps the table: a long-lived socket that talks to many remotes
// (DHT, games, WebRTC) adds records per remote. Beyond the cap the least
// recently refreshed records go first; a lookup that misses them falls back
// to the socket's bind, the pending wait and IP Helper.
const maxRecords = 1 << 15

// Key5 is the full connection key.
type Key5 struct {
	Proto  uint8
	Local  netip.AddrPort
	Remote netip.AddrPort
}

type portKey struct {
	Proto  uint8
	Port   uint16
	Remote netip.AddrPort // zero for bind entries
}

// bindMarker keys the bind table: (proto, local port).
type bindMarker portKey

type rec struct {
	pid      uint32
	endpoint uint64
	at       time.Time // last event that recorded it
}

// queued is an expiry queue entry: key was recorded as r, last refreshed at
// at. A record refreshed in place keeps its entry and is re-queued when the
// entry reaches the front; the entry of a replaced or removed record is dead.
type queued struct {
	key any // Key5, portKey or bindMarker
	r   *rec
	at  time.Time
}

// endpointKeys is what one socket endpoint has recorded.
type endpointKeys struct {
	keys map[any]struct{}
	last time.Time // last event of the socket; keeps its bind alive
}

// Table is safe for concurrent use. Lookups go from most to least precise:
// exact 5-tuple, then (proto, local port, remote) for events that carried
// an unspecified local address, then the bind of (proto, local port) —
// the main path for unconnected UDP sockets.
//
// Every record belongs to one socket endpoint (removed together on
// SOCKET_CLOSE) and has one entry in an expiry queue kept roughly in
// refresh order, so Sweep and the size cap only visit the oldest records.
type Table struct {
	mu         sync.RWMutex
	exact      map[Key5]*rec
	byPort     map[portKey]*rec
	bind       map[bindMarker]*rec
	byEndpoint map[uint64]*endpointKeys
	queue      []queued // oldest first
	dead       int      // queue entries whose record was replaced or removed
	notify     chan struct{}
}

func NewTable() *Table {
	return &Table{
		exact:      make(map[Key5]*rec),
		byPort:     make(map[portKey]*rec),
		bind:       make(map[bindMarker]*rec),
		byEndpoint: make(map[uint64]*endpointKeys),
		notify:     make(chan struct{}),
	}
}

func norm(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// Connect records a SOCKET_CONNECT (or FLOW_ESTABLISHED) event. Repeated
// events of a socket for the same remote refresh its records in place.
func (t *Table) Connect(k Key5, pid uint32, endpoint uint64, now time.Time) {
	k.Local, k.Remote = norm(k.Local), norm(k.Remote)
	pk := portKey{k.Proto, k.Local.Port(), k.Remote}
	t.mu.Lock()
	if k.Local.Addr().IsValid() && !k.Local.Addr().IsUnspecified() {
		t.setLocked(k, pid, endpoint, now)
	}
	t.setLocked(pk, pid, endpoint, now)
	t.wakeLocked()
	t.mu.Unlock()
}

// Bind records a SOCKET_BIND event.
func (t *Table) Bind(proto uint8, localPort uint16, pid uint32, endpoint uint64, now time.Time) {
	t.mu.Lock()
	t.setLocked(bindMarker{Proto: proto, Port: localPort}, pid, endpoint, now)
	t.wakeLocked()
	t.mu.Unlock()
}

// setLocked records key for the socket endpoint id.
func (t *Table) setLocked(key any, pid uint32, id uint64, now time.Time) {
	ep := t.byEndpoint[id]
	if ep == nil {
		ep = &endpointKeys{keys: make(map[any]struct{})}
		t.byEndpoint[id] = ep
	}
	ep.last = now
	if r := t.getLocked(key); r != nil {
		if r.endpoint == id {
			r.pid, r.at = pid, now
			return
		}
		// Reused by a new socket before the old CLOSE arrived.
		t.removeLocked(key, r)
		t.dead++
	}
	r := &rec{pid, id, now}
	switch k := key.(type) {
	case Key5:
		t.exact[k] = r
	case portKey:
		t.byPort[k] = r
	case bindMarker:
		t.bind[k] = r
	}
	ep.keys[key] = struct{}{}
	if t.dead > 1024 && t.dead > len(t.queue)/2 {
		t.compactLocked()
	}
	t.queue = append(t.queue, queued{key, r, now})
	for t.lenLocked() > maxRecords {
		if !t.evictLocked() {
			break
		}
	}
}

func (t *Table) getLocked(key any) *rec {
	switch k := key.(type) {
	case Key5:
		return t.exact[k]
	case portKey:
		return t.byPort[k]
	case bindMarker:
		return t.bind[k]
	}
	return nil
}

// removeLocked deletes key, recorded as r, and unlinks it from r's socket.
// Its queue entry becomes dead unless the caller has just popped it.
func (t *Table) removeLocked(key any, r *rec) {
	switch k := key.(type) {
	case Key5:
		delete(t.exact, k)
	case portKey:
		delete(t.byPort, k)
	case bindMarker:
		delete(t.bind, k)
	}
	if ep := t.byEndpoint[r.endpoint]; ep != nil {
		delete(ep.keys, key)
		if len(ep.keys) == 0 {
			delete(t.byEndpoint, r.endpoint)
		}
	}
}

// Close removes everything recorded for a socket endpoint (SOCKET_CLOSE).
func (t *Table) Close(endpoint uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ep := t.byEndpoint[endpoint]
	if ep == nil {
		return
	}
	for k := range ep.keys {
		if r := t.getLocked(k); r != nil && r.endpoint == endpoint {
			t.removeLocked(k, r)
			t.dead++
		}
	}
	delete(t.byEndpoint, endpoint)
}

// Lookup returns the PID owning the connection.
func (t *Table) Lookup(k Key5) (uint32, bool) {
	return t.lookup(k, true)
}

// LookupConn is Lookup without the bind: only what the events recorded for
// this connection. A bind is keyed by the local port alone, so for a
// connection the events never saw (one opened before start) it names
// whichever socket took that port number since.
func (t *Table) LookupConn(k Key5) (uint32, bool) {
	return t.lookup(k, false)
}

func (t *Table) lookup(k Key5, bind bool) (uint32, bool) {
	k.Local, k.Remote = norm(k.Local), norm(k.Remote)
	t.mu.RLock()
	defer t.mu.RUnlock()
	if r := t.exact[k]; r != nil {
		return r.pid, true
	}
	if r := t.byPort[portKey{k.Proto, k.Local.Port(), k.Remote}]; r != nil {
		return r.pid, true
	}
	if !bind {
		return 0, false
	}
	if r := t.bind[bindMarker{Proto: k.Proto, Port: k.Local.Port()}]; r != nil {
		return r.pid, true
	}
	return 0, false
}

// Changed returns a channel closed on the next insertion; used by the
// pending queue to wait for a late SOCKET event without polling.
func (t *Table) Changed() <-chan struct{} {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.notify
}

func (t *Table) wakeLocked() {
	close(t.notify)
	t.notify = make(chan struct{})
}

// Sweep drops records not refreshed for maxAge: lost CLOSE events, and
// remotes a long-lived socket no longer talks to. A bind lives as long as
// its socket keeps producing events. Only expired queue entries are visited.
func (t *Table) Sweep(now time.Time, maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for len(t.queue) > 0 && now.Sub(t.queue[0].at) >= maxAge {
		q := t.popLocked()
		if t.getLocked(q.key) != q.r {
			t.dead--
			continue
		}
		if last := t.lastLocked(q.key, q.r); now.Sub(last) < maxAge {
			t.queue = append(t.queue, queued{q.key, q.r, last}) // refreshed since queued
			continue
		}
		t.removeLocked(q.key, q.r)
	}
}

// evictLocked removes the least recently refreshed record; false when there
// is none.
func (t *Table) evictLocked() bool {
	for len(t.queue) > 0 {
		q := t.popLocked()
		if t.getLocked(q.key) != q.r {
			t.dead--
			continue
		}
		if last := t.lastLocked(q.key, q.r); last.After(q.at) {
			t.queue = append(t.queue, queued{q.key, q.r, last}) // refreshed since queued
			continue
		}
		t.removeLocked(q.key, q.r)
		return true
	}
	return false
}

// lastLocked is when r was last refreshed; a bind counts every event of its
// socket.
func (t *Table) lastLocked(key any, r *rec) time.Time {
	at := r.at
	if _, ok := key.(bindMarker); ok {
		if ep := t.byEndpoint[r.endpoint]; ep != nil && ep.last.After(at) {
			at = ep.last
		}
	}
	return at
}

func (t *Table) popLocked() queued {
	q := t.queue[0]
	t.queue[0] = queued{}
	t.queue = t.queue[1:]
	return q
}

// compactLocked drops dead queue entries.
func (t *Table) compactLocked() {
	live := make([]queued, 0, t.lenLocked()+1)
	for _, q := range t.queue {
		if t.getLocked(q.key) == q.r {
			live = append(live, q)
		}
	}
	t.queue, t.dead = live, 0
}

func (t *Table) lenLocked() int { return len(t.exact) + len(t.byPort) + len(t.bind) }

// Len returns the number of entries (tests, diagnostics).
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lenLocked()
}
