// Package nat holds the reflect-NAT state for TCP flows diverted into the
// local relay and the pure packet rewrites that implement the reflection.
//
//	app:    L:lp  -> R:rp            (outbound, captured)
//	to relay: R:lp -> L:RELAY        (injected as inbound)
//	relay:  L:RELAY -> R:lp          (outbound, captured)
//	to app: R:rp  -> L:lp            (injected as inbound)
//
// The relay sees the peer R:lp and recovers the original destination through
// the reflect index (R, lp).
package nat

import (
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/packet"
)

// Mode says what the relay does with an accepted connection.
type Mode uint8

const (
	// NoSniff: the route is already Tunnel; SOCKS5 CONNECT to the IP at once.
	NoSniff Mode = iota
	// Sniff: the route depends on the domain; read ClientHello/Host first.
	Sniff
)

// FlowKey is the application's TCP 4-tuple as seen on the outbound packet.
type FlowKey struct {
	Src netip.AddrPort // L:lp
	Dst netip.AddrPort // R:rp
}

// ReflectKey is how the relay sees the reflected connection: peer (R, lp).
type ReflectKey struct {
	Remote    netip.Addr
	LocalPort uint16
}

// Entry is one reflected flow.
type Entry struct {
	Flow FlowKey
	PID  uint32
	Mode Mode
	// Profile is the tunnel profile of a NoSniff entry.
	Profile string
	Created time.Time
	// Rec is the "Connections" record the relay updates (may be nil).
	Rec *flows.Record
	// Meta is opaque to the table.
	Meta any

	lastSeen  time.Time
	closedAt  time.Time // zero while open
	finApp    bool      // the application sent FIN or RST: no more data from it
	finRelay  bool
	relayGone bool
	appGone   bool // FLOW_DELETED: the application's socket is gone

	// What ResetApps needs: the application's outbound address and the
	// sequence numbers seen on both sides.
	appAddr  divert.Address
	appNxt   uint32 // next sequence number the application sends
	appAck   uint32 // highest acknowledgment from the application
	relayNxt uint32 // next sequence number the relay sends
	seen     uint8  // seenApp | seenAck | seenRelay
}

const (
	seenApp = 1 << iota
	seenAck
	seenRelay
)

func (e *Entry) reflectKey() ReflectKey {
	return ReflectKey{Remote: e.Flow.Dst.Addr(), LocalPort: e.Flow.Src.Port()}
}

// ErrCollision means another live flow already owns the (R, lp) reflect key
// (same local port to the same remote IP but a different remote port). Such
// a flow must be decided at the packet level instead.
var ErrCollision = errors.New("nat: reflect key collision")

// Table is safe for concurrent use.
type Table struct {
	// Grace keeps an entry after close so trailing ACK/FIN still translate.
	Grace time.Duration
	// Idle removes entries with no packets for this long (lost FLOW_DELETED).
	Idle time.Duration

	mu        sync.RWMutex
	byFlow    map[FlowKey]*Entry
	byReflect map[ReflectKey]*Entry
}

func NewTable() *Table {
	return &Table{
		Grace:     30 * time.Second,
		Idle:      2 * time.Hour,
		byFlow:    make(map[FlowKey]*Entry),
		byReflect: make(map[ReflectKey]*Entry),
	}
}

func normFlow(k FlowKey) FlowKey {
	return FlowKey{
		Src: netip.AddrPortFrom(k.Src.Addr().Unmap(), k.Src.Port()),
		Dst: netip.AddrPortFrom(k.Dst.Addr().Unmap(), k.Dst.Port()),
	}
}

// Insert registers a new flow. If an entry for the same flow exists (SYN
// retransmit) it is returned instead of e.
func (t *Table) Insert(e *Entry, now time.Time) (*Entry, error) {
	e.Flow = normFlow(e.Flow)
	e.Created, e.lastSeen = now, now
	rk := e.reflectKey()
	t.mu.Lock()
	defer t.mu.Unlock()
	if old := t.byFlow[e.Flow]; old != nil {
		if old.closedAt.IsZero() {
			return old, nil
		}
		// Port reuse after close: replace the lingering entry.
		t.removeLocked(old)
	}
	if other := t.byReflect[rk]; other != nil {
		if other.closedAt.IsZero() {
			return nil, ErrCollision
		}
		t.removeLocked(other)
	}
	t.byFlow[e.Flow] = e
	t.byReflect[rk] = e
	return e, nil
}

// LookupFlow finds the entry for an application-side packet.
func (t *Table) LookupFlow(k FlowKey) *Entry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byFlow[normFlow(k)]
}

// RemoveClosed removes e if its connection has ended and reports whether
// it did. A new SYN on the same flow (port reuse) must not follow such an
// entry: it gets its own decision, and the entry's grace timer would
// otherwise cut the new connection off.
func (t *Table) RemoveClosed(e *Entry) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e.closedAt.IsZero() {
		return false
	}
	t.removeLocked(e)
	return true
}

// AppMaySend reports whether the application may still send data on e's
// connection: it has neither closed its side (FIN or RST) nor deleted the
// socket (FLOW_DELETED).
func (t *Table) AppMaySend(e *Entry) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return !e.appGone && !e.finApp
}

// LookupReflect finds the entry by the relay-side peer (R, lp).
func (t *Table) LookupReflect(remote netip.Addr, localPort uint16) *Entry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byReflect[ReflectKey{Remote: remote.Unmap(), LocalPort: localPort}]
}

// Touch records packet activity and FIN/RST state for either side.
func (t *Table) Touch(e *Entry, fromApp bool, flags uint8, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e.touchLocked(fromApp, flags, now)
}

// TouchPacket is Touch for a TCP segment of the flow, before it is
// rewritten. It also keeps what ResetApps needs: the sequence numbers and,
// for the application's segments, addr (its outbound address).
func (t *Table) TouchPacket(e *Entry, p *packet.Packet, fromApp bool, addr *divert.Address, now time.Time) {
	f := p.TCPFlags()
	next := p.Seq() + uint32(len(p.Payload()))
	if f&packet.FlagSYN != 0 {
		next++
	}
	if f&packet.FlagFIN != 0 {
		next++
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if fromApp {
		if e.seen&seenApp == 0 || seqAfter(next, e.appNxt) {
			e.appNxt = next
		}
		if f&packet.FlagACK != 0 && (e.seen&seenAck == 0 || seqAfter(p.Ack(), e.appAck)) {
			e.appAck = p.Ack()
			e.seen |= seenAck
		}
		if addr != nil {
			e.appAddr = *addr
		}
		e.seen |= seenApp
	} else {
		if e.seen&seenRelay == 0 || seqAfter(next, e.relayNxt) {
			e.relayNxt = next
		}
		e.seen |= seenRelay
	}
	e.touchLocked(fromApp, f, now)
}

// seqAfter compares TCP sequence numbers modulo 2^32.
func seqAfter(a, b uint32) bool { return int32(a-b) > 0 }

func (e *Entry) touchLocked(fromApp bool, flags uint8, now time.Time) {
	e.lastSeen = now
	if flags&(packet.FlagFIN|packet.FlagRST) != 0 {
		if fromApp {
			e.finApp = true
		} else {
			e.finRelay = true
		}
	}
	if flags&packet.FlagRST != 0 || (e.finApp && e.finRelay) {
		e.markClosed(now)
	}
}

// RelayClosed is called when the relay finishes with the connection.
func (t *Table) RelayClosed(e *Entry, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e.relayGone = true
	e.markClosed(now)
}

// FlowDeleted is called on WinDivert FLOW_DELETED for the app flow.
func (t *Table) FlowDeleted(k FlowKey, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.byFlow[normFlow(k)]; e != nil {
		e.appGone = true
		e.markClosed(now)
	}
}

func (e *Entry) markClosed(now time.Time) {
	if e.closedAt.IsZero() {
		e.closedAt = now
	}
}

// Sweep removes entries whose grace period expired or that went idle and
// returns them.
func (t *Table) Sweep(now time.Time) []*Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*Entry
	for _, e := range t.byFlow {
		if (!e.closedAt.IsZero() && now.Sub(e.closedAt) >= t.Grace) || now.Sub(e.lastSeen) >= t.Idle {
			t.removeLocked(e)
			out = append(out, e)
		}
	}
	return out
}

// AppReset is a segment that aborts an application's reflected connection.
type AppReset struct {
	Pkt  []byte
	Addr divert.Address // the application's outbound address; inject inbound
}

// ResetApps builds, for every entry whose application socket may still be
// open, the RST its remote end would send (see the engine's
// ResetReflected). The sequence number is the relay's next one, and also
// the application's highest acknowledgment when that differs (data in
// flight): one of them is what the application expects. The ACK covers
// everything the application sent, so a connection still in SYN_SENT is
// refused as well.
func (t *Table) ResetApps() []AppReset {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []AppReset
	for _, e := range t.byFlow {
		out = appendResets(out, e)
	}
	return out
}

// ResetApp is ResetApps for one entry, also one that Sweep removed.
func (t *Table) ResetApp(e *Entry) []AppReset {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return appendResets(nil, e)
}

func appendResets(out []AppReset, e *Entry) []AppReset {
	if e.appGone || e.seen&seenApp == 0 {
		return out
	}
	var seqs []uint32
	if e.seen&seenRelay != 0 {
		seqs = append(seqs, e.relayNxt)
	}
	if e.seen&seenAck != 0 && (len(seqs) == 0 || e.appAck != seqs[0]) {
		seqs = append(seqs, e.appAck)
	}
	if len(seqs) == 0 {
		seqs = append(seqs, 0) // SYN_SENT: only the ACK is checked
	}
	for _, seq := range seqs {
		out = append(out, AppReset{
			Pkt:  packet.BuildTCP(e.Flow.Dst, e.Flow.Src, packet.FlagRST|packet.FlagACK, seq, e.appNxt, nil),
			Addr: e.appAddr,
		})
	}
	return out
}

// Len returns the number of entries.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.byFlow)
}

func (t *Table) removeLocked(e *Entry) {
	if t.byFlow[e.Flow] == e {
		delete(t.byFlow, e.Flow)
	}
	if rk := e.reflectKey(); t.byReflect[rk] == e {
		delete(t.byReflect, rk)
	}
}

// ReflectToRelay rewrites an application packet L:lp -> R:rp into
// R:lp -> L:relayPort. The caller injects it as inbound and fixes checksums.
func ReflectToRelay(p *packet.Packet, relayPort uint16) {
	p.SwapIPs()
	p.SetDstPort(relayPort)
}

// ReflectFromRelay rewrites a relay packet L:relay -> R:lp into R:rp -> L:lp.
// The caller injects it as inbound and fixes checksums.
func ReflectFromRelay(p *packet.Packet, e *Entry) {
	p.SwapIPs()
	p.SetSrcPort(e.Flow.Dst.Port())
}
