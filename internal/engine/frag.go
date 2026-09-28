package engine

import (
	"errors"
	"math"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

// IP fragments. Only the first fragment of a datagram has the transport
// header (ports); the others are matched to it by (addresses, protocol,
// IP ID). UDP datagrams (IPv4, options included, and IPv6 whose fragment
// header directly follows the fixed header) are reassembled: a new flow's
// datagram is decided whole by the normal path, a Tunnel datagram goes
// into the tunnel whole, and a Direct one leaves as its original
// fragments, unchanged. An existing Direct or Block flow's datagrams take
// a fast path: decided by their first fragment, the rest follow. DNS
// queries (port 53) never take the fast path: they are always assembled,
// so the whole query goes through udpOut. TCP fragments and IPv6 datagrams
// with extension headers in front of the fragment header keep the
// per-fragment routing (the legacy path): Direct passes, Tunnel and Block
// are dropped. A fragment of a Tunnel or Block datagram never leaves
// directly. Fragments of other protocols (a large ping, IPsec ESP, GRE)
// are not routed and pass unchanged.
//
// All table state is under Core.mu and changes only in fragStep and
// fragLegacyStore (deferred unlock, poison on panic) and in the sweep.

const (
	fragAsmTTL   = 5 * time.Second // held / assembling entries (from creation, not extended)
	fragPassTTL  = 2 * time.Second // pass / drop decisions: a datagram's fragments leave within milliseconds
	fragDoneTTL  = 1 * time.Second // assembled datagrams: only duplicates can still come
	fragMax      = 16384           // entries (decided ones are evicted oldest-first, never refused)
	fragHeldMax  = 256             // entries holding data
	fragBytesMax = 4 << 20         // held bytes
	// fragSweepEvery throttles the sweep a refused fragment triggers.
	fragSweepEvery = 50 * time.Millisecond
)

type fragState uint8

const (
	fragHeld fragState = iota // later fragments only, no offset-0 yet: data held, never injected before a decision
	fragAsm                   // offset-0 seen: collecting the whole datagram
	fragPass                  // decided Direct (fast path or legacy): later fragments pass
	fragDrop                  // decided Block / too big / poisoned / legacy not direct: later fragments dropped
	fragDone                  // assembled and handed on: duplicates dropped silently
)

type fragEntry struct {
	state  fragState
	exp    time.Time
	flow   nat.FlowKey // ports of the offset-0 fragment (zero while fragHeld)
	legacy bool        // decided by the legacy path (TCP, IPv6 extension headers)
	asm    *packet.Assembly[divert.Address]
	n      int // fragments held (copy of asm.Pieces(): the sweep never calls into asm)
	bytes  int // raw bytes held (copy of asm.Bytes())
}

// holding: fragHeld or fragAsm. Such an entry is counted in fragHeldN and
// fragBytes while its asm is set (fragReleaseLocked clears it).
func (e *fragEntry) holding() bool { return e.state == fragHeld || e.state == fragAsm }

type fragQItem struct {
	k packet.FragKey
	e *fragEntry
}

// fragTable is the reassembly state of Core (embedded). Everything but the
// atomics is under Core.mu.
type fragTable struct {
	fragQ       []fragQItem // decided entries, oldest first (eviction order)
	fragQHead   int
	fragBytes   int // raw bytes held by all entries
	fragHeldN   int // entries holding data (fragHeld + fragAsm)
	fragSweptAt time.Time
	pendBytes   int // bytes parked in c.pending (packets and their originals)

	bigCount      atomic.Int64 // too-big drops, for the log rate limit
	fragFailCount atomic.Int64 // datagrams not reassembled, for the log rate limit
	fragHealed    atomic.Bool  // the "counters corrected" warning was logged

	fragHook   func() // tests only: called inside fragStep, under c.mu
	replayHook func() // tests only: called at the start of replayWhole
}

// fragOrigin: the original fragments of a reassembled packet, arrival
// order, with the addresses they were captured with (packet.Packet.Orig).
type fragOrigin struct {
	raws  [][]byte
	addrs []divert.Address
}

func (o *fragOrigin) size() int {
	n := 0
	for _, b := range o.raws {
		n += len(b)
	}
	return n
}

// fragIn: what fragOut computed before taking the lock.
type fragIn struct {
	lim   int      // payload limit for an oversize datagram, else math.MaxInt
	peek  *udpFlow // the flow seen when tunUp was computed (oversize only)
	tunUp bool     // peek's tunnel could carry UDP (checked unlocked)
}

type fragFail struct {
	dst    netip.Addr
	reason string // timeout | overlap | invalid | budget | panic
}

// fragAct is what fragOut does after unlocking.
type fragAct struct {
	inject bool                             // pass this fragment on
	whole  *packet.Assembly[divert.Address] // complete: build and route it
	big    *flows.Record                    // too big for Hysteria: count and log
	bigN   int
	bigLim int
	bigDst netip.AddrPort
	fails  []fragFail
	swept  fragSwept
}

// fragOut handles an outbound fragment.
func (c *Core) fragOut(raw []byte, addr *divert.Address) {
	f, err := packet.ParseFragment(raw)
	if err != nil {
		c.Malformed.Add(1)
		return
	}
	if !f.Routable() || c.excluded(f.Dst) {
		// Protocols the engine does not route (ICMP, ESP, GRE...: their
		// whole packets are not captured either) go on unchanged.
		c.Inject(raw, addr)
		return
	}
	now := time.Now()
	fk := f.Key()
	var key nat.FlowKey
	if f.HasPorts {
		key = nat.FlowKey{Src: netip.AddrPortFrom(f.Src, f.SrcPort), Dst: netip.AddrPortFrom(f.Dst, f.DstPort)}
	}
	if f.Offset == 0 && !f.HasPorts {
		// A first fragment too short to carry ports cannot be routed: it is
		// dropped, and the rest of its datagram with it.
		c.fragReport(c.fragLegacyStore(fk, key, rules.Block, now), fragSwept{})
		c.FragDropped.Add(1)
		return
	}
	if f.Offset == 0 && !f.Reassemblable() {
		c.fragLegacy(&f, fk, key, raw, addr, now)
		return
	}
	in := fragIn{lim: math.MaxInt}
	if f.Offset == 0 && f.UDPLen-8 > socks5.UDPPayloadAlways {
		if lim := socks5.MaxUDPPayload(socks5.AddrFromAddrPort(key.Dst)); f.UDPLen-8 > lim {
			// Too big for Hysteria. An existing Tunnel flow drops it at
			// once, but only while its tunnel is up: otherwise udpOut
			// retargets the flow or fails it as unavailable, as it would a
			// whole datagram. Tunnels must not be asked under c.mu.
			in.lim = lim
			var profile string
			c.mu.Lock()
			if uf := c.udp[key]; uf != nil && uf.route == rules.Tunnel {
				in.peek, profile = uf, uf.profile
			}
			c.mu.Unlock()
			if in.peek != nil {
				// udpSend's availability check.
				t := c.tunnel(profile)
				in.tunUp = t != nil && t.Available() && t.UDPAvailable()
			}
		}
	}
	act := c.fragStep(fk, key, &f, raw, addr, in, now)
	if act.inject {
		c.Inject(raw, addr)
	}
	if act.big != nil {
		// As udpApply does for a whole datagram: a flow recorded as refused
		// whose tunnel is up again shows as tunneled (and so as too big).
		if uf := in.peek; uf.refused.Load() && uf.refused.CompareAndSwap(true, false) {
			c.finish(uf.rec, rules.Tunnel, "tunneled")
		}
		c.tooBig(act.big, act.bigN, act.bigLim, act.bigDst)
	}
	c.fragReport(act.fails, act.swept)
	if act.whole != nil {
		c.fragDeliver(act.whole, f.Dst)
	}
}

// fragLegacy routes a datagram that is not reassembled by its first
// fragment (TCP, IPv6 extension headers in front of the fragment header).
func (c *Core) fragLegacy(f *packet.Fragment, fk packet.FragKey, key nat.FlowKey, raw []byte, addr *divert.Address, now time.Time) {
	route := c.fragRoute(f.Proto, key)
	c.fragReport(c.fragLegacyStore(fk, key, route, now), fragSwept{})
	if route == rules.Direct {
		c.Inject(raw, addr)
		return
	}
	c.FragDropped.Add(1)
	if n := c.FragLegacy.Add(1); n <= 5 || n%100 == 0 {
		c.Log.Warn("fragmented datagram dropped: its route is not direct (TCP or IPv6 extension headers)",
			"dst", key.Dst, "route", route.String(), "count", n)
	}
}

// fragRoute is the route of the flow a first fragment belongs to: an
// existing flow's route, or the rules. The owner is not waited for, but
// when no SOCKET event has named it yet the OS tables are asked at once,
// as the pending queue would: a program's rule must not miss the first
// datagram of its flow and let it go direct.
func (c *Core) fragRoute(proto uint8, key nat.FlowKey) rules.Action {
	c.mu.Lock()
	if proto == packet.ProtoUDP {
		if uf := c.udp[key]; uf != nil {
			c.mu.Unlock()
			return uf.route
		}
	} else if tf := c.tcp[key]; tf != nil {
		c.mu.Unlock()
		return rules.Direct
	}
	c.mu.Unlock()
	if proto == packet.ProtoTCP && c.NAT.LookupFlow(key) != nil {
		return rules.Tunnel // reflected flow
	}
	pid, known := c.Conns.Lookup(attrib.Key5{Proto: proto, Local: key.Src, Remote: key.Dst})
	if !known && c.OwnerFallback != nil {
		pid, known = c.OwnerFallback(proto, key.Src, key.Dst)
	}
	sub := rules.Subject{Proto: proto, Dst: key.Dst}
	if known {
		sub.Proc = c.Procs.Get(pid)
	}
	if res, kind := c.exclusion(pid, known, sub.Proc, proto, key.Dst); kind != "" {
		return res.Action
	}
	set := c.Rules.Load()
	res := set.EvaluateSites(sub, c.packetSites(set, proto, key.Dst))
	if res.NeedsDomain {
		// Same as a whole UDP datagram with an unknown name (applyUDP).
		if c.Opt.BlockQUIC && key.Dst.Port() == 443 {
			return rules.Block
		}
		res = set.EvaluateNoDomain(sub)
	}
	return res.Action
}

// fragLegacyStore records a legacy decision for fk. Simple fragments held
// under the key belong to an inconsistent datagram (its first fragment is
// not Simple, or too short to carry ports): they are dropped.
func (c *Core) fragLegacyStore(fk packet.FragKey, key nat.FlowKey, route rules.Action, now time.Time) (fails []fragFail) {
	var poisoned bool
	defer c.fragPanicLog(&poisoned, fk.Dst)
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			c.fragPoisonLocked(nil, fk, now, "panic")
			poisoned = true
			panic(r)
		}
	}()
	e := c.fragLookupLocked(fk, now, &fails)
	if e != nil && e.holding() {
		c.FragDropped.Add(int64(e.n))
		c.FragIncomplete.Add(1)
		fails = append(fails, fragFail{fk.Dst, "invalid"})
	}
	st := fragDrop
	if route == rules.Direct {
		st = fragPass
	}
	e = c.fragSetLocked(fk, e, st, now.Add(fragPassTTL))
	e.flow, e.legacy = key, true
	return fails
}

// fragStep applies one fragment to the table. Reassembly handles
// untrusted bytes under c.mu: the deferred unlock keeps the lock usable
// after a panic, and the recover poisons the datagram before HandlePacket's
// guard counts the panic; the datagram is logged after the unlock.
func (c *Core) fragStep(fk packet.FragKey, key nat.FlowKey, f *packet.Fragment, raw []byte,
	addr *divert.Address, in fragIn, now time.Time) (act fragAct) {
	var poisoned bool
	defer c.fragPanicLog(&poisoned, fk.Dst)
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			c.fragPoisonLocked(nil, fk, now, "panic")
			poisoned = true
			act = fragAct{}
			panic(r)
		}
	}()
	if c.fragHook != nil {
		c.fragHook()
	}
	e := c.fragLookupLocked(fk, now, &act.fails)
	if f.Offset > 0 {
		c.fragLaterLocked(&act, fk, e, f, raw, addr, now)
	} else {
		c.fragFirstLocked(&act, fk, key, e, f, raw, addr, in, now)
	}
	return act
}

// fragPanicLog logs the datagram a recovered panic poisoned. Deferred
// before the unlock, it runs after it, while the panic goes on to guard.
func (c *Core) fragPanicLog(poisoned *bool, dst netip.Addr) {
	if *poisoned {
		c.fragReport([]fragFail{{dst, "panic"}}, fragSwept{})
	}
}

// fragLookupLocked is fk's entry while it lives: a decision is honoured for
// its lifetime, not until the next sweep. An expired entry is removed as
// the sweep would (a holding one counted as lost) and nil is returned.
func (c *Core) fragLookupLocked(fk packet.FragKey, now time.Time, fails *[]fragFail) *fragEntry {
	e := c.frags[fk]
	if e == nil || !now.After(e.exp) {
		return e
	}
	if f, ok := c.fragExpireLocked(fk, e); ok {
		*fails = append(*fails, f)
	}
	return nil
}

// fragExpireLocked removes an expired entry. Entry fields only: it cannot
// panic.
func (c *Core) fragExpireLocked(k packet.FragKey, e *fragEntry) (fail fragFail, failed bool) {
	switch e.state {
	case fragHeld:
		c.FragOrphan.Add(int64(e.n))
		c.FragDropped.Add(int64(e.n))
	case fragAsm:
		c.FragIncomplete.Add(1)
		c.FragDropped.Add(int64(e.n))
		fail, failed = fragFail{k.Dst, "timeout"}, true
	}
	c.fragReleaseLocked(e)
	e.state = fragDrop
	delete(c.frags, k)
	return fail, failed
}

// fragLaterLocked: a fragment with a non-zero offset.
func (c *Core) fragLaterLocked(act *fragAct, fk packet.FragKey, e *fragEntry, f *packet.Fragment, raw []byte, addr *divert.Address, now time.Time) {
	switch {
	case e == nil:
		if !f.Reassemblable() {
			c.FragOrphan.Add(1) // first fragment not seen (or expired)
			c.FragDropped.Add(1)
			return
		}
		// Held until its first fragment comes and the datagram is decided.
		c.fragNewLocked(act, fk, fragHeld, nat.FlowKey{}, f, raw, addr, now)
	case e.state == fragPass:
		act.inject = true
	case e.state == fragDrop:
		c.FragDropped.Add(1)
	case e.state == fragDone:
		// A duplicate of a datagram already handed on.
	case !f.Reassemblable():
		// A non-Simple fragment joining a Simple datagram.
		c.FragDropped.Add(1)
		c.fragPoisonLocked(act, fk, now, "invalid")
	default:
		c.fragAddLocked(act, fk, e, f, raw, addr, now)
	}
}

// fragFirstLocked: the offset-0 fragment of a reassemblable datagram. It
// always starts or completes exactly one datagram: a decision never
// outlives the next offset-0 fragment of its key.
func (c *Core) fragFirstLocked(act *fragAct, fk packet.FragKey, key nat.FlowKey, e *fragEntry, f *packet.Fragment,
	raw []byte, addr *divert.Address, in fragIn, now time.Time) {
	uf := c.udp[key]
	if uf != nil {
		uf.last = now
	}
	// Dropped at once only when the whole datagram would reach udpSend's
	// size check anyway: the flow's tunnel is up, so udpOut would neither
	// retarget it nor fail it as unavailable.
	tooBig := uf != nil && uf.route == rules.Tunnel && f.UDPLen-8 > in.lim && uf == in.peek && in.tunUp
	big := func() {
		act.big, act.bigN, act.bigLim, act.bigDst = uf.rec, f.UDPLen-8, in.lim, key.Dst
	}
	switch {
	case e == nil || !e.holding(): // a new datagram; the old decision is replaced
		switch {
		case f.DstPort == 53 || f.UDPLen < 8 || uf == nil:
			// DNS: the whole query goes through udpOut. A UDP length below
			// the header: Add rejects it (the fast path must not pass an
			// unchecked length). A new flow: decided whole by udpOut.
			c.fragNewLocked(act, fk, fragAsm, key, f, raw, addr, now)
		case uf.route == rules.Direct:
			c.fragSetLocked(fk, e, fragPass, now.Add(fragPassTTL)).flow = key
			act.inject = true
			uf.rec.Sent.Add(int64(f.UDPLen - 8))
		case uf.route == rules.Block:
			c.fragSetLocked(fk, e, fragDrop, now.Add(fragPassTTL)).flow = key
			c.FragDropped.Add(1)
		case tooBig:
			c.fragSetLocked(fk, e, fragDrop, now.Add(fragPassTTL)).flow = key
			c.FragDropped.Add(1)
			big()
		default: // Tunnel: sent whole
			c.fragNewLocked(act, fk, fragAsm, key, f, raw, addr, now)
		}
	case e.state == fragHeld: // later fragments came first
		if tooBig {
			c.FragDropped.Add(int64(e.n) + 1)
			c.fragSetLocked(fk, e, fragDrop, now.Add(fragPassTTL)).flow = key
			big()
			return
		}
		// Assembled completely whatever the flow's route: the held pieces
		// are released only as part of a datagram whose geometry matches
		// this fragment's UDP length.
		e.state, e.flow = fragAsm, key
		c.fragAddLocked(act, fk, e, f, raw, addr, now)
	default: // assembling: anything but an exact duplicate overlaps
		c.fragAddLocked(act, fk, e, f, raw, addr, now)
	}
}

// fragNewLocked starts a holding entry with its first fragment. The
// Assembly takes the fragment before anything is counted or inserted.
func (c *Core) fragNewLocked(act *fragAct, fk packet.FragKey, st fragState, flow nat.FlowKey, f *packet.Fragment,
	raw []byte, addr *divert.Address, now time.Time) {
	n := len(raw)
	if !c.fragBudgetLocked(act, n, true, now) {
		c.FragDropped.Add(1)
		c.fragPoisonLocked(act, fk, now, "budget")
		return
	}
	asm := packet.NewAssembly[divert.Address]()
	if err := asm.Add(append([]byte(nil), raw...), f, *addr); err != nil {
		c.FragDropped.Add(1)
		c.fragPoisonLocked(act, fk, now, fragReason(err))
		return
	}
	if _, ok := c.frags[fk]; !ok {
		c.fragRoomLocked()
	}
	e := &fragEntry{state: st, exp: now.Add(fragAsmTTL), flow: flow, asm: asm, n: 1, bytes: n}
	c.frags[fk] = e
	c.fragHeldN++
	c.fragBytes += n
	if st == fragAsm && asm.Complete() {
		c.fragFinishLocked(act, fk, e, now)
	}
}

// fragAddLocked adds a fragment to a holding entry.
func (c *Core) fragAddLocked(act *fragAct, fk packet.FragKey, e *fragEntry, f *packet.Fragment, raw []byte,
	addr *divert.Address, now time.Time) {
	n := len(raw)
	fits := c.fragBudgetLocked(act, n, false, now)
	if c.frags[fk] != e {
		// The entry expired in the sweep the budget check ran (and was
		// counted there): the rest of its datagram is dropped.
		c.FragDropped.Add(1)
		c.fragSetLocked(fk, c.frags[fk], fragDrop, now.Add(fragPassTTL))
		return
	}
	if !fits {
		c.FragDropped.Add(1)
		c.fragPoisonLocked(act, fk, now, "budget")
		return
	}
	before := e.asm.Pieces()
	if err := e.asm.Add(append([]byte(nil), raw...), f, *addr); err != nil {
		c.FragDropped.Add(1)
		c.fragPoisonLocked(act, fk, now, fragReason(err))
		return
	}
	if e.asm.Pieces() == before {
		return // exact duplicate
	}
	e.n++
	e.bytes += n
	c.fragBytes += n
	if e.state == fragAsm && e.asm.Complete() {
		c.fragFinishLocked(act, fk, e, now)
	}
}

func fragReason(err error) string {
	if errors.Is(err, packet.ErrFragOverlap) {
		return "overlap"
	}
	return "invalid"
}

// fragBudgetLocked reports whether n more bytes (and a new holding entry)
// fit. Before refusing, expired holding entries are swept (at most every
// fragSweepEvery).
func (c *Core) fragBudgetLocked(act *fragAct, n int, entry bool, now time.Time) bool {
	fits := func() bool {
		return (!entry || c.fragHeldN < fragHeldMax) && c.fragBytes+n <= fragBytesMax
	}
	if fits() {
		return true
	}
	if now.Sub(c.fragSweptAt) >= fragSweepEvery {
		sw := c.fragSweepLocked(now)
		act.fails = append(act.fails, sw.fails...)
		act.swept.healed = act.swept.healed || sw.healed
		act.swept.held, act.swept.bytes = sw.held, sw.bytes
	}
	return fits()
}

// fragFinishLocked hands a complete datagram on (built after unlock).
func (c *Core) fragFinishLocked(act *fragAct, fk packet.FragKey, e *fragEntry, now time.Time) {
	act.whole = e.asm
	c.fragSetLocked(fk, e, fragDone, now.Add(fragDoneTTL))
}

// fragPoisonLocked drops the datagram of fk: its held fragments and every
// later one. Only map and counter operations: it cannot panic.
func (c *Core) fragPoisonLocked(act *fragAct, fk packet.FragKey, now time.Time, reason string) {
	e := c.frags[fk]
	var flow nat.FlowKey
	if e != nil {
		flow = e.flow
		if e.holding() {
			c.FragDropped.Add(int64(e.n))
		}
	}
	c.fragSetLocked(fk, e, fragDrop, now.Add(fragPassTTL)).flow = flow
	c.FragIncomplete.Add(1)
	if act != nil {
		act.fails = append(act.fails, fragFail{fk.Dst, reason})
	}
}

// fragSetLocked makes fk's entry a decided one (pass, drop or done) and
// queues it for eviction. A holding entry changes in place (released); a
// decided or missing one is replaced by a new entry, so that every entry is
// queued exactly once.
func (c *Core) fragSetLocked(fk packet.FragKey, e *fragEntry, st fragState, exp time.Time) *fragEntry {
	if e != nil && e.holding() {
		c.fragReleaseLocked(e)
	} else {
		e = &fragEntry{}
	}
	if _, ok := c.frags[fk]; !ok {
		c.fragRoomLocked()
	}
	c.frags[fk] = e
	e.state, e.exp, e.legacy = st, exp, false
	c.fragQ = append(c.fragQ, fragQItem{fk, e})
	// The whole slice, evicted prefix included: under sustained eviction
	// the live part stays near fragMax while the prefix grows.
	if len(c.fragQ) > 2*fragMax {
		c.fragCompactLocked()
	}
	return e
}

// fragReleaseLocked is the single place a holding entry stops being
// counted.
func (c *Core) fragReleaseLocked(e *fragEntry) {
	if e.asm == nil {
		return
	}
	c.fragHeldN--
	c.fragBytes -= e.bytes
	e.n, e.bytes, e.asm = 0, 0, nil
}

// fragRoomLocked evicts the oldest decisions until a new key fits. Holding
// entries are never evicted; they are bounded by fragHeldMax << fragMax.
func (c *Core) fragRoomLocked() {
	for len(c.frags) >= fragMax && c.fragQHead < len(c.fragQ) {
		it := c.fragQ[c.fragQHead]
		c.fragQ[c.fragQHead] = fragQItem{}
		c.fragQHead++
		if c.frags[it.k] == it.e && !it.e.holding() {
			delete(c.frags, it.k)
		}
	}
}

// fragCompactLocked keeps the queue items of current decided entries,
// oldest first.
func (c *Core) fragCompactLocked() {
	q := make([]fragQItem, 0, len(c.fragQ)-c.fragQHead)
	for _, it := range c.fragQ[c.fragQHead:] {
		if it.e != nil && c.frags[it.k] == it.e && !it.e.holding() {
			q = append(q, it)
		}
	}
	c.fragQ, c.fragQHead = q, 0
}

// fragSwept is what a sweep found, reported after unlocking.
type fragSwept struct {
	fails       []fragFail
	healed      bool
	held, bytes int // the drifted counters, when healed
}

// fragSweepLocked expires entries (Maintain, and a refused fragment). It
// reads entry fields only, never the Assembly. The counters are recomputed
// from the holding entries left: a drift would keep the budget full for
// good.
func (c *Core) fragSweepLocked(now time.Time) (sw fragSwept) {
	held, bytes := 0, 0
	for k, e := range c.frags {
		if !now.After(e.exp) {
			if e.holding() && e.asm != nil {
				held++
				bytes += e.bytes
			}
			continue
		}
		if f, ok := c.fragExpireLocked(k, e); ok {
			sw.fails = append(sw.fails, f)
		}
	}
	if held != c.fragHeldN || bytes != c.fragBytes {
		sw.healed, sw.held, sw.bytes = true, c.fragHeldN, c.fragBytes
		c.fragHeldN, c.fragBytes = held, bytes
	}
	c.fragCompactLocked()
	c.fragSweptAt = now
	return sw
}

// fragReport logs what the table found, after unlocking.
func (c *Core) fragReport(fails []fragFail, sw fragSwept) {
	for _, f := range append(fails, sw.fails...) {
		if n := c.fragFailCount.Add(1); n <= 5 || n%100 == 0 {
			c.Log.Warn("fragmented datagram not reassembled: dropped", "dst", f.dst, "reason", f.reason, "count", n)
		}
	}
	if sw.healed && !c.fragHealed.Swap(true) {
		c.Log.Warn("fragment table counters corrected", "held", sw.held, "bytes", sw.bytes)
	}
}

// fragDeliver builds a complete datagram (no lock held) and routes it
// like a whole one, with its original fragments attached.
func (c *Core) fragDeliver(asm *packet.Assembly[divert.Address], dst netip.Addr) {
	whole, raws, addrs, err := asm.Build()
	if err != nil {
		c.FragIncomplete.Add(1)
		c.FragDropped.Add(int64(asm.Pieces()))
		c.fragReport([]fragFail{{dst, "invalid"}}, fragSwept{})
		return
	}
	p, err := packet.Parse(whole)
	if err != nil {
		c.Malformed.Add(1)
		return
	}
	p.Orig = &fragOrigin{raws: raws, addrs: addrs}
	c.FragReassembled.Add(1)
	a := addrs[asm.First()]
	c.udpOut(&p, &a)
}

// injectDirect sends a Direct packet on: a packet rebuilt from fragments
// leaves as the fragments the sender made, unchanged (no re-cutting, no
// checksum rewrite); a whole one as itself. A rebuilt DNS query is
// recorded in the DNS cache here: the sniff handle saw only its first
// fragment, which does not parse, so without this the answer would be
// rejected as unmatched and the name would never be cached.
func (c *Core) injectDirect(p *packet.Packet, addr *divert.Address) {
	if o, ok := p.Orig.(*fragOrigin); ok {
		if p.Proto == packet.ProtoUDP && p.DstPort() == 53 {
			c.DNS.AddQuery(false, p.Src(), p.Dst(), p.Payload()) // error ignored, as in HandleDNS
		}
		for i := range o.raws {
			c.Inject(o.raws[i], &o.addrs[i])
		}
		return
	}
	c.Inject(p.Buf, addr)
}

// tooBig drops a tunnel datagram larger than Hysteria carries. It is not a
// server failure: nothing is counted against the tunnel.
func (c *Core) tooBig(rec *flows.Record, size, limit int, dst netip.AddrPort) {
	c.UDPTooBig.Add(1)
	c.UDPDropped.Add(1)
	rec.TooBig.Add(1)
	if n := c.bigCount.Add(1); n <= 5 || n%100 == 0 {
		c.Log.Warn("UDP datagram larger than Hysteria carries: dropped",
			"size", size, "limit", limit, "dst", dst, "process", rec.Process, "count", n)
	}
}

// replayWhole replays a parked reassembled datagram (newFlow): its own
// guard, so that a panic costs only this datagram, not the rest of the
// flow's parked packets.
func (c *Core) replayWhole(pp *pendingPkt) {
	defer c.guard("packet")
	if c.replayHook != nil {
		c.replayHook()
	}
	p, err := packet.Parse(pp.raw)
	if err != nil {
		c.Malformed.Add(1)
		return
	}
	p.Orig = pp.orig
	c.udpOut(&p, &pp.addr)
}

// pendSize is what parking p costs in pendBytes.
func pendSize(p *packet.Packet) (int, *fragOrigin) {
	o, _ := p.Orig.(*fragOrigin)
	if o == nil {
		return len(p.Buf), nil
	}
	return len(p.Buf) + o.size(), o
}
