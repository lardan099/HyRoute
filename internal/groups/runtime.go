package groups

import (
	"hash/fnv"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/rules"
)

// Hint is what a decision needs to know about a new connection (sticky).
type Hint struct {
	// App is the lower-cased process path (else its name); "proxy:<id>" for
	// a local proxy, "hyroute:<what>" for HyRoute's own use.
	App string
	// Site is the registrable domain the connection is keyed on ("" = key
	// on IP); built by the caller with SiteOf.
	Site string
	// IP is the destination.
	IP netip.Addr
	// Stable: the caller asks for a lookup, not a flow (the dns feature's
	// tunnel resolver). Choose with Stable changes nothing (no round-robin
	// step, no move of the current member, no trial) and gives one site the
	// same member while it is up: see chooseLocked.
	Stable bool
}

// SiteOf builds Hint.Site: rules.Site(decided) when the caller saw a real
// name for this connection (sniffed SNI/Host, a proxy's CONNECT host, a DNS
// query name); else the one site all cached names map to; else "". decided
// is never a rules.Result.Domain with DomainSrc == SrcDNS: that is a cache
// name (or several joined by ","). Never "the first cached name": the
// cache's names of an address are sorted across every unexpired name, so
// the first may belong to an unrelated site and change as names expire.
func SiteOf(decided string, cached []string) string {
	if decided != "" {
		return rules.Site(decided)
	}
	site := ""
	for _, n := range cached {
		s := rules.Site(n)
		switch {
		case s == "":
		case site == "":
			site = s
		case s != site:
			return "" // a shared address: key on the IP
		}
	}
	return site
}

// Pick is one decision.
type Pick struct {
	Group, Member string
	// Healthy is false when the member is merely usable (degraded: every
	// usable member is penalised).
	Healthy bool
	// Failover (statistics): the pick is degraded, or the member this
	// decision would otherwise use (the current one, the first for revert
	// or a new group, the sticky winner) was not usable or healthy.
	Failover bool
	// trial: this pick holds the member's half-open trial (TCP only);
	// claim is when it was claimed (Abandon releases only that claim).
	trial bool
	claim time.Time
}

// SwitchEvent is a change of a failover or latency group's current member.
type SwitchEvent struct{ Group, From, To, Reason string } // reason: unavailable | errors | probe | faster | primary back

// GroupHealth is a group's state for the UI (Snapshot).
type GroupHealth struct {
	// Active is the member a new TCP connection would get now (Peek), ""
	// when none is usable.
	Active string
	// Up counts the usable members.
	Up int
	// Members are the existing members, in list order.
	Members []MemberHealth
	// ProbeBroken: the probe URL failed through every member probed this
	// session (nobody is penalised for it).
	ProbeBroken bool
	// Rejected counts connections refused this session because no member
	// was usable.
	Rejected int64
}

// MemberHealth is one member's measurements and penalties.
type MemberHealth struct {
	ID         string
	Latency    time.Duration // EWMA, 0 = unknown
	Last       time.Duration
	ProbeAt    time.Time // zero = never
	ProbeError string
	Errors     int  // current failed-dial streak
	Skipped    bool // penalised now for this group
	Reason     string
}

type mode uint8

const (
	modePeek    mode = iota // Peek: TCP decision, nothing committed
	modePeekUDP             // PeekUDP
	modeTCP                 // Choose
	modeUDP                 // ChooseUDP
	modeReeval              // after NoteProbe: moves current only
)

func (m mode) udpLike() bool { return m == modeUDP || m == modePeekUDP || m == modeReeval }
func (m mode) commits() bool { return m == modeTCP || m == modeUDP || m == modeReeval }

// compiled is an immutable set of definitions (SetGroups swaps it).
type compiled struct {
	groups   map[string]*Group
	byMember map[string][]string // server ID -> IDs of the groups holding it
}

type groupState struct {
	strategy Strategy
	current  string // failover/latency: the member new connections go to
	rr       uint64
	rejected int64
}

type memberState struct {
	ewma, last    time.Duration
	measured      bool
	probeAt       time.Time
	probeErr      string
	probeFails    int
	failSince     time.Time // first failed probe of the current run
	lastOK        time.Time // last passed probe
	probed        bool      // probed this session (ProbeBroken)
	forceProbe    bool      // (re)connected: probe at once
	upSince       time.Time // zero = not up
	recoveredAt   time.Time // a penalty ended
	streak        int       // failed dials in a row, to distinct destinations
	lastErrDst    string
	lastErrAt     time.Time
	trialAt       time.Time // half-open trial in flight since
	penaltyLogged bool
}

// Runtime is the live selector, shared by the engine, local proxies, the
// prober and the UI. Its lock is innermost: nothing is called while it is
// held (usable callbacks run before, logs and OnSwitch after).
type Runtime struct {
	Log *slog.Logger
	// OnSwitch is optional; called without locks held.
	OnSwitch func(SwitchEvent)
	// Name resolves a member ID to its name for logs (nil = the ID).
	Name func(id string) string

	now   func() time.Time
	randN func(n int) int

	defs atomic.Pointer[compiled]

	mu    sync.Mutex
	grp   map[string]*groupState
	mem   map[string]*memberState
	every time.Duration // probe interval (peer window)
}

// NewRuntime returns a runtime without groups.
func NewRuntime(log *slog.Logger) *Runtime {
	if log == nil {
		log = slog.Default()
	}
	r := &Runtime{Log: log, now: time.Now, randN: rand.IntN, grp: map[string]*groupState{},
		mem: map[string]*memberState{}, every: DefaultInterval}
	r.defs.Store(&compiled{groups: map[string]*Group{}, byMember: map[string][]string{}})
	return r
}

func (r *Runtime) name(id string) string {
	if r.Name != nil {
		if n := r.Name(id); n != "" {
			return n
		}
	}
	return id
}

// SetGroups replaces the definitions atomically; members must already be
// existing servers. Member health is kept; a group's state is kept while
// its ID and strategy are unchanged, and a current member it no longer has
// is dropped. Connections decided before keep their member.
func (r *Runtime) SetGroups(list []Group) {
	c := &compiled{groups: make(map[string]*Group, len(list)), byMember: map[string][]string{}}
	for _, g := range list {
		g.Members = append([]string(nil), g.Members...)
		c.groups[g.ID] = &g
		for _, m := range g.Members {
			c.byMember[m] = append(c.byMember[m], g.ID)
		}
	}
	r.mu.Lock()
	for id, st := range r.grp {
		g := c.groups[id]
		if g == nil || g.Strategy != st.strategy {
			delete(r.grp, id)
			continue
		}
		if !contains(g.Members, st.current) {
			st.current = ""
		}
	}
	for id, g := range c.groups {
		if r.grp[id] == nil {
			r.grp[id] = &groupState{strategy: g.Strategy}
		}
	}
	r.defs.Store(c)
	r.mu.Unlock()
}

// SetInterval is the probe interval (how recent a peer's passed probe must
// be for a member's failures to count, ProbePeerWindow × interval).
func (r *Runtime) SetInterval(every time.Duration) {
	if every <= 0 {
		every = DefaultInterval
	}
	r.mu.Lock()
	r.every = every
	r.mu.Unlock()
}

// IsGroup reports a known group (after SetGroups).
func (r *Runtime) IsGroup(id string) bool { return r.defs.Load().groups[id] != nil }

// Members lists a group's existing members, nil if it is no group.
func (r *Runtime) Members(id string) []string {
	g := r.defs.Load().groups[id]
	if g == nil {
		return nil
	}
	return append([]string{}, g.Members...)
}

// Choose decides a TCP connection (intercepted or a local proxy's). It
// commits the round-robin step, the current member (never to a trial) and
// a trial claim, and logs a switch.
func (r *Runtime) Choose(group string, h Hint, usable func(id string) bool) (Pick, bool) {
	return r.choose(group, h, usable, modeTCP)
}

// ChooseUDP decides a UDP flow. It commits the round-robin step only: never
// the current member (a UDP-only miss must not move the group), never a
// trial (a UDP flow may reuse a session and never dial, so it could not
// settle one; a member waiting for its trial counts as penalised).
func (r *Runtime) ChooseUDP(group string, h Hint, usable func(id string) bool) (Pick, bool) {
	return r.choose(group, h, usable, modeUDP)
}

// Peek is Choose without any state change.
func (r *Runtime) Peek(group string, h Hint, usable func(id string) bool) (Pick, bool) {
	return r.choose(group, h, usable, modePeek)
}

// PeekUDP is ChooseUDP without any state change.
func (r *Runtime) PeekUDP(group string, h Hint, usable func(id string) bool) (Pick, bool) {
	return r.choose(group, h, usable, modePeekUDP)
}

func (r *Runtime) choose(group string, h Hint, usable func(id string) bool, m mode) (Pick, bool) {
	g := r.defs.Load().groups[group]
	if g == nil {
		return Pick{}, false
	}
	// The callback takes the tunnels' lock: evaluated before r.mu.
	us := make([]bool, len(g.Members))
	for i, id := range g.Members {
		us[i] = usable(id)
	}
	if h.Stable && m == modeTCP {
		m = modePeek
	} else if h.Stable && m == modeUDP {
		m = modePeekUDP
	}
	r.mu.Lock()
	p, ok, sw := r.chooseLocked(g, us, h, m)
	r.mu.Unlock()
	r.emit(sw)
	return p, ok
}

// streak states of a member for a group.
const (
	stOK = iota
	stPenalised
	stTrial // half-open: usable for one TCP connection
)

func (r *Runtime) streakState(st *memberState, sae int, m mode, now time.Time) int {
	switch {
	case sae == 0 || st.streak < sae:
		return stOK
	case now.Sub(st.lastErrAt) < PenaltyFor:
		return stPenalised
	case !st.trialAt.IsZero() && now.Sub(st.trialAt) < TrialTimeout:
		return stPenalised // a trial is in flight
	case m.udpLike():
		return stPenalised
	}
	return stTrial
}

// peerOK: another member of a group holding id passed the probe since id
// started failing, recently: the probe URL works, id is the problem.
func (r *Runtime) peerOK(id string, st *memberState, now time.Time) bool {
	c := r.defs.Load()
	window := ProbePeerWindow * r.every
	for _, gid := range c.byMember[id] {
		for _, p := range c.groups[gid].Members {
			if p == id {
				continue
			}
			ps := r.mem[p]
			if ps != nil && !ps.lastOK.IsZero() && !ps.lastOK.Before(st.failSince) && now.Sub(ps.lastOK) < window {
				return true
			}
		}
	}
	return false
}

func (r *Runtime) probeBad(id string, st *memberState, now time.Time) bool {
	return st.probeFails >= ProbeFailLimit && r.peerOK(id, st, now)
}

// state returns a member's state, a zero one when it has none (not
// stored).
func (r *Runtime) state(id string) *memberState {
	if st := r.mem[id]; st != nil {
		return st
	}
	return &memberState{}
}

// stateFor returns a member's state, creating it.
func (r *Runtime) stateFor(id string) *memberState {
	st := r.mem[id]
	if st == nil {
		st = &memberState{}
		r.mem[id] = st
	}
	return st
}

// eval is the health of one member in one decision.
type eval struct {
	usable, healthy, stable bool
	streak                  int
	probeBad                bool
}

func (r *Runtime) evalLocked(g *Group, us []bool, m mode, now time.Time) []eval {
	out := make([]eval, len(g.Members))
	for i, id := range g.Members {
		st := r.state(id)
		e := eval{usable: us[i], streak: r.streakState(st, g.SwitchAfterErrors, m, now), probeBad: r.probeBad(id, st, now)}
		e.healthy = e.usable && !e.probeBad && e.streak != stPenalised
		since := st.upSince
		if st.recoveredAt.After(since) {
			since = st.recoveredAt
		}
		e.stable = e.healthy && !st.upSince.IsZero() && now.Sub(since) >= RevertAfter
		out[i] = e
	}
	return out
}

// chooseLocked is the selection (r.mu held); it returns the switch to
// report once unlocked.
func (r *Runtime) chooseLocked(g *Group, us []bool, h Hint, m mode) (Pick, bool, *SwitchEvent) {
	now := r.now()
	gs := r.grp[g.ID]
	if gs == nil {
		gs = &groupState{strategy: g.Strategy}
		r.grp[g.ID] = gs
	}
	ev := r.evalLocked(g, us, m, now)
	var cand []int // indexes into g.Members
	healthy := true
	for i, e := range ev {
		if e.healthy {
			cand = append(cand, i)
		}
	}
	if len(cand) == 0 {
		healthy = false
		for i, e := range ev {
			if e.usable {
				cand = append(cand, i)
			}
		}
	}
	if len(cand) == 0 {
		return Pick{Group: g.ID}, false, nil
	}
	cur := -1
	for _, i := range cand {
		if g.Members[i] == gs.current {
			cur = i
		}
	}
	key, keyed := stickyKey(h)
	chosen := cand[0]
	switch g.Strategy {
	case Failover:
		// Revert: only a member earlier than current takes over again
		// (a later one stable first must not pull the group down the
		// list). Without current the group starts at the first
		// candidate.
		if cur >= 0 {
			chosen = cur
			if i := firstStable(cand, ev); g.Revert && i >= 0 && i < cur {
				chosen = i
			}
		}
	case Latency:
		chosen = r.latencyPick(g, cand, cur)
	default:
		if h.Stable {
			// A lookup: one site, one member while it is up.
			if h.Site != "" {
				chosen = rendezvous(g.Members, cand, "\x00"+h.Site)
			}
			break
		}
		switch g.Strategy {
		case RoundRobin:
			chosen = cand[gs.rr%uint64(len(cand))]
		case Random:
			chosen = cand[r.randN(len(cand))]
		case Sticky:
			if keyed {
				chosen = rendezvous(g.Members, cand, key)
			}
		}
	}
	p := Pick{Group: g.ID, Member: g.Members[chosen], Healthy: healthy}

	// Failover: pref is the member this pick would use if every member
	// were healthy.
	pref := -1
	all := make([]int, len(g.Members))
	for i := range all {
		all[i] = i
	}
	curAny := indexOf(g.Members, gs.current)
	switch g.Strategy {
	case Failover:
		pref = 0
		if !g.Revert && curAny >= 0 {
			pref = curAny
		}
	case Latency:
		pref = curAny
	case Sticky:
		pref = 0
		if h.Stable {
			if h.Site != "" {
				pref = rendezvous(g.Members, all, "\x00"+h.Site)
			}
		} else if keyed {
			pref = rendezvous(g.Members, all, key)
		}
	}
	if len(g.Members) == 0 {
		pref = -1
	}
	prefOK := pref >= 0 && ev[pref].healthy && (g.Strategy != Failover || !g.Revert || ev[pref].stable)
	p.Failover = !healthy || (pref >= 0 && chosen != pref && !prefOK)

	if !m.commits() {
		return p, true, nil
	}
	if m == modeTCP && ev[chosen].streak == stTrial {
		st := r.stateFor(p.Member)
		st.trialAt = now
		p.trial, p.claim = true, now
	}
	if (m == modeTCP || m == modeUDP) && g.Strategy == RoundRobin {
		gs.rr++
	}
	var sw *SwitchEvent
	if (m == modeTCP || m == modeReeval) && (g.Strategy == Failover || g.Strategy == Latency) && !p.trial && gs.current != p.Member {
		from := gs.current
		gs.current = p.Member
		if from != "" {
			sw = &SwitchEvent{Group: g.ID, From: from, To: p.Member, Reason: reason(g, from, ev)}
		}
	}
	return p, true, sw
}

// reason says why the group left from.
func reason(g *Group, from string, ev []eval) string {
	i := indexOf(g.Members, from)
	switch {
	case i < 0 || !ev[i].usable:
		return "unavailable"
	case ev[i].streak == stPenalised:
		return "errors"
	case ev[i].probeBad:
		return "probe"
	case g.Strategy == Latency:
		return "faster"
	}
	return "primary back"
}

func firstStable(cand []int, ev []eval) int {
	for _, i := range cand {
		if ev[i].stable {
			return i
		}
	}
	return -1
}

// latencyPick: the current member unless another one is faster by more
// than the tolerance (both measured) or the current one is not a
// candidate; then the lowest measured EWMA, unmeasured last, ties by list
// order.
func (r *Runtime) latencyPick(g *Group, cand []int, cur int) int {
	tol := time.Duration(g.ToleranceMs) * time.Millisecond
	if g.ToleranceMs == 0 {
		tol = DefaultToleranceMs * time.Millisecond
	}
	best := -1
	for _, i := range cand {
		st := r.state(g.Members[i])
		if !st.measured {
			continue
		}
		if best < 0 || st.ewma < r.state(g.Members[best]).ewma {
			best = i
		}
	}
	if cur >= 0 {
		cs := r.state(g.Members[cur])
		if best >= 0 && best != cur && cs.measured && r.state(g.Members[best]).ewma+tol < cs.ewma {
			return best
		}
		return cur
	}
	if best >= 0 {
		return best
	}
	return cand[0]
}

// stickyKey is the rendezvous key of a sticky decision: the program and
// the site, or the destination IP when no site is known.
func stickyKey(h Hint) (string, bool) {
	site := h.Site
	if site == "" && h.IP.IsValid() {
		site = h.IP.String()
	}
	if h.App == "" && site == "" {
		return "", false
	}
	return h.App + "\x00" + site, true
}

// rendezvous returns the index (into members) of the candidate with the
// highest score for key: a key moves only when its member goes.
func rendezvous(members []string, cand []int, key string) int {
	kh := fnv64a(key)
	best, bestScore := cand[0], uint64(0)
	for k, i := range cand {
		s := mix64(kh ^ fnv64a(members[i]))
		if k == 0 || s > bestScore {
			best, bestScore = i, s
		}
	}
	return best
}

func fnv64a(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// mix64 is the splitmix64 finaliser.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func indexOf(list []string, id string) int {
	if id == "" {
		return -1
	}
	for i, m := range list {
		if m == id {
			return i
		}
	}
	return -1
}

func contains(list []string, id string) bool { return indexOf(list, id) >= 0 }

// emit logs a switch and calls OnSwitch (no lock held).
func (r *Runtime) emit(sw *SwitchEvent) {
	if sw == nil {
		return
	}
	name := sw.Group
	if g := r.defs.Load().groups[sw.Group]; g != nil {
		name = g.Name
	}
	r.Log.Info("server group: switched", "group", name, "from", r.name(sw.From), "to", r.name(sw.To), "reason", sw.Reason)
	if r.OnSwitch != nil {
		r.OnSwitch(*sw)
	}
}

// Abandon releases the trial a pick holds when its connection was not
// dialled after all (refused after the choice). The round-robin step and a
// move of the current member stay.
func (r *Runtime) Abandon(p Pick) {
	if !p.trial {
		return
	}
	r.mu.Lock()
	if st := r.mem[p.Member]; st != nil && st.trialAt.Equal(p.claim) {
		st.trialAt = time.Time{}
	}
	r.mu.Unlock()
}

// NoteState reports a routing endpoint's state (never a temporary one): up
// from down starts its uptime, clears its penalties and asks for a probe;
// down clears the uptime and releases a trial in flight (its flow may have
// been refused because the member just went down).
func (r *Runtime) NoteState(member string, up bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.stateFor(member)
	switch {
	case up && st.upSince.IsZero():
		st.upSince = r.now()
		st.forceProbe = true
		st.probeFails, st.failSince = 0, time.Time{}
		st.streak, st.lastErrDst, st.trialAt, st.penaltyLogged = 0, "", time.Time{}, false
	case !up:
		st.upSince, st.trialAt = time.Time{}, time.Time{}
	}
}

// NoteDial reports a routing endpoint's dial (cancellations and check
// dials are filtered by the caller). A success clears the streak and a
// trial; a failure to a new destination adds to the streak, and a failed
// trial starts another PenaltyFor. The first result after a trial claim
// settles it, whatever its destination.
func (r *Runtime) NoteDial(member, dst string, err error) {
	var logs []string
	r.mu.Lock()
	now := r.now()
	st := r.stateFor(member)
	if err == nil {
		if !st.trialAt.IsZero() || st.streak >= 2 {
			st.recoveredAt = now
		}
		st.streak, st.lastErrDst, st.trialAt, st.penaltyLogged = 0, "", time.Time{}, false
		r.mu.Unlock()
		return
	}
	switch {
	case !st.trialAt.IsZero():
		st.trialAt, st.lastErrAt = time.Time{}, now
	case dst != st.lastErrDst:
		st.streak++
		st.lastErrDst, st.lastErrAt = dst, now
		c := r.defs.Load()
		for _, gid := range c.byMember[member] {
			if g := c.groups[gid]; g.SwitchAfterErrors > 0 && st.streak == g.SwitchAfterErrors {
				logs = append(logs, g.Name)
			}
		}
	}
	n := st.streak
	r.mu.Unlock()
	for _, g := range logs {
		r.Log.Info("server group: member skipped after N failed connections", "group", g, "member", r.name(member), "n", n)
	}
}

// NoteProbe records a probe result (never a cancelled one). It then
// re-evaluates the current member of the failover and latency groups
// holding member: it may only move the current member (logged), never
// claims a trial or steps round-robin, and a member waiting for its trial
// counts as penalised.
func (r *Runtime) NoteProbe(member string, rtt time.Duration, err error) {
	var sws []*SwitchEvent
	r.mu.Lock()
	now := r.now()
	st := r.stateFor(member)
	st.probeAt, st.probed, st.forceProbe = now, true, false
	if err == nil {
		if st.probeFails >= ProbeFailLimit {
			st.recoveredAt = now
		}
		st.probeFails, st.failSince, st.probeErr = 0, time.Time{}, ""
		st.last = rtt
		if st.measured {
			st.ewma = time.Duration(0.3*float64(rtt) + 0.7*float64(st.ewma))
		} else {
			st.ewma, st.measured = rtt, true
		}
		st.lastOK = now
	} else {
		if st.probeFails == 0 {
			st.failSince = now
		}
		st.probeFails++
		st.probeErr = bounded(err.Error(), 200)
	}
	c := r.defs.Load()
	for _, gid := range c.byMember[member] {
		g := c.groups[gid]
		if g.Strategy != Failover && g.Strategy != Latency {
			continue
		}
		us := make([]bool, len(g.Members))
		for i, id := range g.Members {
			us[i] = !r.state(id).upSince.IsZero()
		}
		if _, _, sw := r.chooseLocked(g, us, Hint{}, modeReeval); sw != nil {
			sws = append(sws, sw)
		}
	}
	r.mu.Unlock()
	for _, sw := range sws {
		r.emit(sw)
	}
}

func bounded(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// NoteRejected counts a connection refused because no member of a known
// group was usable.
func (r *Runtime) NoteRejected(group string) {
	r.mu.Lock()
	if gs := r.grp[group]; gs != nil && r.defs.Load().groups[group] != nil {
		gs.rejected++
	}
	r.mu.Unlock()
}

// ResetSession is called at connect: whatever could penalise a member or
// count failures starts over (streaks, trials, probe failures, uptime,
// rejected counters). Latency measurements and current members are kept,
// except the current member of failover groups with revert: every member
// has just come up, none is stable yet, and the session would otherwise
// start on the previous session's backup member.
func (r *Runtime) ResetSession() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, st := range r.mem {
		st.upSince, st.recoveredAt, st.failSince, st.trialAt = time.Time{}, time.Time{}, time.Time{}, time.Time{}
		st.streak, st.probeFails, st.lastErrDst, st.probed, st.penaltyLogged = 0, 0, "", false, false
	}
	c := r.defs.Load()
	for id, gs := range r.grp {
		gs.rejected = 0
		if g := c.groups[id]; g != nil && g.Strategy == Failover && g.Revert {
			gs.current = ""
		}
	}
}

// DueProbes returns the members to probe now: never probed, just
// (re)connected, or last probed at least every ago.
func (r *Runtime) DueProbes(members []string, every time.Duration) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if every > 0 {
		r.every = every
	}
	now := r.now()
	var out []string
	for _, m := range members {
		st := r.mem[m]
		if st == nil || st.forceProbe || st.probeAt.IsZero() || now.Sub(st.probeAt) >= r.every {
			out = append(out, m)
		}
	}
	return out
}

// Snapshot is a group's state for the UI: Active is Peek now with usable
// (not the last stored choice).
func (r *Runtime) Snapshot(id string, usable func(string) bool) GroupHealth {
	g := r.defs.Load().groups[id]
	if g == nil {
		return GroupHealth{}
	}
	us := make([]bool, len(g.Members))
	for i, m := range g.Members {
		us[i] = usable(m)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var h GroupHealth
	if p, ok, _ := r.chooseLocked(g, us, Hint{}, modePeek); ok {
		h.Active = p.Member
	}
	if gs := r.grp[id]; gs != nil {
		h.Rejected = gs.rejected
	}
	probed, broken := 0, 0
	for i, m := range g.Members {
		if us[i] {
			h.Up++
		}
		st := r.state(m)
		mh := MemberHealth{ID: m, Last: st.last, ProbeAt: st.probeAt, ProbeError: st.probeErr, Errors: st.streak}
		if st.measured {
			mh.Latency = st.ewma
		}
		if st.probed {
			probed++
			if st.probeFails >= ProbeFailLimit {
				broken++
			}
		}
		switch r.streakState(st, g.SwitchAfterErrors, modePeek, now) {
		case stPenalised:
			mh.Skipped, mh.Reason = true, "errors"
			if !st.trialAt.IsZero() && now.Sub(st.trialAt) < TrialTimeout {
				mh.Reason = "trial"
			}
		default:
			if r.probeBad(m, st, now) {
				mh.Skipped, mh.Reason = true, "probe"
			}
		}
		h.Members = append(h.Members, mh)
	}
	h.ProbeBroken = probed > 0 && broken == probed
	return h
}

// SetClock replaces the clock (tests of the packages that use groups).
func (r *Runtime) SetClock(now func() time.Time) {
	r.mu.Lock()
	r.now = now
	r.mu.Unlock()
}
