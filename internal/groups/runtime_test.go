package groups

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// rig is a runtime with a fake clock, a fake rand, a captured log and a
// fake "usable" (up[id], udp[id]).
type rig struct {
	*Runtime
	mu    sync.Mutex
	t     time.Time
	logs  bytes.Buffer
	up    map[string]bool
	udpNo map[string]bool
	rnd   int
}

func newRig(t *testing.T, gs ...Group) *rig {
	t.Helper()
	g := &rig{t: time.Unix(1_000_000, 0), up: map[string]bool{}, udpNo: map[string]bool{}}
	g.Runtime = NewRuntime(slog.New(slog.NewTextHandler(&lockedWriter{w: &g.logs, mu: &g.mu}, nil)))
	g.now = func() time.Time { g.mu.Lock(); defer g.mu.Unlock(); return g.t }
	g.randN = func(n int) int { g.mu.Lock(); defer g.mu.Unlock(); return g.rnd % n }
	g.SetGroups(gs)
	return g
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

func (g *rig) advance(d time.Duration) { g.mu.Lock(); g.t = g.t.Add(d); g.mu.Unlock() }
func (g *rig) usable(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.up[id]
}
func (g *rig) usableUDP(id string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.up[id] && !g.udpNo[id]
}

// set marks members up (NoteState too) or down.
func (g *rig) set(up bool, ids ...string) {
	for _, id := range ids {
		g.mu.Lock()
		g.up[id] = up
		g.mu.Unlock()
		g.NoteState(id, up)
	}
}

func (g *rig) switches() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return strings.Count(g.logs.String(), "server group: switched")
}

func (g *rig) choose(t *testing.T, id string) Pick {
	t.Helper()
	p, ok := g.Choose(id, Hint{}, g.usable)
	if !ok {
		t.Fatalf("Choose(%s): nothing usable", id)
	}
	return p
}

func (g *rig) current(id string) string {
	g.Runtime.mu.Lock()
	defer g.Runtime.mu.Unlock()
	if gs := g.grp[id]; gs != nil {
		return gs.current
	}
	return ""
}

func (g *rig) rr(id string) uint64 {
	g.Runtime.mu.Lock()
	defer g.Runtime.mu.Unlock()
	return g.grp[id].rr
}

var errDial = errors.New("socks5: host unreachable")

const gid = "grp-000000000001"

func TestFailoverOrder(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Failover, Members: []string{"a", "b", "c"}})
	g.set(true, "a", "b", "c")
	if p := g.choose(t, gid); p.Member != "a" || !p.Healthy || p.Failover {
		t.Fatalf("%+v", p)
	}
	g.set(false, "a")
	if p := g.choose(t, gid); p.Member != "b" || !p.Failover {
		t.Fatalf("%+v", p)
	}
	// No revert: stays on b once a is back.
	g.set(true, "a")
	g.advance(time.Hour)
	if p := g.choose(t, gid); p.Member != "b" || p.Failover {
		t.Fatalf("no revert: %+v", p)
	}
	g.set(false, "a", "b", "c")
	if _, ok := g.Choose(gid, Hint{}, g.usable); ok {
		t.Fatal("nothing usable must fail")
	}
	if _, ok := g.Choose("grp-00000000000f", Hint{}, g.usable); ok {
		t.Fatal("unknown group")
	}
}

func TestFailoverRevertAfterUptime(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Failover, Revert: true, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	g.advance(time.Minute)
	if p := g.choose(t, gid); p.Member != "a" || p.Failover {
		t.Fatalf("%+v", p)
	}
	g.set(false, "a")
	if p := g.choose(t, gid); p.Member != "b" || !p.Failover {
		t.Fatalf("%+v", p)
	}
	g.set(true, "a")
	g.advance(RevertAfter - time.Second)
	if p := g.choose(t, gid); p.Member != "b" || !p.Failover {
		t.Fatalf("a not stable yet: %+v", p)
	}
	g.advance(time.Second)
	if p := g.choose(t, gid); p.Member != "a" || p.Failover {
		t.Fatalf("revert: %+v", p)
	}
	if g.switches() != 2 || !strings.Contains(g.logs.String(), "reason=\"primary back\"") {
		t.Fatal(g.logs.String())
	}
}

// Revert only returns to an earlier member: a later one that connected
// first and became stable first never pulls the group off the first.
func TestRevertOnlyToEarlier(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Failover, Revert: true, Members: []string{"a", "b", "c"}})
	g.set(true, "b", "c")
	g.advance(time.Second)
	g.set(true, "a")
	if p := g.choose(t, gid); p.Member != "a" || p.Failover {
		t.Fatalf("%+v", p)
	}
	g.advance(RevertAfter - time.Second) // b stable, a not yet
	if p := g.choose(t, gid); p.Member != "a" || p.Failover {
		t.Fatalf("moved to a later stable member: %+v", p)
	}
	g.NoteProbe("a", 50*time.Millisecond, nil) // a re-evaluation neither
	g.advance(time.Second)
	if p := g.choose(t, gid); p.Member != "a" || p.Failover {
		t.Fatalf("%+v", p)
	}
	// a and b down: on c; b stable again is earlier, so it takes over.
	g.set(false, "a", "b")
	if p := g.choose(t, gid); p.Member != "c" {
		t.Fatalf("%+v", p)
	}
	g.set(true, "b")
	g.advance(RevertAfter)
	if p := g.choose(t, gid); p.Member != "b" {
		t.Fatalf("%+v", p)
	}
	if g.switches() != 2 {
		t.Fatal(g.logs.String())
	}
}

// Revert measures healthy time, not uptime: a penalty resets it.
func TestRevertMeasuresHealthyTime(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Failover, Revert: true, SwitchAfterErrors: 2, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	g.advance(10 * time.Minute)
	g.choose(t, gid)
	// a fails its probes while b passes: peer-confirmed, a is skipped.
	g.NoteProbe("a", 0, errDial)
	g.NoteProbe("b", 40*time.Millisecond, nil)
	g.advance(time.Second)
	g.NoteProbe("a", 0, errDial)
	if p := g.choose(t, gid); p.Member != "b" {
		t.Fatalf("a not skipped: %+v", p)
	}
	g.advance(time.Second)
	g.NoteProbe("a", 30*time.Millisecond, nil)
	g.advance(RevertAfter - time.Second)
	if p := g.choose(t, gid); p.Member != "b" {
		t.Fatalf("reverted before RevertAfter after the probe: %+v", p)
	}
	g.advance(time.Second)
	if p := g.choose(t, gid); p.Member != "a" {
		t.Fatalf("not reverted: %+v", p)
	}

	// The same after a trial success ends an error-streak penalty.
	g.NoteDial("a", "x:1", errDial)
	g.NoteDial("a", "y:1", errDial)
	if p := g.choose(t, gid); p.Member != "b" {
		t.Fatalf("streak: %+v", p)
	}
	g.advance(PenaltyFor)
	if p := g.choose(t, gid); p.Member != "a" || !p.trial {
		t.Fatalf("trial: %+v", p)
	}
	g.NoteDial("a", "z:1", nil)
	g.advance(RevertAfter - time.Second)
	if p := g.choose(t, gid); p.Member != "b" {
		t.Fatalf("reverted right after the trial: %+v", p)
	}
	g.advance(time.Second)
	if p := g.choose(t, gid); p.Member != "a" {
		t.Fatalf("not reverted after the trial: %+v", p)
	}
}

// A member whose probes go fail-fail-pass faster than RevertAfter never
// becomes stable.
func TestRevertFlappingProbes(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Failover, Revert: true, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	g.advance(10 * time.Minute)
	for range 20 {
		g.NoteProbe("b", 10*time.Millisecond, nil)
		g.NoteProbe("a", 0, errDial)
		g.advance(8 * time.Second)
		g.NoteProbe("b", 10*time.Millisecond, nil)
		g.NoteProbe("a", 0, errDial)
		g.advance(8 * time.Second)
		g.NoteProbe("a", 10*time.Millisecond, nil)
		g.advance(8 * time.Second)
		if p := g.choose(t, gid); p.Member != "b" {
			t.Fatalf("a became stable: %+v", p)
		}
	}
}

func TestLatency(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Latency, Members: []string{"a", "b", "c"}})
	g.set(true, "a", "b", "c")
	// Unmeasured members come last; a new group's first pick is no failover.
	g.NoteProbe("b", 100*time.Millisecond, nil)
	if p := g.choose(t, gid); p.Member != "b" || p.Failover {
		t.Fatalf("%+v", p)
	}
	g.NoteProbe("c", 80*time.Millisecond, nil)
	if p := g.choose(t, gid); p.Member != "b" {
		t.Fatalf("switched within tolerance: %+v", p)
	}
	g.NoteProbe("a", 20*time.Millisecond, nil)
	if p := g.choose(t, gid); p.Member != "a" || p.Failover {
		t.Fatalf("faster is no failover: %+v", p)
	}
	g.set(false, "a")
	if p := g.choose(t, gid); p.Member != "c" || !p.Failover {
		t.Fatalf("current unusable: %+v", p)
	}
}

func TestRoundRobinAndRandom(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "RR", Strategy: RoundRobin, Members: []string{"a", "b", "c"}},
		Group{ID: "grp-000000000002", Name: "R", Strategy: Random, Members: []string{"a", "b", "c"}})
	g.set(true, "a", "c")
	var got []string
	for range 4 {
		p := g.choose(t, gid)
		if p.Failover {
			t.Fatal("round robin is never a failover while healthy")
		}
		got = append(got, p.Member)
	}
	if strings.Join(got, "") != "acac" {
		t.Fatal(got)
	}
	g.rnd = 1
	if p := g.choose(t, "grp-000000000002"); p.Member != "c" || p.Failover {
		t.Fatalf("%+v", p)
	}
}

func TestSticky(t *testing.T) {
	members := []string{"a", "b", "c", "d"}
	g := newRig(t, Group{ID: gid, Name: "S", Strategy: Sticky, Members: members})
	g.set(true, members...)
	hint := func(i int) Hint { return Hint{App: `c:\chrome.exe`, Site: fmt.Sprintf("site%d.com", i)} }
	before := map[int]string{}
	for i := range 1000 {
		p, _ := g.Choose(gid, hint(i), g.usable)
		q, _ := g.Choose(gid, hint(i), g.usable)
		if p.Member != q.Member || p.Failover {
			t.Fatalf("key %d: %s then %s", i, p.Member, q.Member)
		}
		before[i] = p.Member
	}
	// b leaves the group: only its keys move.
	g.SetGroups([]Group{{ID: gid, Name: "S", Strategy: Sticky, Members: []string{"a", "c", "d"}}})
	moved := 0
	for i := range 1000 {
		p, _ := g.Choose(gid, hint(i), g.usable)
		switch {
		case before[i] == "b":
			moved++
		case p.Member != before[i]:
			t.Fatalf("key %d moved from %s to %s", i, before[i], p.Member)
		}
	}
	if moved < 150 || moved > 350 {
		t.Fatalf("%d of 1000 keys were on b", moved)
	}
	// A member going down moves its keys, marked as failovers.
	g.set(false, "a")
	for i := range 1000 {
		if before[i] != "a" {
			continue
		}
		if p, _ := g.Choose(gid, hint(i), g.usable); p.Member == "a" || !p.Failover {
			t.Fatalf("%+v", p)
		}
	}
	// No key at all: the first candidate.
	if p, _ := g.Choose(gid, Hint{}, g.usable); p.Member != "c" {
		t.Fatalf("%+v", p)
	}
	// The IP stands in for the site.
	ip := Hint{App: "x", IP: netip.MustParseAddr("192.0.2.1")}
	p1, _ := g.Choose(gid, ip, g.usable)
	p2, _ := g.Choose(gid, ip, g.usable)
	if p1.Member != p2.Member {
		t.Fatal("IP key unstable")
	}
}

func TestErrorStreak(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Failover, SwitchAfterErrors: 3, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	g.choose(t, gid)
	// The same destination again does not count.
	for range 5 {
		g.NoteDial("a", "x:443", errDial)
	}
	g.NoteDial("a", "y:443", errDial)
	if p := g.choose(t, gid); p.Member != "a" {
		t.Fatalf("2 distinct errors skipped a: %+v", p)
	}
	// A success resets.
	g.NoteDial("a", "z:443", nil)
	g.NoteDial("a", "x:443", errDial)
	g.NoteDial("a", "y:443", errDial)
	if p := g.choose(t, gid); p.Member != "a" {
		t.Fatalf("%+v", p)
	}
	g.NoteDial("a", "z:443", errDial)
	if p := g.choose(t, gid); p.Member != "b" || !p.Failover {
		t.Fatalf("3 errors: %+v", p)
	}
	if !strings.Contains(g.logs.String(), "member skipped after N failed connections") || !strings.Contains(g.logs.String(), "reason=errors") {
		t.Fatal(g.logs.String())
	}
	g.advance(PenaltyFor - time.Second)
	if p, _ := g.Peek(gid, Hint{}, g.usable); p.Member != "b" {
		t.Fatalf("penalty shorter than PenaltyFor: %+v", p)
	}
	g.advance(time.Second)
	// Half-open: the member is back for one connection (no revert: the
	// failover group stays on b, so pick a without it by taking b down).
	g.set(false, "b")
	if p := g.choose(t, gid); p.Member != "a" || !p.trial {
		t.Fatalf("trial: %+v", p)
	}
}

func halfOpen(t *testing.T) *rig {
	t.Helper()
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: RoundRobin, SwitchAfterErrors: 2, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	g.NoteDial("a", "x:1", errDial)
	g.NoteDial("a", "y:1", errDial)
	g.advance(PenaltyFor)
	return g
}

// countA counts picks of a in n Choose calls.
func countA(t *testing.T, g *rig, n int) (a int, trial int) {
	for range n {
		p := g.choose(t, gid)
		if p.Member == "a" {
			a++
			if p.trial {
				trial++
			}
		}
	}
	return a, trial
}

func TestHalfOpenTrial(t *testing.T) {
	g := halfOpen(t)
	// Peeks never claim it.
	for range 5 {
		g.Peek(gid, Hint{}, g.usable)
		g.PeekUDP(gid, Hint{}, g.usable)
	}
	// ChooseUDP never claims it, never uses a while b is healthy.
	for range 10 {
		if p, _ := g.ChooseUDP(gid, Hint{}, g.usable); p.Member != "b" || p.trial {
			t.Fatalf("UDP: %+v", p)
		}
	}
	// 50 concurrent Choose calls: exactly one gets a (its trial).
	var wg sync.WaitGroup
	var mu sync.Mutex
	var picks []Pick
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, _ := g.Choose(gid, Hint{}, g.usable)
			mu.Lock()
			picks = append(picks, p)
			mu.Unlock()
		}()
	}
	wg.Wait()
	var trial Pick
	n := 0
	for _, p := range picks {
		if p.Member == "a" {
			n++
			trial = p
		}
	}
	if n != 1 || !trial.trial {
		t.Fatalf("%d picks of a", n)
	}
	// No result: after TrialTimeout exactly one new trial.
	g.advance(TrialTimeout - time.Second)
	if a, _ := countA(t, g, 10); a != 0 {
		t.Fatal("second trial before TrialTimeout")
	}
	g.advance(time.Second)
	if a, tr := countA(t, g, 10); a != 1 || tr != 1 {
		t.Fatalf("after TrialTimeout: %d picks, %d trials", a, tr)
	}
	// Abandon frees it at once.
	g.advance(TrialTimeout)
	p := Pick{}
	for p.Member != "a" {
		p = g.choose(t, gid)
	}
	g.Abandon(p)
	if a, tr := countA(t, g, 4); a != 1 || tr != 1 {
		t.Fatalf("after Abandon: %d picks, %d trials", a, tr)
	}
	// A member going down frees it too; coming back up clears the streak.
	g.set(false, "a")
	g.set(true, "a")
	if a, tr := countA(t, g, 4); a != 2 || tr != 0 {
		t.Fatalf("after reconnect: %d picks, %d trials", a, tr)
	}
}

func TestHalfOpenResult(t *testing.T) {
	g := halfOpen(t)
	p := Pick{}
	for p.Member != "a" {
		p = g.choose(t, gid)
	}
	// A failed trial: another PenaltyFor.
	g.NoteDial("a", "z:1", errDial)
	g.advance(PenaltyFor - time.Second)
	if a, _ := countA(t, g, 10); a != 0 {
		t.Fatal("a used during the new penalty")
	}
	g.advance(time.Second)
	p = Pick{}
	for p.Member != "a" {
		p = g.choose(t, gid)
	}
	if !p.trial {
		t.Fatal("no trial after the new penalty")
	}
	// A passed trial: a is back for everyone.
	g.NoteDial("a", "w:1", nil)
	if a, tr := countA(t, g, 10); a != 5 || tr != 0 {
		t.Fatalf("after success: %d picks, %d trials", a, tr)
	}
	// NoteState(down) frees a claim.
	g.NoteDial("a", "x:1", errDial)
	g.NoteDial("a", "y:1", errDial)
	g.advance(PenaltyFor)
	p = Pick{}
	for p.Member != "a" {
		p = g.choose(t, gid)
	}
	g.mu.Lock()
	g.up["a"] = false
	g.mu.Unlock()
	g.NoteState("a", false)
	g.Runtime.mu.Lock()
	freed := g.mem["a"].trialAt.IsZero()
	g.Runtime.mu.Unlock()
	if !freed {
		t.Fatal("NoteState(down) kept the trial")
	}
}

// A trial pick never moves the current member.
func TestTrialDoesNotMoveCurrent(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Latency, SwitchAfterErrors: 2, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	g.NoteProbe("b", 100*time.Millisecond, nil)
	g.NoteProbe("a", 10*time.Millisecond, nil)
	g.NoteDial("a", "x:1", errDial)
	g.NoteDial("a", "y:1", errDial)
	if p := g.choose(t, gid); p.Member != "b" {
		t.Fatalf("%+v", p)
	}
	sw := g.switches()
	g.advance(PenaltyFor)
	if p := g.choose(t, gid); p.Member != "a" || !p.trial {
		t.Fatalf("%+v", p)
	}
	if g.current(gid) != "b" || g.switches() != sw {
		t.Fatalf("trial moved current to %s", g.current(gid))
	}
	if p := g.choose(t, gid); p.Member != "b" {
		t.Fatalf("%+v", p)
	}
	g.NoteDial("a", "z:1", nil)
	if p := g.choose(t, gid); p.Member != "a" || g.current(gid) != "a" || g.switches() != sw+1 {
		t.Fatalf("%+v current %s", p, g.current(gid))
	}
}

// Re-evaluations after a probe never claim a trial, never step round
// robin, and count a member waiting for its trial as penalised.
func TestReevalAfterProbe(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "L", Strategy: Latency, SwitchAfterErrors: 2, Members: []string{"a", "b"}},
		Group{ID: "grp-000000000002", Name: "RR", Strategy: RoundRobin, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	g.NoteProbe("b", 100*time.Millisecond, nil)
	g.choose(t, gid)
	g.NoteDial("a", "x:1", errDial)
	g.NoteDial("a", "y:1", errDial)
	sw := g.switches()
	// a is faster but fails every trial, for 5 minutes of probes.
	for range 10 {
		g.advance(PenaltyFor / 2)
		g.NoteProbe("a", 10*time.Millisecond, nil)
		g.NoteProbe("b", 100*time.Millisecond, nil)
		if g.current(gid) != "b" {
			t.Fatal("re-evaluation moved current to a member waiting for its trial")
		}
		g.Runtime.mu.Lock()
		claimed := !g.mem["a"].trialAt.IsZero()
		g.Runtime.mu.Unlock()
		if claimed {
			t.Fatal("re-evaluation claimed the trial")
		}
		if p, _ := g.Choose(gid, Hint{}, g.usable); p.Member == "a" {
			g.NoteDial("a", "z:1", errDial)
		}
	}
	if g.switches() != sw || g.rr("grp-000000000002") != 0 {
		t.Fatalf("switches %d rr %d", g.switches()-sw, g.rr("grp-000000000002"))
	}
	// A probe that makes the current member unhealthy moves current at once.
	g.NoteDial("a", "w:1", nil)
	g.choose(t, gid) // current = a
	if g.current(gid) != "a" {
		t.Fatal(g.current(gid))
	}
	sw = g.switches()
	g.NoteProbe("a", 0, errDial)
	g.NoteProbe("b", 100*time.Millisecond, nil)
	g.NoteProbe("a", 0, errDial)
	if g.current(gid) != "b" || g.switches() != sw+1 || !strings.Contains(g.logs.String(), "reason=probe") {
		t.Fatalf("current %s switches %d", g.current(gid), g.switches()-sw)
	}
}

func TestProbePenalty(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Failover, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	// Everyone fails: the probe URL is the problem, nobody is penalised.
	for range 3 {
		g.NoteProbe("a", 0, errDial)
		g.NoteProbe("b", 0, errDial)
	}
	if p := g.choose(t, gid); p.Member != "a" || !p.Healthy {
		t.Fatalf("%+v", p)
	}
	if h := g.Snapshot(gid, g.usable); !h.ProbeBroken || h.Members[0].Skipped {
		t.Fatalf("%+v", h)
	}
	// b passes after a's first failure: a's failures count.
	// The re-evaluation after the probe moves the group, not a flow.
	g.NoteProbe("b", 50*time.Millisecond, nil)
	if p := g.choose(t, gid); p.Member != "b" || p.Failover || g.current(gid) != "b" {
		t.Fatalf("%+v", p)
	}
	if h := g.Snapshot(gid, g.usable); h.ProbeBroken || !h.Members[0].Skipped || h.Members[0].Reason != "probe" {
		t.Fatalf("%+v", h)
	}
	// b's success too old: no longer a peer.
	g.advance(ProbePeerWindow * DefaultInterval)
	if p, _ := g.Peek(gid, Hint{}, g.usable); p.Member != "b" {
		// failover without revert stays on b anyway; check health instead.
		t.Fatalf("%+v", p)
	}
	if h := g.Snapshot(gid, g.usable); h.Members[0].Skipped {
		t.Fatal("a stale peer success still penalises a")
	}
	// Reconnecting clears a's failures.
	g.NoteProbe("b", 50*time.Millisecond, nil)
	g.set(false, "a")
	g.set(true, "a")
	if h := g.Snapshot(gid, g.usable); h.Members[0].Skipped {
		t.Fatal("NoteState(up) kept probe failures")
	}
	if due := g.DueProbes([]string{"a", "b"}, time.Minute); len(due) != 1 || due[0] != "a" {
		t.Fatalf("due %v", due)
	}
}

func TestResetSession(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "L", Strategy: Latency, SwitchAfterErrors: 2, Members: []string{"a", "b"}},
		Group{ID: "grp-000000000002", Name: "F", Strategy: Failover, Revert: true, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	g.NoteProbe("a", 10*time.Millisecond, nil)
	g.choose(t, gid)
	g.set(false, "a")
	g.choose(t, "grp-000000000002") // current b
	g.NoteRejected(gid)
	g.NoteDial("b", "x:1", errDial)
	g.NoteDial("b", "y:1", errDial)
	g.ResetSession()
	g.set(true, "a", "b")
	h := g.Snapshot(gid, g.usable)
	if h.Rejected != 0 || h.Members[1].Errors != 0 || h.Members[0].Latency != 10*time.Millisecond {
		t.Fatalf("%+v", h)
	}
	if g.current(gid) != "a" {
		t.Fatal("latency current dropped")
	}
	if p := g.choose(t, "grp-000000000002"); p.Member != "a" || p.Failover {
		t.Fatalf("revert group after reset: %+v", p)
	}
}

func TestPickFailover(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "G", Strategy: Failover, SwitchAfterErrors: 2, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	g.NoteDial("a", "x:1", errDial)
	g.NoteDial("a", "y:1", errDial)
	g.NoteDial("b", "x:1", errDial)
	g.NoteDial("b", "y:1", errDial)
	// Degraded: every member penalised but running.
	if p := g.choose(t, gid); p.Healthy || !p.Failover || p.Member != "a" {
		t.Fatalf("%+v", p)
	}
	// UDP skipping a UDP-less current member.
	l := newRig(t, Group{ID: gid, Name: "L", Strategy: Latency, Members: []string{"a", "b"}})
	l.set(true, "a", "b")
	l.NoteProbe("a", 10*time.Millisecond, nil)
	l.choose(t, gid)
	l.udpNo["a"] = true
	if p, _ := l.ChooseUDP(gid, Hint{}, l.usableUDP); p.Member != "b" || !p.Failover {
		t.Fatalf("%+v", p)
	}
	if l.current(gid) != "a" {
		t.Fatal("ChooseUDP moved current")
	}
}

func TestPeekAndSetGroups(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "RR", Strategy: RoundRobin, Members: []string{"a", "b"}})
	g.set(true, "a", "b")
	for range 5 {
		g.Peek(gid, Hint{}, g.usable)
		g.PeekUDP(gid, Hint{}, g.usable)
	}
	if g.rr(gid) != 0 {
		t.Fatal("Peek stepped round robin")
	}
	g.choose(t, gid)
	g.NoteProbe("a", 10*time.Millisecond, nil)
	// Same strategy: state kept; another strategy: reset; health kept.
	g.SetGroups([]Group{{ID: gid, Name: "RR2", Strategy: RoundRobin, Members: []string{"a", "b"}}})
	if g.rr(gid) != 1 {
		t.Fatal("state lost")
	}
	g.SetGroups([]Group{{ID: gid, Name: "L", Strategy: Latency, Members: []string{"b", "a"}}})
	if g.rr(gid) != 0 {
		t.Fatal("state kept across a strategy change")
	}
	if h := g.Snapshot(gid, g.usable); h.Members[1].Latency != 10*time.Millisecond {
		t.Fatalf("%+v", h)
	}
	// Snapshot.Active is the member a connection gets now.
	g.choose(t, gid)
	g.mu.Lock()
	g.up["a"] = false
	g.mu.Unlock()
	if h := g.Snapshot(gid, g.usable); h.Active != "b" || h.Up != 1 {
		t.Fatalf("%+v", h)
	}
	g.NoteRejected(gid)
	g.NoteRejected("grp-00000000000f")
	if h := g.Snapshot(gid, g.usable); h.Rejected != 1 {
		t.Fatalf("%+v", h)
	}
	if g.IsGroup("grp-00000000000f") || !g.IsGroup(gid) || len(g.Members(gid)) != 2 || g.Members("x") != nil {
		t.Fatal("IsGroup/Members")
	}
}

// Stable lookups change nothing and keep one site on one member.
func TestChooseStable(t *testing.T) {
	members := []string{"a", "b", "c"}
	g := newRig(t,
		Group{ID: "grp-000000000001", Name: "RR", Strategy: RoundRobin, Members: members},
		Group{ID: "grp-000000000002", Name: "R", Strategy: Random, Members: members},
		Group{ID: "grp-000000000003", Name: "S", Strategy: Sticky, Members: members},
		Group{ID: "grp-000000000004", Name: "F", Strategy: Failover, SwitchAfterErrors: 2, Members: members},
		Group{ID: "grp-000000000005", Name: "L", Strategy: Latency, Members: members})
	g.set(true, members...)
	g.NoteProbe("b", 5*time.Millisecond, nil)
	g.NoteDial("a", "x:1", errDial)
	g.NoteDial("a", "y:1", errDial)
	g.advance(PenaltyFor) // a waits for its trial
	sw := g.switches()
	g.Runtime.mu.Lock()
	cur0 := g.grp["grp-000000000004"].current + g.grp["grp-000000000005"].current
	g.Runtime.mu.Unlock()
	for i := range 1000 {
		g.mu.Lock()
		g.rnd = i
		g.mu.Unlock()
		site := fmt.Sprintf("s%d.com", i%10)
		var got []string
		for _, id := range []string{"grp-000000000001", "grp-000000000002", "grp-000000000003"} {
			p, ok := g.Choose(id, Hint{App: "hyroute:dns", Site: site, Stable: true}, g.usable)
			if !ok {
				t.Fatal("nothing chosen")
			}
			got = append(got, p.Member)
		}
		if got[0] != got[1] || got[1] != got[2] {
			t.Fatalf("site %s: %v", site, got)
		}
		for _, id := range []string{"grp-000000000004", "grp-000000000005"} {
			p, _ := g.Choose(id, Hint{Site: site, Stable: true}, g.usable)
			q, _ := g.Peek(id, Hint{}, g.usable)
			if p.Member != q.Member {
				t.Fatalf("%s: %s, Peek %s", id, p.Member, q.Member)
			}
		}
	}
	g.Runtime.mu.Lock()
	claimed := !g.mem["a"].trialAt.IsZero()
	rr := g.grp["grp-000000000001"].rr
	cur := g.grp["grp-000000000004"].current + g.grp["grp-000000000005"].current
	g.Runtime.mu.Unlock()
	if claimed || rr != 0 || cur != cur0 || g.switches() != sw {
		t.Fatalf("state changed: trial %v rr %d current %q", claimed, rr, cur)
	}
}

// Everything at once under -race.
func TestRuntimeConcurrent(t *testing.T) {
	g := newRig(t, Group{ID: gid, Name: "L", Strategy: Latency, SwitchAfterErrors: 2, Members: []string{"a", "b", "c"}})
	g.set(true, "a", "b", "c")
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 300 {
				m := []string{"a", "b", "c"}[i%3]
				switch w % 4 {
				case 0:
					if p, ok := g.Choose(gid, Hint{App: "x", Site: "s.com"}, g.usable); ok && i%7 == 0 {
						g.Abandon(p)
					}
					g.ChooseUDP(gid, Hint{}, g.usable)
				case 1:
					g.NoteDial(m, fmt.Sprint(i), errDial)
					g.NoteDial(m, "ok", nil)
				case 2:
					g.NoteProbe(m, time.Duration(i)*time.Millisecond, nil)
					g.Snapshot(gid, g.usable)
				case 3:
					g.SetGroups([]Group{{ID: gid, Name: "L", Strategy: Latency, SwitchAfterErrors: 2, Members: []string{"a", "b", "c"}}})
					g.NoteState(m, i%2 == 0)
					g.advance(time.Second)
				}
			}
		}()
	}
	wg.Wait()
}
