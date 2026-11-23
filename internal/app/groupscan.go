package app

import (
	"context"
	"net"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
)

// Large groups. A group of more than groups.MaxRunning members (all the
// servers of a subscription: hundreds) does not run them all — a process
// each would take the computer down. Its chosen members run (groupRun,
// the best by the measurements); the scanner measures the others a few at
// a time through temporary endpoints, the way «Проверить» does, and swaps
// in a better one. A member that failed its measurement waits a while
// before it is measured again.

var (
	groupScanEvery   = 20 * time.Second // a scanner round
	groupScanBatch   = 4                // temporary endpoints at once, all groups together
	groupScanStale   = 30 * time.Minute // a measurement older than this is taken again
	groupScanBadWait = time.Hour        // a member that failed is measured again after this
)

// groupScanState is the Controller's part (c.mu).
type groupScanState struct {
	// groupRun: the chosen members of each large group (they run while
	// the group is used); kept across sessions.
	groupRun map[string][]string
	// scanned: when a member was last measured by the scanner, and
	// whether it answered.
	scanned map[string]scanResult
}

type scanResult struct {
	at time.Time
	ok bool
}

// runMembersLocked: the members of g that run while it is used: every one
// of a group of at most groups.MaxRunning, else its chosen ones.
func (c *Controller) runMembersLocked(g *groups.Group) []string {
	all := c.membersLocked(g)
	if len(all) <= groups.MaxRunning {
		return all
	}
	return c.chosenLocked(g.ID, all)
}

// chosenLocked keeps the chosen members that are still members and fills
// up to MaxRunning in list order, passing over members whose last
// measurement failed.
func (c *Controller) chosenLocked(gid string, all []string) []string {
	in := make(map[string]bool, len(all))
	for _, m := range all {
		in[m] = true
	}
	var out []string
	for _, m := range c.groupRun[gid] {
		if in[m] && len(out) < groups.MaxRunning {
			out = append(out, m)
		}
	}
	now := time.Now()
	for _, pass := range []bool{false, true} {
		for _, m := range all {
			if len(out) >= groups.MaxRunning {
				return out
			}
			r, seen := c.scanned[m]
			bad := seen && !r.ok && now.Sub(r.at) < groupScanBadWait
			if bad == pass && !slices.Contains(out, m) {
				out = append(out, m)
			}
		}
	}
	return out
}

// scanGroups is the scanner of a session (startProber): it ends with ctx.
func (c *Controller) scanGroups(ctx context.Context) {
	t := time.NewTicker(groupScanEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c.scanRound(ctx)
	}
}

// scanRound measures up to groupScanBatch members of the used large
// groups that do not run and were not measured lately, then chooses each
// group's running members again.
func (c *Controller) scanRound(ctx context.Context) {
	c.mu.Lock()
	sess := c.sess
	if sess == nil || c.groupsBroken != nil {
		c.mu.Unlock()
		return
	}
	set, _, used := c.routingLocked()
	direct := map[string]bool{}
	for _, id := range set.Profiles() {
		direct[id] = true
	}
	for _, p := range c.proxies {
		if p.Enabled {
			direct[c.proxyProfileLocked(p)] = true
		}
	}
	var todo []hysteria.Profile
	large := map[string][]string{}
	now := time.Now()
	for _, gid := range used {
		g := c.groupLocked(gid)
		if g == nil {
			continue
		}
		all := c.membersLocked(g)
		if !direct[gid] {
			all = c.chainGroupMembersLocked(g, "")
		}
		if len(all) <= groups.MaxRunning {
			continue
		}
		large[gid] = all
		running := c.chosenLocked(gid, all)
		for _, m := range all {
			if len(todo) >= groupScanBatch {
				break
			}
			if slices.Contains(running, m) || slices.ContainsFunc(todo, func(p hysteria.Profile) bool { return p.ID == m }) {
				continue
			}
			wait := groupScanStale
			if r, ok := c.scanned[m]; ok && !r.ok {
				wait = groupScanBadWait
			}
			if r, ok := c.scanned[m]; ok && now.Sub(r.at) < wait {
				continue
			}
			if p := c.profiles.Find(m); p != nil {
				todo = append(todo, *p)
			}
		}
	}
	var probe groups.Probe
	if c.groupsFile.Probe != nil {
		probe = *c.groupsFile.Probe
	}
	c.mu.Unlock()
	if len(large) == 0 {
		return
	}
	rawURL, _ := probe.Effective()
	var wg sync.WaitGroup
	results := make(map[string]bool, len(todo))
	var mu sync.Mutex
	for _, p := range todo {
		if sess.ServerIPRoom() < 4*groupScanBatch {
			break // the exclusions are full: no temporary endpoint
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := c.scanOne(ctx, p, rawURL)
			mu.Lock()
			results[p.ID] = ok
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != sess {
		return
	}
	if c.scanned == nil {
		c.scanned = map[string]scanResult{}
	}
	for id, ok := range results {
		c.scanned[id] = scanResult{at: time.Now(), ok: ok}
	}
	changed := false
	for gid, all := range large {
		g := c.groupLocked(gid)
		if g == nil {
			continue
		}
		next := c.rechooseLocked(g, all, sess)
		cur := c.chosenLocked(gid, all)
		if !sameSet(next, cur) {
			if c.groupRun == nil {
				c.groupRun = map[string][]string{}
			}
			c.groupRun[gid] = next
			changed = true
			c.Log.Info("server group: running members chosen again", "group", g.Name, "running", len(next), "members", len(all))
		}
	}
	if changed {
		c.applyRoutingLocked()
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// scanOne measures one member through a temporary endpoint.
func (c *Controller) scanOne(ctx context.Context, p hysteria.Profile, rawURL string) bool {
	ep, release := c.acquire(p)
	defer release()
	if ep == nil {
		return false
	}
	if _, err := waitConnectedCtx(ctx, ep, connectWait(p, probeConnectWait)); err != nil {
		return false
	}
	pctx, cancel := context.WithTimeout(ctx, groups.ProbeTimeout+time.Second)
	defer cancel()
	rtt, err := groups.ProbeOnce(pctx, func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		cl := ep.SOCKS()
		return cl.Connect(ctx, dst)
	}, rawURL, nil)
	if ctx.Err() != nil {
		return false
	}
	c.groupsRT.NoteProbe(p.ID, rtt, err)
	return err == nil
}

// rechooseLocked picks a large group's running members. Failover keeps
// the list order (its first working members). The other strategies keep
// the running ones that work, fill the empty places with the fastest
// measured, and swap at most one running member a round for a faster one
// (by the group's tolerance): a swap stops a member, and its connections
// with it. Members whose last measurement failed come last.
func (c *Controller) rechooseLocked(g *groups.Group, all []string, sess Session) []string {
	h := c.groupsRT.Snapshot(g.ID, endpointUsable(sess))
	health := make(map[string]groups.MemberHealth, len(h.Members))
	for _, m := range h.Members {
		health[m.ID] = m
	}
	now := time.Now()
	bad := func(m string) bool {
		if mh, ok := health[m]; ok && (mh.ProbeError != "" || mh.Skipped) {
			return true
		}
		r, ok := c.scanned[m]
		return ok && !r.ok && now.Sub(r.at) < groupScanBadWait
	}
	lat := func(m string) time.Duration {
		if l := health[m].Latency; l > 0 {
			return l
		}
		return time.Hour // unknown: after the measured ones
	}
	if g.Strategy == groups.Failover {
		var out, later []string
		for _, m := range all {
			if bad(m) {
				later = append(later, m)
			} else {
				out = append(out, m)
			}
		}
		out = append(out, later...)
		return out[:min(len(out), groups.MaxRunning)]
	}
	tol := time.Duration(g.ToleranceMs) * time.Millisecond
	if tol == 0 {
		tol = groups.DefaultToleranceMs * time.Millisecond
	}
	var next []string
	for _, m := range c.chosenLocked(g.ID, all) {
		if !bad(m) {
			next = append(next, m)
		}
	}
	ranked := slices.Clone(all)
	sort.SliceStable(ranked, func(i, j int) bool { return lat(ranked[i]) < lat(ranked[j]) })
	var spare []string // good members not running, fastest first
	for _, m := range ranked {
		if !bad(m) && !slices.Contains(next, m) {
			spare = append(spare, m)
		}
	}
	for len(next) < groups.MaxRunning && len(spare) > 0 {
		next, spare = append(next, spare[0]), spare[1:]
	}
	if len(spare) > 0 && len(next) > 0 {
		worst := slices.MaxFunc(next, func(a, b string) int { return int(lat(a) - lat(b)) })
		if lat(spare[0])+tol < lat(worst) {
			next[slices.Index(next, worst)] = spare[0]
		}
	}
	// Still short (failed ones): they run rather than nothing.
	for _, m := range ranked {
		if len(next) >= groups.MaxRunning {
			break
		}
		if !slices.Contains(next, m) {
			next = append(next, m)
		}
	}
	sort.SliceStable(next, func(i, j int) bool { return lat(next[i]) < lat(next[j]) })
	return next
}
