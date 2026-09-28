package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// Server groups (groups.json): a group is a routing target like a server.
// Its ID sits in the same fields (rules, fallbacks, the default route,
// local proxies, the main target); the engine resolves it to a member per
// new connection (groups.Runtime). While a group is used by the routing,
// all its members run. A group with no usable member, an unknown group and
// every group while groups.json is broken fail closed.

// groupsState is the Controller's part for server groups. Guarded by c.mu
// unless noted.
type groupsState struct {
	// groupsFile is never nil after New: empty when missing or broken (a
	// broken one keeps only the main group its lenient read found).
	groupsFile *groups.File
	// groupsBroken: groups.json did not load; it is never overwritten.
	groupsBroken error
	// groupsRT is the live selector (its own lock, innermost).
	groupsRT *groups.Runtime
	// probeStop stops the prober of the session (guarded by lifeMu).
	probeStop context.CancelFunc
	// probing: running «Проверить» per group (ProbeGroup).
	probing map[string]*probeRun
	// proxyWarnAt: the last «no server of the group» warning of a local
	// proxy (Unix ns), rate-limited.
	proxyWarnAt atomic.Int64
	// runningMemo: the running groups for one Profiles() call (c.mu
	// held throughout), so each server card does not recompute them.
	runningMemo *[]string
}

// probeRun is one «Проверить» of a group; a second call waits for it.
type probeRun struct {
	done  chan struct{}
	notes map[string]string // member -> «не проверен: …» / «нет результата за 60 с»
}

// Test hooks.
var (
	probeGroupBudget = groups.ProbeGroupBudget
	probeConnectWait = 20 * time.Second
)

func (c *Controller) initGroups() {
	c.groupsRT = groups.NewRuntime(c.Log)
	c.groupsRT.Name = c.profileName
	c.groupsFile = &groups.File{Version: groups.FormatVersion, Groups: []groups.Group{}}
	c.probing = map[string]*probeRun{}
}

// loadGroups reads groups.json for Load (its error joins errs). A group
// whose ID a server of p has (a hand-edited file) makes the file broken:
// the server wins, and the file is not rewritten without the group. A
// server whose ID looks like a group's (hand-edited profiles.json) is
// taken for a group everywhere and never runs: say so.
func (c *Controller) loadGroups(errs *[]string, p *store.Profiles) (*groups.File, error) {
	for _, sp := range p.List {
		if groups.IsGroupID(sp.ID) {
			*errs = append(*errs, fmt.Sprintf("profiles.json: у сервера «%s» id начинается с grp- (%s): такой сервер не работает, удалите и добавьте его заново", sp.Name, sp.ID))
		}
	}
	f, err := c.Store.LoadGroups()
	if err == nil {
		for _, g := range f.Groups {
			if p.Find(g.ID) != nil {
				err = fmt.Errorf("groups.json: у группы «%s» тот же id, что у сервера (%s): группы не загружены", g.Name, g.ID)
				f = &groups.File{Version: groups.FormatVersion, Main: f.Main, Groups: []groups.Group{}}
				break
			}
		}
	}
	if err != nil {
		*errs = append(*errs, err.Error())
	}
	return f, err
}

// loadedGroupsLocked installs what Load read (c.mu held, c.profiles set).
func (c *Controller) loadedGroupsLocked(f *groups.File, err error) {
	c.installGroupsLocked(f)
	c.groupsBroken = err
	c.syncGroupsLocked() // none while broken
}

// installGroupsLocked makes f the groups (c.mu held; no I/O, no other
// lock): the one install path of a save, Load and backup's restore.
func (c *Controller) installGroupsLocked(f *groups.File) {
	c.groupsFile = f
	c.groupsBroken = nil
	c.syncGroupsLocked()
	c.updateNamesLocked()
}

// syncGroupsLocked gives the runtime the groups with their existing
// members (none while groups.json is broken: group targets fail closed).
func (c *Controller) syncGroupsLocked() {
	var list []groups.Group
	if c.groupsBroken == nil {
		for _, g := range c.groupsFile.Groups {
			g.Members = c.existingLocked(g.Members)
			list = append(list, g)
		}
	}
	c.groupsRT.SetGroups(list)
	_, every := c.groupsFile.Probe.Effective()
	c.groupsRT.SetInterval(every)
}

// existingLocked keeps the IDs that are servers.
func (c *Controller) existingLocked(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if c.profiles.Find(id) != nil {
			out = append(out, id)
		}
	}
	return out
}

// groupNamesLocked adds the group names to the names map (profileName).
func (c *Controller) groupNamesLocked(m map[string]string) {
	if c.groupsFile == nil {
		return
	}
	for _, g := range c.groupsFile.Groups {
		m[g.ID] = g.Name
	}
}

// groupLocked is a group of the loaded groups.json, nil when unknown
// (deleted) or while the file is broken (statistics mark such rows gone).
func (c *Controller) groupLocked(id string) *groups.Group {
	if c.groupsBroken != nil || c.groupsFile == nil {
		return nil
	}
	return c.groupsFile.Find(id)
}

// mainTargetLocked is the only resolver of the main target: the group
// main of groups.json (also the one a broken file's lenient read found:
// unknown to the runtime, so "via VPN" traffic is refused), else the
// active server of profiles.json.
func (c *Controller) mainTargetLocked() string {
	if c.groupsFile != nil && c.groupsFile.Main != "" {
		return c.groupsFile.Main
	}
	return c.profiles.Active
}

// targetRefsLocked is the one answer to "who references this target"
// (server or group): Tunnel rules (disabled ones too), the default route,
// fallback lists, local proxies and the main target.
func (c *Controller) targetRefsLocked(id string) []string {
	refs := append(c.explicitRefsLocked(id), c.proxyRefsLocked(id)...)
	if id != "" && c.mainTargetLocked() == id {
		refs = append(refs, "основной")
	}
	return refs
}

// groupUsedLocked: something references the group (pins and deletes).
// What runs follows routingLocked instead (usedGroups).
func (c *Controller) groupUsedLocked(gid string) bool { return len(c.targetRefsLocked(gid)) > 0 }

// expandGroupsLocked replaces the groups in used by their existing
// members and returns the used loaded groups, sorted (an unknown group
// runs nothing: its traffic is refused, and its rule warns).
func (c *Controller) expandGroupsLocked(used map[string]bool) []string {
	var out []string
	for id := range used {
		if !groups.IsGroupID(id) {
			continue
		}
		delete(used, id)
		if g := c.groupLocked(id); g != nil {
			out = append(out, id)
			for _, m := range c.existingLocked(g.Members) {
				used[m] = true
			}
		}
	}
	sort.Strings(out)
	return out
}

// groupsWritableLocked refuses a groups.json write while it or
// profiles.json is broken: with profiles.json unloaded the server list is
// empty, and a prune would strip every member for good.
func (c *Controller) groupsWritableLocked() error {
	if c.groupsBroken != nil {
		return fmt.Errorf("groups.json не загружен, изменения не сохраняются, чтобы не потерять группы: %v", c.groupsBroken)
	}
	if c.profilesBroken != nil {
		return fmt.Errorf("profiles.json не загружен, группы не сохраняются, чтобы не потерять их серверы: %v", c.profilesBroken)
	}
	return nil
}

// saveGroupsLocked is the one write path of groups.json: members that are
// no servers go from every group, the load rules hold for the whole file
// (another group's empty member list never blocks a save), then it is
// stored, installed and applied.
func (c *Controller) saveGroupsLocked(next *groups.File) error {
	if err := c.groupsWritableLocked(); err != nil {
		return err
	}
	next.Prune(func(id string) bool { return c.profiles.Find(id) != nil })
	if err := c.Store.SaveGroups(next); err != nil {
		return err
	}
	c.installGroupsLocked(next)
	c.applyRoutingLocked()
	return nil
}

// ---- public API ----

// MemberView is one member of a group for the UI.
type MemberView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"` // stopped | connecting | connected | failed (routing endpoint)
	UDP      bool   `json:"udp"`
	FastOpen bool   `json:"fastOpen"` // error streaks cannot see its failures
	// LatencyMs is the EWMA (0 = unknown), LastMs the last sample.
	LatencyMs int64 `json:"latencyMs"`
	LastMs    int64 `json:"lastMs"`
	// ProbeAt: Unix ms of the last probe, 0 = never.
	ProbeAt    int64  `json:"probeAt"`
	ProbeError string `json:"probeError"`
	Errors     int    `json:"errors"`  // current failed-dial streak
	Skipped    bool   `json:"skipped"` // penalised now
	Reason     string `json:"reason"`  // errors | trial | probe | ""
	Missing    bool   `json:"missing"` // not in the server list («удалён»)
	// NotInSub: dropped by its subscription and kept («нет в подписке»).
	NotInSub bool `json:"notInSub"`
}

// GroupView is a group for the UI.
type GroupView struct {
	groups.Group
	Main   bool     `json:"main"`
	UsedBy []string `json:"usedBy"`
	// Active: failover/latency, while connected and used, the member a new
	// connection would get now; "" otherwise.
	Active   string `json:"active"`
	Up       int    `json:"up"`      // usable members now
	Running  bool   `json:"running"` // used while connected: members run
	Missing  int    `json:"missing"`
	Rejected int64  `json:"rejected"` // refused this session: no member usable
	// ProbeBroken: the probe URL failed through every probed member.
	ProbeBroken bool         `json:"probeBroken"`
	Views       []MemberView `json:"memberViews"`
}

// GroupsInfo is the «Группы» tab.
type GroupsInfo struct {
	Groups          []GroupView  `json:"groups"`
	Probe           groups.Probe `json:"probe"`
	DefaultProbeURL string       `json:"defaultProbeURL"`
	LoadError       string       `json:"loadError,omitempty"`
	// ServersBroken: profiles.json did not load; groups are not changed.
	ServersBroken bool `json:"serversBroken,omitempty"`
	// ActiveServer is profiles.json's active server: the main again once
	// a group main is deleted ("" = none).
	ActiveServer string `json:"activeServer"`
}

// GroupBrief is the main group on Home (Status).
type GroupBrief struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Strategy   groups.Strategy `json:"strategy"`
	Active     string          `json:"active"`
	ActiveName string          `json:"activeName"`
	Up         int             `json:"up"`
	Total      int             `json:"total"`
	Rejected   int64           `json:"rejected"`
}

// Groups lists the groups with their state.
func (c *Controller) Groups() GroupsInfo {
	c.mu.Lock()
	info := GroupsInfo{Groups: []GroupView{}, DefaultProbeURL: groups.DefaultProbeURL}
	if c.groupsFile.Probe != nil {
		info.Probe = *c.groupsFile.Probe
	}
	if c.groupsBroken != nil {
		info.LoadError = c.groupsBroken.Error()
	}
	info.ServersBroken = c.profilesBroken != nil
	info.ActiveServer = c.profiles.Active
	views, sess := c.groupViewsLocked()
	c.mu.Unlock()
	for i := range views {
		c.fillHealth(&views[i], sess, nil)
	}
	info.Groups = append(info.Groups, views...)
	return info
}

// groupView is the view of one group (after a save or a check).
func (c *Controller) groupView(id string, notes map[string]string) (GroupView, error) {
	c.mu.Lock()
	views, sess := c.groupViewsLocked()
	c.mu.Unlock()
	for i := range views {
		if views[i].ID == id {
			c.fillHealth(&views[i], sess, notes)
			return views[i], nil
		}
	}
	return GroupView{}, groups.Errorf("Группа не найдена")
}

// groupViewsLocked builds what c.mu guards; fillHealth adds the runtime's
// part outside it.
func (c *Controller) groupViewsLocked() ([]GroupView, Session) {
	sess := c.sess
	_, _, used := c.routingLocked()
	main := c.mainTargetLocked()
	var out []GroupView
	if c.groupsBroken != nil {
		return out, sess
	}
	for _, g := range c.groupsFile.Groups {
		v := GroupView{Group: g, Main: main == g.ID, UsedBy: c.targetRefsLocked(g.ID), Views: []MemberView{}}
		v.Members = append([]string{}, g.Members...)
		if v.UsedBy == nil {
			v.UsedBy = []string{}
		}
		v.Running = sess != nil && slices.Contains(used, g.ID)
		for _, id := range g.Members {
			mv := MemberView{ID: id, Name: c.profileName(id), State: "stopped"}
			if p := c.profiles.Find(id); p != nil {
				mv.FastOpen, mv.NotInSub = p.FastOpen, p.Missing
			} else {
				mv.Missing, mv.Name = true, "удалённый сервер"
				v.Missing++
			}
			v.Views = append(v.Views, mv)
		}
		out = append(out, v)
	}
	return out, sess
}

// endpointUsable: a routing endpoint of sess can carry TCP now.
func endpointUsable(sess Session) func(string) bool {
	return func(id string) bool {
		if sess == nil {
			return false
		}
		ep := sess.Endpoint(id)
		return ep != nil && ep.Available()
	}
}

// fillHealth adds the endpoints' state and the runtime's measurements to v.
func (c *Controller) fillHealth(v *GroupView, sess Session, notes map[string]string) {
	h := c.groupsRT.Snapshot(v.ID, endpointUsable(sess))
	byID := map[string]groups.MemberHealth{}
	for _, m := range h.Members {
		byID[m.ID] = m
	}
	v.Up, v.Rejected, v.ProbeBroken = h.Up, h.Rejected, h.ProbeBroken
	if v.Running && (v.Strategy == groups.Failover || v.Strategy == groups.Latency) {
		v.Active = h.Active
	}
	for i := range v.Views {
		mv := &v.Views[i]
		if mh, ok := byID[mv.ID]; ok {
			mv.LatencyMs, mv.LastMs = mh.Latency.Milliseconds(), mh.Last.Milliseconds()
			if !mh.ProbeAt.IsZero() {
				mv.ProbeAt = mh.ProbeAt.UnixMilli()
			}
			mv.ProbeError, mv.Errors, mv.Skipped, mv.Reason = mh.ProbeError, mh.Errors, mh.Skipped, mh.Reason
		}
		if n := notes[mv.ID]; n != "" {
			mv.ProbeError = n
		}
		if sess != nil && !mv.Missing {
			if ep := sess.Endpoint(mv.ID); ep != nil {
				st := ep.Status()
				mv.State, mv.UDP = st.State.String(), st.UDPEnabled
			}
		}
	}
}

// SaveGroup creates (empty ID) or replaces a group. Members that are no
// longer servers are dropped silently; options that do not apply to the
// strategy are cleared. Only this group must have 1..32 existing servers.
func (c *Controller) SaveGroup(g groups.Group) (GroupView, error) {
	g.Name = strings.TrimSpace(g.Name)
	if g.Strategy != groups.Failover {
		g.Revert = false
	}
	if g.Strategy != groups.Latency {
		g.ToleranceMs = 0
	}
	c.mu.Lock()
	if err := c.groupsWritableLocked(); err != nil {
		c.mu.Unlock()
		return GroupView{}, err
	}
	seen := map[string]bool{}
	var members []string
	for _, id := range g.Members {
		if !seen[id] && (c.profiles.Find(id) != nil || groups.IsGroupID(id)) {
			seen[id] = true
			members = append(members, id)
		}
	}
	g.Members = members
	if err := groups.ValidateEdited(g, func(id string) bool { return c.profiles.Find(id) != nil }); err != nil {
		c.mu.Unlock()
		return GroupView{}, err
	}
	next := c.groupsFile.Clone()
	if g.ID == "" {
		if len(next.Groups) >= groups.MaxGroups {
			c.mu.Unlock()
			return GroupView{}, groups.Errorf("Групп может быть не больше %d", groups.MaxGroups)
		}
		for g.ID == "" || next.Find(g.ID) != nil || c.profiles.Find(g.ID) != nil {
			g.ID = groups.NewID(newID())
		}
		next.Groups = append(next.Groups, g)
	} else if old := next.Find(g.ID); old != nil {
		*old = g
	} else {
		c.mu.Unlock()
		return GroupView{}, groups.Errorf("Группа не найдена")
	}
	err := c.saveGroupsLocked(next)
	c.mu.Unlock()
	if err != nil {
		return GroupView{}, err
	}
	c.Log.Info("server group saved", "group", g.Name, "strategy", string(g.Strategy), "members", len(g.Members))
	c.changed()
	return c.groupView(g.ID, nil)
}

// DeleteGroup refuses while a rule, the default route, a fallback list or
// a local proxy names the group; the main target is cleared instead (the
// active server is the main again).
func (c *Controller) DeleteGroup(id string) error {
	c.mu.Lock()
	err := c.deleteGroupLocked(id)
	c.mu.Unlock()
	if err == nil {
		c.changed()
	}
	return err
}

func (c *Controller) deleteGroupLocked(id string) error {
	if err := c.groupsWritableLocked(); err != nil {
		return err
	}
	if err := c.refsUnknownLocked(); err != nil {
		return err
	}
	g := c.groupsFile.Find(id)
	if g == nil {
		return groups.Errorf("Группа не найдена")
	}
	if refs := append(c.explicitRefsLocked(id), c.proxyRefsLocked(id)...); len(refs) > 0 {
		return groups.Errorf("Группа используется: %s. Выберите в них другой сервер или группу", strings.Join(refs, ", "))
	}
	name := g.Name
	next := c.groupsFile.Clone()
	next.Groups = slices.DeleteFunc(next.Groups, func(g groups.Group) bool { return g.ID == id })
	if next.Main == id {
		next.Main = ""
	}
	if err := c.saveGroupsLocked(next); err != nil {
		return err
	}
	c.Log.Info("server group deleted", "group", name)
	return nil
}

// SetProbe saves the latency probe settings.
func (c *Controller) SetProbe(p groups.Probe) error {
	p.URL = strings.TrimSpace(p.URL)
	if p.URL == groups.DefaultProbeURL {
		p.URL = ""
	}
	if p.IntervalSec == int(groups.DefaultInterval/time.Second) {
		p.IntervalSec = 0
	}
	if err := groups.ValidateProbe(p); err != nil {
		return err
	}
	c.mu.Lock()
	var cur groups.Probe
	if c.groupsFile.Probe != nil {
		cur = *c.groupsFile.Probe
	}
	if p == cur && c.groupsBroken == nil {
		c.mu.Unlock()
		return nil // unchanged: no write (no groups.json for the defaults)
	}
	var err error
	if err = c.groupsWritableLocked(); err == nil {
		next := c.groupsFile.Clone()
		next.Probe = nil
		if p != (groups.Probe{}) {
			next.Probe = &p
		}
		err = c.saveGroupsLocked(next)
	}
	c.mu.Unlock()
	if err == nil {
		// Never the URL: it may carry a token.
		c.Log.Info("server group probe settings saved", "customURL", p.URL != "", "intervalSec", p.IntervalSec)
		c.changed()
	}
	return err
}

// setMainGroupLocked makes group gid the main target (groups.json only;
// profiles.json keeps its active server for a rollback).
func (c *Controller) setMainGroupLocked(gid string) error {
	if err := c.groupsWritableLocked(); err != nil {
		return err
	}
	g := c.groupsFile.Find(gid)
	if g == nil {
		return groups.Errorf("Группа не найдена")
	}
	if len(c.existingLocked(g.Members)) == 0 {
		return groups.Errorf("В группе «%s» нет серверов — её нельзя сделать основной", g.Name)
	}
	next := c.groupsFile.Clone()
	next.Main = gid
	return c.saveGroupsLocked(next)
}

// mainGroupBlocksLocked refuses a server main while a broken groups.json
// still names a main group: the file cannot be rewritten, and the group
// would silently stay in charge.
func (c *Controller) mainGroupBlocksLocked() error {
	if c.groupsBroken != nil && c.groupsFile.Main != "" {
		return fmt.Errorf("groups.json не загружен, изменения не сохраняются, чтобы не потерять группы: %v", c.groupsBroken)
	}
	return nil
}

// clearMainGroupLocked drops the group main after a server became the
// active one (profiles.json is written first). Only when groups.json names
// one: a user without groups never gets the file.
func (c *Controller) clearMainGroupLocked() error {
	if c.groupsFile.Main == "" {
		return nil
	}
	name := c.profileName(c.groupsFile.Main)
	next := c.groupsFile.Clone()
	next.Main = ""
	if err := c.saveGroupsLocked(next); err != nil {
		return groups.Errorf("Основной осталась группа «%s»: не удалось записать groups.json: %v", name, err)
	}
	return nil
}

// deleteServerCheckLocked: a server delete is refused while groups.json is
// broken (memberships unknown) and when the server is the last existing
// member of a used group.
func (c *Controller) deleteServerCheckLocked(id string) error {
	if c.groupsBroken != nil {
		return errors.New("groups.json не загружен: сервер не удаляется, пока нельзя проверить, в каких группах он состоит")
	}
	for _, g := range c.groupsFile.Groups {
		if !slices.Contains(g.Members, id) {
			continue
		}
		if others := slices.DeleteFunc(c.existingLocked(g.Members), func(m string) bool { return m == id }); len(others) > 0 {
			continue
		}
		if refs := c.targetRefsLocked(g.ID); len(refs) > 0 {
			return groups.Errorf("Сервер — последний в группе «%s», которую используют: %s. Добавьте в группу другой сервер или удалите группу", g.Name, strings.Join(refs, ", "))
		}
	}
	return nil
}

// pruneServerLocked drops a deleted server from the groups, only when one
// holds it (best effort: the runtime ignores dangling members anyway).
func (c *Controller) pruneServerLocked(id string) {
	if c.groupsBroken != nil || !slices.ContainsFunc(c.groupsFile.Groups, func(g groups.Group) bool { return slices.Contains(g.Members, id) }) {
		return
	}
	if err := c.saveGroupsLocked(c.groupsFile.Clone()); err != nil {
		c.Log.Warn("deleted server not removed from groups.json", "err", err)
	}
}

// ---- references and subscriptions ----

// targetNameLocked is a server or group name, "" when unknown.
func (c *Controller) targetNameLocked(id string) string {
	if p := c.profiles.Find(id); p != nil {
		return p.Name
	}
	if g := c.groupLocked(id); g != nil {
		return g.Name
	}
	return ""
}

// noteGroupsLocked adds the IDs of the groups defined here to known: the
// v1.2.0 backup (backup.go) carries no groups, and its restore keeps rules
// that name a group of this computer instead of sending them to the main
// server.
func (c *Controller) noteGroupsLocked(known map[string]bool) {
	for _, g := range c.groupsFile.Groups {
		known[g.ID] = true
	}
}

// targetExistsLocked: a server or a loaded group.
func (c *Controller) targetExistsLocked(id string) bool {
	return c.profiles.Find(id) != nil || c.groupLocked(id) != nil
}

// groupPinsLocked keeps a used group from being emptied: for each used
// group that has an existing member now and none in result, its current
// members (to keep as «нет в подписке» or as manual servers).
func (c *Controller) groupPinsLocked(result []hysteria.Profile) map[string]bool {
	if c.groupsBroken != nil {
		return nil // every server is kept anyway (profileUsedLocked)
	}
	after := map[string]bool{}
	for _, p := range result {
		after[p.ID] = true
	}
	pins := map[string]bool{}
	for _, g := range c.groupsFile.Groups {
		before := c.existingLocked(g.Members)
		if len(before) == 0 || slices.ContainsFunc(before, func(m string) bool { return after[m] }) || !c.groupUsedLocked(g.ID) {
			continue
		}
		for _, m := range before {
			pins[m] = true
		}
		c.Log.Info("subscription: servers kept so group «"+g.Name+"» is not empty", "servers", len(before))
	}
	return pins
}

// mergeKeepingGroupsLocked is mergeSubscription that never empties a used
// group: when the merge would, it runs again with that group's members
// kept like a server a rule names.
func (c *Controller) mergeKeepingGroupsLocked(source string, fresh []hysteria.Profile) ([]hysteria.Profile, MergeStats) {
	list, st := mergeSubscription(c.profiles.List, source, fresh, c.profileUsedLocked, newID)
	if pins := c.groupPinsLocked(list); len(pins) > 0 {
		list, st = mergeSubscription(c.profiles.List, source, fresh, func(id string) bool { return c.profileUsedLocked(id) || pins[id] }, newID)
	}
	return list, st
}

// subDeletePinsLocked: the servers of subscription source that deleting it
// keeps as manual ones so that no used group is emptied.
func (c *Controller) subDeletePinsLocked(source string) map[string]bool {
	var result []hysteria.Profile
	for _, p := range c.profiles.List {
		if p.Source != source || c.profileUsedLocked(p.ID) {
			result = append(result, p)
		}
	}
	return c.groupPinsLocked(result)
}

// ---- rules and Status ----

// groupCheckLocked is the rule warning of a target that is (or, for "",
// whose main target is) a group; isGroup is false for servers.
func (c *Controller) groupCheckLocked(target string, fallback bool) (kind, text string, isGroup bool) {
	t := target
	if t == "" {
		t = c.mainTargetLocked()
	}
	if !groups.IsGroupID(t) {
		return "", "", false
	}
	main := target == ""
	if c.groupsBroken != nil {
		return "deleted", "группы не загружены (groups.json): соединения будут отклоняться", true
	}
	g := c.groupsFile.Find(t)
	if g == nil {
		if fallback {
			return "deleted", "запасная группа удалена: уберите её из правила", true
		}
		return "deleted", "группа удалена: соединения будут отклоняться, выберите другую", true
	}
	which := "в группе"
	switch {
	case main:
		which = "в основной группе"
	case fallback:
		which = "в запасной группе"
	}
	existing := c.existingLocked(g.Members)
	if len(existing) == 0 {
		if fallback {
			return "empty", fmt.Sprintf("%s «%s» нет серверов", which, g.Name), true
		}
		return "empty", fmt.Sprintf("%s «%s» нет серверов: соединения будут отклоняться", which, g.Name), true
	}
	if !slices.ContainsFunc(existing, func(m string) bool { return !c.profiles.Find(m).Missing }) {
		if fallback {
			return "missing", fmt.Sprintf("%s «%s» остались только серверы, которых нет в подписке", which, g.Name), true
		}
		return "missing", fmt.Sprintf("%s «%s» остались только серверы, которых нет в подписке: выберите замену", which, g.Name), true
	}
	return "", "", true
}

// groupStatus is what Status needs about groups (read under c.mu).
type groupStatus struct {
	used []string
	// viaGroup: servers used only through groups; one of them down alone
	// is not "tunnel-down" while its group has another usable member.
	viaGroup  map[string]bool
	members   map[string][]string // used group -> existing members
	names     map[string]string
	mainGroup *groups.Group
}

func (c *Controller) groupStatusLocked(st *Status) groupStatus {
	main := c.mainTargetLocked()
	gs := groupStatus{viaGroup: map[string]bool{}, members: map[string][]string{}, names: map[string]string{}}
	if groups.IsGroupID(main) {
		st.MainID, st.Main = main, ""
		if g := c.groupLocked(main); g != nil {
			cp := *g
			cp.Members = c.existingLocked(g.Members)
			gs.mainGroup, st.Main = &cp, g.Name
		} else {
			st.MainUnloaded = true
		}
	}
	if c.groupsBroken != nil {
		note := "groups.json не загружен: группы не работают, их соединения отклоняются."
		switch {
		case groups.IsGroupID(main):
			note += " Основная группа не загружена: соединения «через VPN» отклоняются."
		case main != "":
			note += fmt.Sprintf(" Если основной была группа, сейчас вместо неё используется сервер «%s».", c.profileName(main))
		}
		st.GroupsNote = note
	}
	if c.groupsBroken != nil || len(c.groupsFile.Groups) == 0 {
		return gs // no group runs: skip the routing walk of every poll
	}
	set, _, used := c.routingLocked()
	gs.used = used
	direct := map[string]bool{}
	for _, id := range set.Profiles() {
		direct[id] = true
	}
	for _, p := range c.proxies {
		if p.Enabled {
			direct[c.proxyProfileLocked(p)] = true
		}
	}
	for _, gid := range used {
		g := c.groupLocked(gid)
		if g == nil {
			continue
		}
		gs.names[gid] = g.Name
		gs.members[gid] = c.existingLocked(g.Members)
		for _, m := range gs.members[gid] {
			if !direct[m] {
				gs.viaGroup[m] = true
			}
		}
	}
	return gs
}

// mainGroupBrief is the main group with the member a new connection would
// get now (nil unless the main target is a loaded group).
func (c *Controller) mainGroupBrief(gs groupStatus, s Session) *GroupBrief {
	g := gs.mainGroup
	if g == nil {
		return nil
	}
	h := c.groupsRT.Snapshot(g.ID, endpointUsable(s))
	b := &GroupBrief{ID: g.ID, Name: g.Name, Strategy: g.Strategy, Up: h.Up, Total: len(g.Members), Rejected: h.Rejected}
	if s != nil && (g.Strategy == groups.Failover || g.Strategy == groups.Latency) {
		if b.Active = h.Active; b.Active != "" {
			b.ActiveName = c.profileName(h.Active)
		}
	}
	return b
}

// groupsDownStatus turns the state into tunnel-down for every running
// group that is down and adds its message.
func (c *Controller) groupsDownStatus(st *Status, gs groupStatus, s Session, msgs *[]string) {
	if gm := c.groupsDown(gs, s, st.Tunnels); len(gm) > 0 {
		st.State = "tunnel-down"
		*msgs = append(*msgs, gm...)
	}
}

// groupsDown: the running groups none of whose members can carry traffic
// (each failed, or reconnecting after it worked). A group still starting
// is not down.
func (c *Controller) groupsDown(gs groupStatus, s Session, ts []tunnels.Status) []string {
	byID := map[string]tunnels.Status{}
	for _, t := range ts {
		byID[t.ID] = t
	}
	var out []string
	for _, gid := range gs.used {
		ms, ok := gs.members[gid]
		if !ok {
			continue
		}
		isDown := true
		for _, m := range ms {
			if t, ok := byID[m]; ok && !down(t) {
				isDown = false
			}
		}
		if !isDown {
			continue
		}
		msg := fmt.Sprintf("Группа «%s»: все серверы недоступны", gs.names[gid])
		if n := c.groupsRT.Snapshot(gid, endpointUsable(s)).Rejected; n > 0 {
			msg += fmt.Sprintf(", отклонено соединений: %d", n)
		}
		out = append(out, msg)
	}
	return out
}

// explainGroup completes an explanation whose winner is a group: the
// member a connection would take now, or why that is not known.
func (c *Controller) explainGroup(ex *Explanation, sess Session) {
	id := ex.Winner.Profile
	if !groups.IsGroupID(id) {
		return
	}
	ex.Group = true
	c.mu.Lock()
	g := c.groupLocked(id)
	var cp groups.Group
	if g != nil {
		cp = *g
	}
	c.mu.Unlock()
	if g == nil {
		ex.ProfileName = "удалённая группа"
		ex.Notes = append(ex.Notes, "Группа не найдена (удалена или groups.json не загружен): такое соединение будет отклонено.")
		return
	}
	ex.ProfileName = cp.Name
	label := groups.StrategyLabel(cp.Strategy)
	switch {
	case sess == nil:
		ex.Notes = append(ex.Notes, "HyRoute не подключён: сервер группы выберется при подключении.")
	case cp.Strategy == groups.Failover || cp.Strategy == groups.Latency:
		p, ok := c.groupsRT.Peek(id, groups.Hint{}, endpointUsable(sess))
		if !ok {
			ex.Notes = append(ex.Notes, fmt.Sprintf("Группа «%s» (%s): сейчас нет доступных серверов — соединение будет отклонено.", cp.Name, label))
			return
		}
		ex.Via = c.profileName(p.Member)
		ex.Notes = append(ex.Notes, fmt.Sprintf("Группа «%s» (%s): сейчас соединение пошло бы через «%s».", cp.Name, label, ex.Via))
	default:
		ex.Notes = append(ex.Notes, fmt.Sprintf("Группа «%s» (%s): сервер выбирается для каждого соединения.", cp.Name, label))
	}
}

// ---- session: health, prober, checks ----

// groupsSession wires a starting session to the runtime; whatever could
// penalise a member starts over.
func (c *Controller) groupsSession(cfg *session.Config) {
	c.groupsRT.ResetSession()
	cfg.Groups = c.groupsRT
	cfg.OnDial = c.groupsRT.NoteDial
	cfg.OnHealth = func(id string, s hysteria.Status) { c.groupsRT.NoteState(id, s.State == hysteria.Connected) }
}

// startProber starts the latency prober of the session (lifeMu held).
func (c *Controller) startProber() {
	c.stopProber()
	ctx, cancel := context.WithCancel(context.Background())
	c.probeStop = cancel
	p := &groups.Prober{RT: c.groupsRT, Dial: c.probeDial, Targets: c.probeTargets, Log: c.Log}
	go p.Run(ctx)
}

// stopProber cancels it (lifeMu held); it does not wait: a probe cut by
// the Hysteria stop is not noted.
func (c *Controller) stopProber() {
	if c.probeStop != nil {
		c.probeStop()
		c.probeStop = nil
	}
}

// probeTargets are the members of the running groups that run as routing
// endpoints and are connected now, and the probe settings.
func (c *Controller) probeTargets() ([]string, groups.Probe) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var p groups.Probe
	if c.groupsFile.Probe != nil {
		p = *c.groupsFile.Probe
	}
	if c.sess == nil {
		return nil, p
	}
	_, _, used := c.routingLocked()
	seen := map[string]bool{}
	var out []string
	for _, gid := range used {
		if g := c.groupLocked(gid); g != nil {
			for _, m := range c.existingLocked(g.Members) {
				if ep := c.sess.Endpoint(m); !seen[m] && ep != nil && ep.Available() {
					seen[m] = true
					out = append(out, m)
				}
			}
		}
	}
	return out, p
}

// probeDial goes through a routing endpoint's SOCKS5 directly: not its
// Dial, whose errors count against the member and may restart it. A
// member not connected now is groups.ErrNotRunning: no result.
func (c *Controller) probeDial(ctx context.Context, member string, dst socks5.Addr) (net.Conn, error) {
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	if sess == nil {
		return nil, groups.ErrNotRunning
	}
	ep := sess.Endpoint(member)
	if ep == nil || !ep.Available() {
		return nil, groups.ErrNotRunning
	}
	cl := ep.SOCKS()
	return cl.Connect(ctx, dst)
}

// ProbeGroup measures every member of a group now, also while HyRoute is
// disconnected: members that run as routing endpoints through them, the
// others through a temporary Hysteria each (at most 4 at a time), the
// whole check bounded to 60 s. A second call for the group while one runs
// waits for it and gets its result.
func (c *Controller) ProbeGroup(id string) (GroupView, error) {
	c.mu.Lock()
	if c.groupsBroken != nil {
		err := c.groupsWritableLocked()
		c.mu.Unlock()
		return GroupView{}, err
	}
	g := c.groupsFile.Find(id)
	if g == nil {
		c.mu.Unlock()
		return GroupView{}, groups.Errorf("Группа не найдена")
	}
	if run := c.probing[id]; run != nil {
		c.mu.Unlock()
		<-run.done
		return c.groupView(id, run.notes)
	}
	run := &probeRun{done: make(chan struct{}), notes: map[string]string{}}
	c.probing[id] = run
	sess := c.sess
	var members []hysteria.Profile
	for _, m := range g.Members {
		if p := c.profiles.Find(m); p != nil {
			members = append(members, *p)
		}
	}
	var probe groups.Probe
	if c.groupsFile.Probe != nil {
		probe = *c.groupsFile.Probe
	}
	name := g.Name
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.probing, id)
		c.mu.Unlock()
		close(run.done)
	}()
	rawURL, _ := probe.Effective()
	ctx, cancel := context.WithTimeout(context.Background(), probeGroupBudget)
	defer cancel()
	var mu sync.Mutex
	note := func(m, text string) { mu.Lock(); run.notes[m] = text; mu.Unlock() }
	var wg sync.WaitGroup
	sem := make(chan struct{}, groups.ProbeGroupWorkers)
	var roomMu sync.Mutex
	inFlight := 0 // temporary endpoints started by this check and running
	for _, p := range members {
		if sess != nil && sess.Endpoint(p.ID) != nil {
			// A routing endpoint: probed in place, as the prober would.
			wg.Add(1)
			go func() {
				defer wg.Done()
				rtt, err := groups.ProbeOnce(ctx, func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
					return c.probeDial(ctx, p.ID, dst)
				}, rawURL, nil)
				c.noteGroupProbe(ctx, p.ID, rtt, err, note)
			}()
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			note(p.ID, "нет результата за 60 с")
			continue
		}
		// Room for this endpoint's IPs and those of the ones in flight
		// that may not have reported theirs yet.
		roomMu.Lock()
		if sess != nil && sess.ServerIPRoom() < 4*(inFlight+1) {
			roomMu.Unlock()
			<-sem
			note(p.ID, "не проверен: запущено слишком много серверов")
			continue
		}
		inFlight++
		roomMu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { roomMu.Lock(); inFlight--; roomMu.Unlock() }()
			ep, release := c.acquire(p)
			defer release()
			if ep == nil {
				note(p.ID, "не проверен: сервер не запустился")
				return
			}
			if _, err := waitConnectedCtx(ctx, ep, probeConnectWait); err != nil {
				if ctx.Err() != nil {
					note(p.ID, "нет результата за 60 с")
				} else {
					note(p.ID, err.Error())
				}
				return
			}
			rtt, err := groups.ProbeOnce(ctx, func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
				cl := ep.SOCKS()
				return cl.Connect(ctx, dst)
			}, rawURL, nil)
			// The same server and egress: the result counts; a temporary
			// endpoint never reports health or dials.
			c.noteGroupProbe(ctx, p.ID, rtt, err, note)
		}()
	}
	wg.Wait()
	c.Log.Info("server group checked", "group", name, "members", len(members))
	c.changed()
	return c.groupView(id, run.notes)
}

// noteGroupProbe records a check's probe; one cut by the budget, or not
// sent because the member is not connected, is not.
func (c *Controller) noteGroupProbe(ctx context.Context, member string, rtt time.Duration, err error, note func(m, text string)) {
	if ctx.Err() != nil || errors.Is(err, groups.ErrCanceled) {
		note(member, "нет результата за 60 с")
		return
	}
	if errors.Is(err, groups.ErrNotRunning) {
		note(member, "не проверен: сервер не подключён")
		return
	}
	c.groupsRT.NoteProbe(member, rtt, err)
}

// waitConnectedCtx is waitConnected that also ends with ctx.
func waitConnectedCtx(ctx context.Context, ep *tunnels.Endpoint, timeout time.Duration) (hysteria.Status, error) {
	deadline := time.Now().Add(timeout)
	for {
		st := ep.Status()
		switch {
		case st.State == hysteria.Connected:
			return st, nil
		case st.State == hysteria.Failed && st.Message != "":
			return st, errors.New(st.Message)
		case ctx.Err() != nil:
			return st, ctx.Err()
		case time.Now().After(deadline):
			if st.Message != "" {
				return st, errors.New(st.Message)
			}
			return st, groups.Errorf("Hysteria не подключилась за %d с", int(timeout.Seconds()))
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// ---- local proxies and geodata ----

// proxyGroupDial is a local proxy's connection through group gid: the
// member is chosen per connection like an intercepted one (sticky on the
// proxy and the destination site). No usable member: SOCKS5 reply 1 /
// HTTP 502, counted for the group.
func (c *Controller) proxyGroupDial(ctx context.Context, s Session, p store.LocalProxy, gid string, dst socks5.Addr) (net.Conn, error) {
	h := groups.Hint{App: "proxy:" + p.ID, IP: dst.IP}
	if dst.Host != "" {
		h.Site = groups.SiteOf(dst.Host, nil) // the CONNECT host: a name of this connection
	}
	pk, ok := c.groupsRT.Choose(gid, h, endpointUsable(s))
	var ep *tunnels.Endpoint
	if ok {
		if ep = s.Endpoint(pk.Member); ep == nil {
			c.groupsRT.Abandon(pk) // the member stopped since the choice
		}
	}
	if ep == nil {
		c.groupsRT.NoteRejected(gid)
		if now := time.Now().UnixNano(); now-c.proxyWarnAt.Load() > int64(10*time.Second) {
			c.proxyWarnAt.Store(now)
			c.Log.Warn("local proxy: no server of the group is available", "name", p.Name, "group", c.profileName(gid))
		}
		c.proxyRecord(p, 6, dst, refusedVia(pk, gid), gid, pk.Failover, "rst: tunnel unavailable") // stats
		return nil, socks5.ReplyError(1)
	}
	conn, err := ep.Dial(ctx, dst)
	if err != nil {
		if !proxyDialStopped(ctx) { // stats
			ep.NoteRejected()
			c.proxyRecord(p, 6, dst, pk.Member, gid, pk.Failover, "rst: socks5 connect failed")
		}
		return nil, err
	}
	return c.newTunnelConn(conn, ep, c.proxyRecord(p, 6, dst, pk.Member, gid, pk.Failover, "proxied")), nil
}

// groupDialer is the main group as geodata's VPN route: the member is
// chosen only when the download actually dials through the VPN.
type groupDialer struct {
	c    *Controller
	sess Session
	gid  string
}

func (d groupDialer) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	h := groups.Hint{App: "hyroute:geo", IP: dst.IP}
	if dst.Host != "" {
		h.Site = groups.SiteOf(dst.Host, nil)
	}
	pk, ok := d.c.groupsRT.Choose(d.gid, h, endpointUsable(d.sess))
	if !ok {
		return nil, errors.New("ни один сервер основной группы не доступен")
	}
	ep := d.sess.Endpoint(pk.Member)
	if ep == nil {
		d.c.groupsRT.Abandon(pk)
		return nil, errors.New("сервер основной группы не запущен")
	}
	return ep.Dial(ctx, dst)
}

// mainGroupEndpoint answers mainEndpoint for a group main: only "is a VPN
// attempt possible" (a Peek, nothing committed).
func (c *Controller) mainGroupEndpoint(sess Session, gid string) interface {
	Dial(context.Context, socks5.Addr) (net.Conn, error)
} {
	if _, ok := c.groupsRT.Peek(gid, groups.Hint{App: "hyroute:geo"}, endpointUsable(sess)); !ok {
		return nil
	}
	return groupDialer{c: c, sess: sess, gid: gid}
}

// ---- names ----

// ResolveTarget reads a server or group as rules text does: vpn/основной
// is "" (the main target), a server name or a part of it, группа:Имя,
// id:…. Shared with the CLI and imports.
func (c *Controller) ResolveTarget(text string) (string, error) {
	c.mu.Lock()
	ts := c.targetsLocked()
	c.mu.Unlock()
	a, id, err := parseTarget(strings.TrimSpace(text), ts)
	if err != nil {
		return "", err
	}
	if a != rules.Tunnel {
		return "", errors.New("нужен сервер или группа, а не «напрямую» или «блок»")
	}
	return id, nil
}

// TargetName is a server or group name, "" for "" (the main target) or an
// unknown ID.
func (c *Controller) TargetName(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.targetNameLocked(id)
}

// ---- diagnostics ----

// groupDiagLines is the «== Группы» section (nil without groups).
func (c *Controller) groupDiagLines() []string {
	info := c.Groups()
	custom := info.Probe != (groups.Probe{})
	if len(info.Groups) == 0 && info.LoadError == "" && !custom {
		return nil
	}
	out := []string{"", "== Группы"}
	if info.LoadError != "" {
		out = append(out, "   ! groups.json не загружен: "+info.LoadError)
	}
	for _, g := range info.Groups {
		state := "не используется"
		if g.Running {
			state = "работает"
		}
		line := fmt.Sprintf("   %q %s, серверов %d, %s", g.Name, groups.StrategyLabel(g.Strategy), len(g.Members), state)
		if g.Main {
			line += ", основная"
		}
		if g.Active != "" {
			line += ", сейчас " + c.profileName(g.Active)
		}
		if g.Rejected > 0 {
			line += fmt.Sprintf(", отклонено: %d", g.Rejected)
		}
		out = append(out, line)
		if g.ProbeBroken {
			out = append(out, "      адрес проверки не отвечает ни через один сервер")
		}
		for _, m := range g.Views {
			var parts []string
			switch {
			case m.Missing:
				parts = append(parts, "удалён")
			case m.Reason == "trial":
				parts = append(parts, "пробное соединение")
			case m.Reason == "errors":
				parts = append(parts, fmt.Sprintf("ошибок подряд %d", m.Errors))
			case m.ProbeError != "":
				parts = append(parts, "нет ответа")
			case m.LatencyMs > 0:
				parts = append(parts, fmt.Sprintf("%d мс", m.LatencyMs))
			}
			if m.NotInSub {
				parts = append(parts, "нет в подписке")
			}
			if len(parts) == 0 {
				parts = append(parts, "—")
			}
			out = append(out, fmt.Sprintf("      %q: %s", m.Name, strings.Join(parts, ", ")))
		}
	}
	url, every := info.Probe.Effective()
	out = append(out, fmt.Sprintf("   адрес проверки: %s, каждые %d с", MaskURL(url), int(every.Seconds())))
	return out
}

// memberOfLocked: «группа «X»» for each running group holding server id
// (a server card's «Используют»).
func (c *Controller) memberOfLocked(id string) []string {
	if c.groupsBroken != nil || len(c.groupsFile.Groups) == 0 {
		return nil
	}
	var used []string
	if c.runningMemo != nil {
		used = *c.runningMemo
	} else {
		_, _, used = c.routingLocked()
	}
	var out []string
	for _, gid := range used {
		if g := c.groupLocked(gid); g != nil && slices.Contains(g.Members, id) {
			out = append(out, "группа «"+g.Name+"»")
		}
	}
	return out
}

// memoRunningGroupsLocked computes the running groups once for a list of
// server cards (c.mu held until the returned func, which forgets them).
func (c *Controller) memoRunningGroupsLocked() func() {
	if c.groupsBroken != nil || len(c.groupsFile.Groups) == 0 {
		return func() {}
	}
	_, _, used := c.routingLocked()
	c.runningMemo = &used
	return func() { c.runningMemo = nil }
}
