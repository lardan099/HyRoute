package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/netmode"
)

// «Сети» (network modes): network rules connect, disconnect or switch the
// rule profile when the computer moves to another network. A change is a
// change of the network's identity (netmode.Ident), never of its
// attributes. What protects (connect, the «Неизвестная сеть» profile in
// place of one a network rule set) runs on the first read of a new
// network; what relaxes protection (disconnect, a matched rule's profile)
// waits for a confirming read with an NLM ID. The user's own actions win
// until the next network change. Nothing is read while the feature is off.

// NetWatcher reads the networks Windows is connected to (internal/netwatch).
type NetWatcher interface {
	Snapshot(wantSSID bool) (netmode.Snapshot, error)
	Watch(ctx context.Context) (<-chan struct{}, error)
	// SSID of one adapter (Network.AdapterID); netmode.ErrSSIDDenied when
	// Windows refuses (location privacy).
	SSID(adapterID string) (string, error)
}

// firstRead: what the first identity does while there is no baseline.
type firstRead int

const (
	firstChange           firstRead = iota // a change, unless the user acted since baseGen
	firstBaseline                          // enabling: the current network is the baseline, no action
	firstBaselineOverride                  // Restore start: baseline, override = true, no action
)

type pendKind int

const (
	pendChange  pendKind = iota // a Changed identity: protective part done, relaxing part waits
	pendRefine                  // an unidentified-settled baseline got its ID: re-decide
	pendUnclear                 // an Unclear read of the baseline: re-read, fail towards protection
)

func (k pendKind) String() string {
	return [...]string{"change", "refine", "unclear"}[k]
}

type netPending struct {
	kind  pendKind
	id    netmode.Ident
	since time.Time
	gen   uint64 // net.gen when the pending read was taken
}

type netState struct {
	cfg     netmode.Config
	broken  error            // networks.json did not load: nothing acts
	snap    netmode.Snapshot // last read (the page's cached view)
	read    bool             // snap holds a read
	base    netmode.Ident    // baseline; zero = none yet
	onFirst firstRead        // meaning of the first identity while base is zero
	baseGen uint64           // gen when the baseline was cleared (start, enabling)
	// baseIdless: the baseline's decision was made on a read without an NLM
	// ID (settled after netSettleMax); baseDecGen: gen of that decision.
	// Refined + baseIdless + gen == baseDecGen → pendRefine.
	baseIdless bool
	baseDecGen uint64
	pend       *netPending   // not settled yet
	quiet      netmode.Ident // an Unclear read already timed out without wouldAct: not re-timed
	// The Wi-Fi name of the identity ssidFor (one WLAN query per identity).
	ssidFor  netmode.Ident
	ssidOK   bool
	ssid     string
	ssidDeny bool
	gen      uint64 // bumped by the user's actions
	// rev is bumped by every install of a config (save, toggle, reload,
	// backup): a decision taken on an older config is not applied.
	rev      uint64
	override bool   // the user acted since the last change
	restored bool   // the override comes from a Restore start, not a click
	closed   bool   // exiting / update / move
	watchErr string // Watch failed: polling only
	nlmNoted bool   // "NLM does not answer" logged
	last     NetState
}

// NetState is Status.Net and part of the page's view.
type NetState struct {
	Rule     string    `json:"rule"` // matched rule name ("Неизвестная сеть"); "" = none evaluated yet
	RuleID   string    `json:"ruleId"`
	Unknown  bool      `json:"unknown"`
	NoNet    bool      `json:"noNet"`   // no active network now
	Pending  bool      `json:"pending"` // a change or re-decision waits for its confirming read
	Text     string    `json:"text"`
	Error    string    `json:"error,omitempty"`
	At       time.Time `json:"at"`
	Override bool      `json:"override"`
	Restored bool      `json:"restored"` // override from a Restore start (Home suffix)
	// Off: routing is off because a network rule turned it off (and the
	// user has not acted since). OffBy: that rule's name. A later applied
	// decision with Connect «не менять» keeps Off/OffBy; a connect or a user
	// action clears them.
	Off   bool   `json:"off"`
	OffBy string `json:"offBy,omitempty"`
}

// NetStartMode is what the start does about the network rules (main's
// planStart, from the launch reason).
type NetStartMode int

const (
	NetStartDecide      NetStartMode = iota // normal start: the rule of the network (or AutoConnect)
	NetStartRestore                         // update / rollback / move with --reconnect: a restore goroutine reconnects
	NetStartRestoreIdle                     // the same launches without --reconnect: stay as restored (disconnected)
)

// netmodesState is the Controller's «Сети» state.
type netmodesState struct {
	// NetWatcher reads the networks Windows is connected to (nil = network
	// modes unavailable: tests, other systems).
	NetWatcher NetWatcher
	// OnStartDecided: called once (on its own goroutine) after the start
	// decision of a normal start (NetStartDecide) or of a start without
	// --reconnect (NetStartRestoreIdle), with or without network modes.
	// main joins it with the window's startup (the start gate).
	OnStartDecided func()

	// netActMu orders automatic network actions against the user's: held
	// for a whole netApply, and briefly by netManual/ApplyNetModes/
	// StopNetModes. Order: netActMu → saveMu → mu, and netActMu → lifeMu →
	// mu/ksMu/proxyMu/recMu. Never taken while holding any of those.
	netActMu sync.Mutex
	// netMu guards net; innermost: nothing is taken or called with it held.
	// May be taken with saveMu and/or mu held (NetRulesUsing,
	// netInstallLocked, netExportLocked).
	netMu sync.Mutex
	net   netState
	// netWake: the feature was turned on or off, or StopNetModes closed it
	// (1-buffered, non-blocking send; the loop re-checks netOn()).
	netWake chan struct{}
	// netQuiet, netConfirm, netSettleMax, netPoll: timing of change
	// detection (tests shorten them).
	netQuiet, netConfirm, netSettleMax, netPoll time.Duration
	// testNetManual (tests) runs first in netManual.
	testNetManual func()
}

const (
	// whyAtOnce: the protective step of a new network's first read.
	whyAtOnce = "network change: at once"
	// whyStartAtOnce: the start's protective step when it switches to the
	// «Неизвестная сеть» profile until the confirming read.
	whyStartAtOnce = "start: at once"
	restoreText    = "Восстановлено прежнее подключение — правила сетей сработают при смене сети"
)

func (c *Controller) initNetModes() {
	c.netWake = make(chan struct{}, 1)
	c.netQuiet, c.netConfirm, c.netSettleMax, c.netPoll = 2*time.Second, 2*time.Second, 15*time.Second, 30*time.Second
	c.net.cfg = netmode.Default()
}

// fillNetRuleIDs gives rules without an ID (hand-written) one: the ID of
// the rule of the same name in prev (the config in memory, so a reload
// keeps them), else a new one.
func fillNetRuleIDs(cfg *netmode.Config, prev netmode.Config) {
	used := map[string]bool{}
	for _, r := range cfg.Rules {
		used[r.ID] = true
	}
	byName := map[string]string{}
	for _, r := range prev.Rules {
		if _, dup := byName[r.Name]; !dup && r.ID != "" && !used[r.ID] {
			byName[r.Name] = r.ID
		}
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.ID != "" {
			continue
		}
		if id, ok := byName[r.Name]; ok && !used[id] {
			r.ID = id
		} else {
			r.ID = newID()
		}
		used[r.ID] = true
	}
}

// netOn: the feature runs (a watcher, enabled, loaded, not closed).
func (c *Controller) netOn() bool {
	c.netMu.Lock()
	defer c.netMu.Unlock()
	return c.netOnLocked()
}

func (c *Controller) netOnLocked() bool {
	return c.NetWatcher != nil && c.net.cfg.Enabled && c.net.broken == nil && !c.net.closed
}

func (c *Controller) netWakeUp() {
	select {
	case c.netWake <- struct{}{}:
	default:
	}
}

// sessionActive: routing is on or starting.
func (c *Controller) sessionActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sess != nil || c.starting
}

// ---- manual actions, start and exit ----

// netManual: the user connected, disconnected, reconnected, released the
// kill switch or switched rule profiles. It waits for an automatic action
// under way, which the user's action then follows. Called holding no lock.
func (c *Controller) netManual() {
	if c.testNetManual != nil {
		c.testNetManual()
	}
	c.netActMu.Lock()
	c.netMu.Lock()
	c.net.gen++
	c.net.override = c.net.cfg.Enabled && c.net.broken == nil
	c.net.restored = false
	c.net.last.Off, c.net.last.OffBy = false, ""
	c.netMu.Unlock()
	c.netActMu.Unlock()
}

// StopNetModes: nothing acts any more (exit, update, move). Waits for an
// action under way.
func (c *Controller) StopNetModes() {
	c.netActMu.Lock()
	c.netMu.Lock()
	c.net.closed, c.net.pend = true, nil
	c.netMu.Unlock()
	c.netActMu.Unlock()
	c.netWakeUp()
}

// ResumeNetModes undoes StopNetModes when an update or move did not go
// ahead (HyRoute keeps running).
func (c *Controller) ResumeNetModes() {
	c.netMu.Lock()
	c.net.closed = false
	c.netMu.Unlock()
	c.netWakeUp()
}

// ConnectAtStart connects without counting as the user's action (the
// setting «Подключаться сразу после запуска», a restore after an update or
// a move). No servers: nothing (logged); settings.json broken: logged and
// returned.
func (c *Controller) ConnectAtStart(why string) error {
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	return c.connectAtStartLocked(why)
}

func (c *Controller) connectAtStartLocked(why string) error {
	if c.closing { // cli: HyRoute is exiting (BeginExit)
		c.Log.Info("not connecting at start: HyRoute is exiting")
		return nil
	}
	c.mu.Lock()
	none, broken := len(c.profiles.List) == 0, c.settingsBroken
	c.mu.Unlock()
	if none {
		c.Log.Info("not connecting at start: no servers")
		return nil
	}
	// The default rules send everything direct: not what the user set.
	if broken != nil {
		c.Log.Error("not connecting at start: settings.json did not load, the rules would be the defaults", "err", broken)
		return fmt.Errorf("settings.json не загружен: %v", broken)
	}
	c.Log.Info(why)
	if err := c.startLocked(false); err != nil {
		c.Log.Error("connect at start failed", "err", err)
		return err
	}
	return nil
}

func (c *Controller) autoConnectAtStart() {
	if c.Prefs().AutoConnect {
		c.ConnectAtStart("connecting at start (setting \"connect when HyRoute starts\")")
	}
}

// netAutoConnect is AutoConnect at a start that read the network first
// (up to a few seconds): skipped when the user acted during the read (their
// choice wins) or HyRoute is exiting. netActMu orders it against both, as
// netApply does.
func (c *Controller) netAutoConnect(gen uint64) {
	c.netActMu.Lock()
	defer c.netActMu.Unlock()
	c.netMu.Lock()
	ok := gen == c.net.gen && !c.net.closed
	c.netMu.Unlock()
	if !ok {
		c.Log.Debug("connect at start skipped: the user acted or HyRoute is exiting")
		return
	}
	c.autoConnectAtStart()
}

func (c *Controller) startDecided() {
	if c.OnStartDecided != nil {
		go c.OnStartDecided()
	}
}

// RunNetModes makes the start decision, then watches the networks while the
// feature is on, until ctx ends. Started once by main.
func (c *Controller) RunNetModes(ctx context.Context, mode NetStartMode) {
	c.netStart(ctx, mode)
	for ctx.Err() == nil {
		if !c.netOn() {
			select {
			case <-ctx.Done():
				return
			case <-c.netWake:
				continue
			}
		}
		c.netWatch(ctx)
	}
}

// netStart is the start decision (see NetStartMode).
func (c *Controller) netStart(ctx context.Context, mode NetStartMode) {
	switch mode {
	case NetStartRestore:
		// The restore goroutine reconnects and marks main's gate.
		c.netMu.Lock()
		if c.netOnLocked() {
			c.net.onFirst = firstBaselineOverride
		}
		c.netMu.Unlock()
		return
	case NetStartRestoreIdle:
		c.netMu.Lock()
		on := c.netOnLocked()
		if on {
			c.net.onFirst = firstBaselineOverride
		}
		c.netMu.Unlock()
		if !on {
			c.autoConnectAtStart() // as such a launch always did
		}
		c.startDecided()
		return
	}
	defer c.startDecided() // after the applies: the gate's check sees their result
	c.netMu.Lock()
	on := c.netOnLocked()
	c.net.baseGen, c.net.onFirst = c.net.gen, firstChange
	cfg, g, rev := c.net.cfg, c.net.gen, c.net.rev
	c.netMu.Unlock()
	if !on {
		c.autoConnectAtStart() // no snapshot: users of no network rules pay nothing
		return
	}
	rsID, rsSrc := c.rulesetActive()
	rsByNet := rsSrc == SourceNetwork || (rsSrc == "" && netmode.SelectsRuleset(cfg, rsID))
	snap := c.netRead(netmode.UsesSSID(cfg))
	if snap.Active == nil || !snap.Active.Identified {
		// Protection first; the first identity follows firstChange.
		c.netAutoConnect(g)
		c.changed()
		return
	}
	cur := snap.Active.Ident()
	auto := c.Prefs().AutoConnect
	d := netmode.Decide(cfg, *snap.Active)
	p := netmode.Protective(cfg, d, true, rsID, rsByNet)
	if d.Connect == netmode.Keep && auto {
		p.Connect = netmode.Connect
	}
	if !p.None() {
		why := "start"
		if p.Ruleset != "" && p.Ruleset != d.Ruleset {
			why = whyStartAtOnce // the «Неизвестная сеть» profile until the network is confirmed
		}
		c.netApply(g, rev, netmode.Decision{RuleID: d.RuleID, Name: d.Name, Unknown: d.Unknown, Action: p}, why, true)
	}
	if !netmode.Relaxing(d, p) {
		c.netMu.Lock()
		c.net.base, c.net.baseIdless, c.net.baseDecGen = cur, false, g
		if p.None() {
			c.noteRuleLocked(d)
		}
		c.netMu.Unlock()
		c.changed()
		return
	}
	// A disconnect or a matched rule's profile waits for a confirming read.
	select {
	case <-ctx.Done():
		return
	case <-time.After(c.netConfirm):
	}
	snap2 := c.netRead(netmode.UsesSSID(cfg))
	if snap2.Active == nil || !snap2.Active.Identified || netmode.Compare(cur, snap2.Active.Ident()) != netmode.Same {
		c.changed() // the loop takes the first identity as a change (the protective part ran)
		return
	}
	cur2 := snap2.Active.Ident()
	cur2.Fill(cur)
	d2 := netmode.Decide(cfg, *snap2.Active)
	if d2.Connect == netmode.Keep && auto {
		d2.Connect = netmode.Connect
	}
	c.netMu.Lock()
	c.net.base, c.net.baseIdless, c.net.baseDecGen = cur2, false, g
	c.netMu.Unlock()
	c.netApply(g, rev, d2, "start", true)
}

// noteRuleLocked records the rule of the current network when it is taken
// without acting (baselines), for the Home line.
func (c *Controller) noteRuleLocked(d netmode.Decision) {
	c.net.last.Rule, c.net.last.RuleID, c.net.last.Unknown = d.Name, d.RuleID, d.Unknown
}

// ---- reading ----

// netRead reads the networks now (holding no lock; wantSSID: with the Wi-Fi
// name, cached per identity) and stores the read.
func (c *Controller) netRead(wantSSID bool) netmode.Snapshot {
	snap, err := c.NetWatcher.Snapshot(false)
	if err != nil {
		snap.Err = joinMsg(snap.Err, err.Error())
	}
	if snap.Active != nil && wantSSID {
		if msg := c.netSSID(snap.Active); msg != "" {
			snap.Err = joinMsg(snap.Err, msg)
		}
	}
	c.netMu.Lock()
	first := c.storeSnapLocked(snap)
	c.netMu.Unlock()
	c.noteNLMDown(first)
	return snap
}

// netSSID fills n's Wi-Fi name: from the cache when it belongs to n's
// identity, else from one WLAN query (holding no lock). Returns a failure
// to show ("" when none).
func (c *Controller) netSSID(n *netmode.Network) string {
	if n.Adapter != netmode.WiFi {
		return ""
	}
	id := n.Ident()
	c.netMu.Lock()
	cached := c.ssidCoversLocked(id)
	ssid, deny := c.net.ssid, c.net.ssidDeny
	c.netMu.Unlock()
	if !cached {
		return c.netQuerySSID(n)
	}
	n.SSID, n.SSIDDenied = ssid, deny
	return ""
}

// netQuerySSID asks Windows for n's Wi-Fi name now (holding no lock) and
// fills n. A name or a refusal is cached for n's identity; a failure is
// not (the next read of the network asks again).
func (c *Controller) netQuerySSID(n *netmode.Network) string {
	s, err := c.NetWatcher.SSID(n.AdapterID)
	deny := errors.Is(err, netmode.ErrSSIDDenied)
	msg := ""
	if err != nil {
		s = ""
		if !deny {
			msg = "имя Wi-Fi: " + err.Error()
		}
	}
	c.netMu.Lock()
	c.netCacheSSIDLocked(n.Ident(), s, deny)
	c.netMu.Unlock()
	n.SSID, n.SSIDDenied = s, deny
	return msg
}

// netCacheSSIDLocked caches the Wi-Fi name of identity id when the query
// answered (a name, or Windows refused); otherwise it drops the cache.
func (c *Controller) netCacheSSIDLocked(id netmode.Ident, ssid string, deny bool) {
	if ssid == "" && !deny {
		c.net.ssidFor, c.net.ssidOK, c.net.ssid, c.net.ssidDeny = netmode.Ident{}, false, "", false
		return
	}
	c.net.ssidFor, c.net.ssidOK, c.net.ssid, c.net.ssidDeny = id, true, ssid, deny
}

// ssidCoversLocked: the cached Wi-Fi name is cur's. cur is the identity it
// was read for (Same: proved by the NLM ID or both gateway MACs), that
// identity with its NLM ID now (Refined), or a later read of the pending
// change it was read for. Never a read that may be another network
// (Unclear, Changed): only a query of its own names that one.
func (c *Controller) ssidCoversLocked(cur netmode.Ident) bool {
	if !c.net.ssidOK {
		return false
	}
	switch netmode.Compare(c.net.ssidFor, cur) {
	case netmode.Same, netmode.Refined:
		return true
	}
	p := c.net.pend
	return p != nil && p.kind != pendUnclear && netmode.SameRead(c.net.ssidFor, cur) && netmode.SameRead(p.id, cur)
}

// storeSnapLocked keeps snap as the cached read, with the cached Wi-Fi
// name of its identity. It reports whether NLM went down just now.
func (c *Controller) storeSnapLocked(snap netmode.Snapshot) bool {
	snap = snap.Clone() // the caller may go on filling its copy
	if a := snap.Active; a != nil && a.Adapter == netmode.WiFi && a.SSID == "" && !a.SSIDDenied && c.ssidCoversLocked(a.Ident()) {
		a.SSID, a.SSIDDenied = c.net.ssid, c.net.ssidDeny
	}
	c.net.snap, c.net.read = snap, true
	if snap.NLMDown && !c.net.nlmNoted {
		c.net.nlmNoted = true
		return true
	}
	return false
}

func (c *Controller) noteNLMDown(first bool) {
	if first {
		c.Log.Info("network list manager does not answer: network modes work without it until restart")
	}
}

func joinMsg(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + "; " + b
}

// ---- the loop ----

// netWatch reads at a fixed time after the first event of a burst (an
// armed read is never pushed later), every netConfirm while something is
// pending, and every netPoll, until ctx ends or the feature goes off.
func (c *Controller) netWatch(ctx context.Context) {
	wctx, cancel := context.WithCancel(ctx)
	defer cancel() // unregisters the notifications
	events, err := c.NetWatcher.Watch(wctx)
	c.netMu.Lock()
	c.net.watchErr = ""
	if err != nil {
		c.net.watchErr = err.Error()
		events = nil
	}
	c.netMu.Unlock()
	if err != nil {
		c.Log.Warn("network change notifications unavailable: checking the network every 30 s", "err", err)
	}
	c.netCheck(time.Now()) // baseline on enabling, catch-up otherwise
	poll := time.NewTicker(c.netPoll)
	defer poll.Stop()
	var timer *time.Timer
	arm := func(d time.Duration) {
		if timer == nil {
			timer = time.NewTimer(d)
		}
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	if c.netPendingNow() {
		arm(c.netConfirm)
	}
	for {
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}
		select {
		case <-ctx.Done():
			return
		case <-c.netWake:
			if !c.netOn() {
				return
			}
			if c.netBaselineDue() {
				// Turned off and on again before this loop saw the off: the
				// current network is the baseline now, not whatever a read
				// up to netPoll later finds.
				c.netCheck(time.Now())
				if c.netPendingNow() {
					arm(c.netConfirm)
				}
			}
		case <-events:
			arm(c.netQuiet)
		case <-timerC:
			timer = nil
			c.netCheck(time.Now())
			if c.netPendingNow() {
				arm(c.netConfirm)
			}
		case <-poll.C:
			c.netCheck(time.Now())
			if c.netPendingNow() {
				arm(c.netConfirm)
			}
		}
	}
}

// pendRefinesLocked: cur is pending p read with its NLM ID now. Not when
// that ID is the baseline's: the network may be the one just left (NLM
// can report it for a moment on the new link), and the baseline
// comparison decides that read.
func (c *Controller) pendRefinesLocked(p *netPending, cur netmode.Ident) bool {
	return netmode.Refines(p.id, cur) && !(c.net.base.NetID != "" && strings.EqualFold(c.net.base.NetID, cur.NetID))
}

// netBaselineDue: enabling cleared the baseline and no read has taken it.
func (c *Controller) netBaselineDue() bool {
	c.netMu.Lock()
	defer c.netMu.Unlock()
	return c.net.base.Empty() && c.net.onFirst == firstBaseline
}

func (c *Controller) netPendingNow() bool {
	c.netMu.Lock()
	defer c.netMu.Unlock()
	return c.net.pend != nil
}

// netCheck reads the networks and acts on a change. Windows reads happen
// holding no lock; netApply runs after netMu is released.
func (c *Controller) netCheck(now time.Time) {
	routing := c.sessionActive()
	rsID, rsSrc := c.rulesetActive()
	snap, err := c.NetWatcher.Snapshot(false)
	if err != nil {
		snap.Err = joinMsg(snap.Err, err.Error())
	}
	c.netMu.Lock()
	if !c.netOnLocked() {
		c.netMu.Unlock()
		return
	}
	visible := c.netVisibleLocked()
	cfg, rev := c.net.cfg, c.net.rev
	rsByNet := rsSrc == SourceNetwork || (rsSrc == "" && netmode.SelectsRuleset(cfg, rsID))
	if snap.Active == nil {
		first := c.storeSnapLocked(snap)
		c.net.pend = nil
		if c.net.base.Empty() && c.net.onFirst == firstBaseline {
			// Enabled while offline: the first network that appears is a
			// change, unless the user acts meanwhile.
			c.net.onFirst, c.net.baseGen = firstChange, c.net.gen
		}
		c.netDoneLocked(visible, first)
		return
	}
	cur := snap.Active.Ident()
	base := c.net.base
	rel := netmode.Changed
	kind := "-"
	defer func() {
		c.Log.Debug("network read", "rel", rel.String(), "kind", kind, "cur", cur.Hash8(), "base", base.Hash8(),
			"nlmErr", snap.Err != "", "identified", snap.Active.Identified)
	}()
	if p := c.net.pend; p != nil && p.kind != pendUnclear && (netmode.SameRead(p.id, cur) || c.pendRefinesLocked(p, cur)) {
		// A later read of the pending network.
		kind = p.kind.String()
		var early *netmode.Decision
		if p.id.NetID == "" && cur.NetID != "" {
			// It has its NLM ID now: still the same pending change (the
			// user's action since stays), but what relaxes waits for a
			// confirming read with this ID, netConfirm from now.
			p.id.NetID, p.since = cur.NetID, now
			early = c.netRefineConnectLocked(p, snap.Active, cfg, routing, rsID, rsByNet)
		}
		p.id.Fill(cur)
		g := p.gen
		c.netSettle(now, snap, cur, visible)
		if early != nil {
			c.netApply(g, rev, *early, whyAtOnce, false)
		}
		return
	}
	since := now
	if c.net.base.Empty() {
		switch {
		case c.net.onFirst == firstBaseline:
			c.net.base, c.net.baseIdless, c.net.onFirst = cur, false, firstChange
			c.noteRuleLocked(netmode.Decide(cfg, *snap.Active))
			c.netDoneLocked(visible, c.storeSnapLocked(snap))
			return
		case c.net.onFirst == firstBaselineOverride:
			c.net.base, c.net.override, c.net.restored, c.net.onFirst = cur, true, true, firstChange
			c.noteRuleLocked(netmode.Decide(cfg, *snap.Active))
			c.net.last.Text, c.net.last.Error, c.net.last.At = restoreText, "", now
			c.netDoneChangedLocked(c.storeSnapLocked(snap))
			return
		case c.net.gen != c.net.baseGen:
			// The user acted since the start or since enabling: their choice
			// stays until the network changes.
			c.net.base, c.net.override = cur, true
			c.noteRuleLocked(netmode.Decide(cfg, *snap.Active))
			c.netDoneChangedLocked(c.storeSnapLocked(snap))
			return
		}
	} else {
		rel = netmode.Compare(c.net.base, cur)
	}
	switch rel {
	case netmode.Same:
		c.net.base.Fill(cur)
		c.net.pend, c.net.quiet = nil, netmode.Ident{}
		c.netDoneLocked(visible, c.storeSnapLocked(snap))
		return
	case netmode.Refined:
		if c.net.baseIdless && c.net.gen == c.net.baseDecGen && cfg.Enabled && c.net.broken == nil {
			c.net.pend = &netPending{kind: pendRefine, id: cur, since: now, gen: c.net.gen}
			first := c.storeSnapLocked(snap)
			c.netMu.Unlock()
			c.noteNLMDown(first)
			// The identified network's rule decides: its Wi-Fi name first.
			if netmode.UsesSSID(cfg) {
				c.netSSID(snap.Active)
			}
			c.changed()
			return
		}
		nb := cur
		nb.Fill(c.net.base)
		c.net.base, c.net.baseIdless = nb, false
		c.netDoneLocked(visible, c.storeSnapLocked(snap))
		return
	case netmode.Unclear:
		p := c.net.pend
		if cur == c.net.quiet {
			c.netDoneLocked(visible, c.storeSnapLocked(snap))
			return
		}
		if p == nil || p.kind != pendUnclear {
			c.net.pend = &netPending{kind: pendUnclear, id: cur, since: now, gen: c.net.gen}
			c.netDoneLocked(visible, c.storeSnapLocked(snap))
			return
		}
		if now.Sub(p.since) < c.netSettleMax {
			c.netDoneLocked(visible, c.storeSnapLocked(snap))
			return
		}
		wouldAct := (cfg.Unknown.Connect == netmode.Connect && !routing) ||
			netmode.Protective(cfg, netmode.UnknownDecision(cfg), false, rsID, rsByNet).Ruleset != ""
		if !wouldAct {
			// A degraded read of the same network: nothing would change.
			c.net.pend, c.net.quiet = nil, cur
			c.netDoneLocked(visible, c.storeSnapLocked(snap))
			return
		}
		// Taken as a change whose settle time has passed.
		since = now.Add(-c.netSettleMax)
	}
	// Changed: the first read of a new network. The cached Wi-Fi name is
	// not its own (an Unclear read taken as a change may look like the
	// cached network): its name is asked for below.
	c.netCacheSSIDLocked(netmode.Ident{}, "", false)
	first := c.storeSnapLocked(snap)
	c.net.override, c.net.restored, c.net.quiet = false, false, netmode.Ident{}
	g := c.net.gen
	c.net.pend = &netPending{kind: pendChange, id: cur, since: since, gen: g}
	c.netMu.Unlock()
	c.noteNLMDown(first)
	if netmode.UsesSSID(cfg) {
		c.netSSID(snap.Active)
		c.netMu.Lock()
		c.storeSnapLocked(snap)
		c.netMu.Unlock()
	}
	d := netmode.Decide(cfg, *snap.Active)
	p := netmode.Protective(cfg, d, cur.NetID != "", rsID, rsByNet)
	if p.None() {
		c.changed()
		return
	}
	name, unknown := d.Name, d.Unknown
	if p.Connect == netmode.Connect && d.Connect != netmode.Connect || p.Connect == "" && p.Ruleset != "" {
		name, unknown = netmode.UnknownName, true // the Unknown fallback or the Unknown ruleset alone
	}
	c.netApply(g, rev, netmode.Decision{RuleID: d.RuleID, Name: name, Unknown: unknown, Action: p}, whyAtOnce, false)
}

// netRefineConnectLocked: pending change p was first read without an NLM
// ID and a is its first read with one. A connect the identified network's
// rule asks for is protective: it runs now (whyAtOnce), not after the
// confirming read. nil when there is nothing to connect (routing is on, p
// is not a change, or the user acted since).
func (c *Controller) netRefineConnectLocked(p *netPending, a *netmode.Network, cfg netmode.Config, routing bool, rsID string, rsByNet bool) *netmode.Decision {
	if routing || p.kind != pendChange || p.gen != c.net.gen {
		return nil
	}
	n := *a
	if n.Adapter == netmode.WiFi && n.SSID == "" && !n.SSIDDenied && c.ssidCoversLocked(n.Ident()) {
		n.SSID, n.SSIDDenied = c.net.ssid, c.net.ssidDeny
	}
	d := netmode.Decide(cfg, n)
	if netmode.Protective(cfg, d, true, rsID, rsByNet).Connect != netmode.Connect {
		return nil
	}
	return &netmode.Decision{RuleID: d.RuleID, Name: d.Name, Unknown: d.Unknown, Action: netmode.Action{Connect: netmode.Connect}}
}

// netSettle is a later read of a pending change or refine (netMu held; it
// releases it).
func (c *Controller) netSettle(now time.Time, snap netmode.Snapshot, cur netmode.Ident, visible bool) {
	p := c.net.pend
	if now.Sub(p.since) < c.netConfirm || p.kind == pendChange && cur.NetID == "" && now.Sub(p.since) < c.netSettleMax {
		c.netDoneLocked(visible, c.storeSnapLocked(snap))
		return
	}
	nb := cur
	nb.Fill(p.id)
	c.net.base, c.net.baseIdless = nb, cur.NetID == ""
	why := "network change"
	if p.kind == pendRefine {
		why = "network identified"
	}
	first := c.storeSnapLocked(snap) // before pend goes: its Wi-Fi name is the pending read's
	c.net.pend = nil
	active := *c.net.snap.Active // with the cached Wi-Fi name
	if p.gen != c.net.gen || !c.netOnLocked() {
		// The user acted since: their choice stays (baseDecGen untouched,
		// so a later Refined does not re-decide).
		c.netDoneChangedLocked(first)
		return
	}
	c.net.baseDecGen = c.net.gen
	cfg, rev := c.net.cfg, c.net.rev
	c.netMu.Unlock()
	c.noteNLMDown(first)
	if netmode.UsesSSID(cfg) && active.Adapter == netmode.WiFi && active.SSID == "" && !active.SSIDDenied {
		// The first read's WLAN query failed: ask once more before deciding.
		c.netQuerySSID(&active)
	}
	c.netApply(p.gen, rev, netmode.Decide(cfg, active), why, false)
}

// netVisibleLocked is what Home shows of the loop (pending or not).
func (c *Controller) netVisibleLocked() bool {
	return c.net.pend != nil && c.net.pend.kind != pendUnclear
}

// netDoneLocked releases netMu at the end of a read that did not act and
// tells the UI when what it shows changed.
func (c *Controller) netDoneLocked(wasVisible, nlmFirst bool) {
	changed := wasVisible != c.netVisibleLocked()
	c.netMu.Unlock()
	c.noteNLMDown(nlmFirst)
	if changed {
		c.changed()
	}
}

// netDoneChangedLocked is netDoneLocked after a change the UI shows.
func (c *Controller) netDoneChangedLocked(nlmFirst bool) {
	c.netMu.Unlock()
	c.noteNLMDown(nlmFirst)
	c.changed()
}

// ---- acting ----

// netApply runs decision d unless the user acted since gen (their action
// wins), or the config changed since rev or the feature went off (d was
// decided on what is no longer set). The ruleset first, then the
// connection. atStart: no servers is not an error (AutoConnect's
// behaviour). Never call it holding netActMu.
func (c *Controller) netApply(gen, rev uint64, d netmode.Decision, why string, atStart bool) {
	c.netActMu.Lock()
	defer c.netActMu.Unlock()
	c.netMu.Lock()
	ok := gen == c.net.gen && rev == c.net.rev && c.netOnLocked()
	c.netMu.Unlock()
	if !ok {
		c.Log.Debug("network rule skipped: the user acted, the rules changed or network rules are off")
		return
	}
	var texts, errs []string
	rsName := ""
	if d.Ruleset != "" {
		if cur, _ := c.rulesetActive(); cur != d.Ruleset {
			// rulesets' contract: saveMu → mu inside; never netActMu, lifeMu
			// or netManual for SourceNetwork.
			if err := c.ActivateRuleset(d.Ruleset, SourceNetwork); err != nil {
				if errors.Is(err, errRulesetNotFound) {
					errs = append(errs, "профиль правил не найден")
				} else {
					errs = append(errs, "профиль правил: "+err.Error())
				}
			} else {
				rsName = c.rulesetName(d.Ruleset)
				switch why {
				case whyAtOnce:
					texts = append(texts, fmt.Sprintf("Профиль правил «%s» включён: сеть сменилась, правило «%s»", rsName, netmode.UnknownName))
				case whyStartAtOnce:
					texts = append(texts, fmt.Sprintf("Профиль правил «%s» включён при запуске: правило «%s», пока сеть не подтверждена", rsName, netmode.UnknownName))
				default:
					texts = append(texts, fmt.Sprintf("Профиль правил «%s» включён правилом сети «%s»", rsName, d.Name))
				}
			}
		}
	}
	off, offBy := false, ""
	switch d.Connect {
	case netmode.Connect:
		c.lifeMu.Lock()
		done, err := c.netConnectLocked(atStart)
		c.lifeMu.Unlock()
		switch {
		case err != nil:
			errs = append(errs, err.Error())
		case done:
			texts = append(texts, fmt.Sprintf("Подключено правилом сети «%s»", d.Name))
		case len(texts) == 0:
			texts = append(texts, netLead(why, d.Name)+", HyRoute уже подключён")
		}
	case netmode.Disconnect:
		c.lifeMu.Lock()
		c.mu.Lock()
		had := c.sess != nil
		c.mu.Unlock()
		ks, _ := c.killSwitchStatus()
		blocked := ks == "blocking"
		if had || blocked {
			c.disconnectLocked(true)
		}
		c.lifeMu.Unlock()
		off, offBy = true, d.Name
		switch {
		case had || blocked:
			t := fmt.Sprintf("Отключено правилом сети «%s»", d.Name)
			if blocked {
				t += ", kill switch снял блокировку"
			}
			texts = append(texts, t)
		case len(texts) == 0:
			texts = append(texts, netLead(why, d.Name)+", HyRoute уже отключён")
		}
	default: // Keep: an earlier rule's Off stays while routing is still off
		c.netMu.Lock()
		prev := c.net.last
		c.netMu.Unlock()
		if prev.Off && !c.sessionActive() {
			off, offBy = true, prev.OffBy
		}
		if len(texts) == 0 && len(errs) == 0 {
			texts = append(texts, netLead(why, d.Name)+", ничего менять не нужно")
		}
	}
	st := NetState{Rule: d.Name, RuleID: d.RuleID, Unknown: d.Unknown, Text: strings.Join(texts, "; "),
		Error: strings.Join(errs, "; "), At: time.Now(), Off: off, OffBy: offBy}
	c.netMu.Lock()
	c.net.last = st
	c.netMu.Unlock()
	if st.Error != "" {
		// A refused or failed connect or profile switch (design §3.7).
		c.Log.Error("network rule failed", "rule", d.Name, "why", why, "connect", d.Connect, "ruleset", rsName, "err", st.Error)
	} else {
		c.Log.Info("network rule applied", "rule", d.Name, "why", why, "connect", d.Connect, "ruleset", rsName)
	}
	c.changed()
}

// netLead starts the texts of an action that changed nothing.
func netLead(why, rule string) string {
	switch why {
	case "start", whyStartAtOnce:
		return fmt.Sprintf("При запуске: правило «%s»", rule)
	case "apply":
		return fmt.Sprintf("Применено правило «%s»", rule)
	}
	return fmt.Sprintf("Сеть сменилась: правило «%s»", rule)
}

// netConnectLocked is the tray's «Подключить» for a rule (c.lifeMu held):
// a session whose engine failed is reconnected (the kill switch block
// stays), a running one is left alone, none is started. done: a session was
// started.
func (c *Controller) netConnectLocked(atStart bool) (done bool, err error) {
	c.mu.Lock()
	s := c.sess
	none, broken := len(c.profiles.List) == 0 && !c.Base.Stub, c.settingsBroken
	c.mu.Unlock()
	if s != nil && s.EngineFailed() {
		// Also stops a pending automatic reconnect (a new recovery gen).
		c.disconnectLocked(false)
		if err := c.startLocked(false); err != nil {
			return false, fmt.Errorf("не подключено: %v", err)
		}
		return true, nil
	}
	switch {
	case s != nil:
		return false, nil
	case c.closing: // cli: HyRoute is exiting; StopNetModes ran already
		return false, nil
	case broken != nil:
		return false, errors.New("settings.json не загружен")
	case none && atStart:
		return false, nil
	case none:
		return false, errors.New("нет серверов")
	}
	if err := c.startLocked(false); err != nil {
		return false, fmt.Errorf("не подключено: %v", err)
	}
	return true, nil
}

// ---- status ----

// netStatus is Status.Net: nil unless the feature is on.
func (c *Controller) netStatus(state string) *NetState {
	if c.NetWatcher == nil {
		return nil
	}
	c.netMu.Lock()
	defer c.netMu.Unlock()
	return c.netStatusLocked(state)
}

// netStatusLocked: state is Status.State ("" = not known: Off as recorded).
func (c *Controller) netStatusLocked(state string) *NetState {
	if !c.net.cfg.Enabled || c.net.broken != nil {
		return nil
	}
	s := c.net.last
	s.Override, s.Restored = c.net.override, c.net.override && c.net.restored
	s.NoNet = c.net.read && c.net.snap.Active == nil
	s.Pending = c.netVisibleLocked() || !c.net.read && !c.net.closed
	s.Off = s.Off && !c.net.override && (state == "" || state == "disconnected")
	if !s.Off {
		s.OffBy = ""
	}
	return &s
}

// ---- page API ----

// NetModesView is the page «Сети».
type NetModesView struct {
	Config      netmode.Config   `json:"config"`
	Current     netmode.Snapshot `json:"current"`
	Match       *NetMatchView    `json:"match"` // decision for Current.Active with the saved config; nil without network
	State       NetState         `json:"state"`
	Available   bool             `json:"available"`             // NetWatcher != nil
	Unavailable string           `json:"unavailable,omitempty"` // why not, or a lasting degradation
	LoadError   string           `json:"loadError,omitempty"`
	UsesSSID    bool             `json:"usesSSID"`
	// Rulesets for the editor: the saved profiles in display order ([] while
	// not saved or broken).
	Rulesets     []NetRuleset `json:"rulesets"`
	RulesetsNote string       `json:"rulesetsNote,omitempty"` // why the list is empty
	// RuleErrors: rule ID (or "unknown") → problem of its ruleset reference.
	RuleErrors map[string]string `json:"ruleErrors"`
	// Confirm: ApplyNetModes did not act, because the current network's
	// rule (Match, from the read it just took) disconnects and that rule
	// was not the one confirmed. Ask, then call again with its key.
	Confirm bool `json:"confirm,omitempty"`
}

// NetMatchView is the rule the current network gets.
type NetMatchView struct {
	RuleID  string `json:"ruleId"`
	Name    string `json:"name"`
	Unknown bool   `json:"unknown"`
	netmode.Action
}

// NetModes is the page's view: refresh=false → the loop's cached read (no
// Windows call; status events); refresh=true → a fresh read (mount,
// «Обновить»), also while the feature is off, which updates the cache.
func (c *Controller) NetModes(refresh bool) NetModesView {
	if refresh && c.NetWatcher != nil {
		c.netMu.Lock()
		uses := netmode.UsesSSID(c.net.cfg) && c.net.broken == nil
		c.netMu.Unlock()
		snap, err := c.NetWatcher.Snapshot(uses)
		if err != nil {
			snap.Err = joinMsg(snap.Err, err.Error())
		}
		c.netMu.Lock()
		if a := snap.Active; uses && a != nil && a.Adapter == netmode.WiFi && (a.SSID != "" || a.SSIDDenied) {
			// Only an answer is cached: a failed WLAN query leaves the cache.
			c.netCacheSSIDLocked(a.Ident(), a.SSID, a.SSIDDenied)
		}
		first := c.storeSnapLocked(snap)
		c.netMu.Unlock()
		c.noteNLMDown(first)
	}
	c.netMu.Lock()
	v := NetModesView{
		Config:    c.net.cfg.Clone(),
		Current:   c.net.snap.Clone(),
		Available: c.NetWatcher != nil,
		UsesSSID:  netmode.UsesSSID(c.net.cfg),
	}
	if c.net.broken != nil {
		v.LoadError = c.net.broken.Error()
	}
	if s := c.netStatusLocked(""); s != nil {
		v.State = *s
	} else {
		v.State = c.net.last
	}
	switch {
	case c.NetWatcher == nil:
		v.Unavailable = "HyRoute не получает сведения о сетях Windows"
	case c.net.cfg.Enabled && c.net.snap.NLMDown:
		v.Unavailable = "Windows не отвечает на запросы о сетях (NLM). Правила «Именно эта сеть», тип и имя сети не проверяются; перезапустите HyRoute."
	case c.net.cfg.Enabled && c.net.watchErr != "":
		v.Unavailable = "Смена сети замечается с задержкой до 30 с: " + c.net.watchErr
	}
	if a := v.Current.Active; a != nil {
		d := netmode.Decide(c.net.cfg, *a)
		v.Match = &NetMatchView{RuleID: d.RuleID, Name: d.Name, Unknown: d.Unknown, Action: d.Action}
	}
	c.netMu.Unlock()
	if v.Current.Others == nil {
		v.Current.Others = []netmode.Network{}
	}
	// No lock of ours is held: each of these takes c.mu itself.
	v.Rulesets = c.RulesetList()
	if v.Rulesets == nil {
		v.Rulesets = []NetRuleset{}
	}
	if len(v.Rulesets) == 0 {
		v.RulesetsNote = c.netRulesetsNote()
	}
	v.RuleErrors = map[string]string{}
	check := func(key, id string) {
		if id == "" {
			return
		}
		if !c.rulesetExists(id) {
			v.RuleErrors[key] = "Профиль правил удалён — выберите другой"
		} else if c.rulesetError(id) != "" {
			v.RuleErrors[key] = fmt.Sprintf("Профиль правил «%s» не загружается — выберите другой", c.rulesetName(id))
		}
	}
	for _, r := range v.Config.Rules {
		check(r.ID, r.Ruleset)
	}
	check("unknown", v.Config.Unknown.Ruleset)
	return v
}

// netRulesetsNote: why no profile can be chosen.
func (c *Controller) netRulesetsNote() string {
	c.mu.Lock()
	broken := c.rulesetsBroken
	c.mu.Unlock()
	if broken != nil {
		return "Профили правил не загружены: " + broken.Error()
	}
	return "Чтобы переключать профиль правил по сети, создайте второй профиль на странице «Правила»."
}

// SaveNetModes saves the rules and «Неизвестная сеть» (cfg.Enabled is kept
// as saved: SetNetModesEnabled changes it). Never acts.
func (c *Controller) SaveNetModes(cfg netmode.Config) (NetModesView, error) {
	if err := c.saveNetModes(cfg); err != nil {
		return NetModesView{}, err
	}
	c.changed()
	return c.NetModes(false), nil
}

func (c *Controller) saveNetModes(cfg netmode.Config) error {
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.netMu.Lock()
	broken, saved := c.net.broken, c.net.cfg.Clone()
	var active *netmode.Network
	if a := c.net.snap.Active; a != nil {
		n := *a
		active = &n
	}
	c.netMu.Unlock()
	if broken != nil {
		return netBrokenError(broken)
	}
	cfg = cfg.Clone()
	fillNetRuleIDs(&cfg, saved)
	netmode.Normalize(&cfg)
	cfg.Version, cfg.Enabled = netmode.Version, saved.Enabled
	if err := netmode.Validate(cfg); err != nil {
		return err
	}
	// Only a new or changed ruleset reference is checked: a stale one
	// stays saveable (ruleErrors marks it).
	savedRS := map[string]string{}
	knownIDs := map[string]bool{}
	for _, r := range saved.Rules {
		savedRS[r.ID] = r.Ruleset
		for _, k := range r.Match.Networks {
			knownIDs[strings.ToUpper(k.ID)] = true
		}
	}
	for _, r := range cfg.Rules {
		if r.Ruleset != "" && savedRS[r.ID] != r.Ruleset && !c.rulesetExists(r.Ruleset) {
			return sentencef("Правило сети «%s»: профиль правил не найден", r.Name)
		}
		for _, k := range r.Match.Networks {
			if !knownIDs[k.ID] && active != nil && strings.EqualFold(active.ID, k.ID) && !active.Identified {
				return sentencef("Правило сети «%s»: Windows ещё не опознала эту сеть", r.Name)
			}
		}
	}
	if u := cfg.Unknown.Ruleset; u != "" && u != saved.Unknown.Ruleset && !c.rulesetExists(u) {
		return sentencef("%s: профиль правил не найден", netmode.UnknownName)
	}
	if err := c.Store.SaveNetModes(cfg); err != nil {
		return err
	}
	c.netInstallLocked(cfg)
	c.Log.Info("network rules saved", "rules", len(cfg.Rules), "enabled", cfg.Enabled)
	return nil
}

func netBrokenError(broken error) error {
	return fmt.Errorf("networks.json не загружен, изменения не сохраняются, чтобы не потерять правила сетей: %v", broken)
}

// SetNetModesEnabled toggles only `enabled`, on the config in memory under
// saveMu (page checkbox, the CLI): an edit saved meanwhile is never lost.
// Never acts: enabling takes the current network as the baseline.
func (c *Controller) SetNetModesEnabled(on bool) (NetModesView, error) {
	changed, err := c.setNetModesEnabled(on)
	if err != nil {
		return NetModesView{}, err
	}
	if changed {
		c.changed()
	}
	return c.NetModes(false), nil
}

func (c *Controller) setNetModesEnabled(on bool) (bool, error) {
	c.saveMu.Lock()
	defer c.saveMu.Unlock()
	c.netMu.Lock()
	broken, cfg := c.net.broken, c.net.cfg.Clone()
	c.netMu.Unlock()
	if broken != nil {
		return false, netBrokenError(broken)
	}
	if cfg.Enabled == on {
		return false, nil
	}
	cfg.Enabled = on
	if err := c.Store.SaveNetModes(cfg); err != nil {
		return false, err
	}
	c.netInstallLocked(cfg)
	if on {
		c.Log.Info("network rules enabled")
	} else {
		c.Log.Info("network rules disabled")
	}
	return true, nil
}

// NetRuleKey is the key ApplyNetModes takes to confirm a disconnect: the
// rule ID, "unknown" for «Неизвестная сеть» (as RuleErrors).
func NetRuleKey(ruleID string, unknown bool) string {
	if unknown {
		return "unknown"
	}
	return ruleID
}

// ApplyNetModes («Применить сейчас») acts on the current network at once:
// the override goes and the current network becomes the baseline. A rule
// that disconnects (routing off, the kill switch block released) acts only
// when confirmDisconnect is its NetRuleKey: the decision is the fresh
// read's, which may not be the one the user saw; otherwise nothing acts
// and the view comes back with Confirm set.
func (c *Controller) ApplyNetModes(confirmDisconnect string) (NetModesView, error) {
	c.netMu.Lock()
	on, cfg := c.netOnLocked(), c.net.cfg
	c.netMu.Unlock()
	if !on {
		return NetModesView{}, sentenceError("Правила сетей выключены")
	}
	snap, err := c.NetWatcher.Snapshot(netmode.UsesSSID(cfg))
	if err != nil {
		snap.Err = joinMsg(snap.Err, err.Error())
	}
	if snap.Active == nil {
		c.netMu.Lock()
		first := c.storeSnapLocked(snap)
		c.netMu.Unlock()
		c.noteNLMDown(first)
		return NetModesView{}, sentenceError("Нет подключения к сети")
	}
	cur := snap.Active.Ident()
	c.netActMu.Lock()
	c.netMu.Lock()
	if cfg = c.net.cfg; !c.netOnLocked() {
		c.netMu.Unlock()
		c.netActMu.Unlock()
		return NetModesView{}, sentenceError("Правила сетей выключены")
	}
	if d := netmode.Decide(cfg, *snap.Active); d.Connect == netmode.Disconnect && NetRuleKey(d.RuleID, d.Unknown) != confirmDisconnect {
		first := c.storeSnapLocked(snap)
		c.netMu.Unlock()
		c.netActMu.Unlock()
		c.noteNLMDown(first)
		v := c.NetModes(false)
		v.Confirm = true
		return v, nil
	}
	c.net.gen++
	g := c.net.gen
	c.net.override, c.net.restored = false, false
	c.net.base, c.net.baseIdless, c.net.baseDecGen = cur, cur.NetID == "", g
	c.net.pend, c.net.quiet = nil, netmode.Ident{}
	if a := snap.Active; netmode.UsesSSID(cfg) && a.Adapter == netmode.WiFi {
		c.netCacheSSIDLocked(cur, a.SSID, a.SSIDDenied) // a failed WLAN query drops it
	}
	first := c.storeSnapLocked(snap)
	d := netmode.Decide(cfg, *snap.Active)
	rev := c.net.rev
	c.netMu.Unlock()
	c.netActMu.Unlock() // netApply takes it: not reentrant
	c.noteNLMDown(first)
	c.netApply(g, rev, d, "apply", false)
	return c.NetModes(false), nil
}

// CurrentSSID is the Wi-Fi name of the active network ("" when it is not
// Wi-Fi): the editor's «Текущее».
func (c *Controller) CurrentSSID() (string, error) {
	if c.NetWatcher == nil {
		return "", sentenceError("Определение сети недоступно")
	}
	snap, err := c.NetWatcher.Snapshot(false)
	if err != nil {
		return "", err
	}
	a := snap.Active
	if a == nil {
		return "", sentenceError("Нет подключения к сети")
	}
	if a.Adapter != netmode.WiFi {
		return "", nil
	}
	s, err := c.NetWatcher.SSID(a.AdapterID)
	if errors.Is(err, netmode.ErrSSIDDenied) {
		return "", sentenceError("Windows не даёт HyRoute имя Wi-Fi. В Windows 11 24H2 и новее включите «Параметры → Конфиденциальность и защита → Расположение → Разрешить классическим приложениям доступ к расположению».")
	}
	if err != nil {
		return "", fmt.Errorf("имя Wi-Fi не получено: %v", err)
	}
	return s, nil
}

// ---- contracts for other features ----

// NetRulesUsing names the network rules (and «Неизвестная сеть») whose
// action switches to rule profile id: rulesets' delete confirmation and
// RulesetView.UsedBy. Takes netMu only; callable with saveMu/mu held.
func (c *Controller) NetRulesUsing(id string) []string {
	if id == "" {
		return nil
	}
	c.netMu.Lock()
	defer c.netMu.Unlock()
	var out []string
	for _, r := range c.net.cfg.Rules {
		if r.Ruleset == id {
			out = append(out, r.Name)
		}
	}
	if c.net.cfg.Unknown.Ruleset == id {
		out = append(out, netmode.UnknownName)
	}
	return out
}

// netExportLocked is a deep copy of the config and the load error, for
// backup's snapshot (c.mu held; takes netMu only).
func (c *Controller) netExportLocked() (netmode.Config, error) {
	c.netMu.Lock()
	defer c.netMu.Unlock()
	return c.net.cfg.Clone(), c.net.broken
}

// netInstallLocked installs an already written, validated config
// (SaveNetModes with saveMu held; backup commit/rollback with saveMu+mu
// held). netMu only, no I/O. Never acts: turning the feature on takes the
// current network as the baseline.
func (c *Controller) netInstallLocked(cfg netmode.Config) {
	c.netMu.Lock()
	was := c.net.cfg.Enabled && c.net.broken == nil
	c.net.cfg, c.net.broken = cfg.Clone(), nil
	c.net.rev++
	switch {
	case !was && cfg.Enabled:
		c.net.base, c.net.pend, c.net.quiet, c.net.baseIdless = netmode.Ident{}, nil, netmode.Ident{}, false
		c.net.onFirst, c.net.baseGen = firstBaseline, c.net.gen
		c.net.override, c.net.restored = false, false
	case was && !cfg.Enabled:
		c.net.pend = nil
	}
	c.netMu.Unlock()
	c.netWakeUp()
}

// netInstallLoadedLocked installs what Store.LoadNetModes returned (Load,
// backup's undo re-parse): err != nil → broken (nothing acts).
func (c *Controller) netInstallLoadedLocked(cfg netmode.Config, err error) {
	if err == nil {
		c.netMu.Lock()
		prev := c.net.cfg.Clone()
		c.netMu.Unlock()
		fillNetRuleIDs(&cfg, prev)
		c.netInstallLocked(cfg)
		return
	}
	c.netMu.Lock()
	c.net.cfg, c.net.broken, c.net.pend = netmode.Default(), err, nil
	c.net.rev++
	c.netMu.Unlock()
	c.netWakeUp()
}

// ---- privacy (hyroutectl --private; the window masks by itself) ----

const masked = "***"

func maskNonEmpty(s string) string {
	if s == "" {
		return ""
	}
	return masked
}

// netRuleQuote is a name quoted after «правило сети» (networks.json load
// errors name rules the caller may not know).
var netRuleQuote = regexp.MustCompile(`([Пп]равил[а-я]* сет(?:и|ей) «)([^»]*)»`)

// maskRuleNames replaces each name (longest first) in s, and any name
// quoted after «правило сети», with «***», then masks hosts, IPs, domains
// and URLs.
func maskRuleNames(s string, names []string) string {
	if s == "" {
		return s
	}
	names = append([]string(nil), names...)
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, n := range names {
		if n != "" && n != netmode.UnknownName {
			s = strings.ReplaceAll(s, "«"+n+"»", "«"+masked+"»")
		}
	}
	s = netRuleQuote.ReplaceAllStringFunc(s, func(m string) string {
		sm := netRuleQuote.FindStringSubmatch(m)
		if sm[2] == netmode.UnknownName {
			return m
		}
		return sm[1] + masked + "»"
	})
	return logx.Sanitize(s, nil)
}

func (s NetState) private(names []string) NetState {
	names = append(names, s.Rule, s.OffBy)
	if s.Rule != netmode.UnknownName {
		s.Rule = maskNonEmpty(s.Rule)
	}
	if s.OffBy != netmode.UnknownName {
		s.OffBy = maskNonEmpty(s.OffBy)
	}
	s.Text, s.Error = maskRuleNames(s.Text, names), maskRuleNames(s.Error, names)
	return s
}

// Private masks the rule names and the texts of Status.Net.
func (s NetState) Private() NetState { return s.private(nil) }

func privateNetwork(n netmode.Network) netmode.Network {
	n.Name, n.SSID, n.AdapterName = maskNonEmpty(n.Name), maskNonEmpty(n.SSID), maskNonEmpty(n.AdapterName)
	return n
}

// Private is a copy with SSIDs, network and adapter names and rule names
// masked, and the state texts with the rule names replaced and hosts and
// IPs masked.
func (v NetModesView) Private() NetModesView {
	var names []string
	cfg := v.Config.Clone()
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		names = append(names, r.Name)
		r.Name = masked
		for j := range r.Match.Networks {
			r.Match.Networks[j].Name = maskNonEmpty(r.Match.Networks[j].Name)
		}
		for j := range r.Match.SSIDs {
			r.Match.SSIDs[j] = masked
		}
		for j := range r.Match.Names {
			r.Match.Names[j] = masked
		}
	}
	v.Config = cfg
	cur := v.Current.Clone()
	if cur.Active != nil {
		a := privateNetwork(*cur.Active)
		cur.Active = &a
	}
	for i := range cur.Others {
		cur.Others[i] = privateNetwork(cur.Others[i])
	}
	cur.Err = maskRuleNames(cur.Err, names)
	v.Current = cur
	v.LoadError = maskRuleNames(v.LoadError, names)
	if v.Match != nil {
		m := *v.Match
		if !m.Unknown {
			m.Name = masked
		}
		v.Match = &m
	}
	v.State = v.State.private(names)
	return v
}

// ---- diagnostics ----

var netCategoryText = map[string]string{netmode.Public: "общедоступная", netmode.Private: "частная", netmode.Domain: "доменная"}

// netDiagLines is the «сети» line of the report: never SSIDs, network
// names, IDs, adapter GUIDs or gateway addresses. privacy («Скрыть
// данные») also masks the rule names (often the SSID) in the line and in
// the last action's text, as the window and hyroutectl --private do.
func (c *Controller) netDiagLines(privacy bool) []string {
	if c.NetWatcher == nil {
		return nil
	}
	c.netMu.Lock()
	defer c.netMu.Unlock()
	switch {
	case c.net.broken != nil:
		return []string{"   сети: networks.json не загружен"}
	case !c.net.cfg.Enabled:
		return []string{fmt.Sprintf("   сети: выключены, правил %d", len(c.net.cfg.Rules))}
	}
	b := fmt.Sprintf("   сети: включены, правил %d; сейчас: ", len(c.net.cfg.Rules))
	switch a := c.net.snap.Active; {
	case !c.net.read:
		b += "ещё не прочитано"
	case a == nil:
		b += "нет сети"
	default:
		cat := netCategoryText[a.Category]
		if cat == "" {
			cat = "тип не определён"
		}
		b += a.Adapter + ", " + cat
		if r := c.net.last.Rule; r != "" {
			if privacy && r != netmode.UnknownName {
				r = masked
			}
			b += ", правило «" + r + "»"
		}
		if !a.Identified {
			b += ", не опознана"
		}
	}
	if c.net.snap.NLMDown {
		b += "; NLM не отвечает"
	}
	if c.net.override {
		b += "; вручную до смены сети"
	}
	if l := c.net.last; !l.At.IsZero() {
		text, errText := l.Text, l.Error
		if privacy {
			names := []string{l.Rule, l.OffBy}
			for _, r := range c.net.cfg.Rules {
				names = append(names, r.Name)
			}
			text, errText = maskRuleNames(text, names), maskRuleNames(errText, names)
		}
		b += "; последнее: " + l.At.Format("15:04") + " " + text + msgSuffix(errText)
	}
	return []string{b}
}
