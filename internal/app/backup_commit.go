package app

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/netmode"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// A restore's writes (backup.md §3.5 «Commit») and the reload of raw bytes
// its undo uses. Load reads through the same two halves: loadFile (one
// data file, no lock) and installLoadedLocked.

// loadOrder is the order of Load's reads and of the load errors it shows.
var loadOrder = []string{"profiles.json", "subscriptions.json", "prefs.json", "proxies.json", "dns.json", "groups.json", "settings.json", "networks.json"}

// loaded is one data file as Load reads it: its value (the fallback when
// it did not load), its error and the load texts it adds to loadErr.
// "settings.json" stands for settings.json and rulesets.json together
// (reconcileRulesets).
type loaded struct {
	name     string
	err      error
	notes    []string
	profiles *store.Profiles
	subs     []store.Subscription
	prefs    store.Prefs
	proxies  []store.LocalProxy
	groups   *groups.File
	rules    rsLoad
	dns      dnspolicy.Config // dns
	net      netmode.Config   // netmodes
}

// loadedOf is the entry of name in ls (a zero one when absent).
func loadedOf(ls []loaded, name string) loaded {
	for _, l := range ls {
		if l.name == name {
			return l
		}
	}
	return loaded{name: name}
}

// loadFile reads one data file (no lock held). groups.json needs the
// servers it is installed with (a group with a server's ID is refused).
func (c *Controller) loadFile(name string, profiles *store.Profiles) loaded {
	l := loaded{name: name}
	note := func(err error) {
		if err != nil {
			l.notes = append(l.notes, err.Error())
		}
	}
	switch name {
	case "profiles.json":
		p, err := c.Store.LoadProfiles()
		if err != nil {
			p = &store.Profiles{}
		}
		l.profiles, l.err = p, err
		note(err)
	case "subscriptions.json":
		subs, err := c.Store.LoadSubscriptions()
		if err != nil {
			subs = nil
		}
		l.subs, l.err = subs, err
		note(err)
	case "prefs.json":
		prefs, err := c.Store.LoadPrefs()
		if err != nil {
			// The user's choices are unknown: logs stay in memory (log files
			// may have been turned off), and the rule databases are left as
			// they are (geoDue).
			off := false
			prefs = store.Prefs{LogsToDisk: &off}
		}
		l.prefs, l.err = prefs, err
		note(err)
	case "proxies.json":
		proxies, err := c.Store.LoadProxies()
		if err != nil {
			proxies = nil
		}
		l.proxies, l.err = proxies, err
		note(err)
	case "groups.json":
		l.groups, l.err = c.loadGroups(&l.notes, profiles)
	case "settings.json":
		// rulesets: whether settings.json exists, read before LoadSettings.
		existed := c.Store.HasSettings()
		st, set, err := c.Store.LoadSettings()
		if err != nil {
			note(err)
			st = store.DefaultSettings()
			set, _ = rules.Compile(st.Config)
			set.ExactWeb = st.ExactWeb()
		}
		rl := c.loadRulesets(st, set, err, existed) // the active rules may come from rulesets.json
		if rl.RulesUnknown != nil {
			// The defaults stand in for rules that exist: as with a
			// settings.json that did not load, nothing connects or saves.
			note(rl.RulesUnknown)
			err = rl.RulesUnknown
		} else if rl.Broken != nil {
			note(rl.Broken)
		}
		l.rules, l.err = rl, err
	case "dns.json":
		// dns: a broken one keeps every option off.
		l.dns, l.err = c.loadDNS(&l.notes)
	case "networks.json":
		// netmodes: a broken one acts on nothing.
		l.net, l.err = c.Store.LoadNetModes()
		note(l.err)
	}
	return l
}

// installLoadedLocked installs what loadFile read (c.mu held; in
// loadOrder, so groups.json finds the servers installed) and recomputes
// loadErr from every file's texts. dnsErr: a loaded dns.json could not be
// applied to the running session (an undo while connected).
func (c *Controller) installLoadedLocked(ls []loaded) (dnsErr error) {
	if c.loadNotes == nil {
		c.loadNotes = map[string][]string{}
	}
	groupsDone := false
	for _, l := range ls {
		switch l.name {
		case "profiles.json":
			c.profiles, c.profilesBroken = l.profiles, l.err
		case "subscriptions.json":
			c.subs, c.subsBroken = l.subs, l.err
			for _, s := range l.subs {
				c.Redactor.SetGroup("sub:"+s.ID, urlSecrets(s.URL)...)
			}
		case "prefs.json":
			c.prefs, c.prefsBroken = l.prefs, l.err
		case "proxies.json":
			c.proxies, c.proxiesBroken = l.proxies, l.err
			for _, p := range l.proxies {
				c.Redactor.SetGroup("proxy:"+p.ID, p.Password)
			}
		case "groups.json":
			c.loadedGroupsLocked(l.groups, l.err)
			groupsDone = true
		case "settings.json":
			c.settingsBroken = l.err
			c.rulesAt = c.settingsRev.Add(1)
			c.installRulesetsLoadLocked(l.rules)
		case "dns.json":
			if l.err != nil {
				c.installLoadedDNSLocked(l.dns, l.err)
			} else {
				dnsErr = c.dnsInstallLocked(l.dns) // applies to a running session
			}
		case "networks.json":
			c.netInstallLoadedLocked(l.net, l.err)
		}
		c.loadNotes[l.name] = l.notes
	}
	if !groupsDone {
		c.syncGroupsLocked() // the servers may have changed
	}
	c.updateNamesLocked()
	c.recomputeLoadErrLocked()
	return dnsErr
}

func (c *Controller) recomputeLoadErrLocked() {
	var errs []string
	for _, n := range loadOrder {
		errs = append(errs, c.loadNotes[n]...)
	}
	c.loadErr = strings.Join(errs, "; ")
}

// brokenField is the *Broken error of a data file.
func (c *Controller) brokenField(name string) *error {
	switch name {
	case "profiles.json":
		return &c.profilesBroken
	case "subscriptions.json":
		return &c.subsBroken
	case "settings.json":
		return &c.settingsBroken
	case "proxies.json":
		return &c.proxiesBroken
	case "prefs.json":
		return &c.prefsBroken
	case "groups.json":
		return &c.groupsBroken
	case "rulesets.json":
		return &c.rulesetsBroken
	case "dns.json":
		return &c.dnsBroken
	}
	return nil // networks.json: markBrokenLocked
}

// markBrokenLocked marks a data file broken in memory (c.mu held), so no
// save overwrites what a failed rollback left on disk.
func (c *Controller) markBrokenLocked(name string, err error) {
	if p := c.brokenField(name); p != nil {
		*p = err
		return
	}
	if name == "networks.json" {
		c.netMu.Lock()
		c.net.cfg, c.net.broken, c.net.pend = netmode.Default(), err, nil
		c.net.rev++
		c.netMu.Unlock()
	}
}

// commitResult is what the post step needs to know.
type commitResult struct {
	needsReconnect bool
	settingsWrote  bool // settings.json written (B8: OnSettings)
	rulesChanged   bool
	// dns: flushRules — the rules were written while connected with «DNS по
	// правилам» on (cached answers followed the old rules); dnsWritten —
	// dns.json was written while connected; dnsErr — its policy did not
	// reach the running session.
	flushRules, dnsWritten bool
	dnsErr                 error
}

// commitRestoreLocked writes pl's files in order and installs them. The
// subscription locks, saveMu and mu are held. before holds the raw bytes
// of every file pl may write (the undo record's too). A failed write puts
// every written file back byte for byte (nothing re-sealed) and removes the
// copies of broken files: rollbackErr is the first failure of that.
func (c *Controller) commitRestoreLocked(pl *restorePlan, before map[string]store.RawFile) (res commitResult, rollbackErr, err error) {
	now := time.Now()
	var copies []string
	next := &pl.next
	var written []string
	rollback := func(err error) (commitResult, error, error) {
		var first error
		for _, f := range slices.Backward(written) {
			if rerr := c.Store.WriteRaw(f, before[f]); rerr != nil {
				if first == nil {
					first = rerr
				}
				c.markBrokenLocked(f, fmt.Errorf("файл изменён частично при восстановлении: %v", rerr))
			}
		}
		for _, n := range copies {
			c.Store.RemoveBroken(n)
		}
		return commitResult{}, first, err
	}
	write := func(name string, fn func() error) error {
		if c.restoreWriteHook != nil {
			if err := c.restoreWriteHook(name); err != nil {
				written = append(written, name)
				return err
			}
		}
		written = append(written, name)
		return fn()
	}
	has := func(f string) bool { return slices.Contains(pl.writes, f) }

	// The rules step's decision, made on the live state (under the locks).
	var (
		b       []byte
		parsed  *settings.Settings
		set     *rules.Set
		hash    string
		pair    *store.Rulesets
		rsOnly  *store.Rulesets
		prep    rsPrep
		cleared bool
	)
	s := c.rsStateLocked()
	if has("settings.json") {
		st := next.Settings
		if st.Rules == nil {
			st.Rules = []rules.Rule{}
		}
		if b, parsed, set, err = validateSettings(&st); err != nil {
			return res, nil, err
		}
		hash = store.ConfigHash(parsed.Config)
		if has("rulesets.json") {
			pair = rulesetsForCommit(s, pl.rules.rulesets, parsed.Config)
		} else {
			pair = rulesetsForCommit(s, nil, parsed.Config)
		}
		if pair != nil {
			prep = prepRulesets(s, pair)
		}
	} else if has("rulesets.json") {
		rsOnly = rulesetsOnlyState(s, pl.rules.rulesets)
		prep = prepRulesets(s, rsOnly)
	}

	// The copies of broken files, only once nothing above can refuse.
	for _, f := range pl.keepBroken {
		name, err := c.Store.KeepBroken(f, before[f].Data, now)
		if err != nil {
			for _, n := range copies {
				c.Store.RemoveBroken(n)
			}
			return res, nil, err
		}
		copies = append(copies, name)
	}

	for _, f := range pl.writes {
		var err error
		switch f {
		case "subscriptions.json":
			err = write(f, func() error { return c.Store.SaveSubscriptions(next.Subs) })
		case "profiles.json":
			err = write(f, func() error { return c.Store.SaveProfiles(&next.Profiles) })
		case "groups.json":
			err = write(f, func() error { return c.Store.SaveGroups(next.Groups) })
		case "proxies.json":
			err = write(f, func() error { return c.Store.SaveProxies(next.Proxies) })
		case "settings.json":
			if pair != nil {
				written = append(written, "rulesets.json") // both are put back on a failure
				err = write(f, func() error {
					var revErr, werr error
					cleared, revErr, werr = c.Store.WriteRulesPair(b, pair, s.SettingsHash, hash)
					if revErr != nil {
						c.Log.Warn("restore: rulesets.json could not be reverted", "err", revErr)
					}
					return werr
				})
			} else {
				err = write(f, func() error { return c.Store.WriteSettings(b) })
			}
		case "rulesets.json":
			if rsOnly != nil {
				err = write(f, func() error { return c.Store.SaveRulesets(rsOnly) })
			}
		case "networks.json":
			err = write(f, func() error { return c.Store.SaveNetModes(next.Net) })
		case "dns.json":
			err = write(f, func() error { return c.Store.SaveDNS(next.DNS) })
		case "prefs.json":
			err = write(f, func() error { return c.Store.SavePrefs(next.Prefs) })
		}
		if err != nil {
			return rollback(err)
		}
	}

	// Install: memory follows the files (no I/O).
	for _, f := range pl.writes {
		if p := c.brokenField(f); p != nil {
			*p = nil
		}
		delete(c.loadNotes, f)
	}
	if has("subscriptions.json") {
		c.subs = slices.Clone(next.Subs)
	}
	if has("profiles.json") {
		c.profiles = &store.Profiles{Active: next.Profiles.Active, List: slices.Clone(next.Profiles.List)}
		delete(c.loadNotes, "groups.json") // its grp- server notes were about the old list
	}
	if has("groups.json") {
		c.installGroupsLocked(next.Groups.Clone())
	} else {
		c.syncGroupsLocked()
	}
	if has("proxies.json") {
		c.proxies = slices.Clone(next.Proxies)
	}
	if has("prefs.json") {
		c.prefs = next.Prefs
	}
	if has("networks.json") {
		c.netInstallLocked(next.Net) // never acts
	}
	if has("dns.json") {
		res.dnsErr = c.dnsInstallLocked(next.DNS)
		res.dnsWritten = c.sess != nil
	}
	switch {
	case has("settings.json"):
		old := c.settings
		c.settings, c.set = parsed, set
		c.settingsHash = hash
		if pair != nil {
			c.installPairLocked(pair, prep, hash, cleared)
		}
		rev := c.settingsRev.Add(1)
		res.settingsWrote = true
		if old == nil || !sameRules(old.Config, parsed.Config) {
			c.rulesAt = rev
			res.rulesChanged = true
		}
	case rsOnly != nil:
		c.installRulesetsLocked(rsOnly, prep, c.settingsHash, rsOnly.Pending != nil)
	}
	c.recomputeLoadErrLocked()
	c.updateNamesLocked()
	if c.sess != nil || c.starting {
		c.applyRoutingLocked()
		res.needsReconnect = engineOptionsDiffer(c.sessSet, c.settings)
	}
	res.flushRules = res.rulesChanged && c.dnsRulesChangedLocked()
	return res, nil, nil
}

// reloadRawLocked re-reads the data files an undo put back, with Load's
// own parsers (a file that was broken before the restore is broken again),
// and applies the result (c.mu held; the engine is not restarted).
func (c *Controller) reloadRawLocked(names []string) commitResult {
	var res commitResult
	want := map[string]bool{}
	for _, n := range names {
		if n == "rulesets.json" {
			n = "settings.json"
		}
		want[n] = true
	}
	oldCfg := c.settings.Config
	var ls []loaded
	profiles := c.profiles
	for _, n := range loadOrder {
		if !want[n] {
			continue // groups.json not reloaded: installLoadedLocked syncs the groups with the servers
		}
		l := c.loadFile(n, profiles)
		if n == "profiles.json" {
			profiles = l.profiles
		}
		ls = append(ls, l)
	}
	res.dnsErr = c.installLoadedLocked(ls)
	res.dnsWritten = want["dns.json"] && c.sess != nil
	if want["settings.json"] {
		res.settingsWrote = true
		res.rulesChanged = !sameRules(oldCfg, c.settings.Config)
	}
	if c.sess != nil || c.starting {
		c.applyRoutingLocked()
		res.needsReconnect = engineOptionsDiffer(c.sessSet, c.settings)
	}
	res.flushRules = res.rulesChanged && c.dnsRulesChangedLocked()
	return res
}

// errNothingToUndo: no restore to take back.
var errNothingToUndo = sentenceError("Нечего возвращать: сохранённого состояния до восстановления нет")
