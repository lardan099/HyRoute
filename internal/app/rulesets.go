package app

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
	"github.com/lardan099/hyroute/internal/store"
)

// Rule profiles («Профили правил»): the rules part of the settings
// (rules.Config) kept as several named sets, exactly one active. The
// active one's rules are in settings.json, which stays authoritative for
// them; rulesets.json (only once there is a second profile) holds every
// profile, its copy of the active one refreshed at each of its writes.
// Engine options, the main server and the proxies are global.
//
// Writes, all under c.saveMu:
//   - S: settings.json alone (a rule edit of the active profile);
//   - R: rulesets.json alone (create, rename, move, delete, an edit of an
//     inactive profile), its active entry refreshed from the live rules;
//   - P: both (a switch, and any settings write while the pending marker
//     is on disk or the running rules are not those of settings.json):
//     store.WriteRulesPair. A crash between its two writes is completed at
//     the next Load (reconcileRulesets).
//
// Pages send the token of the rules their copy belongs to (EditGuard): the
// active profile's ID ("implicit" before rulesets.json exists) or
// "edit:<id>" for an inactive profile opened without switching to it.

const (
	implicitToken      = "implicit" // the rules while rulesets.json does not exist
	editTokenPrefix    = "edit:"    // "edit:<id>": a page edits inactive profile <id>
	defaultRulesetName = "Основной"
	// rsNewerText is the error of a profile saved by a newer HyRoute.
	rsNewerText = "создан более новой версией HyRoute — обновите HyRoute"
)

// rulesetSwitch is the last successful switch (diagnostics, netmodes).
type rulesetSwitch struct {
	ID  string
	Src Source
	At  time.Time
}

// rulesetsState is the Controller's rule profile state, guarded by c.mu
// and written only with c.saveMu held too. rulesets, rsErrors and rsAt are
// copy-on-write: an install replaces them and nothing changes them in
// place, so a holder of saveMu may use what it read after releasing c.mu.
type rulesetsState struct {
	rulesets       *store.Rulesets   // nil = not used (no rulesets.json), or broken
	rulesetsBroken error             // rulesets.json did not load; never overwritten by normal operations
	rsErrors       map[string]string // inactive profile ID → why its rules do not load
	settingsHash   string            // store.ConfigHash of the rules in settings.json on disk ("" = no file)
	settingsLag    bool              // the running rules are not those of settings.json on disk
	rsMarker       bool              // rulesets.json on disk carries the pending marker
	rsLeftover     bool              // rulesets.json of a failed first pair could not be removed: the next settings write removes it
	rsImplicitID   string            // the ID the rules got when rulesets.json was created ("implicit" stays valid for it)
	rsRev          uint64            // +1 by every install (Status.Ruleset.Rev): pages reload their lists
	rsAt           map[string]uint64 // profile ID → rsRev of the last install that changed its rules (edit mode's guard)
	rsLast         rulesetSwitch
	// testManual (tests) runs where a user's switch counts as a manual
	// choice (after netManual).
	testManual func()
}

// RulesetRef is the active profile in Status (JSON "ruleset").
type RulesetRef struct {
	ID    string `json:"id"`    // "" while not saved
	Name  string `json:"name"`  // defaultRulesetName while not saved
	Count int    `json:"count"` // 1 while not saved; 0 when rulesets.json is broken
	Token string `json:"token"`
	Rev   uint64 `json:"rev"`
}

// RulesetView is one profile in the list («Профиль ▾»).
type RulesetView struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	Rules         int          `json:"rules"`
	DefaultAction rules.Action `json:"defaultAction"`
	Active        bool         `json:"active"`
	Warnings      int          `json:"warnings"`
	Error         string       `json:"error,omitempty"` // does not load: cannot be switched to
	Newer         bool         `json:"newer,omitempty"` // saved by a newer HyRoute: no edit mode, no copy
	UsedBy        []string     `json:"usedBy"`          // network rules switching to it
}

// RulesetsView is the list of profiles.
type RulesetsView struct {
	Active string        `json:"active"` // "" while not saved
	List   []RulesetView `json:"list"`   // one implicit entry (ID "") while not saved
	Saved  bool          `json:"saved"`
	Error  string        `json:"error,omitempty"` // rulesets.json / settings.json did not load
	Token  string        `json:"token"`
	Rev    uint64        `json:"rev"`
}

// RulesetInput creates a profile.
type RulesetInput struct {
	Name     string        `json:"name"`
	From     string        `json:"from"`   // "active", a profile ID, or "" (Config)
	Config   *rules.Config `json:"config"` // with From == ""
	Activate bool          `json:"activate"`
	// FirstName names the current rules when rulesets.json is created
	// ("" = defaultRulesetName).
	FirstName string `json:"firstName"`
}

// SwitchOptions: Reconnect after the switch while a session runs (not with
// SourceNetwork: netmodes reconnects itself).
type SwitchOptions struct {
	Reconnect bool
}

// SwitchResult is what a switch did.
type SwitchResult struct {
	Ruleset   RulesetRef    `json:"ruleset"`
	Warnings  []RuleWarning `json:"warnings"`
	Connected bool          `json:"connected"` // a session runs: the UI offers «Переподключить»
	// Stopped names the servers the new rules no longer need: they stop
	// and the connections through them close.
	Stopped []string `json:"stopped"`
	// Note is the message with the names as they are (CLI, log); the
	// window builds its own from the fields to mask them.
	Note           string `json:"note"`
	Reconnected    bool   `json:"reconnected"`
	ReconnectError string `json:"reconnectError,omitempty"`
}

// CreateResult is the new profile, and the switch when it was activated.
type CreateResult struct {
	View   RulesetView   `json:"view"`
	Switch *SwitchResult `json:"switch,omitempty"`
}

// NetRuleset is a profile as «Сети» lists it.
type NetRuleset struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RulesetsBrief is the light read for the tray: c.mu only.
type RulesetsBrief struct {
	Usable bool
	Saved  bool
	Active string
	List   []RulesetBriefItem
}

type RulesetBriefItem struct {
	ID, Name string
	Error    bool // does not load (newer ones included)
}

// sentenceError is a message for the user that starts with a capital
// letter.
type sentenceError string

func (e sentenceError) Error() string { return string(e) }

func sentencef(format string, a ...any) error { return sentenceError(fmt.Sprintf(format, a...)) }

var errRulesetNotFound error = sentenceError("Профиль правил не найден")

// errRulesetChanged is what the refusals of a copy made for another rule
// profile match (errors.Is).
var errRulesetChanged = errors.New("rule profile changed")

type rulesetChangedError string

func (e rulesetChangedError) Error() string        { return string(e) }
func (e rulesetChangedError) Is(target error) bool { return target == errRulesetChanged }

// invalidSettings marks a commit refused because the rules do not compile
// (not a write error).
type invalidSettings struct{ error }

func (e invalidSettings) Unwrap() error { return e.error }

// testCompileHook (tests only) runs before each compile of rules on the
// rule profile paths. Atomic: a test sets it while the controller's
// goroutines may compile.
var testCompileHook atomic.Pointer[func()]

func runCompileHook() {
	if h := testCompileHook.Load(); h != nil {
		(*h)()
	}
}

func checkRules(cfg rules.Config) error {
	runCompileHook()
	return rules.Check(cfg)
}

func validateSettings(st *settings.Settings) ([]byte, *settings.Settings, *rules.Set, error) {
	runCompileHook()
	return store.ValidateSettings(st)
}

// ---- state readers (c.mu held) ----

// tokenLocked is the token of the active rules.
func (c *Controller) tokenLocked() string {
	if c.rulesets == nil {
		return implicitToken
	}
	return c.rulesets.Active
}

// tokenOKLocked: a copy made with tok belongs to the active rules.
func (c *Controller) tokenOKLocked(tok string) bool {
	return tok == "" || tok == c.tokenLocked() ||
		tok == implicitToken && c.rsImplicitID != "" && c.rulesets != nil && c.rsImplicitID == c.rulesets.Active
}

func (c *Controller) activeRulesetIDLocked() string {
	if c.rulesets == nil {
		return ""
	}
	return c.rulesets.Active
}

func (c *Controller) activeRulesetNameLocked() string {
	if c.rulesets == nil {
		return ""
	}
	if e := c.rulesets.Find(c.rulesets.Active); e != nil {
		return e.Name
	}
	return ""
}

func (c *Controller) rulesetRefLocked() RulesetRef {
	r := RulesetRef{Name: defaultRulesetName, Count: 1, Token: c.tokenLocked(), Rev: c.rsRev}
	switch {
	case c.rulesetsBroken != nil:
		r.Name, r.Count = "", 0
	case c.rulesets != nil:
		r.ID, r.Name, r.Count = c.rulesets.Active, c.activeRulesetNameLocked(), len(c.rulesets.List)
	}
	return r
}

// rulesetsUsableLocked refuses every profile operation while either file
// did not load.
func (c *Controller) rulesetsUsableLocked() error {
	if c.settingsBroken != nil {
		return fmt.Errorf("settings.json не загружен, профиль правил не переключается: %v", c.settingsBroken)
	}
	if c.rulesetsBroken != nil {
		return fmt.Errorf("rulesets.json не загружен: профили правил недоступны, текущие правила работают. Исправьте или удалите файл и перезапустите HyRoute: %v", c.rulesetsBroken)
	}
	return nil
}

// configOfLocked is the lookup of a profile's rules by ID: the active one
// ("" too) is the live c.settings.Config (the copy in c.rulesets is only
// refreshed at R and P writes); another saved one is its entry. Callers
// must not change what it points to.
func (c *Controller) configOfLocked(id string) (*rules.Config, bool) {
	if id == "" || c.rulesets != nil && id == c.rulesets.Active {
		return &c.settings.Config, true
	}
	if c.rulesets == nil {
		return nil, false
	}
	if e := c.rulesets.Find(id); e != nil {
		return &e.Config, true
	}
	return nil, false
}

// eachRulesConfigLocked visits the active rules (label "") and every
// inactive saved profile (label = its name): the one way to scan rules for
// references (servers, groups), rule databases and backups.
func (c *Controller) eachRulesConfigLocked(fn func(label string, active bool, cfg *rules.Config)) {
	fn("", true, &c.settings.Config)
	if c.rulesets == nil {
		return
	}
	for i := range c.rulesets.List {
		if e := &c.rulesets.List[i]; e.ID != c.rulesets.Active {
			fn(e.Name, false, &e.Config)
		}
	}
}

// rsState is what a write decision needs (rsStateLocked).
type rsState struct {
	Cur          *store.Rulesets
	Errors       map[string]string
	Active       rules.Config // a copy of the live active rules
	Broken       error
	SettingsHash string
	Marker, Lag  bool
}

func (c *Controller) rsStateLocked() rsState {
	return rsState{Cur: c.rulesets, Errors: c.rsErrors, Active: store.CloneConfig(c.settings.Config), Broken: c.rulesetsBroken,
		SettingsHash: c.settingsHash, Marker: c.rsMarker, Lag: c.settingsLag}
}

// ---- the write decision (pure) ----

// rulesetsForCommit is the rulesets.json to write together with
// settings.json whose rules parse to cfg, or nil for settings.json alone.
// next (a switch, a restore) always makes a pair; otherwise only a marker
// on disk or lagging settings.json do, so that the marker on disk always
// describes the write under way.
func rulesetsForCommit(s rsState, next *store.Rulesets, cfg rules.Config) *store.Rulesets {
	var w *store.Rulesets
	switch {
	case next != nil:
		w = next.Clone()
	case s.Cur == nil || s.Broken != nil:
		return nil
	case s.Marker || s.Lag:
		w = s.Cur.Clone()
	default:
		return nil
	}
	if a := w.Find(w.Active); a != nil {
		a.SetConfig(cfg)
	}
	w.Pending = nil
	return w
}

// rulesetsOnlyState is what an R write saves: next with its active entry
// refreshed from the live rules, and the marker only while settings.json
// lags them (a restart must still take them from rulesets.json).
func rulesetsOnlyState(s rsState, next *store.Rulesets) *store.Rulesets {
	w := next.Clone()
	if a := w.Find(w.Active); a != nil {
		a.SetConfig(s.Active)
	}
	w.Pending = nil
	if s.Lag {
		w.Pending = &store.RulesetsPending{Was: s.SettingsHash, To: store.ConfigHash(s.Active)}
	}
	return w
}

// rsPrep is what an install needs that costs a compile, computed with
// saveMu held and c.mu not.
type rsPrep struct {
	Errors  map[string]string // the new rsErrors
	Changed []string          // IDs whose rules differ from s.Cur's (new ones and the one that stops being active too)
}

// prepRulesets checks the inactive profiles of next that are new, changed
// or were active in s.Cur (rules.Check, no rule databases); the others
// keep their error. compiled are known to compile. A newer entry gets
// rsNewerText.
func prepRulesets(s rsState, next *store.Rulesets, compiled ...string) rsPrep {
	p := rsPrep{Errors: map[string]string{}}
	for _, e := range next.List {
		var old *store.Ruleset
		if s.Cur != nil {
			old = s.Cur.Find(e.ID)
		}
		changed := old == nil || old.Newer() != e.Newer() || !sameRules(old.Config, e.Config)
		// A profile that stops being active counts as changed even when
		// s.Cur's copy already holds its rules (an R write refreshed it while
		// it was active): an edit-mode copy made before it became active may
		// have missed edits made meanwhile.
		if changed || s.Cur != nil && s.Cur.Active == e.ID && next.Active != e.ID {
			p.Changed = append(p.Changed, e.ID)
		}
		if e.ID == next.Active {
			continue
		}
		switch {
		case e.Newer():
			p.Errors[e.ID] = rsNewerText
		case slices.Contains(compiled, e.ID):
		case changed || s.Cur != nil && s.Cur.Active == e.ID:
			if err := checkRules(e.Config); err != nil {
				p.Errors[e.ID] = err.Error()
			}
		case s.Errors[e.ID] != "":
			p.Errors[e.ID] = s.Errors[e.ID]
		}
	}
	return p
}

// installRulesetsLocked installs the result of an R or P write (c.mu held;
// only assigns): the profiles (nil keeps them), the hash of settings.json
// on disk, the marker, the errors of p; rsRev grows and rsAt moves for the
// profiles p found changed. settingsLag is the caller's: a pair clears it
// (installPairLocked: settings.json now holds the running rules), an R
// write leaves it.
func (c *Controller) installRulesetsLocked(next *store.Rulesets, p rsPrep, settingsHash string, marker bool) {
	if next != nil {
		if next.Pending != nil {
			n := *next
			n.Pending = nil
			next = &n
		}
		c.rulesets = next
		c.rsLeftover = false // the file written replaced it
	}
	c.rulesetsBroken = nil
	c.settingsHash = settingsHash
	c.rsMarker = marker
	c.rsErrors = p.Errors
	if c.rsImplicitID != "" && (c.rulesets == nil || c.rulesets.Find(c.rsImplicitID) == nil) {
		c.rsImplicitID = ""
	}
	c.rsRev++
	at := map[string]uint64{}
	if c.rulesets != nil {
		for _, e := range c.rulesets.List {
			if v, ok := c.rsAt[e.ID]; ok {
				at[e.ID] = v
			}
		}
		for _, id := range p.Changed {
			if c.rulesets.Find(id) != nil {
				at[id] = c.rsRev
			}
		}
	}
	c.rsAt = at
}

// ---- the settings commit's part (settings.go calls these) ----

// rsWrite is how a settings commit was written.
type rsWrite struct {
	hash    string
	pair    *store.Rulesets // nil: settings.json alone
	prep    rsPrep
	cleared bool
}

// writeSettingsLocked writes settings.json (b, whose rules parse to cfg)
// alone or together with rulesets.json (next, or as rulesetsForCommit
// decides). c.saveMu held; c.mu only briefly: the checks and the I/O run
// without it. A pair whose revert failed leaves the marker set, so the
// next write of either file rewrites rulesets.json; when there was no
// rulesets.json before (the first create and activate), rsLeftover makes
// the next write of settings.json alone remove the file first.
func (c *Controller) writeSettingsLocked(b []byte, cfg rules.Config, next *store.Rulesets) (rsWrite, error) {
	wr := rsWrite{hash: store.ConfigHash(cfg)}
	c.mu.Lock()
	s := c.rsStateLocked()
	leftover := c.rsLeftover
	c.mu.Unlock()
	if wr.pair = rulesetsForCommit(s, next, cfg); wr.pair == nil {
		if leftover {
			c.removeLeftoverRulesets()
		}
		return wr, c.Store.WriteSettings(b)
	}
	wr.prep = prepRulesets(s, wr.pair)
	cleared, revErr, err := c.Store.WriteRulesPair(b, wr.pair, s.SettingsHash, wr.hash)
	if revErr != nil {
		c.mu.Lock()
		if s.Cur != nil {
			c.rsMarker = true
		} else {
			c.rsLeftover = true // no list to rewrite the file with: remove it
		}
		c.mu.Unlock()
		name := ""
		if e := wr.pair.Find(wr.pair.Active); e != nil {
			name = e.Name
		}
		c.Log.Error("rulesets.json could not be restored: until the next save, a restart applies this rule set", "ruleset", name, "err", revErr)
	}
	wr.cleared = cleared
	return wr, err
}

// removeLeftoverRulesets removes the rulesets.json of a failed first pair
// (c.saveMu held): with its marker still matching settings.json, a restart
// would take it for real. A failure keeps rsLeftover for the next write.
func (c *Controller) removeLeftoverRulesets() {
	if err := c.Store.WriteRaw("rulesets.json", store.RawFile{}); err != nil {
		c.Log.Warn("rulesets.json of a failed save still not removed", "err", err)
		return
	}
	c.mu.Lock()
	c.rsLeftover = false
	c.mu.Unlock()
	c.Log.Info("rulesets.json of a failed save removed")
}

// installWriteLocked records a written settings commit (c.mu held).
func (c *Controller) installWriteLocked(wr rsWrite) {
	c.settingsHash = wr.hash
	if wr.pair != nil {
		c.installPairLocked(wr.pair, wr.prep, wr.hash, wr.cleared)
	}
}

// installPairLocked records a pair written by WriteRulesPair (c.mu held):
// next with settings.json of hash h, the marker left on disk unless
// cleared, and settings.json no longer lagging. Every pair install goes
// through here (a backup's restore of both files too), not through
// installRulesetsLocked alone, which leaves settingsLag as it is.
func (c *Controller) installPairLocked(next *store.Rulesets, p rsPrep, h string, cleared bool) {
	c.installRulesetsLocked(next, p, h, !cleared)
	c.settingsLag = false
}

// ---- guard ----

// rulesetChangedLocked is the refusal of a copy made for other rules than
// the active ones.
func (c *Controller) rulesetChangedLocked() error {
	name := c.activeRulesetNameLocked()
	if name == "" {
		name = defaultRulesetName
	}
	return rulesetChangedError(fmt.Sprintf("Профиль правил сменился на «%s», пока была открыта эта страница: изменение не сохранено, список обновлён — повторите.", name))
}

// rulesetTargetLocked is the ruleset part of the guard: which rules tok
// addresses ("" = the active ones, else an inactive profile's ID) and
// whether the copy still belongs to them.
func (c *Controller) rulesetTargetLocked(tok string) (string, error) {
	if strings.HasPrefix(tok, editTokenPrefix) {
		return c.editTargetLocked(tok)
	}
	if !c.tokenOKLocked(tok) {
		return "", c.rulesetChangedLocked()
	}
	return "", nil
}

// editTargetLocked resolves "edit:<id>": a saved, present, inactive and
// loadable-format profile.
func (c *Controller) editTargetLocked(tok string) (string, error) {
	id := strings.TrimPrefix(tok, editTokenPrefix)
	if err := c.rulesetsUsableLocked(); err != nil {
		return "", err
	}
	var e *store.Ruleset
	if c.rulesets != nil {
		e = c.rulesets.Find(id)
	}
	switch {
	case e == nil:
		return "", rulesetChangedError("Профиль правил удалили, пока он был открыт: изменение не сохранено — откройте его снова.")
	case id == c.rulesets.Active:
		return "", rulesetChangedError(fmt.Sprintf("Профиль правил «%s» включили или удалили, пока он был открыт: изменение не сохранено — откройте его снова.", e.Name))
	case e.Newer():
		return "", sentencef("Профиль правил «%s» создан более новой версией HyRoute: обновите HyRoute", e.Name)
	}
	return id, nil
}

// editRevStaleLocked is edit mode's revision rule: a copy of inactive
// profile id read before its rules last changed (EditRev < rsAt[id]) may
// not replace them with something else.
func (c *Controller) editRevStaleLocked(g EditGuard, id string, cfg rules.Config) bool {
	cur, ok := c.configOfLocked(id)
	return ok && g.EditRev != 0 && g.EditRev < c.rsAt[id] && !sameRules(cfg, *cur)
}

// ---- inactive edits ----

// commitInactiveLocked saves cfg as the rules of inactive profile id: an R
// write, nothing running changes. The rules compile fully (with the rule
// databases), so a profile that did not load is fixed here. c.saveMu held.
func (c *Controller) commitInactiveLocked(id string, cfg rules.Config) (SaveResult, func(), error) {
	cfg = store.CloneConfig(cfg)
	fillRuleIDs(&cfg)
	c.mu.Lock()
	st := *c.settings
	st.Config = cfg
	c.mu.Unlock()
	_, parsed, _, err := validateSettings(&st)
	if err != nil {
		return SaveResult{}, nil, sentencef("Правила не проходят проверку: %v", err)
	}
	c.mu.Lock()
	s := c.rsStateLocked()
	c.mu.Unlock()
	next := s.Cur.Clone()
	e := next.Find(id)
	if e == nil {
		return SaveResult{}, nil, errRulesetNotFound
	}
	e.SetConfig(parsed.Config)
	name := e.Name
	if err := c.saveRulesetsOnlyLocked(s, next, prepRulesets(s, next, id)); err != nil {
		return SaveResult{}, nil, err
	}
	c.mu.Lock()
	res := SaveResult{Rev: c.settingsRev.Load(), EditRev: c.rsRev}
	c.mu.Unlock()
	return res, func() {
		c.Log.Info("rule set edited (not active)", "ruleset", name, "rules", len(parsed.Rules))
		c.pokeGeo()
		c.changed()
	}, nil
}

// saveRulesetsOnlyLocked is an R write of next and its install (c.saveMu
// held, c.mu not).
func (c *Controller) saveRulesetsOnlyLocked(s rsState, next *store.Rulesets, p rsPrep) error {
	w := rulesetsOnlyState(s, next)
	if err := c.Store.SaveRulesets(w); err != nil {
		return fmt.Errorf("не удалось сохранить профиль правил: %v", err)
	}
	c.mu.Lock()
	c.installRulesetsLocked(w, p, s.SettingsHash, s.Lag)
	c.mu.Unlock()
	return nil
}

// fillRuleIDs gives rules without an ID a new one.
func fillRuleIDs(cfg *rules.Config) {
	for i := range cfg.Rules {
		if cfg.Rules[i].ID == "" {
			cfg.Rules[i].ID = newID()
		}
	}
}

// ---- API ----

// Rulesets lists the profiles; while rulesets.json does not exist, the
// current rules as the one implicit profile.
func (c *Controller) Rulesets() RulesetsView {
	c.mu.Lock()
	v := RulesetsView{Token: c.tokenLocked(), Rev: c.rsRev, List: []RulesetView{}}
	switch err := c.rulesetsUsableLocked(); {
	case err != nil:
		v.Error = err.Error()
	case c.rulesets == nil:
		cfg := &c.settings.Config
		v.List = append(v.List, RulesetView{Name: defaultRulesetName, Rules: len(cfg.Rules), DefaultAction: cfg.DefaultAction, Active: true,
			Warnings: len(c.ruleWarningsFor(cfg)), UsedBy: []string{}})
	default:
		v.Saved, v.Active = true, c.rulesets.Active
		for i := range c.rulesets.List {
			v.List = append(v.List, c.rulesetViewLocked(&c.rulesets.List[i]))
		}
	}
	c.mu.Unlock()
	for i := range v.List {
		if v.List[i].ID != "" {
			if used := c.NetRulesUsing(v.List[i].ID); used != nil {
				v.List[i].UsedBy = used
			}
		}
	}
	return v
}

func (c *Controller) rulesetViewLocked(e *store.Ruleset) RulesetView {
	cfg, _ := c.configOfLocked(e.ID)
	return RulesetView{ID: e.ID, Name: e.Name, Rules: len(cfg.Rules), DefaultAction: cfg.DefaultAction, Active: e.ID == c.rulesets.Active,
		Warnings: len(c.ruleWarningsFor(cfg)), Error: c.rsErrors[e.ID], Newer: e.Newer(), UsedBy: []string{}}
}

// RulesetsBrief is the list for the tray: c.mu only, no warnings.
func (c *Controller) RulesetsBrief() RulesetsBrief {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := RulesetsBrief{Usable: c.rulesetsUsableLocked() == nil, Saved: c.rulesets != nil}
	if c.rulesets != nil {
		b.Active = c.rulesets.Active
		for _, e := range c.rulesets.List {
			b.List = append(b.List, RulesetBriefItem{ID: e.ID, Name: e.Name, Error: c.rsErrors[e.ID] != "" || e.Newer()})
		}
	}
	return b
}

// switchCheckLocked is what a switch to id needs: both files loaded, the
// profile saved (in base, else c.rulesets) and loadable.
func (c *Controller) switchCheckLocked(id string, base *store.Rulesets) (*store.Ruleset, error) {
	if err := c.rulesetsUsableLocked(); err != nil {
		return nil, err
	}
	rs := base
	if rs == nil {
		rs = c.rulesets
	}
	var e *store.Ruleset
	if rs != nil {
		e = rs.Find(id)
	}
	switch {
	case e == nil:
		return nil, errRulesetNotFound
	case id == rs.Active:
		return e, nil
	case e.Newer():
		return nil, sentencef("Профиль правил «%s» создан более новой версией HyRoute: обновите HyRoute", e.Name)
	case c.rsErrors[id] != "":
		return nil, sentencef("Профиль правил «%s» не загружается: %s", e.Name, c.rsErrors[id])
	}
	return e, nil
}

// switchPrecheck refuses a switch that cannot happen before it counts as a
// manual choice (takes c.mu).
func (c *Controller) switchPrecheck(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.switchCheckLocked(id, nil)
	return err
}

// userManual: a user's switch counts as a manual choice for «Сети».
// Called holding no lock.
func (c *Controller) userManual() {
	c.netManual()
	if c.testManual != nil {
		c.testManual()
	}
}

// ActivateRuleset switches to profile id (netmodes' contract).
func (c *Controller) ActivateRuleset(id string, src Source) error {
	_, err := c.SwitchRuleset(id, src, SwitchOptions{})
	return err
}

// SwitchRuleset makes profile id the active one: its rules are saved to
// settings.json and apply at once, like a rules save. A switch by the user
// (not SourceNetwork) that passes the checks counts as a manual choice for
// «Сети»; with SourceNetwork the caller holds netmodes' lock.
func (c *Controller) SwitchRuleset(id string, src Source, o SwitchOptions) (SwitchResult, error) {
	if src == SourceNetwork && o.Reconnect {
		return SwitchResult{}, errors.New("internal: reconnect is done by the caller")
	}
	if src != SourceNetwork {
		if err := c.switchPrecheck(id); err != nil {
			return SwitchResult{}, err
		}
		c.userManual()
	}
	c.saveMu.Lock()
	res, post, err := c.switchLocked(id, src, nil)
	c.saveMu.Unlock()
	if post != nil {
		post()
	}
	if err != nil {
		return SwitchResult{}, err
	}
	if o.Reconnect && res.Connected {
		if err := c.Reconnect(); err != nil {
			res.ReconnectError = err.Error()
		} else {
			res.Reconnected = true
		}
	}
	return res, nil
}

// switchLocked switches to id (c.saveMu held): one P write through
// commitSettingsLocked. base, when set, is a list not saved yet that holds
// id (create and activate); otherwise c.rulesets. A switch refused because
// the rules of id do not compile records that and returns a post func
// with the error.
func (c *Controller) switchLocked(id string, src Source, base *store.Rulesets) (SwitchResult, func(), error) {
	c.mu.Lock()
	target, err := c.switchCheckLocked(id, base)
	if err != nil {
		c.mu.Unlock()
		return SwitchResult{}, nil, err
	}
	cur := base
	if cur == nil {
		cur = c.rulesets
	}
	if base == nil && id == cur.Active {
		res := c.switchResultLocked(nil)
		c.mu.Unlock()
		return res, func() {}, nil
	}
	var before []hysteria.Profile
	if c.sess != nil {
		_, before, _ = c.routingLocked()
	}
	st := *c.settings
	st.Config = store.CloneConfig(target.Config)
	next := cur.Clone()
	if left := next.Find(next.Active); left != nil {
		left.SetConfig(c.settings.Config)
	}
	next.Active = id
	name := target.Name
	c.mu.Unlock()
	_, post, err := c.commitSettingsLocked(st, next)
	if err != nil {
		var inv invalidSettings
		if !errors.As(err, &inv) {
			return SwitchResult{}, nil, fmt.Errorf("не удалось сохранить профиль правил: %v", err)
		}
		var notify func()
		if base == nil {
			c.mu.Lock()
			errs := maps.Clone(c.rsErrors)
			if errs == nil {
				errs = map[string]string{}
			}
			errs[id] = inv.Error()
			c.rsErrors = errs
			c.rsRev++ // the menus show it as not loading
			c.mu.Unlock()
			notify = c.changed
		}
		return SwitchResult{}, notify, sentencef("Профиль правил «%s» не загружается: %v", name, inv.error)
	}
	c.mu.Lock()
	c.rsLast = rulesetSwitch{ID: id, Src: src, At: time.Now()}
	res := c.switchResultLocked(before)
	c.mu.Unlock()
	return res, func() {
		c.Log.Info("rule set switched", "ruleset", name, "by", string(src), "rules", len(st.Rules), "default", st.DefaultAction,
			"stopped", strings.Join(res.Stopped, ", "))
		post()
	}, nil
}

// switchResultLocked describes the active profile after a switch; before
// are the servers that ran before it (nil: none, or not connected).
func (c *Controller) switchResultLocked(before []hysteria.Profile) SwitchResult {
	res := SwitchResult{Ruleset: c.rulesetRefLocked(), Warnings: c.ruleWarningsLocked(), Connected: c.sess != nil || c.starting, Stopped: []string{}}
	if before != nil && c.sess != nil {
		_, after, _ := c.routingLocked()
		for _, p := range before {
			if !slices.ContainsFunc(after, func(q hysteria.Profile) bool { return q.ID == p.ID }) {
				res.Stopped = append(res.Stopped, p.Name)
			}
		}
	}
	res.Note = switchNote(res)
	return res
}

// switchNote is the message of a switch with the names as they are.
func switchNote(r SwitchResult) string {
	var b strings.Builder
	switch {
	case !r.Connected:
		b.WriteString("Он начнёт действовать при подключении.")
	case len(r.Stopped) == 0:
		b.WriteString("Новые соединения идут по его правилам, уже открытые — по прежнему профилю.")
	default:
		b.WriteString("Новые соединения идут по его правилам, уже открытые — по прежнему профилю, кроме шедших через " + quotedList(r.Stopped) +
			": этим серверам новый профиль не нужен, такие соединения закроются, и программы откроют их заново уже по нему.")
	}
	if len(r.Warnings) > 0 {
		b.WriteString(" В нём есть правила с удалёнными или пропавшими серверами: такие соединения будут отклоняться.")
	}
	if r.Connected {
		b.WriteString(" «Переподключить» откроет заново большинство открытых соединений уже по новому профилю.")
	}
	return b.String()
}

// quotedList is «A», «B», «C» и ещё n.
func quotedList(names []string) string {
	shown := names
	if len(shown) > 3 {
		shown = shown[:3]
	}
	q := make([]string, len(shown))
	for i, n := range shown {
		q[i] = "«" + n + "»"
	}
	s := strings.Join(q, ", ")
	if more := len(names) - len(shown); more > 0 {
		s += fmt.Sprintf(" и ещё %d", more)
	}
	return s
}

// createCheckLocked checks a new profile: files loaded, room, the name
// (and the name the current rules get when the file is created), and
// where its rules come from. Returns the clean names.
func (c *Controller) createCheckLocked(in RulesetInput) (name, first string, err error) {
	if err := c.rulesetsUsableLocked(); err != nil {
		return "", "", err
	}
	if name, err = store.CleanRulesetName(in.Name); err != nil {
		return "", "", err
	}
	names := []string{}
	if c.rulesets == nil {
		f := in.FirstName
		if strings.TrimSpace(f) == "" {
			f = defaultRulesetName
		}
		if first, err = store.CleanRulesetName(f); err != nil {
			return "", "", err
		}
		names = append(names, first)
	} else {
		if len(c.rulesets.List) >= store.MaxRulesets {
			return "", "", sentencef("Профилей правил не больше %d", store.MaxRulesets)
		}
		for _, e := range c.rulesets.List {
			names = append(names, e.Name)
		}
	}
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return "", "", sentenceError("Профиль правил с таким названием уже есть")
		}
	}
	_, err = c.configFromLocked(in)
	return name, first, err
}

// configFromLocked is the rules a new profile starts with: a copy of the
// live active rules, of another profile, or in.Config (its rules without
// an ID get one).
func (c *Controller) configFromLocked(in RulesetInput) (rules.Config, error) {
	switch {
	case in.From == "active" || c.rulesets != nil && in.From == c.rulesets.Active:
		return store.CloneConfig(c.settings.Config), nil
	case in.From != "":
		var e *store.Ruleset
		if c.rulesets != nil {
			e = c.rulesets.Find(in.From)
		}
		if e == nil {
			return rules.Config{}, errRulesetNotFound
		}
		if e.Newer() {
			return rules.Config{}, sentencef("Профиль правил «%s» создан более новой версией HyRoute: обновите HyRoute", e.Name)
		}
		return store.CloneConfig(e.Config), nil
	case in.Config == nil:
		return rules.Config{}, errors.New("нет правил для нового профиля")
	}
	cfg := store.CloneConfig(*in.Config)
	fillRuleIDs(&cfg)
	return cfg, nil
}

// CreateRuleset adds a profile (and creates rulesets.json with the current
// rules as the first one when it does not exist); with in.Activate it
// switches to it in the same write.
func (c *Controller) CreateRuleset(in RulesetInput, src Source) (CreateResult, error) {
	if in.Activate && src != SourceNetwork {
		c.mu.Lock()
		_, _, err := c.createCheckLocked(in)
		c.mu.Unlock()
		if err != nil {
			return CreateResult{}, err
		}
		c.userManual()
	}
	c.saveMu.Lock()
	res, post, err := c.createLocked(in, src)
	c.saveMu.Unlock()
	if err != nil {
		return CreateResult{}, err
	}
	post()
	return res, nil
}

func (c *Controller) createLocked(in RulesetInput, src Source) (CreateResult, func(), error) {
	c.mu.Lock()
	name, first, err := c.createCheckLocked(in)
	var cfg rules.Config
	if err == nil {
		cfg, err = c.configFromLocked(in)
	}
	s := c.rsStateLocked()
	st := *c.settings
	st.Config = cfg
	c.mu.Unlock()
	if err != nil {
		return CreateResult{}, nil, err
	}
	_, parsed, _, err := validateSettings(&st)
	if err != nil {
		return CreateResult{}, nil, sentencef("Правила нового профиля не проходят проверку: %v", err)
	}
	next, implicit := s.Cur.Clone(), ""
	if next == nil {
		implicit = newID()
		next = &store.Rulesets{Version: store.RulesetsVersion, Active: implicit, List: []store.Ruleset{{ID: implicit, Name: first}}}
		next.List[0].SetConfig(s.Active)
	}
	id := newID()
	for next.Find(id) != nil {
		id = newID()
	}
	e := store.Ruleset{ID: id, Name: name}
	e.SetConfig(parsed.Config)
	next.List = append(next.List, e)
	var res CreateResult
	var post func()
	if in.Activate {
		sw, swPost, err := c.switchLocked(id, src, next)
		if err != nil {
			return CreateResult{}, nil, err
		}
		res.Switch, post = &sw, swPost
	} else {
		if err := c.saveRulesetsOnlyLocked(s, next, prepRulesets(s, next, id)); err != nil {
			return CreateResult{}, nil, err
		}
		post = func() {
			c.pokeGeo() // the rule databases it names are ready before a switch
			c.changed()
		}
	}
	c.mu.Lock()
	if implicit != "" {
		c.rsImplicitID = implicit
	}
	res.View = c.rulesetViewLocked(c.rulesets.Find(id))
	c.mu.Unlock()
	return res, func() {
		c.Log.Info("rule set created", "ruleset", name, "rules", len(parsed.Rules), "active", in.Activate)
		post()
	}, nil
}

// editRulesetList runs op on a copy of the saved list and saves the result
// (an R write). Operations that change no rules move no rsAt.
func (c *Controller) editRulesetList(what string, op func(next *store.Rulesets) error) error {
	c.saveMu.Lock()
	c.mu.Lock()
	err := c.rulesetsUsableLocked()
	if err == nil && c.rulesets == nil {
		err = errRulesetNotFound
	}
	s := c.rsStateLocked()
	c.mu.Unlock()
	if err == nil {
		next := s.Cur.Clone()
		if err = op(next); err == nil {
			err = c.saveRulesetsOnlyLocked(s, next, prepRulesets(s, next))
		}
	}
	c.saveMu.Unlock()
	if err != nil {
		return err
	}
	c.Log.Info("rule set " + what)
	c.changed()
	return nil
}

// RenameRuleset renames profile id.
func (c *Controller) RenameRuleset(id, name string) error {
	name, err := store.CleanRulesetName(name)
	if err != nil {
		return err
	}
	return c.editRulesetList("renamed", func(next *store.Rulesets) error {
		e := next.Find(id)
		if e == nil {
			return errRulesetNotFound
		}
		for _, o := range next.List {
			if o.ID != id && strings.EqualFold(o.Name, name) {
				return sentenceError("Профиль правил с таким названием уже есть")
			}
		}
		e.Name = name
		return nil
	})
}

// MoveRuleset moves profile id to position to (the order of the menu, Home
// and the tray).
func (c *Controller) MoveRuleset(id string, to int) error {
	return c.editRulesetList("moved", func(next *store.Rulesets) error {
		from := next.Index(id)
		if from < 0 || to < 0 || to >= len(next.List) {
			return errors.New("bad move")
		}
		e := next.List[from]
		next.List = slices.Delete(next.List, from, from+1)
		next.List = slices.Insert(next.List, to, e)
		return nil
	})
}

// DeleteRuleset deletes an inactive profile. Network rules that switch to
// it are no reason to refuse: they report it («Сети»).
func (c *Controller) DeleteRuleset(id string) error {
	return c.editRulesetList("deleted", func(next *store.Rulesets) error {
		i := next.Index(id)
		switch {
		case i < 0:
			return errRulesetNotFound
		case id == next.Active:
			return sentenceError("Нельзя удалить активный профиль правил: сначала переключитесь на другой")
		}
		next.List = slices.Delete(next.List, i, i+1)
		return nil
	})
}

// RulesetSettings is the settings with the rules of profile id, for edit
// mode (token "edit:<id>"); the active profile gets the normal view.
func (c *Controller) RulesetSettings(id string) (SettingsView, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.rulesetsUsableLocked(); err != nil {
		return SettingsView{}, err
	}
	if c.rulesets != nil && id == c.rulesets.Active {
		// Read under the same lock: a switch in between would give the
		// view of another profile.
		return c.settingsViewLocked(), nil
	}
	var e *store.Ruleset
	if c.rulesets != nil && id != "" {
		e = c.rulesets.Find(id)
	}
	if e == nil {
		return SettingsView{}, errRulesetNotFound
	}
	if e.Newer() {
		return SettingsView{}, sentencef("Профиль правил «%s» создан более новой версией HyRoute: обновите HyRoute", e.Name)
	}
	st := *c.settings
	st.Config = store.CloneConfig(e.Config)
	return SettingsView{Settings: st, Ruleset: editTokenPrefix + id, Rev: c.settingsRev.Load(), EditRev: c.rsRev, Warnings: c.ruleWarningsFor(&e.Config)}, nil
}

// ResolveRuleset finds a profile by what a person types (CLI): "id:…", an
// ID, a name in any case, or a unique part of one. "" = the implicit
// profile (not saved yet).
func (c *Controller) ResolveRuleset(q string) (string, error) {
	q = strings.TrimSpace(q)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.rulesetsUsableLocked(); err != nil {
		return "", err
	}
	if c.rulesets == nil {
		if strings.EqualFold(q, defaultRulesetName) {
			return "", nil
		}
		return "", sentencef("Профиль правил «%s» не найден", q)
	}
	list := c.rulesets.List
	if id, ok := strings.CutPrefix(q, "id:"); ok {
		if c.rulesets.Find(id) != nil {
			return id, nil
		}
		return "", sentencef("Профиль правил «%s» не найден", q)
	}
	if c.rulesets.Find(q) != nil {
		return q, nil
	}
	for _, e := range list {
		if strings.EqualFold(e.Name, q) {
			return e.ID, nil
		}
	}
	var hits []store.Ruleset
	if q != "" {
		for _, e := range list {
			if strings.Contains(strings.ToLower(e.Name), strings.ToLower(q)) {
				hits = append(hits, e)
			}
		}
	}
	switch len(hits) {
	case 0:
		return "", sentencef("Профиль правил «%s» не найден", q)
	case 1:
		return hits[0].ID, nil
	}
	names := make([]string, len(hits))
	for i, e := range hits {
		names[i] = "«" + e.Name + "»"
	}
	return "", fmt.Errorf("«%s» подходит к нескольким профилям правил: %s — уточните", q, strings.Join(names, ", "))
}

// RulesetsExport is the saved list for a backup: a deep copy with the
// active entry holding the live rules and no marker; false while not saved
// or broken.
func (c *Controller) RulesetsExport() (*store.Rulesets, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rulesets == nil || c.rulesetsBroken != nil {
		return nil, false
	}
	out := c.rulesets.Clone()
	out.Pending = nil
	if a := out.Find(out.Active); a != nil {
		a.SetConfig(c.settings.Config)
	}
	return out, true
}

// ---- netmodes' reads (each takes c.mu: never call with it held) ----

// RulesetList is the saved profiles in display order; nil when not saved
// or broken.
func (c *Controller) RulesetList() []NetRuleset {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rulesets == nil || c.rulesetsBroken != nil {
		return nil
	}
	out := make([]NetRuleset, len(c.rulesets.List))
	for i, e := range c.rulesets.List {
		out[i] = NetRuleset{ID: e.ID, Name: e.Name}
	}
	return out
}

// rulesetExists: profile id is saved. True while rulesets.json is broken
// (it cannot tell; a switch then fails with the broken file's error).
func (c *Controller) rulesetExists(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rulesetsBroken != nil || c.rulesets != nil && c.rulesets.Find(id) != nil
}

// rulesetName is profile id's name ("" when missing).
func (c *Controller) rulesetName(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rulesets != nil {
		if e := c.rulesets.Find(id); e != nil {
			return e.Name
		}
	}
	return ""
}

// rulesetError is why profile id cannot be switched to ("" = it can).
func (c *Controller) rulesetError(id string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rsErrors[id]
}

// rulesetActive is the active saved profile ("" when not saved or broken)
// and who made the last successful switch in this process ("" = none).
func (c *Controller) rulesetActive() (id string, src Source) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rulesetsBroken == nil {
		id = c.activeRulesetIDLocked()
	}
	return id, c.rsLast.Src
}

// ---- references, rule databases, diagnostics ----

// rulesetsRefsUnknownLocked: while rulesets.json did not load, the rules
// of its profiles are unknown, and every server counts as used.
func (c *Controller) rulesetsRefsUnknownLocked() error {
	if c.rulesetsBroken != nil {
		return errors.New("rulesets.json не загружен: сервер или группа не удаляются, пока нельзя проверить, какие профили правил на них ссылаются")
	}
	return nil
}

// rulesetRefSuffix labels a reference from an inactive profile.
func rulesetRefSuffix(label string) string { return " (профиль правил «" + label + "»)" }

// rulesetRefsHint is the advice when a reference is in an inactive profile.
func rulesetRefsHint(refs []string) string {
	for _, r := range refs {
		if strings.Contains(r, " (профиль правил «") {
			return ". Профиль правил можно поправить, не включая его: «Правила» → «Профиль» → «Открыть без включения»."
		}
	}
	return ""
}

// geoKindsLocked: which rule databases any profile uses (an inactive one's
// are kept fresh too, so a switch does not wait for a download).
func (c *Controller) geoKindsLocked() (site, ip bool) {
	c.eachRulesConfigLocked(func(_ string, _ bool, cfg *rules.Config) {
		s, i := geoKinds(*cfg)
		site, ip = site || s, ip || i
	})
	return site, ip
}

// rulesetDiagLines is the diagnostics line (none while not used).
func (c *Controller) rulesetDiagLines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.rulesetsBroken != nil:
		return []string{"   профиль правил: rulesets.json не загружен — " + c.rulesetsBroken.Error()}
	case c.rulesets == nil && c.rsLeftover:
		return []string{"   профиль правил: не удалён rulesets.json незавершённой записи — удалится при следующем сохранении правил"}
	case c.rulesets == nil:
		return nil
	}
	var notes []string
	if n := len(c.rsErrors); n > 0 {
		notes = append(notes, fmt.Sprintf("не загружаются: %d", n))
	}
	if c.rsMarker {
		notes = append(notes, "незавершённая запись rulesets.json")
	}
	if c.settingsLag {
		notes = append(notes, "settings.json отстаёт")
	}
	if !c.rsLast.At.IsZero() {
		notes = append(notes, fmt.Sprintf("переключён %s (%s)", c.rsLast.At.Format("01-02 15:04:05"), c.rsLast.Src))
	}
	suffix := ""
	if len(notes) > 0 {
		suffix = " — " + strings.Join(notes, "; ")
	}
	return []string{fmt.Sprintf("   профиль правил: %q (всего %d)%s", c.activeRulesetNameLocked(), len(c.rulesets.List), suffix)}
}

// ---- Load ----

// rsLoad is the reconciled result of reading settings.json and
// rulesets.json.
type rsLoad struct {
	Settings     *settings.Settings // possibly with the active rules taken from rulesets.json
	Set          *rules.Set
	Rulesets     *store.Rulesets // nil = not used (or broken)
	Broken       error
	Errors       map[string]string
	SettingsHash string
	Lag, Marker  bool
	Note         string // the info log line of the case taken ("" = none)
	// RulesUnknown: settings.json is missing and rulesets.json could not
	// supply the active rules, so the rules in memory are the defaults
	// standing in for the user's. Load treats it as a settings.json that
	// did not load (settingsBroken): nothing connects or saves on them.
	RulesUnknown error
}

// rulesUnknownError is RulesUnknown: why rulesets.json could not supply
// the active rules.
type rulesUnknownError struct{ err error }

func (e *rulesUnknownError) Error() string {
	return "settings.json нет, а правила из rulesets.json не загрузились: " + e.err.Error()
}

func (e *rulesUnknownError) Unwrap() error { return e.err }

// loadRulesets reads rulesets.json and reconciles it with the settings
// Load read (Load, no lock held). existed: settings.json was there before
// LoadSettings.
func (c *Controller) loadRulesets(st *settings.Settings, set *rules.Set, stErr error, existed bool) rsLoad {
	rs, err := c.Store.LoadRulesets()
	return reconcileRulesets(st, set, stErr, existed, rs, err)
}

// reconcileRulesets decides which rules are active after a start (or a
// backup's undo), with no lock held (it compiles). settings.json is
// authoritative for the active profile's rules, except right after an
// interrupted pair write (the marker, with settings.json still holding the
// rules before it) and when settings.json is missing: then they come from
// rulesets.json. No file is written.
func reconcileRulesets(st *settings.Settings, set *rules.Set, stErr error, existed bool, rs *store.Rulesets, rsErr error) rsLoad {
	l := rsLoad{Settings: st, Set: set}
	h := ""
	if stErr == nil && existed {
		h = store.ConfigHash(st.Config)
	}
	l.SettingsHash = h
	if rsErr != nil {
		l.Broken = rsErr
		if stErr == nil && !existed {
			l.RulesUnknown = &rulesUnknownError{rsErr}
		}
		return l
	}
	if rs == nil {
		return l
	}
	rs = rs.Clone()
	active := rs.Find(rs.Active)
	l.Marker = rs.Pending != nil
	// take makes the active profile's copy the running rules, with the
	// engine options loaded.
	take := func(why string) bool {
		if active.Newer() {
			l.Broken = fmt.Errorf("включённый профиль правил «%s» %s", active.Name, rsNewerText)
			return false
		}
		next := *st
		next.Config = store.CloneConfig(active.Config)
		_, parsed, pset, err := validateSettings(&next)
		if err != nil {
			l.Broken = fmt.Errorf("профиль правил «%s» из rulesets.json не загружается: %v", active.Name, err)
			return false
		}
		l.Settings, l.Set = parsed, pset
		l.Note = fmt.Sprintf("rules of rule set «%s» taken from rulesets.json: %s", active.Name, why)
		return true
	}
	switch {
	case stErr != nil:
		// Kept for reference checks only: every operation is refused.
	case !existed:
		if !take("settings.json was missing") {
			l.Marker = false
			l.RulesUnknown = &rulesUnknownError{l.Broken}
			return l
		}
		l.Lag = true
	case l.Marker && h == rs.Pending.Was && !active.Newer():
		if !take("the last save was interrupted") {
			l.Marker = false
			return l
		}
		l.Lag, l.Marker = true, true
	default:
		if active.Newer() || h != store.ConfigHash(active.Config) {
			active.SetConfig(st.Config)
			l.Note = fmt.Sprintf("rules changed outside HyRoute adopted into rule set «%s»", active.Name)
		}
	}
	rs.Pending = nil
	l.Rulesets = rs
	l.Errors = prepRulesets(rsState{}, rs).Errors
	return l
}

// installRulesetsLoadLocked installs a reconciled load (c.mu held; only
// assigns): the settings and every field of rulesetsState. Every page's
// copy made before is stale afterwards (rsAt).
func (c *Controller) installRulesetsLoadLocked(l rsLoad) {
	c.settings, c.set = l.Settings, l.Set
	c.rulesets, c.rulesetsBroken, c.rsErrors = l.Rulesets, l.Broken, l.Errors
	c.settingsHash, c.settingsLag, c.rsMarker = l.SettingsHash, l.Lag, l.Marker
	c.rsLeftover = false
	if c.rsImplicitID != "" && (c.rulesets == nil || c.rulesets.Find(c.rsImplicitID) == nil) {
		c.rsImplicitID = ""
	}
	c.rsRev++
	c.rsAt = map[string]uint64{}
	if c.rulesets != nil {
		for _, e := range c.rulesets.List {
			c.rsAt[e.ID] = c.rsRev
		}
	}
}
