package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
)

func (c *Controller) Settings() settings.Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return *c.settings
}

// SettingsError is why settings.json did not load (nil = loaded): the
// rules in memory are then the defaults, not the user's.
func (c *Controller) SettingsError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.settingsBroken
}

// SaveResult is what a settings save returns.
type SaveResult struct {
	// NeedsReconnect: engine options changed; rules already apply.
	NeedsReconnect bool `json:"needsReconnect"`
	// Rev is the settings revision after the call (SettingsRev).
	Rev uint64 `json:"rev"`
	// EditRev: the revision of the rule profiles after an edit of an
	// inactive one (rulesets); 0 otherwise.
	EditRev uint64 `json:"editRev,omitempty"`
}

// EditGuard says what a writer based its change on. The zero value checks
// nothing (internal callers, CLI).
type EditGuard struct {
	// Ruleset is the token of the rules the copy belongs to ("" = any).
	Ruleset string `json:"ruleset"`
	// Rev is the settings revision the copy was read at (0 = no check);
	// checked for the active rules only.
	Rev uint64 `json:"rev"`
	// EditRev is the rule profiles' revision the copy was read at (0 = no
	// check); checked only when editing an inactive profile.
	EditRev uint64 `json:"editRev"`
}

// SettingsView is the settings as a page reads them, with the revision it
// sends back when it saves. Wails only, never stored.
type SettingsView struct {
	settings.Settings
	Ruleset string `json:"ruleset"`
	// Rev is always the settings revision, read together with the copy.
	Rev uint64 `json:"rev"`
	// EditRev and Warnings: editing an inactive rule profile only.
	EditRev  uint64        `json:"editRev,omitempty"`
	Warnings []RuleWarning `json:"warnings,omitempty"`
}

// errRulesChanged refuses a save built on a copy of the rules read before
// the last change of the active rules (guardLocked). A type of its own: the
// text is a sentence for the user.
var errRulesChanged error = staleError("Правила изменились в другом месте (например, из «Соединений»): изменение не сохранено, список обновлён — повторите.")

type staleError string

func (e staleError) Error() string { return string(e) }

// SettingsRev is the settings revision: +1 by every successful settings
// commit, 1 after Load. Pages holding a copy reload when it grows.
func (c *Controller) SettingsRev() uint64 { return c.settingsRev.Load() }

// SettingsView reads the settings and their revision together.
func (c *Controller) SettingsView() SettingsView {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SettingsView{Settings: *c.settings, Rev: c.settingsRev.Load()}
}

func (c *Controller) settingsBrokenError() error {
	if err := c.SettingsError(); err != nil {
		return fmt.Errorf("settings.json не загружен, изменения не сохраняются, чтобы не потерять правила: %v", err)
	}
	return nil
}

// sameRules compares two rules parts through their JSON, as settings.json
// holds them. A nil rule list counts as an empty one (commitSettingsLocked
// stores it so); the lists inside a rule are omitempty, so there nil and
// empty already marshal alike.
func sameRules(a, b rules.Config) bool {
	if a.Rules == nil {
		a.Rules = []rules.Rule{}
	}
	if b.Rules == nil {
		b.Rules = []rules.Rule{}
	}
	ja, err1 := json.Marshal(a)
	jb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && bytes.Equal(ja, jb)
}

// guardLocked checks a save against what its copy was read at (c.mu
// held): guardTargetLocked, then guardRevLocked on the rules to save.
// Returns the inactive rule profile an edit addresses ("" = the active
// rules).
func (c *Controller) guardLocked(g EditGuard, cfg rules.Config) (editID string, err error) {
	if editID, err = c.guardTargetLocked(g); err != nil {
		return "", err
	}
	return editID, c.guardRevLocked(g, editID, cfg)
}

// guardTargetLocked is the part of the guard that does not depend on the
// rules to save: which rules g addresses and whether its copy still
// belongs to them. editRulesIn runs it before fn, so fn never edits rules
// the guard refuses. Only the active rules exist so far: rule profiles add
// the token check and the edit mode here.
func (c *Controller) guardTargetLocked(g EditGuard) (editID string, err error) {
	return "", nil
}

// guardRevLocked is the revision rule (c.mu held): a copy of the active
// rules read before their last change (g.Rev < rulesAt) may not replace
// them with something else. A copy stale only because of an engine option
// save passes, and so does one whose rules equal the current ones.
func (c *Controller) guardRevLocked(g EditGuard, editID string, cfg rules.Config) error {
	if editID == "" && g.Rev != 0 && g.Rev < c.rulesAt && !sameRules(cfg, c.settings.Config) {
		return errRulesChanged
	}
	return nil
}

// commitSettingsLocked validates, stores and applies st; c.saveMu must be
// held. At install (under c.mu) it increments the settings revision and,
// when the rules part changed, sets rulesAt to it. post runs the follow-ups
// (log, geo, kill switch, OnChange, OnSettings) and must be called after
// c.saveMu is released. A failed write changes nothing.
func (c *Controller) commitSettingsLocked(st settings.Settings) (res SaveResult, post func(), err error) {
	if st.Rules == nil {
		st.Rules = []rules.Rule{}
	}
	set, err := c.Store.SaveSettings(&st)
	if err != nil {
		return SaveResult{}, nil, err
	}
	c.mu.Lock()
	ksChanged := c.settings == nil || c.settings.KillSwitchOn() != st.KillSwitchOn()
	rulesChanged := c.settings == nil || !sameRules(c.settings.Config, st.Config)
	c.settings, c.set = &st, set
	rev := c.settingsRev.Add(1)
	if rulesChanged {
		c.rulesAt = rev
	}
	res.Rev = rev
	_, want := c.routingLocked()
	// A session still starting gets the rules from Connect once it runs,
	// but its engine options are those it started with.
	if c.sess != nil || c.starting {
		c.applyRoutingLocked()
		res.NeedsReconnect = engineOptionsDiffer(c.sessSet, &st)
	}
	c.mu.Unlock()
	post = func() {
		names := make([]string, len(want))
		for i, p := range want {
			names[i] = p.Name
		}
		c.Log.Info("rules saved: new flows use them, existing flows keep their route", "rules", len(st.Rules), "default", st.DefaultAction,
			"tunnelProfiles", strings.Join(names, ", "))
		for _, w := range set.Warnings {
			c.Log.Warn("rules: " + w)
		}
		c.pokeGeo() // a new category may need the databases
		if ksChanged {
			c.applyKillSwitch()
		}
		c.changed()
		if c.OnSettings != nil {
			c.OnSettings(rev)
		}
	}
	return res, post, nil
}

// SaveSettings validates and stores. Rules apply to new flows at once;
// profiles the new rules need start, unused ones stop.
func (c *Controller) SaveSettings(st settings.Settings) (SaveResult, error) {
	return c.SaveSettingsIn(EditGuard{}, st)
}

// SaveSettingsIn saves the whole settings (rules and engine options) if g
// allows it. Pages save the two parts separately (SaveRulesIn,
// SaveEngineOptions); this is for internal callers and tests.
func (c *Controller) SaveSettingsIn(g EditGuard, st settings.Settings) (SaveResult, error) {
	if st.Rules == nil {
		st.Rules = []rules.Rule{}
	}
	return c.commitWith(func() (settings.Settings, bool, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		_, err := c.guardLocked(g, st.Config)
		return st, true, err
	})
}

// SaveRulesIn saves cfg as the rules part if g allows it; the engine
// options stay the current ones, whatever the page had.
func (c *Controller) SaveRulesIn(g EditGuard, cfg rules.Config) (SaveResult, error) {
	if cfg.Rules == nil {
		cfg.Rules = []rules.Rule{}
	}
	return c.commitWith(func() (settings.Settings, bool, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, err := c.guardLocked(g, cfg); err != nil {
			return settings.Settings{}, false, err
		}
		st := *c.settings
		st.Config = cfg
		return st, true, nil
	})
}

// SaveEngineOptions saves o as the engine options; the rules part stays
// the current one. No guard: it cannot conflict with a rules change.
func (c *Controller) SaveEngineOptions(o settings.EngineOptions) (SaveResult, error) {
	return c.commitWith(func() (settings.Settings, bool, error) {
		st := c.Settings()
		st.SetOptions(o)
		return st, true, nil
	})
}

// editRulesIn applies fn to a private copy of the current rules and saves
// the result, all under c.saveMu, so no other writer can come between the
// read and the write. fn returns false to save nothing (the result then
// carries the current revision). Order: guardTargetLocked and the copy in
// one c.mu section, so a refusal comes before fn runs (a false or an error
// from fn never hides it); then fn; then guardRevLocked on the edited
// rules, which the revision rule compares with the current ones.
func (c *Controller) editRulesIn(g EditGuard, fn func(cfg *rules.Config) (bool, error)) (SaveResult, error) {
	return c.commitWith(func() (settings.Settings, bool, error) {
		c.mu.Lock()
		editID, err := c.guardTargetLocked(g)
		st := *c.settings
		c.mu.Unlock()
		if err != nil {
			return settings.Settings{}, false, err
		}
		// fn replaces whole elements; the shared inner slices stay intact.
		st.Rules = slices.Clone(st.Rules)
		if ok, err := fn(&st.Config); err != nil || !ok {
			return settings.Settings{}, false, err
		}
		if st.Rules == nil {
			st.Rules = []rules.Rule{}
		}
		// c.saveMu is still held: the rules and rulesAt are those fn saw.
		c.mu.Lock()
		defer c.mu.Unlock()
		return st, true, c.guardRevLocked(g, editID, st.Config)
	})
}

// editRules is editRulesIn without a guard.
func (c *Controller) editRules(fn func(cfg *rules.Config) (bool, error)) (SaveResult, error) {
	return c.editRulesIn(EditGuard{}, fn)
}

// commitWith is the one settings write path: under c.saveMu it checks that
// settings.json loaded, builds the settings to save with next (which runs
// the guard; save = false saves nothing) and commits them. The follow-ups
// run after c.saveMu is released.
func (c *Controller) commitWith(next func() (st settings.Settings, save bool, err error)) (SaveResult, error) {
	c.saveMu.Lock()
	if err := c.settingsBrokenError(); err != nil {
		c.saveMu.Unlock()
		return SaveResult{}, err
	}
	st, save, err := next()
	if err != nil || !save {
		c.saveMu.Unlock()
		return SaveResult{Rev: c.SettingsRev()}, err
	}
	res, post, err := c.commitSettingsLocked(st)
	c.saveMu.Unlock()
	if err != nil {
		return SaveResult{}, err
	}
	post()
	return res, nil
}

func engineOptionsDiffer(a, b *settings.Settings) bool {
	return a.QUICBlocked() != b.QUICBlocked() || a.IPv6TunnelBlocked() != b.IPv6TunnelBlocked() ||
		a.RemoteDNS() != b.RemoteDNS() || a.SniffTimeout() != b.SniffTimeout()
}

// RuleWarning is a problem with one rule's profile.
type RuleWarning struct {
	Index   int    `json:"index"` // -1 = default route
	Rule    string `json:"rule"`
	Profile string `json:"profile"`
	Kind    string `json:"kind"` // no-main | deleted | missing
	Text    string `json:"text"`
}

// RuleWarnings reports Tunnel rules whose profile cannot carry traffic:
// such flows are refused, never sent through another profile.
func (c *Controller) RuleWarnings() []RuleWarning {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ruleWarningsLocked()
}

func (c *Controller) ruleWarningsLocked() []RuleWarning {
	out := []RuleWarning{}
	check := func(i int, name, profile string) {
		w := RuleWarning{Index: i, Rule: name, Profile: profile}
		switch p := c.profiles.Find(profile); {
		case profile == "" && c.profiles.Active == "" && !c.Base.Stub:
			w.Kind, w.Text = "no-main", "нет основного профиля: соединения будут отклоняться"
		case profile == "":
			return
		case p == nil:
			w.Kind, w.Text = "deleted", "профиль удалён: соединения будут отклоняться, выберите другой"
		case p.Missing:
			w.Kind, w.Text = "missing", fmt.Sprintf("профиль «%s» больше отсутствует в подписке: выберите замену", p.Name)
		default:
			return
		}
		out = append(out, w)
	}
	// A fallback server that is gone only weakens the fallback.
	checkFallback := func(i int, name string, fb []string) {
		for _, id := range fb {
			if id == "" {
				continue
			}
			switch p := c.profiles.Find(id); {
			case p == nil:
				out = append(out, RuleWarning{Index: i, Rule: name, Profile: id, Kind: "deleted",
					Text: "запасной сервер удалён: уберите его из правила"})
			case p.Missing:
				out = append(out, RuleWarning{Index: i, Rule: name, Profile: id, Kind: "missing",
					Text: fmt.Sprintf("запасной сервер «%s» больше отсутствует в подписке", p.Name)})
			}
		}
	}
	for i, r := range c.settings.Rules {
		if r.Action != rules.Tunnel || (r.Enabled != nil && !*r.Enabled) {
			continue
		}
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("правило %d", i+1)
		}
		check(i, name, r.Profile)
		checkFallback(i, name, r.Fallback)
	}
	if c.settings.DefaultAction == rules.Tunnel {
		check(-1, "по умолчанию", c.settings.DefaultProfile)
		checkFallback(-1, "по умолчанию", c.settings.DefaultFallback)
	}
	return out
}

// LintRules checks an edited (unsaved) rule list.
func (c *Controller) LintRules(st settings.Settings) []rules.Issue { return rules.Lint(st.Config) }

// ExplainQuery is "why does this go there?" from the rule editor.
type ExplainQuery struct {
	App    string `json:"app"`
	Target string `json:"target"` // domain or IP
	Proto  string `json:"proto"`  // tcp | udp
}

type Explanation struct {
	rules.Explanation
	// ProfileName resolves Winner.Profile.
	ProfileName string `json:"profileName"`
}

// Explain traces a hypothetical connection through the saved rules, or
// through st when it is given (the editor's unsaved state).
func (c *Controller) Explain(q ExplainQuery, st *settings.Settings) Explanation {
	c.mu.Lock()
	cfg := c.settings.Config
	if st != nil {
		cfg = st.Config
	}
	main := c.profiles.Active
	sess := c.sess
	c.mu.Unlock()
	rq := rules.Query{App: q.App, Proto: 6}
	if strings.EqualFold(q.Proto, "udp") {
		rq.Proto = 17
	}
	var notes []string
	target := cleanTarget(q.Target)
	if ip, err := netip.ParseAddr(strings.Trim(target, "[]")); err == nil {
		rq.IP = ip.Unmap()
		if sess != nil {
			rq.Sites = sess.DNSSites(ip.Unmap())
		}
		if len(rq.Sites) == 0 {
			notes = append(notes, "Для IP без имени в DNS-кэше доменные правила не срабатывают; для HTTPS/HTTP HyRoute увидит домен в SNI/Host.")
		}
	} else {
		rq.Domain = target
		if target != "" && usesAddresses(cfg) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", target)
			cancel()
			if err == nil && len(ips) > 0 {
				rq.IP = ips[0].Unmap()
				notes = append(notes, "Для правил по IP и geoip взят адрес "+rq.IP.String()+" (из DNS). У сайта может быть несколько адресов.")
			} else {
				notes = append(notes, "IP сайта узнать не удалось: правила по IP и geoip не проверены.")
			}
		}
	}
	ex := Explanation{Explanation: rules.Explain(cfg, main, rq)}
	ex.Notes = append(ex.Notes, notes...)
	if ex.Winner.Action == rules.Tunnel {
		ex.ProfileName = c.profileName(ex.Winner.Profile)
		if ex.Winner.Profile == "" {
			ex.ProfileName = ""
			ex.Notes = append(ex.Notes, "Основной профиль не выбран: такое соединение будет отклонено.")
		}
	}
	return ex
}

// usesAddresses reports whether an enabled rule has an IP or geoip item.
func usesAddresses(cfg rules.Config) bool {
	for _, r := range cfg.Rules {
		if r.Enabled != nil && !*r.Enabled {
			continue
		}
		for _, d := range r.AllDomains() {
			if rules.IsAddressItem(d) {
				return true
			}
		}
	}
	return false
}

// cleanTarget accepts what people paste: a URL, host:port, a rule-style
// pattern (.example.com, *.example.com) or an IP.
func cleanTarget(s string) string {
	s = strings.TrimSpace(s)
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = u.Hostname()
	} else if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.TrimPrefix(s, "*.")
	return strings.Trim(s, ".[]")
}
