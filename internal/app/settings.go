package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
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

type SaveResult struct {
	// NeedsReconnect: engine options changed; rules already apply.
	NeedsReconnect bool `json:"needsReconnect"`
}

// SaveSettings validates and stores. Rules apply to new flows at once;
// profiles the new rules need start, unused ones stop.
func (c *Controller) SaveSettings(st settings.Settings) (SaveResult, error) {
	if err := c.SettingsError(); err != nil {
		return SaveResult{}, fmt.Errorf("settings.json не загружен, изменения не сохраняются, чтобы не потерять правила: %v", err)
	}
	if st.Rules == nil {
		st.Rules = []rules.Rule{}
	}
	// Two saves at once: the file and the rules in use end up the same.
	c.saveMu.Lock()
	set, err := c.Store.SaveSettings(&st)
	if err != nil {
		c.saveMu.Unlock()
		return SaveResult{}, err
	}
	c.mu.Lock()
	ksChanged := c.settings == nil || c.settings.KillSwitchOn() != st.KillSwitchOn()
	c.settings, c.set = &st, set
	res := SaveResult{}
	_, want := c.routingLocked()
	// A session still starting gets the rules from Connect once it runs,
	// but its engine options are those it started with.
	if c.sess != nil || c.starting {
		c.applyRoutingLocked()
		res.NeedsReconnect = engineOptionsDiffer(c.sessSet, &st)
	}
	c.mu.Unlock()
	c.saveMu.Unlock()
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
