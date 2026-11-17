package app

import (
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/store"
)

// The browser extension (browser/): it asks how the sites of a page go and
// sends a site to a server, direct or to the block list. Its sites live in
// rules of their own at the top of the active rule profile, one per page's
// site and route: «Из браузера: example.com» holds what the user sent from
// the pages of example.com (the site itself and what its pages load), so a
// site reads as one rule and goes away as one. An edit without a page (an
// extension before 1.1) goes to «Из браузера: <куда>», one rule per route.
// Exact addresses are in the «(адреса)» rules, whole sites
// (".example.com") in the others, the address rules above the site rules.
// A name has one route in the extension's rules (the last one chosen), and
// an address is narrower than its site, so this order lets every choice
// decide its own name whatever the user picked before. What a page sends
// leaves the rules by route for the page's rule; «Навести порядок» puts
// the rules by route themselves in order (browser_tidy.go).

// browserState is the Controller's part for the extension.
type browserState struct {
	// browserSeen: when the extension last asked (Unix seconds; 0 = not
	// since start).
	browserSeen atomic.Int64
}

// BrowserSeen is when the extension last asked about a page (zero: not
// since HyRoute started).
func (c *Controller) BrowserSeen() time.Time {
	if s := c.browserSeen.Load(); s != 0 {
		return time.Unix(s, 0)
	}
	return time.Time{}
}

// BrowserRulePrefix starts the name of a rule the extension keeps.
const BrowserRulePrefix = "Из браузера: "

// browserHostsSuffix ends the name of an address rule of the extension.
const browserHostsSuffix = " (адреса)"

// Limits of one request from the extension.
const (
	maxBrowserHosts = 200
	maxBrowserEdit  = 200 // a whole page at once
)

// BrowserQuery is what the extension asks about: the names a page used.
type BrowserQuery struct {
	// App is the browser's exe ("chrome.exe"; "" = unknown): rules for
	// programs decide its connections too.
	App   string   `json:"app,omitempty"`
	Hosts []string `json:"hosts"`
	// Page is the tab's own host ("" = an extension before 1.1).
	Page string `json:"page,omitempty"`
}

// BrowserRoute is where a name goes now.
type BrowserRoute struct {
	// To: vpn (the main server), direct, block or id:<server or group>.
	To string `json:"to"`
	// Server: the server or group name of a tunnel route.
	Server string `json:"server,omitempty"`
	// Rule: the deciding rule's name ("" = «Всё остальное»); Index -1 for
	// the default route.
	Rule  string `json:"rule,omitempty"`
	Index int    `json:"index"`
	// Browser: the deciding rule is one of the extension's.
	Browser bool `json:"browser,omitempty"`
	// Pattern: the extension's item that catches the name (".example.com"
	// or "www.example.com"), "" when no rule of the extension does.
	Pattern string `json:"pattern,omitempty"`
}

// BrowserSite is a name the extension asked about.
type BrowserSite struct {
	Host  string `json:"host"`  // as the rules see it (punycode)
	Label string `json:"label"` // as people read it
	// Site: the registrable domain ("" for an IP, a single label or a
	// public suffix: no whole-site choice then).
	Site      string       `json:"site,omitempty"`
	SiteLabel string       `json:"siteLabel,omitempty"`
	Route     BrowserRoute `json:"route"`
}

// BrowserTarget is a choice the extension offers.
type BrowserTarget struct {
	To    string `json:"to"`
	Name  string `json:"name"`
	Group bool   `json:"group,omitempty"`
}

// BrowserPage is what the extension's rules hold for the page's site.
type BrowserPage struct {
	Site  string `json:"site"` // the registrable domain
	Label string `json:"label"`
	// Items: the names in the site's own rules (0 = it has none).
	Items int `json:"items"`
}

// BrowserInfo answers BrowserQuery.
type BrowserInfo struct {
	State   string          `json:"state"`   // as Status
	Ruleset string          `json:"ruleset"` // the active rule profile
	App     string          `json:"app,omitempty"`
	Main    string          `json:"main"` // the main server or group ("" = none)
	Targets []BrowserTarget `json:"targets"`
	Sites   []BrowserSite   `json:"sites"`
	// Page: the page's site, when it can have rules of its own.
	Page *BrowserPage `json:"page,omitempty"`
	// Problem: why rules cannot be changed now ("" = they can).
	Problem string `json:"problem,omitempty"`
}

// BrowserEdit sends sites somewhere (BrowserAdd) or takes them out of the
// extension's rules (BrowserRemove, To unused).
type BrowserEdit struct {
	App string `json:"app,omitempty"`
	// Sites: ".example.com" (the site and its subdomains) or
	// "www.example.com" (only that name).
	Sites []string `json:"sites"`
	To    string   `json:"to,omitempty"`
	// Page is the tab's own host: BrowserAdd keeps the sites in the rules
	// of its site; BrowserRemove with no Sites removes those rules whole.
	Page string `json:"page,omitempty"`
}

// BrowserLoss is a name an edit did not give the chosen route.
type BrowserLoss struct {
	Pattern string `json:"pattern"`
	Rule    string `json:"rule"` // the rule above that still decides it
}

// BrowserResult is what an edit did.
type BrowserResult struct {
	Rule    string `json:"rule,omitempty"` // the rule the sites went to
	Added   int    `json:"added"`
	Moved   int    `json:"moved"` // were in another rule of the extension
	Same    int    `json:"same"`  // were there already
	Removed int    `json:"removed"`
	// Lost: names a rule above the extension's still decides.
	Lost []BrowserLoss `json:"lost"`
	// Raised: the rule that stood above the extension's and decided a
	// name of the edit; the extension's rules went above it ("" = none).
	Raised string `json:"raised,omitempty"`
	Rev    uint64 `json:"rev"`
}

// ErrBrowserOff: the extension is turned off in HyRoute.
var ErrBrowserOff = sentenceError("Расширение для браузера выключено в HyRoute: «Настройки» → «Расширение для браузера»")

var errBrowserApp = sentenceError("HyRoute не определил браузер. Перезапустите браузер и снова откройте расширение")

// BrowserOn reports whether the extension may talk to HyRoute (prefs
// "browser"; never while prefs.json is broken).
func (c *Controller) BrowserOn() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prefsBroken == nil && c.prefs.Browser == store.BrowserOn
}

// SetBrowserOn turns the extension's access on or off.
func (c *Controller) SetBrowserOn(on bool) error {
	return c.UpdatePrefs(func(p *store.Prefs) error {
		p.Browser = ""
		if on {
			p.Browser = store.BrowserOn
		}
		return nil
	})
}

// BrowserInfo says how each name goes with the saved rules of the active
// rule profile, as a new HTTPS connection of the browser would.
func (c *Controller) BrowserInfo(q BrowserQuery) (BrowserInfo, error) {
	if len(q.Hosts) > maxBrowserHosts {
		return BrowserInfo{}, sentencef("Слишком много адресов: не больше %d", maxBrowserHosts)
	}
	c.browserSeen.Store(time.Now().Unix())
	st := c.Status()
	info := BrowserInfo{State: st.State, Targets: []BrowserTarget{}, Sites: []BrowserSite{}}
	proc := browserProc(q.App)
	if proc != nil {
		info.App = proc.Name
	} else {
		info.Problem = errBrowserApp.Error()
	}
	if err := c.settingsBrokenError(); err != nil {
		info.Problem = err.Error()
	}
	c.mu.Lock()
	cfg := c.settings.Config
	main := c.mainTargetLocked()
	info.Ruleset = c.activeRulesetNameLocked()
	if info.Ruleset == "" {
		info.Ruleset = defaultRulesetName
	}
	for _, p := range c.profiles.List {
		if !p.Missing {
			info.Targets = append(info.Targets, BrowserTarget{To: "id:" + p.ID, Name: c.profileName(p.ID)})
		}
	}
	if c.groupsBroken == nil {
		for _, g := range c.groupsFile.Groups {
			info.Targets = append(info.Targets, BrowserTarget{To: "id:" + g.ID, Name: g.Name, Group: true})
		}
	}
	c.mu.Unlock()
	if main != "" {
		info.Main = c.profileName(main)
	}
	if site, label := browserSite(q.Page); site != "" {
		info.Page = &BrowserPage{Site: site, Label: label}
		for _, r := range cfg.Rules {
			if info.App != "" && browserRuleFor(r, info.App) && browserRuleSite(r) == site {
				info.Page.Items += len(r.Domains)
			}
		}
	}
	seen := map[string]bool{}
	for _, h := range q.Hosts {
		host, ok := rules.HostName(h)
		if !ok || seen[host] {
			continue
		}
		seen[host] = true
		s := BrowserSite{Host: host, Label: unicodeName(host)}
		if site, ok := rules.Registrable(host); ok {
			s.Site, s.SiteLabel = site, unicodeName(site)
		}
		s.Route = c.browserRoute(cfg, main, proc, host)
		info.Sites = append(info.Sites, s)
	}
	return info, nil
}

// browserProc is the browser as the rules see its connections.
func browserProc(app string) *procinfo.Info {
	app = strings.ToLower(strings.TrimSpace(app))
	if app == "" || app == "." || app == ".." || strings.ContainsAny(app, "*?:/\\\r\n\t") {
		return nil
	}
	return &procinfo.Info{Name: app}
}

// Chromium on macOS opens connections from its in-bundle network helper.
func browserAppMatches(app string) []rules.AppMatch {
	apps := []rules.AppMatch{{Pattern: app}}
	if runtime.GOOS == "darwin" && !strings.HasSuffix(app, ".exe") {
		apps = append(apps, rules.AppMatch{Pattern: app + " Helper"})
	}
	return apps
}

// browserRoute is the route of an HTTPS connection of the browser to host.
func (c *Controller) browserRoute(cfg rules.Config, main string, proc *procinfo.Info, host string) BrowserRoute {
	w := browserWinner(cfg, main, proc, host)
	r := connRoute(cfg, w, main)
	out := BrowserRoute{Index: w}
	switch r.Action {
	case rules.Direct:
		out.To = "direct"
	case rules.Block:
		out.To = "block"
	default:
		out.To = "vpn"
		if w >= 0 && cfg.Rules[w].Profile != "" || w < 0 && cfg.DefaultProfile != "" {
			out.To = "id:" + r.Profile
		}
		if r.Profile != "" {
			out.Server = c.profileName(r.Profile)
		}
	}
	if r.Rule != nil {
		out.Rule = r.Rule.Name
		out.Browser = proc != nil && browserRuleFor(*r.Rule, proc.Name)
	}
	for _, rule := range cfg.Rules {
		if proc == nil || !rule.On() || !browserRuleFor(rule, proc.Name) {
			continue
		}
		for _, d := range rule.Domains {
			if browserCatches(d, host) {
				out.Pattern = d
				return out
			}
		}
	}
	return out
}

func browserWinner(cfg rules.Config, main string, proc *procinfo.Info, host string) int {
	w, _ := rules.Winner(cfg, rules.Flow{
		Proc: proc, Proto: 6, Dst: netip.AddrPortFrom(netip.Addr{}, 443), Name: host, Main: main,
	})
	return w
}

// browserCatches: the extension's item d (".site" or an exact name)
// covers host.
func browserCatches(d, host string) bool {
	if s, ok := strings.CutPrefix(d, "."); ok {
		return host == s || strings.HasSuffix(host, d)
	}
	return host == d
}

// isBrowserRule: a rule the extension keeps — its name and plain sites,
// with either a browser scope or the legacy global shape. A user's own
// program rule that only borrowed the prefix is never rewritten.
func isBrowserRule(r rules.Rule) bool {
	if !strings.HasPrefix(r.Name, BrowserRulePrefix) || r.Domain != nil ||
		len(r.Ports) > 0 || (r.Protocol != "" && !strings.EqualFold(r.Protocol, "any")) || len(r.Fallback) > 0 {
		return false
	}
	if apps := r.AllApps(); len(apps) > 0 && !browserRuleScope(r, apps[0].Pattern) {
		return false
	}
	for _, d := range r.Domains {
		if _, ok := browserPattern(d); !ok {
			return false
		}
	}
	return true
}

func browserRuleScope(r rules.Rule, app string) bool {
	return strings.HasSuffix(strings.TrimSuffix(r.Name, browserHostsSuffix), browserAppSuffix(app)) &&
		slices.Equal(r.AllApps(), browserAppMatches(app))
}

func browserRuleFor(r rules.Rule, app string) bool {
	return isBrowserRule(r) && browserRuleScope(r, app)
}

func browserAppSuffix(app string) string { return " [" + app + "]" }

// browserHostsRule: an address rule of the extension (by name).
func browserHostsRule(r rules.Rule) bool { return strings.HasSuffix(r.Name, browserHostsSuffix) }

// browserSite is the site a page's rules are kept under: the registrable
// domain of its host and how people read it ("" for an IP, a single label
// or a public suffix: such a page has no rules of its own).
func browserSite(page string) (site, label string) {
	h, ok := rules.HostName(page)
	if !ok {
		return "", ""
	}
	if site, ok = rules.Registrable(h); !ok {
		return "", ""
	}
	return site, unicodeName(site)
}

// browserRuleSite is the site of a per-site rule of the extension, by its
// name («Из браузера: example.com», «… (адреса)»); "" for a rule by route
// («Из браузера: VPN», «Из браузера: <сервер>»). A server named exactly as
// a registrable domain reads as that site: its rule by route then takes
// the edits of that site's pages with the same route, nothing more.
func browserRuleSite(r rules.Rule) string {
	name := strings.TrimSuffix(strings.TrimPrefix(r.Name, BrowserRulePrefix), browserHostsSuffix)
	if apps := r.AllApps(); len(apps) > 0 && browserRuleScope(r, apps[0].Pattern) {
		name = strings.TrimSuffix(name, browserAppSuffix(apps[0].Pattern))
	}
	h, ok := rules.HostName(name)
	if !ok {
		return ""
	}
	if site, ok := rules.Registrable(h); ok && site == h {
		return site
	}
	return ""
}

// hoistBrowserRules puts this browser's address and site rules first.
func hoistBrowserRules(rs []rules.Rule, app string) []rules.Rule {
	var addrs, sites, rest []rules.Rule
	for _, r := range rs {
		switch {
		case !browserRuleFor(r, app):
			rest = append(rest, r)
		case browserHostsRule(r):
			addrs = append(addrs, r)
		default:
			sites = append(sites, r)
		}
	}
	return slices.Concat(addrs, sites, rest)
}

// browserPattern normalizes an item of the extension: ".example.com" or
// an exact name; no IPs, wildcards or keywords.
func browserPattern(p string) (string, bool) {
	p = strings.TrimSpace(p)
	site, isSite := strings.CutPrefix(p, ".")
	h, ok := rules.HostName(site)
	if !ok || strings.ContainsAny(h, "*:/ ") {
		return "", false
	}
	if isSite {
		return "." + h, true
	}
	return h, true
}

// browserTarget resolves BrowserEdit.To.
func (c *Controller) browserTarget(to string) (rules.Action, string, string, error) {
	c.mu.Lock()
	ts := c.targetsLocked()
	c.mu.Unlock()
	switch to {
	case "vpn":
		return rules.Tunnel, "", "VPN", nil
	case "direct":
		return rules.Direct, "", "напрямую", nil
	case "block":
		return rules.Block, "", "блок", nil
	}
	id, ok := strings.CutPrefix(to, "id:")
	if !ok || id == "" {
		return 0, "", "", sentenceError("Неизвестно, куда отправить сайт")
	}
	for _, t := range ts {
		if t.ID == id {
			if err := c.withLock(func() error { return c.connTargetLocked(rules.Rule{Action: rules.Tunnel, Profile: id}) }); err != nil {
				return 0, "", "", err
			}
			return rules.Tunnel, id, c.profileName(t.ID), nil
		}
	}
	return 0, "", "", sentenceError("Сервер удалён или пропал из подписки: выберите другой")
}

func (c *Controller) withLock(f func() error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return f()
}

// browserItems checks the sites of an edit.
func browserItems(list []string) ([]string, error) {
	if len(list) == 0 {
		return nil, sentenceError("Не выбрано ни одного сайта")
	}
	if len(list) > maxBrowserEdit {
		return nil, sentencef("Слишком много сайтов за раз: не больше %d", maxBrowserEdit)
	}
	var out []string
	for _, s := range list {
		p, ok := browserPattern(s)
		if !ok {
			return nil, sentencef("Не адрес сайта: %q", s)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// BrowserAdd sends sites where e.To says: into the rule of the page's site
// with that route (the rule by route without a page; made at the top when
// missing), out of the extension's rules with another route. A whole site
// also takes its addresses out of the address rules: «весь сайт» is the
// last word on its names. When a rule of the user's above still decides a
// name, the extension's rules go above everything: what the user sends
// from the browser is the latest word.
func (c *Controller) BrowserAdd(e BrowserEdit) (BrowserResult, error) {
	if !c.BrowserOn() {
		return BrowserResult{}, ErrBrowserOff
	}
	proc := browserProc(e.App)
	if proc == nil {
		return BrowserResult{}, errBrowserApp
	}
	items, err := browserItems(e.Sites)
	if err != nil {
		return BrowserResult{}, err
	}
	act, profile, word, err := c.browserTarget(e.To)
	if err != nil {
		return BrowserResult{}, err
	}
	site, label := browserSite(e.Page)
	if site == "" {
		label = word
	}
	var res BrowserResult
	save, err := c.editRules(func(cfg *rules.Config) (bool, error) {
		changed := false
		for _, p := range items {
			hosts := !strings.HasPrefix(p, ".")
			name := BrowserRulePrefix + label + browserAppSuffix(proc.Name)
			if hosts {
				name += browserHostsSuffix
			}
			if res.Rule == "" || !hosts {
				res.Rule = name
			}
			mine := -1
			for i, r := range cfg.Rules {
				if browserRuleFor(r, proc.Name) && r.On() && browserHostsRule(r) == hosts && r.Action == act && r.Profile == profile && browserRuleSite(r) == site {
					mine = i
					break
				}
			}
			if mine >= 0 && slices.Contains(cfg.Rules[mine].Domains, p) {
				res.Same++
				continue
			}
			moved := false
			for i := range cfg.Rules {
				r := &cfg.Rules[i]
				if !browserRuleFor(*r, proc.Name) {
					continue
				}
				// The same name with the same route in another site's rule
				// stays: each site's rule is whole by itself. A rule by
				// route is no site's: what a page sends again leaves it
				// for the page's rule, and the old heaps empty out.
				other := r.Action != act || r.Profile != profile || site != "" && browserRuleSite(*r) == ""
				n := len(r.Domains)
				r.Domains = slices.DeleteFunc(r.Domains, func(d string) bool {
					return other && d == p || !hosts && !strings.HasPrefix(d, ".") && browserCatches(p, d)
				})
				if len(r.Domains) != n {
					moved, changed = true, true
				}
			}
			if mine < 0 {
				at := 0
				if !hosts {
					// Below the address rules of the extension.
					for i, r := range cfg.Rules {
						if browserRuleFor(r, proc.Name) && browserHostsRule(r) {
							at = i + 1
						}
					}
				}
				cfg.Rules = slices.Insert(cfg.Rules, at, rules.Rule{
					ID: newID(), Name: name, Apps: browserAppMatches(proc.Name), Action: act, Profile: profile,
				})
				mine = at
			}
			cfg.Rules[mine].Domains = append(cfg.Rules[mine].Domains, p)
			changed = true
			if moved {
				res.Moved++
			} else {
				res.Added++
			}
		}
		cfg.Rules = dropEmptyBrowserRules(cfg.Rules, proc.Name)
		if !changed {
			return false, nil
		}
		// What the edit could not change: a rule above the extension's.
		lost := func() (out []BrowserLoss, above string) {
			out = []BrowserLoss{}
			for _, p := range items {
				host := strings.TrimPrefix(p, ".")
				w := browserWinner(*cfg, "", proc, host)
				if w < 0 || !browserRuleFor(cfg.Rules[w], proc.Name) || cfg.Rules[w].Action != act || cfg.Rules[w].Profile != profile {
					rule := "«Всё остальное»"
					if w >= 0 {
						rule = cfg.Rules[w].Name
						if above == "" && !browserRuleFor(cfg.Rules[w], proc.Name) {
							above = rule
						}
					}
					out = append(out, BrowserLoss{Pattern: p, Rule: rule})
				}
			}
			return out, above
		}
		var above string
		if res.Lost, above = lost(); above != "" {
			cfg.Rules = hoistBrowserRules(cfg.Rules, proc.Name)
			res.Raised = above
			res.Lost, _ = lost()
		}
		return true, nil
	})
	if err != nil {
		return BrowserResult{}, err
	}
	if res.Lost == nil {
		res.Lost = []BrowserLoss{}
	}
	res.Rev = save.Rev
	c.Log.Info("browser extension: sites sent", "to", act.String(), "added", res.Added, "moved", res.Moved, "same", res.Same, "lost", len(res.Lost))
	return res, nil
}

// BrowserRemove takes items out of the extension's rules: the names go
// back to the rest of the rules. With a page and no items it removes the
// rules of the page's site whole.
func (c *Controller) BrowserRemove(e BrowserEdit) (BrowserResult, error) {
	if !c.BrowserOn() {
		return BrowserResult{}, ErrBrowserOff
	}
	proc := browserProc(e.App)
	if proc == nil {
		return BrowserResult{}, errBrowserApp
	}
	site, _ := browserSite(e.Page)
	whole := len(e.Sites) == 0 && site != ""
	var items []string
	if !whole {
		var err error
		if items, err = browserItems(e.Sites); err != nil {
			return BrowserResult{}, err
		}
	}
	res := BrowserResult{Lost: []BrowserLoss{}}
	save, err := c.editRules(func(cfg *rules.Config) (bool, error) {
		for i := range cfg.Rules {
			r := &cfg.Rules[i]
			if !browserRuleFor(*r, proc.Name) {
				continue
			}
			n := len(r.Domains)
			if whole {
				if browserRuleSite(*r) == site {
					r.Domains = nil
				}
			} else {
				r.Domains = slices.DeleteFunc(r.Domains, func(d string) bool { return slices.Contains(items, d) })
			}
			res.Removed += n - len(r.Domains)
		}
		cfg.Rules = dropEmptyBrowserRules(cfg.Rules, proc.Name)
		return res.Removed > 0, nil
	})
	if err != nil {
		return BrowserResult{}, err
	}
	res.Rev = save.Rev
	c.Log.Info("browser extension: sites removed", "removed", res.Removed)
	return res, nil
}

// dropEmptyBrowserRules removes the extension's rules left without sites.
func dropEmptyBrowserRules(rs []rules.Rule, app string) []rules.Rule {
	return slices.DeleteFunc(rs, func(r rules.Rule) bool { return browserRuleFor(r, app) && len(r.Domains) == 0 })
}
