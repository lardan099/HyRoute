package app

import (
	"cmp"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"github.com/lardan099/hyroute/internal/dnscache"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
)

// «Создать правило из соединения»: the menu of a Connections row
// (ConnRuleInfo), the rule it creates (AddConnRule) and its undo. The rule
// is an ordinary rule written through the single rules write path
// (editRulesIn), placed right above the rule that decides the connection
// now, so it takes effect.

// connUndoCapacity is how many undo entries are kept; the UI mirrors it
// (undoCapacity in frontend/src/toast.svelte.ts): a change of one must
// change the other.
const connUndoCapacity = 20

// connRulesState is the Controller's part for rules made from connections.
type connRulesState struct {
	// SystemRoot overrides %SystemRoot% for the «part of Windows» hint
	// (tests); nil = the environment.
	SystemRoot func() string

	// undoMu guards connUndo and undoSeq. A leaf: never held while taking
	// saveMu, mu or any other lock.
	undoMu   sync.Mutex
	connUndo []connUndo // oldest first, at most connUndoCapacity
	undoSeq  uint64
}

type connUndo struct {
	token, kind   string // kind: added | changed
	id            string // the rule's ID
	before, after rules.Rule
	ruleset       string // token of the rules written
	rulesetName   string
	seq           uint64
}

// ConnFacts is a Connections row as the UI has it (flows.View fields). It
// identifies the flow; what the engine knew about it is read from the flow
// record whenever the registry still has it (resolveFlow), and the row's
// own fields are only the fallback.
type ConnFacts struct {
	ID        uint64 `json:"id"`      // flow ID: the record is looked up in the registry
	Process   string `json:"process"` // lower-case exe name, "" = unknown
	Path      string `json:"path"`
	PID       uint32 `json:"pid"`
	Proto     string `json:"proto"`     // tcp | udp
	Dst       string `json:"dst"`       // ip:port
	Domain    string `json:"domain"`    // one name, or DNS names joined by ","
	DomainSrc string `json:"domainSrc"` // sni | host | dns | unknown | query (a DNS row)
	ECH       bool   `json:"ech"`       // flows.Fields.ECH
	Excluded  string `json:"excluded"`  // flows.Fields.Excluded
	Attrib    string `json:"attrib"`    // flows.Fields.Attrib (dnscache | packet | … for DNS rows)
	Stage     string `json:"stage"`     // flows.Fields.Stage; flows.StageDNS = a DNS row
}

type ConnScope struct {
	Pattern string `json:"pattern"` // rule item: ".example.com" | "a.example.com" | "1.2.3.4"
	Kind    string `json:"kind"`    // site | host | ip | alias (a CNAME target: exact host, never the default)
	Label   string `json:"label"`   // display form (Unicode for IDN)
	ASCII   string `json:"ascii"`   // display form in punycode (== Label unless IDN); used in privacy mode
}

type ConnRoute struct {
	Index     int          `json:"index"` // -1 = «Всё остальное»
	Rule      *rules.Rule  `json:"rule"`  // copy of the deciding rule (nil for «Всё остальное»); the UI titles it
	Action    rules.Action `json:"action"`
	Profile   string       `json:"profile"`   // target ID; resolved main for Tunnel ("" = none)
	Ambiguous bool         `json:"ambiguous"` // sites with different routes: decided without a domain (rules.Winner)
}

type ConnRuleInfo struct {
	Excluded      string      `json:"excluded"`      // non-empty: rules do not apply; why
	Blocked       string      `json:"blocked"`       // non-empty: rules cannot be saved now; why
	App           string      `json:"app"`           // exe file name for an app rule, "" = unknown
	AppSystem     bool        `json:"appSystem"`     // part of Windows: confirm first
	AppLauncher   bool        `json:"appLauncher"`   // shell/launcher: app rules without inheritChildren
	HasParents    bool        `json:"hasParents"`    // the owner's ancestry was known (Explain note)
	Scopes        []ConnScope `json:"scopes"`        // may be empty only for an invalid address
	DNSName       bool        `json:"dnsName"`       // names come from the DNS cache
	Sites         int         `json:"sites"`         // DNS-cache sites of the address the menu decides by (0 with an exact name)
	Nameless      bool        `json:"nameless"`      // QUIC decided without a site name (rules.NamelessUDP): a site rule misses it
	SharedIP      bool        `json:"sharedIP"`      // the IP carries several sites or an ECH public name
	AddrSites     int         `json:"addrSites"`     // DNS-cache sites of the address, also with an exact name (SharedIP hint)
	ECH           string      `json:"ech"`           // "" | public | hidden
	ECHName       string      `json:"echName"`       // the public name, for the «public» hint
	DNSQuery      bool        `json:"dnsQuery"`      // the row is a DNS lookup (a DNS row)
	AppNote       string      `json:"appNote"`       // non-empty: application items hidden, this line shown instead
	ExplainTarget string      `json:"explainTarget"` // what «Проверить адрес» is prefilled with
	Current       ConnRoute   `json:"current"`
	Ruleset       string      `json:"ruleset"`     // token of the active rules
	RulesetName   string      `json:"rulesetName"` // active rule profile name ("" with one profile)
}

type ConnRuleRequest struct {
	Facts   ConnFacts  `json:"facts"`
	Rule    rules.Rule `json:"rule"`    // a quick action's rule or the edited one
	Source  string     `json:"source"`  // quick | editor
	Ruleset string     `json:"ruleset"` // ConnRuleInfo.Ruleset sent back: the rules the menu was built on
}

// ConnRuleRef is a rule the result mentions, as saved, for the UI to title.
type ConnRuleRef struct {
	Index int        `json:"index"`
	Rule  rules.Rule `json:"rule"`
}

type ConnRuleResult struct {
	Kind         string        `json:"kind"`         // added | changed | same
	Index        int           `json:"index"`        // where the rule is now
	RuleID       string        `json:"ruleId"`       // "" only for a same result on a rule without ID
	Rule         rules.Rule    `json:"rule"`         // the rule as saved
	AboveIndex   int           `json:"aboveIndex"`   // index of the rule now right below it; -1 = at the end
	Matches      bool          `json:"matches"`      // the rule catches this connection
	PlacedByRule bool          `json:"placedByRule"` // editor rule that does not fit: placed by PlaceRule
	NotEffective bool          `json:"notEffective"` // matches, but the engine still decides the flow otherwise
	Nameless     bool          `json:"nameless"`     // the flow is decided without a site name (ConnRuleInfo.Nameless)
	Unchanged    bool          `json:"unchanged"`    // the rule decides the connection and it already went this way
	OverriddenBy []int         `json:"overriddenBy"` // enabled rules above that take part of its connections
	Shadowed     []int         `json:"shadowed"`     // rules below that can no longer match
	Narrowed     []int         `json:"narrowed"`     // rules it was put above only as may-matchers and now partly overrides
	Refs         []ConnRuleRef `json:"refs"`         // every rule named by AboveIndex/OverriddenBy/Shadowed/Narrowed
	Undo         string        `json:"undo"`         // token for UndoConnRule ("" for same)
	Seq          uint64        `json:"seq"`          // sequence number of the undo entry; 0 for same
	Ruleset      string        `json:"ruleset"`      // token of the rules written
	RulesetName  string        `json:"rulesetName"`
	Rev          uint64        `json:"rev"` // settings revision after the write
}

// launchers are shells and programs that start other programs: an
// application rule made from one of their connections covers the program
// itself, not everything started from it.
var launchers = map[string]bool{
	"explorer.exe": true, "cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "powershell_ise.exe": true,
	"windowsterminal.exe": true, "wt.exe": true, "openconsole.exe": true, "conhost.exe": true, "rundll32.exe": true,
	"dllhost.exe": true, "svchost.exe": true, "services.exe": true, "taskhostw.exe": true, "sihost.exe": true,
	"runtimebroker.exe": true, "wscript.exe": true, "cscript.exe": true, "mshta.exe": true, "code.exe": true,
	"far.exe": true, "totalcmd.exe": true, "totalcmd64.exe": true, "doublecmd.exe": true,
}

func isLauncher(exe string) bool { return launchers[exe] }

const maxFactLen = 4096

// The refusals are sentences for the user (sentenceError).
var (
	errConnData      error = sentenceError("неверные данные соединения")
	errServiceFlow   error = sentenceError("Служебное соединение: правила к нему не применяются")
	errNoProgram     error = sentenceError("Программа не определена")
	errUndoGone      error = sentenceError("Отменить уже нельзя")
	errUndoNotFound  error = sentenceError("Правило не найдено: оно удалено.")
	errUndoEdited    error = sentenceError("Правило уже изменено на странице «Правила» — отмените изменение там.")
	errConnRuleEmpty error = sentenceError("Укажите программу или сайт")
)

// connFlow is what resolveFlow knows about a row.
type connFlow struct {
	rules.Flow
	DNSName   bool   // the names come from the DNS cache
	DNSQuery  bool   // a DNS-query row
	ECHMarker bool   // the hello carried ECH
	Excluded  string // mandatory exclusion kind
	DomainSrc string
	Attrib    string
	Process   string
	Path      string
	parents   []string
	// addrSites: how many DNS sites the address carries (from the record
	// or the live cache), also with an exact name: SharedIP.
	addrSites int
}

// resolveFlow turns a request into what the engine knew about the flow:
// the flow record when the registry still has it, else the row's facts.
func (c *Controller) resolveFlow(f ConnFacts) (connFlow, error) {
	for _, s := range []string{f.Process, f.Path, f.Proto, f.Dst, f.Domain, f.DomainSrc, f.Excluded, f.Attrib, f.Stage} {
		if len(s) > maxFactLen {
			return connFlow{}, errors.New("слишком длинные данные соединения")
		}
	}
	dst, err := netip.ParseAddrPort(f.Dst)
	if err != nil {
		return connFlow{}, errors.New("неверный адрес соединения")
	}
	var parents []string
	var sites [][]string
	var partial, nameless, found bool
	if v, ok := c.lookupFlow(f); ok {
		// The engine's own facts: the WebView cannot make a service flow
		// look like an ordinary one, and the DNS grouping is the engine's.
		f.Excluded, f.ECH, f.Stage, f.Attrib, f.Domain, f.DomainSrc = v.Excluded, v.ECH, v.Stage, v.Attrib, v.Domain, v.DomainSrc
		parents, sites, partial, nameless, found = v.Parents, v.Sites, v.SitesPartial, v.Nameless, true
	}
	if len(sites) == 0 && f.DomainSrc == "dns" && f.Domain != "" {
		sites, partial = c.rebuildSites(dst.Addr().Unmap(), f.Domain)
		// The same bound as a record's sites: Winner and Place walk them.
		var cut bool
		sites, cut = flows.CapSites(sites)
		partial = partial || cut
	}
	fl, err := buildFlow(f, parents, sites, partial)
	if err != nil || fl.DNSQuery {
		return fl, err
	}
	if !found {
		// The record is gone: the engine decides QUIC as the settings say.
		c.mu.Lock()
		if st := c.settings; st != nil {
			nameless = rules.NamelessUDP(st.ExactWeb(), st.QUICBlocked(), fl.Proto, fl.Dst.Port())
		}
		c.mu.Unlock()
	}
	// The names still offer site rules; Winner and Place use none.
	fl.Nameless = nameless
	return fl, nil
}

// lookupFlow finds the row's record in the session's registry; a record
// with the same ID but another identity (an earlier session) is ignored.
func (c *Controller) lookupFlow(f ConnFacts) (fv flows.View, ok bool) {
	c.mu.Lock()
	reg := c.lastFlows
	c.mu.Unlock()
	if reg == nil {
		return fv, false
	}
	v, ok := reg.Lookup(f.ID, time.Now())
	if !ok || v.PID != f.PID || v.Proto != f.Proto || v.Dst != f.Dst || v.Process != f.Process || v.Path != f.Path {
		return fv, false
	}
	return v, true
}

// rebuildSites groups the row's DNS names as the live cache does when the
// record is gone: each live site keeps the row's names that belong to it,
// in its order; row names in no live site become sites of their own and
// the grouping is partial.
func (c *Controller) rebuildSites(ip netip.Addr, domain string) ([][]string, bool) {
	var row []string
	for _, n := range strings.Split(domain, ",") {
		if n = rules.NormalizeDomain(n); n != "" && !slices.Contains(row, n) {
			row = append(row, n)
		}
	}
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	var live [][]string
	if sess != nil {
		live = sess.DNSSites(ip)
	}
	var out [][]string
	used := map[string]bool{}
	for _, site := range live {
		var keep []string
		for _, n := range site {
			if n = rules.NormalizeDomain(n); slices.Contains(row, n) && !used[n] {
				keep, used[n] = append(keep, n), true
			}
		}
		if len(keep) > 0 {
			out = append(out, keep)
		}
	}
	partial := false
	for _, n := range row {
		if !used[n] {
			out, partial = append(out, []string{n}), true
		}
	}
	return out, partial
}

// buildFlow is the pure part of resolveFlow.
func buildFlow(f ConnFacts, parents []string, sites [][]string, partial bool) (connFlow, error) {
	var fl connFlow
	switch strings.ToLower(f.Proto) {
	case "tcp":
		fl.Proto = 6
	case "udp":
		fl.Proto = 17
	default:
		return fl, errors.New("неизвестный протокол")
	}
	dst, err := netip.ParseAddrPort(f.Dst)
	if err != nil || !dst.Addr().IsValid() {
		return fl, errors.New("неверный адрес соединения")
	}
	fl.Dst = netip.AddrPortFrom(dst.Addr().Unmap().WithZone(""), dst.Port())
	fl.ECHMarker, fl.Excluded, fl.DomainSrc, fl.Attrib = f.ECH, f.Excluded, f.DomainSrc, f.Attrib
	fl.Process, fl.Path, fl.parents = f.Process, f.Path, parents
	switch f.DomainSrc {
	case "sni", "host", rules.SrcQuery.String():
		if strings.Contains(f.Domain, ",") {
			return fl, errConnData
		}
		if n := rules.NormalizeDomain(f.Domain); n != "" && !isIPName(n) {
			fl.Name = n
		}
	case "dns":
		fl.DNSName = true
	}
	// The address's sites: the menu decides by them only without a name.
	for _, site := range sites {
		var names []string
		for _, n := range site {
			if n = rules.NormalizeDomain(n); n != "" && !isIPName(n) && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
		if len(names) > 0 {
			if fl.DNSName {
				fl.Sites = append(fl.Sites, names)
			}
			fl.addrSites++
		}
	}
	if fl.DNSName {
		fl.SitesPartial = partial
	}
	if f.Stage == flows.StageDNS {
		// A name lookup: the connection is still to come, and the row's
		// address is the DNS server's.
		if f.DomainSrc != rules.SrcQuery.String() || fl.Name == "" {
			return fl, errConnData
		}
		fl.DNSQuery, fl.Proto, fl.Dst = true, 0, netip.AddrPort{}
	}
	if (f.Process != "" || f.Path != "") && !(fl.DNSQuery && f.Attrib == "dnscache") {
		fl.Proc = procChain(f.Process, f.Path, parents)
	}
	return fl, nil
}

func isIPName(n string) bool {
	_, err := netip.ParseAddr(strings.Trim(n, "[]"))
	return err == nil
}

// procChain rebuilds the owner as the rules saw it: the program, then its
// ancestors (a path or a name), at most procinfo.MaxDepth.
func procChain(process, path string, parents []string) *procinfo.Info {
	p := &procinfo.Info{Name: process, Path: path}
	if path != "" {
		p.Name = strings.ToLower(baseName(path))
	}
	cur := p
	for i, a := range parents {
		if i >= procinfo.MaxDepth {
			break
		}
		n := &procinfo.Info{Name: strings.ToLower(a)}
		if strings.ContainsAny(a, `\/`) {
			n.Path, n.Name = a, strings.ToLower(baseName(a))
		}
		cur.Parent, cur = n, n
	}
	return p
}

// baseName is the file name of a Windows or Unix path.
func baseName(p string) string {
	return filepath.Base(strings.ReplaceAll(p, `\`, "/"))
}

// echPublic: name is an ECH public name as the running engine knows it,
// else as the built-in list says.
func (c *Controller) echPublic(name string) bool {
	c.mu.Lock()
	sess := c.sess
	c.mu.Unlock()
	if sess != nil {
		return sess.ECHPublicName(name)
	}
	return dnscache.KnownPublicName(name)
}

func (c *Controller) systemRoot() string {
	if c.SystemRoot != nil {
		return c.SystemRoot()
	}
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

// connApp is the program an application rule names: the exe file name in
// its original case, "" when unknown (or the Windows DNS service asked).
func connApp(fl connFlow) string {
	if fl.DNSQuery && fl.Attrib == "dnscache" {
		return ""
	}
	if fl.Path != "" {
		return baseName(fl.Path)
	}
	return fl.Process
}

// connECH classifies the row's name: public (an ECH provider's name, never
// a site), hidden (ECH; the name came from elsewhere or there is none).
func (c *Controller) connECH(fl connFlow) (kind, name string) {
	if fl.Name != "" && c.echPublic(fl.Name) {
		return "public", fl.Name
	}
	if fl.ECHMarker && fl.DomainSrc != "sni" {
		return "hidden", ""
	}
	return "", ""
}

// ConnRuleInfo is what the menu of a Connections row offers.
func (c *Controller) ConnRuleInfo(f ConnFacts) (ConnRuleInfo, error) {
	fl, err := c.resolveFlow(f)
	if err != nil {
		return ConnRuleInfo{}, err
	}
	var info ConnRuleInfo
	info.Excluded = excludedText(fl)
	if err := c.settingsBrokenError(); err != nil {
		info.Blocked = err.Error()
	}
	info.App = connApp(fl)
	info.DNSQuery = fl.DNSQuery
	if fl.DNSQuery && fl.Attrib == "dnscache" {
		info.AppNote = "Запрос сделала служба DNS Windows: какой программе нужен этот адрес, неизвестно."
	}
	if info.App != "" {
		p := strings.ToLower(fl.Process)
		root := strings.ToLower(strings.TrimRight(c.systemRoot(), `\/`)) + `\`
		info.AppSystem = p == "system" || p == "idle" || strings.HasPrefix(strings.ToLower(strings.ReplaceAll(fl.Path, "/", `\`)), root)
		info.AppLauncher = isLauncher(strings.ToLower(info.App))
	}
	info.HasParents = len(fl.parents) > 0
	info.ECH, info.ECHName = c.connECH(fl)
	info.Scopes = c.connScopes(fl, info.ECH)
	info.DNSName = fl.DNSName
	info.Nameless = fl.Nameless
	if fl.Name == "" {
		info.Sites = len(fl.Sites)
	}
	info.SharedIP = fl.addrSites > 1 || info.ECH == "public"
	info.AddrSites = fl.addrSites
	switch {
	case fl.Name != "" && info.ECH != "public":
		info.ExplainTarget = fl.Name
	case fl.Dst.IsValid():
		info.ExplainTarget = fl.Dst.Addr().String()
	}
	c.mu.Lock()
	cfg := c.settings.Config
	main := c.mainTargetLocked()
	info.Ruleset, info.RulesetName = c.tokenLocked(), c.activeRulesetNameLocked()
	c.mu.Unlock()
	fl.Main = main
	w, amb := rules.Winner(cfg, fl.Flow)
	info.Current = connRoute(cfg, w, main)
	info.Current.Ambiguous = amb
	return info, nil
}

func excludedText(fl connFlow) string {
	switch {
	case fl.Excluded == "hysteria":
		return "Соединение Hysteria, запущенной HyRoute: правила к нему не применяются"
	case fl.Excluded == "system-dns":
		return "Системный DNS Windows всегда идёт напрямую: правила к нему не применяются"
	case fl.Excluded != "":
		return "Служебное соединение: правила к нему не применяются"
	case fl.DomainSrc == "proxy":
		return "Соединение локального прокси: сервер задаётся в настройках прокси, правила к нему не применяются"
	}
	return ""
}

// connRoute is the route of rule w of cfg (-1 = the default route).
func connRoute(cfg rules.Config, w int, main string) ConnRoute {
	r := ConnRoute{Index: w, Action: cfg.DefaultAction, Profile: cfg.DefaultProfile}
	if w >= 0 {
		rule := cfg.Rules[w].Clone()
		r.Rule, r.Action, r.Profile = &rule, rule.Action, rule.Profile
	}
	if r.Action != rules.Tunnel {
		r.Profile = ""
	} else if r.Profile == "" {
		r.Profile = main
	}
	return r
}

// connScopes are what a rule from the row can cover: for each site name
// (the exact name, else the head of each cached site; at most 3) the
// whole site and the host, then the IP, then — last — the CDN names the
// first site's chain points to.
func (c *Controller) connScopes(fl connFlow, ech string) []ConnScope {
	var names []string
	if fl.Name != "" {
		if ech != "public" {
			names = []string{fl.Name}
		}
	} else {
		for _, site := range fl.Sites {
			if len(names) < 3 && !c.echPublic(site[0]) && !slices.Contains(names, site[0]) {
				names = append(names, site[0])
			}
		}
	}
	out := []ConnScope{}
	add := func(s ConnScope) {
		if !slices.ContainsFunc(out, func(x ConnScope) bool { return x.Pattern == s.Pattern }) {
			out = append(out, s)
		}
	}
	for _, n := range names {
		if site, ok := rules.Registrable(n); ok {
			add(ConnScope{Pattern: "." + site, Kind: "site", Label: unicodeName(site), ASCII: site})
		}
		add(ConnScope{Pattern: n, Kind: "host", Label: unicodeName(n), ASCII: n})
	}
	if fl.Dst.IsValid() {
		ip := fl.Dst.Addr().String()
		add(ConnScope{Pattern: ip, Kind: "ip", Label: ip, ASCII: ip})
	}
	if fl.Name == "" && len(fl.Sites) > 0 {
		n := 0
		for _, a := range fl.Sites[0][1:] {
			if n < 2 && !c.echPublic(a) && !slices.ContainsFunc(out, func(x ConnScope) bool { return x.Pattern == a }) {
				out = append(out, ConnScope{Pattern: a, Kind: "alias", Label: unicodeName(a), ASCII: a})
				n++
			}
		}
	}
	return out
}

func unicodeName(n string) string {
	if u, err := idna.Lookup.ToUnicode(n); err == nil && u != "" {
		return u
	}
	return n
}

// normalizeNewRule cleans a rule sent by the menu or the editor.
func normalizeNewRule(r rules.Rule, source string) (rules.Rule, error) {
	out := rules.Rule{Name: strings.TrimSpace(r.Name), Action: r.Action, Profile: r.Profile, Fallback: r.Fallback,
		Protocol: r.Protocol, Ports: r.Ports}
	for _, a := range r.AllApps() {
		if a.Pattern = strings.TrimSpace(a.Pattern); a.Pattern != "" {
			out.Apps = append(out.Apps, a)
		}
	}
	for _, d := range r.AllDomains() {
		if d = strings.TrimSpace(d); d != "" {
			out.Domains = append(out.Domains, d)
		}
	}
	if strings.EqualFold(out.Protocol, "any") {
		out.Protocol = ""
	}
	if out.Action != rules.Tunnel {
		out.Profile, out.Fallback = "", nil
	}
	if source == "quick" {
		out.Name = ""
	}
	if len(out.Apps) == 0 && len(out.Domains) == 0 && len(out.Ports) == 0 {
		return out, errConnRuleEmpty
	}
	return out, nil
}

// connRouteKey is a route for "did it change" (action and resolved server).
func connRouteKey(cfg rules.Config, w int, main string) string {
	r := connRoute(cfg, w, main)
	return r.Action.String() + "|" + r.Profile
}

// AddConnRule creates a rule from a Connections row: above the rule that
// decides the connection now (quick items change that rule instead when
// it has exactly the same conditions and nothing above can take the
// connection), or, for an editor rule that does not fit the connection,
// above the first rule that could take any of its connections.
func (c *Controller) AddConnRule(req ConnRuleRequest) (ConnRuleResult, error) {
	fl, err := c.resolveFlow(req.Facts)
	if err != nil {
		return ConnRuleResult{}, err
	}
	if fl.Excluded != "" || fl.DomainSrc == "proxy" {
		return ConnRuleResult{}, errServiceFlow
	}
	if req.Source != "quick" && req.Source != "editor" {
		return ConnRuleResult{}, errors.New("неизвестный источник правила")
	}
	rule, err := normalizeNewRule(req.Rule, req.Source)
	if err != nil {
		return ConnRuleResult{}, err
	}
	if _, err := rules.Matches(rule, fl.Flow); err != nil {
		return ConnRuleResult{}, err
	}
	if req.Source == "quick" {
		if len(rule.Apps) > 0 && connApp(fl) == "" {
			return ConnRuleResult{}, errNoProgram
		}
		// An ECH provider's public name is never made a site: a rule on
		// it would catch every site behind the provider.
		for _, n := range fl.Names() {
			if !c.echPublic(n) {
				continue
			}
			if hit, _ := rules.CatchesName(rule, n); hit {
				return ConnRuleResult{}, sentencef("Сайт скрыт ECH: %s — имя провайдера, правило на него затронуло бы все сайты за ним. Выберите «Только IP» или «Настроить правило…».", n)
			}
		}
	}
	// Only the active profile: ConnRuleInfo never hands out an edit token,
	// and the result and undo entry record the active one.
	if strings.HasPrefix(req.Ruleset, editTokenPrefix) {
		return ConnRuleResult{}, errConnData
	}
	var res ConnRuleResult
	var entry connUndo
	save, err := c.editRulesIn(EditGuard{Ruleset: req.Ruleset}, func(cfg *rules.Config) (bool, error) {
		c.mu.Lock()
		main := c.mainTargetLocked()
		terr := c.connTargetLocked(rule)
		res.Ruleset, res.RulesetName = c.tokenLocked(), c.activeRulesetNameLocked()
		c.mu.Unlock()
		if terr != nil {
			return false, terr
		}
		flow := fl.Flow
		flow.Main = main
		w, _ := rules.Winner(*cfg, flow)
		p := rules.Place(*cfg, flow)
		matches, _ := rules.Matches(rule, flow)
		oldRoute := connRouteKey(*cfg, w, main)
		res.Matches, res.Nameless = matches, fl.Nameless
		switch {
		case req.Source == "quick" && w >= 0 && p == w && cfg.Rules[w].On() && rules.SameMatch(cfg.Rules[w], rule):
			old := cfg.Rules[w]
			res.Index = w
			if old.Action == rule.Action && old.Profile == rule.Profile {
				res.Kind, res.Rule, res.RuleID = "same", old.Clone(), old.ID
				// Nothing is saved: the revision of the list the result describes.
				res.Rev = c.SettingsRev()
				c.connRuleNotes(*cfg, main, &res, -1, -1)
				return false, nil
			}
			// The route changes ("same" above): the old fallbacks were
			// for the old server.
			after := old.Clone()
			after.Fallback = nil
			after.Action, after.Profile = rule.Action, rule.Profile
			if after.ID == "" {
				after.ID = newID()
			}
			cfg.Rules[w] = after
			res.Kind = "changed"
			entry = connUndo{kind: "changed", id: after.ID, before: old.Clone(), after: after.Clone()}
		default:
			rule.ID = newID()
			at := p
			if !matches {
				at, res.PlacedByRule = rules.PlaceRule(*cfg, rule), true
			}
			cfg.Rules = slices.Insert(cfg.Rules, at, rule)
			res.Kind, res.Index = "added", at
			entry = connUndo{kind: "added", id: rule.ID, after: rule.Clone()}
		}
		res.Rule, res.RuleID = cfg.Rules[res.Index].Clone(), cfg.Rules[res.Index].ID
		w2, amb2 := rules.Winner(*cfg, flow)
		effective := w2 == res.Index && !amb2
		res.NotEffective = matches && !effective
		res.Unchanged = effective && oldRoute == connRouteKey(*cfg, w2, main)
		wNew := -1
		if res.Kind == "added" && !res.PlacedByRule {
			wNew = len(cfg.Rules)
			if w >= 0 {
				wNew = w + 1
			}
		}
		c.connRuleNotes(*cfg, main, &res, res.Index+1, wNew)
		return true, nil
	})
	if err != nil {
		return ConnRuleResult{}, err
	}
	if res.Kind != "same" {
		res.Rev = save.Rev
		entry.ruleset, entry.rulesetName = res.Ruleset, res.RulesetName
		res.Undo, res.Seq = c.pushConnUndo(entry)
	}
	c.Log.Info("rule from a connection", "result", res.Kind, "index", res.Index, "source", req.Source,
		"action", res.Rule.Action, "overriddenBy", len(res.OverriddenBy), "shadowed", len(res.Shadowed))
	return res, nil
}

// connRuleNotes fills AboveIndex, OverriddenBy, Shadowed, Narrowed (the
// rules in [from, to) when to >= 0) and Refs from the saved cfg.
func (c *Controller) connRuleNotes(cfg rules.Config, main string, res *ConnRuleResult, from, to int) {
	i := res.Index
	res.AboveIndex = -1
	if i+1 < len(cfg.Rules) {
		res.AboveIndex = i + 1
	}
	res.OverriddenBy = orEmpty(rules.OverriddenBy(cfg, i))
	res.Shadowed = orEmpty(rules.Shadowed(cfg, i))
	res.Narrowed = []int{}
	if to >= 0 {
		res.Narrowed = orEmpty(rules.Narrowed(cfg, main, i, from, to))
	}
	res.Refs = []ConnRuleRef{}
	seen := map[int]bool{}
	for _, l := range [][]int{{res.AboveIndex}, res.OverriddenBy, res.Shadowed, res.Narrowed} {
		for _, j := range l {
			if j >= 0 && j < len(cfg.Rules) && !seen[j] {
				seen[j] = true
				res.Refs = append(res.Refs, ConnRuleRef{Index: j, Rule: cfg.Rules[j].Clone()})
			}
		}
	}
}

func orEmpty(l []int) []int {
	if l == nil {
		return []int{}
	}
	return l
}

// connTargetLocked checks that the server or group a quick rule sends to
// still exists (c.mu held).
func (c *Controller) connTargetLocked(r rules.Rule) error {
	if r.Action != rules.Tunnel || r.Profile == "" {
		return nil
	}
	if groups.IsGroupID(r.Profile) {
		if c.groupsBroken != nil || c.groupsFile.Find(r.Profile) == nil {
			return sentenceError("Группа удалена: выберите другую")
		}
		return nil
	}
	if p := c.profiles.Find(r.Profile); p == nil || p.Missing {
		return sentenceError("Сервер удалён или пропал из подписки: выберите другой")
	}
	return nil
}

// pushConnUndo stores an undo entry, dropping the oldest beyond the
// capacity, and returns its token and sequence number.
func (c *Controller) pushConnUndo(e connUndo) (string, uint64) {
	c.undoMu.Lock()
	defer c.undoMu.Unlock()
	c.undoSeq++
	e.token, e.seq = newID(), c.undoSeq
	c.connUndo = append(c.connUndo, e)
	if n := len(c.connUndo) - connUndoCapacity; n > 0 {
		c.connUndo = slices.Delete(c.connUndo, 0, n)
	}
	return e.token, e.seq
}

// takeConnUndo removes the entry with token.
func (c *Controller) takeConnUndo(token string) (connUndo, bool) {
	c.undoMu.Lock()
	defer c.undoMu.Unlock()
	i := slices.IndexFunc(c.connUndo, func(e connUndo) bool { return e.token == token })
	if i < 0 {
		return connUndo{}, false
	}
	e := c.connUndo[i]
	c.connUndo = slices.Delete(c.connUndo, i, i+1)
	return e, true
}

// putBackConnUndo returns an entry after a transient failure, in sequence
// order; one that fell out of the capacity meanwhile is dropped.
func (c *Controller) putBackConnUndo(e connUndo) {
	c.undoMu.Lock()
	defer c.undoMu.Unlock()
	i, _ := slices.BinarySearchFunc(c.connUndo, e.seq, func(x connUndo, s uint64) int { return cmp.Compare(x.seq, s) })
	c.connUndo = slices.Insert(c.connUndo, i, e)
	if n := len(c.connUndo) - connUndoCapacity; n > 0 {
		c.connUndo = slices.Delete(c.connUndo, 0, n)
	}
}

// clearConnUndo forgets every undo entry (a backup restore replaces the
// rules: an old «Отменить» must not touch the restored ones by ID).
func (c *Controller) clearConnUndo() {
	c.undoMu.Lock()
	c.connUndo = nil
	c.undoMu.Unlock()
}

// UndoConnRule reverts a rule made from a connection: removes an added
// rule, restores a changed one; only while it is exactly as it was made
// and its rule profile is the active one.
func (c *Controller) UndoConnRule(token string) error {
	e, ok := c.takeConnUndo(token)
	if !ok {
		return errUndoGone
	}
	at := -1
	_, err := c.editRulesIn(EditGuard{Ruleset: e.ruleset}, func(cfg *rules.Config) (bool, error) {
		i := slices.IndexFunc(cfg.Rules, func(r rules.Rule) bool { return r.ID == e.id })
		if i < 0 {
			return false, errUndoNotFound
		}
		a, err1 := json.Marshal(cfg.Rules[i])
		b, err2 := json.Marshal(e.after)
		if err1 != nil || err2 != nil || string(a) != string(b) {
			return false, errUndoEdited
		}
		at = i
		if e.kind == "added" {
			cfg.Rules = slices.Delete(cfg.Rules, i, i+1)
		} else {
			cfg.Rules[i] = e.before.Clone()
		}
		return true, nil
	})
	switch {
	case err == nil:
		c.Log.Info("rule from a connection undone", "index", at)
		return nil
	case errors.Is(err, errUndoNotFound), errors.Is(err, errUndoEdited):
		return err
	case errors.Is(err, errRulesetChanged):
		c.putBackConnUndo(e)
		c.mu.Lock()
		name := c.connRulesetNameLocked(e.ruleset, e.rulesetName)
		c.mu.Unlock()
		return sentencef("Профиль правил сменился: переключитесь на «%s», чтобы отменить.", name)
	}
	c.putBackConnUndo(e) // a write that failed: the user may retry
	return err
}

// connRulesetNameLocked is the current name of the rule profile a token
// addresses (the rules of a single profile got an ID and a name when the
// second one was created), else the name recorded with the entry.
func (c *Controller) connRulesetNameLocked(tok, recorded string) string {
	id := tok
	if tok == implicitToken {
		id = c.rsImplicitID
	}
	if c.rulesets != nil && id != "" {
		if e := c.rulesets.Find(id); e != nil {
			return e.Name
		}
	}
	if recorded == "" {
		return defaultRulesetName
	}
	return recorded
}
