// Package rules holds the routing rule model, its compilation and the
// tri-state evaluation used by the engine: an application and protocol are
// always known, a domain may be known exactly (SNI/Host), approximately
// (DNS cache) or not at all.
package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/lardan099/hyroute/internal/procinfo"
)

// Action is a route.
type Action uint8

const (
	Direct Action = iota
	Tunnel
	Block
)

func (a Action) String() string { return [...]string{"direct", "tunnel", "block"}[a] }

func ParseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "direct":
		return Direct, nil
	case "tunnel", "proxy":
		return Tunnel, nil
	case "block":
		return Block, nil
	}
	return 0, fmt.Errorf("unknown action %q", s)
}

func (a Action) MarshalText() ([]byte, error) { return []byte(a.String()), nil }
func (a *Action) UnmarshalText(b []byte) error {
	v, err := ParseAction(string(b))
	*a = v
	return err
}

// Rule is the persisted rule (settings JSON).
type Rule struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled,omitempty"` // nil = enabled
	// Apps and Domains: the rule matches a connection of any listed
	// application to any listed domain (an empty list = any). App and
	// Domain are the older single-item form, still accepted.
	Apps     []AppMatch   `json:"apps,omitempty"`
	Domains  []string     `json:"domains,omitempty"`
	App      *AppMatch    `json:"app,omitempty"`
	Domain   *DomainMatch `json:"domain,omitempty"`
	Protocol string       `json:"protocol,omitempty"` // any|tcp|udp
	// Ports: destination ports ("443", "8000-8100"); empty = any. With
	// Protocol they narrow the rule; a rule may have ports only. Stored in
	// the v1.2.0 string form "80,443,27000-27200" (PortList).
	Ports  PortList `json:"ports,omitempty"`
	Action Action   `json:"action"`
	// Profile is the server or group ID for Tunnel ("" = the main target).
	Profile string `json:"profile,omitempty"`
	// Fallback lists server or group IDs ("" = the main target) tried in
	// order when Profile cannot carry traffic. When every one is down the flow
	// is refused, as without a fallback.
	Fallback []string `json:"fallback,omitempty"`
	// FailMode is reserved for the stage-2 kill switch ("open"/"closed").
	FailMode string `json:"failMode,omitempty"`
}

type AppMatch struct {
	Pattern string `json:"pattern"`
	// Kind: "name" (exe basename), "path" (full path) or "glob" (full path
	// with * and ?). Empty = detect from the pattern.
	Kind            string `json:"kind,omitempty"`
	InheritChildren bool   `json:"inheritChildren,omitempty"`
}

type DomainMatch struct {
	// "example.com" exact, "*.example.com" subdomains only,
	// ".example.com" the domain and its subdomains.
	Pattern string `json:"pattern"`
}

// Config is the rules section of the settings.
type Config struct {
	DefaultAction Action `json:"defaultAction"`
	// DefaultProfile is the server or group for defaultAction tunnel ("" =
	// main).
	DefaultProfile string `json:"defaultProfile,omitempty"`
	// DefaultFallback: fallback servers or groups of the default route.
	DefaultFallback []string `json:"defaultFallback,omitempty"`
	Rules           []Rule   `json:"rules"`
}

// Load parses a JSON config.
func Load(b []byte) (Config, error) {
	var c Config
	err := json.Unmarshal(b, &c)
	return c, err
}

// DomainSource says where the destination name came from.
type DomainSource uint8

const (
	SrcNone DomainSource = iota
	SrcDNS
	SrcHost
	SrcSNI
	// SrcECH is the outer SNI of a ClientHello with encrypted_client_hello:
	// the site itself under GREASE ECH, a provider's public name under real
	// ECH. The relay passes it to the decider, which settles which it is;
	// it is shown as "sni".
	SrcECH
)

func (s DomainSource) String() string { return [...]string{"unknown", "dns", "host", "sni", "sni"}[s] }

// Subject is what the engine knows about a new flow.
type Subject struct {
	Proc  *procinfo.Info // nil when the owner is unknown
	Proto uint8          // 6 or 17
	Dst   netip.AddrPort
}

// Result is the outcome of an evaluation.
type Result struct {
	// NeedsDomain: rules disagree depending on a domain that is not known
	// yet; Action is meaningless.
	NeedsDomain bool
	Action      Action
	// Profile is the resolved profile ID when Action is Tunnel ("" when
	// there is no main profile: the flow is refused).
	Profile string
	// Fallback: resolved profile IDs to use, in order, when Profile is
	// down (see the engine's pick).
	Fallback  []string
	Rule      string // rule name or "default"
	RuleID    string
	Domain    string
	DomainSrc DomainSource
	// groups
	// Group is the server group Profile (a member) was chosen through; set
	// by the engine only (Core.pick), "" otherwise.
	Group string
	// Failover: the flow could not use its preferred server. The chain
	// moved past its first target, or the group avoided the member it
	// would otherwise use (groups.Pick.Failover). Set by the engine only.
	Failover bool
}

// NormalizeDomain lower-cases, strips the trailing dot and converts IDN to
// punycode. The same function is used for rules, DNS, SNI and Host.
func NormalizeDomain(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" {
		return ""
	}
	if a, err := idna.Lookup.ToASCII(s); err == nil {
		return a
	}
	return strings.ToLower(s)
}

type domainKind uint8

const (
	domExact   domainKind = iota
	domSub                // *.x: subdomains only
	domSuffix             // .x: x and subdomains
	domKeyword            // keyword:x: names containing x
	domRegex              // regexp:x
	domGeo                // geosite:x
)

type appPat struct {
	kind    string // name, path, glob
	app     string // normalized pattern
	inherit bool
	src     string
}

type domPat struct {
	kind domainKind
	dom  string
	src  string
	re   *regexp.Regexp
	geo  DomainMatcher // nil when the category is unavailable
	// uni: keyword:/regexp: written with non-ASCII letters ("банк"), also
	// tried on the Unicode form of punycode names (see alt).
	uni bool
}

// alt is the Unicode form of a punycode name (xn--…) for a uni pattern:
// names are compared in punycode (NormalizeDomain), where a word in
// Cyrillic never appears.
func (d *domPat) alt(name string) (string, bool) {
	if !d.uni || !strings.Contains(name, "xn--") {
		return "", false
	}
	u, err := idna.Punycode.ToUnicode(name)
	return u, err == nil && u != name
}

type compiled struct {
	src      Rule
	name     string
	apps     []appPat // empty = any application
	doms     []domPat // names; with ips: the destinations (any = none)
	ips      []ipPat  // addresses
	warns    []string // unusable geosite:/geoip: items
	proto    uint8    // 0 any
	action   Action
	profile  string   // "" = main
	fallback []string // "" = main
	// ports: destination ports, sorted and merged; empty = any port.
	ports []PortRange
}

func (r *compiled) hasApp() bool  { return len(r.apps) > 0 }
func (r *compiled) hasDom() bool  { return len(r.doms) > 0 }
func (r *compiled) hasDest() bool { return len(r.doms) > 0 || len(r.ips) > 0 }

func (r *compiled) matchIP(ip netip.Addr) bool {
	for i := range r.ips {
		if r.ips[i].match(ip) {
			return true
		}
	}
	return false
}

// Set is an immutable compiled rule set.
type Set struct {
	rules       []compiled
	def         Action
	defProfile  string
	defFallback []string
	// Main is the server or group ID used by Tunnel rules without a
	// profile (the main target).
	Main string
	// Warnings list rule items that match nothing for now (a geosite:
	// or geoip: category that is missing or not downloaded yet).
	Warnings []string
	// ExactWeb: web connections (see WebPort) take their domain only from
	// SNI/Host, never from the DNS cache. A CDN address shared by many
	// sites may be cached under a neighbour's name when the application
	// resolved through DoH, which we do not see.
	ExactWeb bool
}

// WebPort reports the TCP ports where SNI/Host can be read.
func WebPort(port uint16) bool {
	switch port {
	case 80, 443, 8080, 8443:
		return true
	}
	return false
}

// QUICNameless reports whether a UDP flow to port 443 is decided without a
// site name: with ExactWeb and BlockQUIC, QUIC gets no DNS-cache names and
// has no SNI. The engine's packetSites, Explain and Lint share it.
func QUICNameless(exactWeb, blockQUIC bool) bool { return exactWeb && blockQUIC }

// NamelessUDP reports whether a flow of proto to port gets no site name at
// packet level (QUICNameless).
func NamelessUDP(exactWeb, blockQUIC bool, proto uint8, port uint16) bool {
	return proto == 17 && port == 443 && QUICNameless(exactWeb, blockQUIC)
}

// Compile validates and normalizes a config.
func Compile(c Config) (*Set, error) {
	s := &Set{def: c.DefaultAction, defProfile: c.DefaultProfile, defFallback: c.DefaultFallback}
	for i, r := range c.Rules {
		if r.Enabled != nil && !*r.Enabled {
			// Ports of disabled rules are checked too: a bad one would
			// widen the rule on export or when it is turned on.
			if _, err := compilePorts(r.Ports); err != nil {
				return nil, fmt.Errorf("%s: %v", ruleName(i, r), err)
			}
			continue
		}
		cr, err := compileRule(i, r)
		if err != nil {
			return nil, err
		}
		for _, w := range cr.warns {
			s.Warnings = append(s.Warnings, cr.name+": "+w)
		}
		s.rules = append(s.rules, cr)
	}
	return s, nil
}

// ruleName is the display name ("правило N" when unnamed). An unnamed rule
// with ports only is named by them ("TCP 22"), as the rules list names it.
func ruleName(i int, r Rule) string {
	if r.Name != "" {
		return r.Name
	}
	if len(r.Ports) > 0 && len(r.AllApps()) == 0 && len(r.AllDomains()) == 0 {
		if l := PortsLabel(r.Protocol, r.Ports); l != "" {
			return l
		}
	}
	return fmt.Sprintf("правило %d", i+1)
}

// AppKind detects the kind of an application pattern: glob (has * or ?),
// path (has a slash) or name.
func AppKind(pattern string) string {
	switch {
	case strings.ContainsAny(pattern, "*?"):
		return "glob"
	case strings.ContainsAny(pattern, `\/`):
		return "path"
	}
	return "name"
}

// AllApps is the rule's application list, old single form included.
func (r Rule) AllApps() []AppMatch {
	out := append([]AppMatch(nil), r.Apps...)
	if r.App != nil {
		out = append(out, *r.App)
	}
	return out
}

// AllDomains is the rule's domain list, old single form included.
func (r Rule) AllDomains() []string {
	out := append([]string(nil), r.Domains...)
	if r.Domain != nil {
		out = append(out, r.Domain.Pattern)
	}
	return out
}

// ParseDomainPattern splits "example.com", "*.example.com" and
// ".example.com".
func parseDomainPattern(p string) (domPat, error) {
	d := domPat{src: strings.TrimSpace(p)}
	p = d.src
	switch {
	case strings.HasPrefix(p, "*."):
		d.kind, p = domSub, p[2:]
	case strings.HasPrefix(p, "."):
		d.kind, p = domSuffix, p[1:]
	}
	if strings.ContainsAny(p, "*/ :") {
		return d, fmt.Errorf("неверный шаблон %q (допустимо: example.com, .example.com, *.example.com, geosite:…, geoip:…, IP или подсеть)", d.src)
	}
	d.dom = NormalizeDomain(p)
	if d.dom == "" {
		return d, errors.New("пустой шаблон домена")
	}
	return d, nil
}

func compileRule(i int, r Rule) (compiled, error) {
	cr := compiled{src: r, name: ruleName(i, r), action: r.Action, profile: r.Profile, fallback: r.Fallback}
	apps, doms := r.AllApps(), r.AllDomains()
	if len(apps) == 0 && len(doms) == 0 && len(r.Ports) == 0 {
		return cr, fmt.Errorf("%s: укажите программу, сайт или порт", cr.name)
	}
	for _, a := range apps {
		p := strings.TrimSpace(a.Pattern)
		if p == "" {
			return cr, fmt.Errorf("%s: пустой шаблон программы", cr.name)
		}
		ap := appPat{kind: strings.ToLower(a.Kind), app: normPath(p), inherit: a.InheritChildren, src: p}
		if ap.kind == "" {
			ap.kind = AppKind(p)
		}
		switch ap.kind {
		case "name", "path", "glob":
		default:
			return cr, fmt.Errorf("%s: неизвестный тип программы %q", cr.name, a.Kind)
		}
		cr.apps = append(cr.apps, ap)
	}
	g := currentGeo()
	for _, p := range doms {
		if IsAddressItem(p) {
			ip, warn, err := parseIPPattern(p, g)
			if err != nil {
				return cr, fmt.Errorf("%s: %v", cr.name, err)
			}
			if warn != "" {
				cr.warns = append(cr.warns, warn)
			}
			cr.ips = append(cr.ips, ip)
			continue
		}
		d, warn, typed, err := parseTypedDomain(p, g)
		if !typed {
			d, err = parseDomainPattern(p)
		}
		if err != nil {
			return cr, fmt.Errorf("%s: %v", cr.name, err)
		}
		if warn != "" {
			cr.warns = append(cr.warns, warn)
		}
		cr.doms = append(cr.doms, d)
	}
	switch strings.ToLower(r.Protocol) {
	case "", "any":
	case "tcp":
		cr.proto = 6
	case "udp":
		cr.proto = 17
	default:
		return cr, fmt.Errorf("%s: неизвестный протокол %q", cr.name, r.Protocol)
	}
	ps, err := compilePorts(r.Ports)
	if err != nil {
		return cr, fmt.Errorf("%s: %v", cr.name, err)
	}
	cr.ports = ps
	return cr, nil
}

// HasDomainRules reports whether any rule has a domain condition.
func (s *Set) HasDomainRules() bool {
	for _, r := range s.rules {
		if r.hasDom() {
			return true
		}
	}
	return false
}

func normPath(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.TrimPrefix(p, `\\?\`)
	return strings.ToLower(p)
}

func (r *compiled) matchApp(p *procinfo.Info) bool {
	if !r.hasApp() {
		return true
	}
	for i := range r.apps {
		if r.apps[i].matchChain(p) {
			return true
		}
	}
	return false
}

func (a *appPat) matchChain(p *procinfo.Info) bool {
	for cur := p; cur != nil; cur = cur.Parent {
		if a.matchOne(cur) {
			return true
		}
		if !a.inherit {
			return false
		}
	}
	return false
}

func (a *appPat) matchOne(p *procinfo.Info) bool {
	switch a.kind {
	case "name":
		return p.Name != "" && p.Name == a.app
	case "path":
		return p.Path != "" && normPath(p.Path) == a.app
	case "glob":
		return p.Path != "" && globMatch(a.app, normPath(p.Path))
	}
	return false
}

func (d *domPat) match(name string) bool {
	switch d.kind {
	case domExact:
		return name == d.dom
	case domSub:
		return strings.HasSuffix(name, "."+d.dom)
	case domKeyword:
		if strings.Contains(name, d.dom) {
			return true
		}
		u, ok := d.alt(name)
		return ok && strings.Contains(u, d.dom)
	case domRegex:
		if d.re.MatchString(name) {
			return true
		}
		u, ok := d.alt(name)
		return ok && d.re.MatchString(u)
	case domGeo:
		return d.geo != nil && d.geo.Match(name)
	default:
		return name == d.dom || strings.HasSuffix(name, "."+d.dom)
	}
}

func (r *compiled) matchDomain(name string) bool {
	for i := range r.doms {
		if r.doms[i].match(name) {
			return true
		}
	}
	return false
}

// globMatch matches * (any run of characters, including \) and ? (one
// character: a whole UTF-8 sequence, so "Игр?" matches "Игры").
func globMatch(pattern, s string) bool {
	px, sx := 0, 0
	nextPx, nextSx := -1, -1
	for px < len(pattern) || sx < len(s) {
		if px < len(pattern) {
			switch c := pattern[px]; c {
			case '*':
				nextPx, nextSx = px, sx+runeLen(s[sx:])
				px++
				continue
			case '?':
				if sx < len(s) {
					px++
					sx += runeLen(s[sx:])
					continue
				}
			default:
				if sx < len(s) && s[sx] == c {
					px++
					sx++
					continue
				}
			}
		}
		if nextSx > 0 && nextSx <= len(s) {
			px, sx = nextPx, nextSx
			continue
		}
		return false
	}
	return true
}

// runeLen is the byte length of the first character of s (1 at the end).
func runeLen(s string) int {
	if _, n := utf8.DecodeRuneInString(s); n > 0 {
		return n
	}
	return 1
}

func (r *compiled) base(sub Subject) bool {
	if r.proto != 0 && r.proto != sub.Proto {
		return false
	}
	if len(r.ports) > 0 && !matchPort(r.ports, sub.Dst.Port()) {
		return false
	}
	if r.hasApp() && (sub.Proc == nil || !r.matchApp(sub.Proc)) {
		return false
	}
	return true
}

func (s *Set) result(r *compiled) Result {
	var res Result
	var fb []string
	if r == nil {
		res = Result{Action: s.def, Rule: "default", Profile: s.defProfile}
		fb = s.defFallback
	} else {
		res = Result{Action: r.action, Rule: r.name, RuleID: r.src.ID, Profile: r.profile}
		fb = r.fallback
	}
	if res.Action == Tunnel {
		if res.Profile == "" {
			res.Profile = s.Main
		}
		res.Fallback = s.resolveFallback(res.Profile, fb)
	} else {
		res.Profile = ""
	}
	return res
}

// resolveFallback maps "" to the main profile and drops empty, repeated
// and primary entries.
func (s *Set) resolveFallback(primary string, fb []string) []string {
	if len(fb) == 0 {
		return nil
	}
	out := make([]string, 0, len(fb))
	for _, id := range fb {
		if id == "" {
			id = s.Main
		}
		if id == "" || id == primary || slices.Contains(out, id) {
			continue
		}
		out = append(out, id)
	}
	return out
}

// route is what must agree for a packet-level decision: the action and,
// for Tunnel, the profile and its fallbacks.
type route struct {
	action   Action
	profile  string
	fallback string
}

func (s *Set) routeOf(r *compiled) route {
	res := s.result(r)
	return route{res.Action, res.Profile, strings.Join(res.Fallback, ",")}
}

// Profiles returns the IDs of the servers and groups that enabled rules
// and the default route can send traffic to (sorted, unique).
func (s *Set) Profiles() []string {
	seen := map[string]bool{}
	var out []string
	add := func(r *compiled) {
		res := s.result(r)
		if res.Action != Tunnel {
			return
		}
		// Fallback profiles run too: switching to them must be instant.
		for _, id := range append([]string{res.Profile}, res.Fallback...) {
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	for i := range s.rules {
		add(&s.rules[i])
	}
	add(nil)
	sort.Strings(out)
	return out
}

// firstMatch evaluates with a known domain ("" = domain rules don't match).
func (s *Set) firstMatch(sub Subject, domain string) *compiled {
	for i := range s.rules {
		r := &s.rules[i]
		if !r.base(sub) {
			continue
		}
		if r.hasDest() && !r.matchIP(sub.Dst.Addr()) && (domain == "" || !r.matchDomain(domain)) {
			continue
		}
		return r
	}
	return nil
}

// firstMatchAny is firstMatch for a site known by several names: a domain
// rule matches when any of them does.
func (s *Set) firstMatchAny(sub Subject, names []string) *compiled {
	for i := range s.rules {
		r := &s.rules[i]
		if !r.base(sub) {
			continue
		}
		if r.hasDest() && !r.matchIP(sub.Dst.Addr()) && !slices.ContainsFunc(names, r.matchDomain) {
			continue
		}
		return r
	}
	return nil
}

// EvaluateDomain decides with an exact domain (SNI, Host, or a single name).
func (s *Set) EvaluateDomain(sub Subject, domain string, src DomainSource) Result {
	domain = NormalizeDomain(domain)
	res := s.result(s.firstMatch(sub, domain))
	res.Domain, res.DomainSrc = domain, src
	return res
}

// EvaluateNoDomain decides as if no domain rule can match: the fallback
// when sniffing found no name and the DNS cache does not settle it.
func (s *Set) EvaluateNoDomain(sub Subject) Result {
	return s.result(s.firstMatch(sub, ""))
}

// Evaluate decides at packet level. dnsNames are the cache's names for the
// destination IP. The result is final when every name gives the same
// action, or when every possible outcome of the unknown domain gives the
// same action; otherwise NeedsDomain.
func (s *Set) Evaluate(sub Subject, dnsNames []string) Result {
	sites := make([][]string, len(dnsNames))
	for i := range dnsNames {
		sites[i] = dnsNames[i : i+1]
	}
	return s.EvaluateSites(sub, sites)
}

// EvaluateSites is Evaluate for cached names grouped by site: the names of
// one CNAME chain (the queried name and the CDN names it points to) are one
// site, which matches a domain rule when any of its names does. Only
// different sites on one address (CDN neighbours) can disagree.
func (s *Set) EvaluateSites(sub Subject, sites [][]string) Result {
	if len(sites) > 0 {
		var first Result
		var all []string
		agree := true
		for i, site := range sites {
			names := make([]string, 0, len(site))
			for _, n := range site {
				if n = NormalizeDomain(n); n != "" && !slices.Contains(names, n) {
					names = append(names, n)
				}
			}
			r := s.result(s.firstMatchAny(sub, names))
			if i == 0 {
				first = r
			} else if r.Action != first.Action || r.Profile != first.Profile || !slices.Equal(r.Fallback, first.Fallback) {
				agree = false
				break
			}
			for _, n := range names {
				if !slices.Contains(all, n) {
					all = append(all, n)
				}
			}
		}
		if agree {
			first.Domain, first.DomainSrc = strings.Join(all, ","), SrcDNS
			return first
		}
	}
	// Unknown domain: final when every outcome gives the same action.
	outcomes := s.unknownOutcomes(sub)
	terminal := outcomes[len(outcomes)-1]
	act := s.routeOf(terminal)
	for _, r := range outcomes {
		if s.routeOf(r) != act {
			return Result{NeedsDomain: true}
		}
	}
	return s.result(terminal)
}

// unknownOutcomes collects every rule that may decide the flow sub
// depending on which domain rules its unknown domain would match, in
// order. The last one ends the evaluation; nil there is the default
// route. Evaluate and MayTunnel share it.
func (s *Set) unknownOutcomes(sub Subject) []*compiled {
	var outcomes []*compiled
	for i := range s.rules {
		r := &s.rules[i]
		if !r.base(sub) {
			continue
		}
		if r.hasDest() && !r.matchIP(sub.Dst.Addr()) {
			if r.hasDom() {
				outcomes = append(outcomes, r) // depends on the name
			}
			continue
		}
		return append(outcomes, r)
	}
	return append(outcomes, nil)
}

// Store holds the active set; swaps are atomic and apply to new flows only.
type Store struct{ p atomic.Pointer[Set] }

func (st *Store) Load() *Set {
	if s := st.p.Load(); s != nil {
		return s
	}
	return &Set{}
}

func (st *Store) Swap(s *Set) { st.p.Store(s) }
