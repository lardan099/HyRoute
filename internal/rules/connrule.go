package rules

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/lardan099/hyroute/internal/procinfo"
)

// Helpers for a rule made from an observed connection («Создать правило из
// соединения»): where it must go to take effect, what the engine decides
// now, and which rules around it share its connections.

// Flow is an observed connection a rule is made from.
type Flow struct {
	Proc  *procinfo.Info // nil = owner unknown; Parent chain as recorded
	Proto uint8          // 6 | 17; 0 = unknown (a DNS-query row: the connection is still to come)
	Dst   netip.AddrPort // invalid = unknown (DNS-query row): IP items never match, port unknown
	// Name is the exact name the engine decided by (SNI, Host, the outer
	// SNI it took for the site, a DNS query's name); "" = none. Normalized.
	Name string
	// Sites are the DNS cache names grouped by site, the head (queried
	// name) first — used by the engine only when Name == "". Normalized.
	Sites [][]string
	// SitesPartial: Sites were cut (more than the record keeps).
	SitesPartial bool
	// Nameless: the engine decides f without any name (UDP 443 under
	// NamelessUDP): Winner and Place ignore Name and Sites, which only say
	// what a rule made from f may name (Names, Matches).
	Nameless bool
	// Main is the main target ID, which Tunnel rules without a server use
	// ("" = none): routes compare as the engine compares them.
	Main string
}

// Names are the names the engine may decide f by: Name alone when set
// (the engine then ignores the DNS cache), else every name of every site.
func (f Flow) Names() []string {
	if f.Name != "" {
		return []string{NormalizeDomain(f.Name)}
	}
	var out []string
	for _, site := range f.Sites {
		for _, n := range siteNames(site) {
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

func (f Flow) subject() Subject { return Subject{Proc: f.Proc, Proto: f.Proto, Dst: f.Dst} }

// decisionNames are the names the engine decides f by: Names, none when
// f.Nameless.
func (f Flow) decisionNames() []string {
	if f.Nameless {
		return nil
	}
	return f.Names()
}

// indexed is a config compiled rule by rule, so that indexes map to
// c.Rules (disabled rules and rules that fail to compile included): set
// holds the enabled ones in order, set.rules[k] is c.Rules[idx[k]].
type indexed struct {
	set *Set
	idx []int
	all []*compiled // by index in c.Rules; nil = does not compile
}

func compileIndexed(c Config, main string) indexed {
	g := currentGeo()
	ix := indexed{set: &Set{def: c.DefaultAction, defProfile: c.DefaultProfile, defFallback: c.DefaultFallback, Main: main},
		all: make([]*compiled, len(c.Rules))}
	for i, r := range c.Rules {
		cr, err := compileRule(i, r, g)
		if err != nil {
			continue // a saved config cannot contain one
		}
		ix.all[i] = &cr
		if enabled(r) {
			ix.set.rules = append(ix.set.rules, cr)
			ix.idx = append(ix.idx, i)
		}
	}
	return ix
}

func (ix indexed) index(k int) int {
	if k < 0 {
		return -1
	}
	return ix.idx[k]
}

// mayBase is base for a flow whose protocol or port may be unknown (a
// DNS-query row): an unknown one satisfies any condition on it.
func (r *compiled) mayBase(sub Subject) bool {
	if r.proto != 0 && sub.Proto != 0 && r.proto != sub.Proto {
		return false
	}
	if len(r.ports) > 0 && sub.Dst.IsValid() && sub.Dst.Port() != 0 && !matchPort(r.ports, sub.Dst.Port()) {
		return false
	}
	if r.hasApp() && (sub.Proc == nil || !r.matchApp(sub.Proc)) {
		return false
	}
	return true
}

// mayMatchIP is matchIP where a geoip: category still downloading counts.
func (r *compiled) mayMatchIP(ip netip.Addr) bool {
	for i := range r.ips {
		if r.ips[i].pending || r.ips[i].match(ip) {
			return true
		}
	}
	return false
}

// mayMatchDomain is matchDomain where a geosite: category still
// downloading counts.
func (r *compiled) mayMatchDomain(name string) bool {
	for i := range r.doms {
		if r.doms[i].pending || r.doms[i].match(name) {
			return true
		}
	}
	return false
}

// Place is the index in c.Rules above which a rule made from f must be
// inserted so that it decides f: the first enabled rule that can match f
// with any of f.Names() or with none. len(c.Rules) when only the default
// route can. Deliberately more conservative than the engine: every name of
// every site counts on its own (a rule matching only a CDN neighbour's or
// a CNAME target's name still counts), and a geosite:/geoip: item whose
// database is not downloaded yet (pending) counts as matching, so the rule
// does not end up below it once the database loads. An unknown protocol,
// port or address (Proto 0, invalid Dst: a DNS-query row, whose connection
// is still to come) satisfies any condition on it, so an IP rule counts.
// A Nameless flow counts its names too: the engine decides it without
// them, but a site rule made from it is for the same site over TCP (the
// browser's fallback), where a rule above catching those names would win.
func Place(c Config, f Flow) int {
	ix := compileIndexed(c, f.Main)
	sub, names := f.subject(), f.Names()
	for k := range ix.set.rules {
		r := &ix.set.rules[k]
		if !r.mayBase(sub) {
			continue
		}
		ip := len(r.ips) > 0
		if f.Dst.IsValid() {
			ip = r.mayMatchIP(f.Dst.Addr())
		}
		if !r.hasDest() || ip || slices.ContainsFunc(names, r.mayMatchDomain) {
			return ix.idx[k]
		}
	}
	return len(c.Rules)
}

// PlaceRule is the index of the first enabled rule that may catch some
// connection r catches (Intersects), len(c.Rules) when none: where a rule
// that does not fit the flow it was made from goes, so that nothing above
// it takes its traffic.
func PlaceRule(c Config, r Rule) int {
	x, err := compileRule(0, r, currentGeo())
	if err != nil {
		return len(c.Rules)
	}
	ix := compileIndexed(c, "")
	for i, y := range ix.all {
		if y != nil && enabled(c.Rules[i]) && intersects(y, &x) {
			return i
		}
	}
	return len(c.Rules)
}

// Winner is the rule that decides f now (-1 = default), exactly as the
// engine does (EvaluateDomain / EvaluateSites / EvaluateNoDomain): with
// f.Name, the first match by that name; else with f.Sites, each site's
// first match (a site matches a domain rule when any of its names does);
// when every site gives the same route (action, profile, fallback — the
// engine's agreement test, not the rule index) the first site's rule wins;
// when they disagree, ambiguous = true and the winner is the rule that
// matches without a domain (what UDP always gets then, and TCP unless the
// relay reads SNI/Host). No name and no sites: the no-domain winner.
// SitesPartial with agreeing sites also reports ambiguous (a cut-off site
// might disagree); the index is then the first site's winner. A protocol
// or port condition never decides a flow whose protocol or port is
// unknown. A Nameless flow: the no-domain winner, never ambiguous.
func Winner(c Config, f Flow) (index int, ambiguous bool) {
	ix := compileIndexed(c, f.Main)
	s, sub := ix.set, f.subject()
	if f.Nameless {
		return ix.index(siteWinner(s.rules, sub, nil)), false
	}
	if f.Name != "" {
		return ix.index(siteWinner(s.rules, sub, []string{NormalizeDomain(f.Name)})), false
	}
	if len(f.Sites) > 0 {
		first := -1
		var firstRes Result
		agree := true
		for i, site := range f.Sites {
			k := siteWinner(s.rules, sub, siteNames(site))
			res := s.result(ix.rule(k))
			if i == 0 {
				first, firstRes = k, res
			} else if !sameRoute(res, firstRes) {
				agree = false
				break
			}
		}
		if agree {
			return ix.index(first), f.SitesPartial
		}
	}
	return ix.index(siteWinner(s.rules, sub, nil)), len(f.Sites) > 0
}

func (ix indexed) rule(k int) *compiled {
	if k < 0 {
		return nil
	}
	return &ix.set.rules[k]
}

// Matches reports whether r catches f with some name of f.Names() or with
// no name (an unknown protocol or port satisfies r's condition on it). It
// decides where a rule goes (above Place, or PlaceRule for an editor rule
// that does not fit); whether it then really decides f is Winner on the
// new config. The error is r's compile error.
func Matches(r Rule, f Flow) (bool, error) {
	cr, err := compileRule(0, r, currentGeo())
	if err != nil {
		return false, err
	}
	if !cr.mayBase(f.subject()) {
		return false, nil
	}
	return !cr.hasDest() || f.Dst.IsValid() && cr.matchIP(f.Dst.Addr()) || slices.ContainsFunc(f.Names(), cr.matchDomain), nil
}

// CatchesName reports whether a domain item of r matches name (IP, app,
// protocol and port conditions ignored; a geosite: list still downloading
// counts): a quick rule that would catch an ECH public name is refused.
func CatchesName(r Rule, name string) (bool, error) {
	cr, err := compileRule(0, r, currentGeo())
	if err != nil {
		return false, err
	}
	return cr.mayMatchDomain(NormalizeDomain(name)), nil
}

// routeKey is what a rule changes for its connections (Narrowed); an
// empty Tunnel profile is the main target.
func (r *compiled) routeKey(main string) string {
	if r.action != Tunnel {
		return r.action.String()
	}
	if r.profile == "" {
		return "tunnel|" + main
	}
	return "tunnel|" + r.profile
}

// Narrowed lists the enabled rules at indexes [from, to) of c (c already
// contains the new rule at at < from) that Intersect c.Rules[at], are not
// covered by it (not Shadowed) and route differently (action, profile):
// rules whose connections the new rule now partly takes although it was
// put above them only because they might catch the flow. Block rules
// first, then tunnel, then direct, each by index. main is the main target
// an empty Tunnel profile resolves to (Flow.Main).
func Narrowed(c Config, main string, at, from, to int) []int {
	ix := compileIndexed(c, "")
	if at < 0 || at >= len(ix.all) || ix.all[at] == nil {
		return nil
	}
	n := ix.all[at]
	var out []int
	for j := max(from, 0); j < to && j < len(ix.all); j++ {
		y := ix.all[j]
		if y == nil || !enabled(c.Rules[j]) || !intersects(n, y) || n.covers(y) || y.routeKey(main) == n.routeKey(main) {
			continue
		}
		out = append(out, j)
	}
	order := map[Action]int{Block: 0, Tunnel: 1, Direct: 2}
	sort.SliceStable(out, func(a, b int) bool { return order[ix.all[out[a]].action] < order[ix.all[out[b]].action] })
	return out
}

// OverriddenBy lists the enabled rules above i that may take some
// connection c.Rules[i] catches (Intersects), as indexes, nearest first.
func OverriddenBy(c Config, i int) []int {
	ix := compileIndexed(c, "")
	if i < 0 || i >= len(ix.all) || ix.all[i] == nil {
		return nil
	}
	var out []int
	for j := i - 1; j >= 0; j-- {
		if y := ix.all[j]; y != nil && enabled(c.Rules[j]) && intersects(y, ix.all[i]) {
			out = append(out, j)
		}
	}
	return out
}

// Shadowed lists the enabled rules below i that c.Rules[i] covers
// entirely (they can never match again), as indexes.
func Shadowed(c Config, i int) []int {
	ix := compileIndexed(c, "")
	if i < 0 || i >= len(ix.all) || ix.all[i] == nil {
		return nil
	}
	var out []int
	for j := i + 1; j < len(ix.all); j++ {
		if y := ix.all[j]; y != nil && enabled(c.Rules[j]) && ix.all[i].covers(y) {
			out = append(out, j)
		}
	}
	return out
}

// SameMatch reports whether a and b catch exactly the same connections by
// their conditions: the same set of applications (kind resolved, path
// normalized, inheritChildren), the same set of destination items
// (normalized), the same protocol ("" == "any") and the same ports. Order
// and duplicates do not matter; old single app/domain fields count.
func SameMatch(a, b Rule) bool {
	x, err1 := compileRule(0, a, nil)
	y, err2 := compileRule(0, b, nil)
	if err1 != nil || err2 != nil {
		return false
	}
	return x.sameMatch(&y)
}

// Duplicate is the index of the first rule in c.Rules other than skip that
// repeats r: the same conditions (SameMatch) and the same route (action,
// and server for Tunnel). Name, fallbacks and on/off do not count. -1 when
// none.
func Duplicate(c Config, r Rule, skip int) int {
	x, err := compileRule(0, r, nil)
	if err != nil {
		return -1
	}
	for i, o := range c.Rules {
		if i == skip || o.Action != r.Action || r.Action == Tunnel && o.Profile != r.Profile {
			continue
		}
		y, err := compileRule(i, o, nil)
		if err == nil && x.sameMatch(&y) {
			return i
		}
	}
	return -1
}

func (r *compiled) sameMatch(y *compiled) bool {
	return r.proto == y.proto && slices.Equal(r.ports, y.ports) &&
		slices.Equal(r.appKeys(), y.appKeys()) && slices.Equal(r.destKeys(), y.destKeys())
}

func (r *compiled) appKeys() []string {
	out := make([]string, 0, len(r.apps))
	for _, a := range r.apps {
		out = append(out, fmt.Sprintf("%s|%s|%v", a.kind, a.app, a.inherit))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (r *compiled) destKeys() []string {
	out := make([]string, 0, len(r.doms)+len(r.ips))
	for _, d := range r.doms {
		out = append(out, fmt.Sprintf("d%d|%s", d.kind, d.dom))
	}
	for _, p := range r.ips {
		if p.pfx.IsValid() {
			out = append(out, "i|"+p.pfx.String())
		} else {
			out = append(out, "g|"+strings.ToLower(p.src))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Intersects reports whether some connection may match both a and b. It
// is conservative where it cannot know (geo data still downloading,
// keyword and regexp items against whole domains) and ignores
// parent/child relations between different programs.
func Intersects(a, b Rule) bool {
	g := currentGeo()
	x, err1 := compileRule(0, a, g)
	y, err2 := compileRule(0, b, g)
	return err1 == nil && err2 == nil && intersects(&x, &y)
}

// intersects is Intersects on compiled rules (next to covers).
func intersects(x, y *compiled) bool {
	if x.proto != 0 && y.proto != 0 && x.proto != y.proto {
		return false
	}
	if len(x.ports) > 0 && len(y.ports) > 0 && !portsOverlap(x.ports, y.ports) {
		return false
	}
	if x.hasApp() && y.hasApp() && !anyPair(x.apps, y.apps, appsOverlap) {
		return false
	}
	if !x.hasDest() || !y.hasDest() {
		return true
	}
	return anyPair(x.doms, y.doms, domsOverlap) || anyPair(x.ips, y.ips, ipsOverlap)
}

func anyPair[T any](a, b []T, f func(p, q *T) bool) bool {
	for i := range a {
		for j := range b {
			if f(&a[i], &b[j]) {
				return true
			}
		}
	}
	return false
}

// appsOverlap: whether one program may match both patterns.
func appsOverlap(p, q *appPat) bool {
	if p.kind > q.kind { // order: glob < name < path
		p, q = q, p
	}
	switch {
	case p.kind == q.kind && p.app == q.app:
		return true
	case p.kind == "glob" && q.kind == "path":
		return globMatch(p.app, q.app)
	case p.kind == "glob":
		return true // against a name or another glob: some path may match both
	case p.kind == "name" && q.kind == "path":
		return strings.HasSuffix(q.app, `\`+p.app)
	}
	return false
}

// plain: an exact, subdomain or suffix pattern.
func (d *domPat) plain() bool { return d.kind <= domSuffix }

// usable: a geosite: category that matches something now or may once its
// database is downloaded (an unknown category never does).
func (d *domPat) usable() bool { return d.kind != domGeo || d.geo != nil || d.pending }

// domsOverlap: whether some name may match both items.
func domsOverlap(a, b *domPat) bool {
	if !a.plain() && b.plain() {
		a, b = b, a
	}
	switch {
	case a.plain() && b.plain():
		return a.covers(b) || b.covers(a)
	case a.plain():
		switch b.kind {
		case domGeo:
			if b.pending {
				return true
			}
			if b.geo == nil {
				return false
			}
			if a.kind == domExact {
				return b.geo.Match(a.dom)
			}
			if u, ok := b.geo.(underMatcher); ok {
				return u.MatchUnder(a.dom, a.kind == domSuffix)
			}
			return true // some subdomain may be in it
		case domKeyword, domRegex:
			if a.kind != domExact {
				return true // some subdomain may match
			}
			return b.match(a.dom)
		}
		return true
	}
	// Both geosite, keyword or regexp.
	if !a.usable() || !b.usable() {
		return false
	}
	// Two different categories may share names (geosite:google holds
	// youtube's): taken to overlap.
	return true
}

// underMatcher is a geosite category that can tell whether it holds a name
// under a domain (geodata.DomainSet).
type underMatcher interface {
	MatchUnder(dom string, self bool) bool
}

// Geoip categories that can compare ranges (geodata.IPSet).
type (
	prefixOverlapper interface {
		OverlapsPrefix(p netip.Prefix) bool
	}
	setOverlapper interface {
		OverlapsSet(o any) (overlap, known bool)
	}
)

// ipsOverlap: whether some address may match both items.
func ipsOverlap(p, q *ipPat) bool {
	if !p.pfx.IsValid() && q.pfx.IsValid() {
		p, q = q, p
	}
	switch {
	case p.pfx.IsValid() && q.pfx.IsValid():
		return p.pfx.Overlaps(q.pfx)
	case p.pfx.IsValid(): // q is geoip
		if q.pending {
			return true
		}
		if q.geo == nil {
			return false
		}
		if o, ok := q.geo.(prefixOverlapper); ok {
			return o.OverlapsPrefix(p.pfx)
		}
		return !p.pfx.IsSingleIP() || q.geo.Contains(p.pfx.Addr())
	}
	if !p.pending && p.geo == nil || !q.pending && q.geo == nil {
		return false
	}
	if p.pending || q.pending || strings.EqualFold(p.src, q.src) {
		return true
	}
	if o, ok := p.geo.(setOverlapper); ok {
		if v, known := o.OverlapsSet(q.geo); known {
			return v
		}
	}
	return true // two different categories may share addresses
}
