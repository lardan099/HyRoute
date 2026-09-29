package dnspolicy

import (
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
)

// Names are the permanent host names the policy passes as before (step 1
// of the classification): the controller builds them and they are never
// logged. HyRoute's transient own names live in the engine (Env.Transient).
type Names struct {
	Servers []string // Hysteria server hosts (IP literals are skipped)
	Service []string // the custom direct upstream's host (the fixed probe names are added by Compile)
}

// Policy is a compiled Config: immutable, swapped atomically in the
// engine. A nil *Policy is "off".
type Policy struct {
	Cfg        Config
	TunnelSpec Spec  // valid when Cfg.ByRules
	DirectSpec *Spec // nil = no direct upstream
	servers    map[string]bool
	service    map[string]bool
}

// Compile builds the policy; nil, nil when no option is on.
func Compile(cfg Config, n Names) (*Policy, error) {
	if !cfg.Active() {
		return nil, nil
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	p := &Policy{Cfg: cfg, servers: map[string]bool{}, service: map[string]bool{}}
	if cfg.ByRules {
		s, err := cfg.Tunnel.Spec(true)
		if err != nil {
			return nil, err
		}
		p.TunnelSpec = s
	}
	if cfg.Direct.Preset != "" {
		s, err := cfg.Direct.Spec(false)
		if err != nil {
			return nil, err
		}
		p.DirectSpec = &s
	}
	for _, h := range n.Servers {
		if name := hostName(h); name != "" {
			p.servers[name] = true
		}
	}
	for _, h := range append(n.Service, serviceNames...) {
		if name := hostName(h); name != "" {
			p.service[name] = true
		}
	}
	return p, nil
}

// hostName normalizes a host; "" for an IP literal or nothing.
func hostName(h string) string {
	if _, err := netip.ParseAddr(h); err == nil {
		return ""
	}
	return rules.NormalizeDomain(h)
}

// Intercept reports that the engine must capture DNS: every option needs
// the queries (browser DoH blocking answers the canary).
func (p *Policy) Intercept() bool { return p != nil }

// Requester is who sent a query.
type Requester struct {
	Proc   *procinfo.Info // nil: unknown owner (after waiting), or the Windows DNS client
	System bool           // the Windows DNS client (Dnscache): it asks for every program
}

// Kind is what happens to a query.
type Kind uint8

const (
	Pass    Kind = iota // continue as without the feature
	Resolve             // resolve upstream (Via says where)
	Answer              // answer at once with Rcode (NXDOMAIN, NODATA = RCodeSuccess, SERVFAIL)
)

// Via is where a query is resolved.
type Via uint8

const (
	ViaDirect Via = iota
	ViaTunnel
)

func (v Via) String() string {
	if v == ViaTunnel {
		return "tunnel"
	}
	return "direct"
}

// Rule texts of the special answers ("Connections" shows them translated).
const (
	RuleCanary     = "dns: DoH canary"
	RuleECH        = "dns: ECH off"
	RuleNoIPv6     = "dns: IPv6 not through tunnel"
	RuleBrowserDoH = "dns: browser DoH"
)

// Outcomes of the answers HyRoute gives ("Connections", English like the
// other outcomes).
const (
	OutTunnel       = "dns: resolved via tunnel"
	OutDirect       = "dns: resolved direct"
	OutBlocked      = "dns: NXDOMAIN (blocked)"
	OutCanary       = "dns: NXDOMAIN (DoH canary)"
	OutECH          = "dns: NODATA (ECH off)"
	OutNoIPv6       = "dns: NODATA (IPv6 not through tunnel)"
	OutTunnelDown   = "dns: SERVFAIL (tunnel unavailable)"
	OutFailed       = "dns: SERVFAIL (upstream failed)"
	OutUpstreamDown = "dns: SERVFAIL (upstream down)"
	OutPortal       = "dns: passed (portal pause)"
	OutTruncated    = ", truncated"
)

// Decision is Classify's answer.
type Decision struct {
	Kind  Kind
	Via   Via
	Rcode dnsmessage.RCode
	// Route is the deciding rule's result (Tunnel: before the engine's
	// pick); zero for special cases.
	Route rules.Result
	// Pos is the deciding rule's index in the compiled set (-1: none).
	Pos int
	// Rule is the Connections rule text: the rule name, "default", or a
	// "dns: …" special.
	Rule    string
	Outcome string // for Answer
	// Local is the Pass reason for Explain: "server" | "service" | "local"
	// | "addr" | "" (not special).
	Local string
	// Cond: Route came from a conditional rule (CondApp/CondProto bits).
	Cond rules.NameCond
	// PassNegative: an upstream answer that says the name or type does not
	// exist is not given; the query is passed on to the server it was sent
	// to instead. NegativeAny selects the wider test (NODATA for any type,
	// not only A).
	PassNegative bool
	NegativeAny  bool
}

// ForSecondary adapts a decision for a query to another adapter's DNS
// server: Resolve ViaDirect → Pass (such a server may know internal names,
// the direct upstream is not used for it); Resolve ViaTunnel → negatives
// are passed on to that server; Pass and Answer unchanged.
func ForSecondary(d Decision) Decision {
	if d.Kind != Resolve {
		return d
	}
	if d.Via == ViaDirect {
		d.Kind, d.PassNegative, d.NegativeAny = Pass, false, false
		return d
	}
	d.PassNegative, d.NegativeAny = true, true
	return d
}

// Question is what Classify needs from a query.
type Question struct {
	Name string // rules.NormalizeDomain'd
	Type dnsmessage.Type
}

// Env is what Classify needs from the engine; every field may be nil.
type Env struct {
	Rules       *rules.Set
	Local       func(name string) bool // adapter DNS suffixes and NRPT namespaces
	Transient   func(name string) bool // HyRoute's transient own names
	IPv6Blocked bool                   // engine.Options.BlockIPv6Tunnel
}

// Classify decides a standard recursive query (the engine has already
// passed everything else and HyRoute's own queries).
func (p *Policy) Classify(q Question, req Requester, env Env) Decision {
	name := rules.NormalizeDomain(q.Name)
	pass := Decision{Kind: Pass, Pos: -1}
	// HyRoute's and Windows' own names: before anything else, so no option
	// and no rule can change them.
	if p.servers[name] {
		pass.Local = "server"
		return pass
	}
	if p.service[name] || env.Transient != nil && env.Transient(name) {
		pass.Local = "service"
		return pass
	}
	if IsLocalName(name) || env.Local != nil && env.Local(name) {
		pass.Local = "local"
		return pass
	}
	block := rules.Result{Action: rules.Block}
	if p.Cfg.BlockBrowserDoH {
		if IsCanary(name) {
			block.Rule = RuleCanary
			return Decision{Kind: Answer, Rcode: dnsmessage.RCodeNameError, Route: block, Pos: -1, Rule: RuleCanary, Outcome: OutCanary}
		}
		if p.Cfg.StripECH && (q.Type == dnsmessage.TypeHTTPS || q.Type == dnsmessage.TypeSVCB) {
			block.Rule = RuleECH
			return Decision{Kind: Answer, Rcode: dnsmessage.RCodeSuccess, Route: block, Pos: -1, Rule: RuleECH, Outcome: OutECH}
		}
	}
	route := rules.Result{Action: rules.Direct, Rule: "default"}
	pos, cond := -1, rules.NameCond(0)
	if p.Cfg.ByRules {
		set := env.Rules
		if set == nil {
			set = &rules.Set{}
		}
		nr := set.EvaluateName(rules.Subject{Proc: procFor(req)}, name, rules.SrcQuery)
		route, pos, cond = byRules(nr)
		if route.Action != rules.Direct && !p.Cfg.IgnoreAddrRules {
			for _, a := range nr.Alt {
				if a.Cond&rules.CondAddr != 0 && !a.AddrLocal && a.Action == rules.Direct && a.Pos < pos {
					pass.Local, pass.Rule, pass.Route, pass.Pos = "addr", a.Rule, a.Result, a.Pos
					return pass
				}
			}
		}
		switch route.Action {
		case rules.Block:
			return Decision{Kind: Answer, Rcode: dnsmessage.RCodeNameError, Route: route, Pos: pos, Rule: route.Rule, Outcome: OutBlocked, Cond: cond}
		case rules.Tunnel:
			if q.Type == dnsmessage.TypeAAAA && env.IPv6Blocked {
				return Decision{Kind: Answer, Rcode: dnsmessage.RCodeSuccess, Route: route, Pos: pos, Rule: RuleNoIPv6, Outcome: OutNoIPv6, Cond: cond}
			}
			return Decision{Kind: Resolve, Via: ViaTunnel, Route: route, Pos: pos, Rule: route.Rule, Cond: cond}
		}
	}
	// Direct: through the own upstream when there is one.
	if p.DirectSpec != nil {
		return Decision{Kind: Resolve, Via: ViaDirect, Route: route, Pos: pos, Rule: route.Rule, PassNegative: true}
	}
	pass.Route, pass.Pos, pass.Rule = route, pos, route.Rule
	return pass
}

// procFor is the program a query is judged with: none for the Windows DNS
// client, which asks for every program.
func procFor(req Requester) *procinfo.Info {
	if req.System {
		return nil
	}
	return req.Proc
}

// byRules is the route of a name by the rules: the winner of
// EvaluateName, unless a conditional rule above it with a matching site
// says otherwise (a candidate): the name goes through VPN when the winner
// or any candidate says so (the first such rule), and is blocked only
// when all of them say block.
func byRules(nr rules.NameResult) (rules.Result, int, rules.NameCond) {
	type cand struct {
		res  rules.Result
		pos  int
		cond rules.NameCond
	}
	var cands []cand
	for _, a := range nr.Alt {
		if a.Cond&rules.CondAddr == 0 {
			cands = append(cands, cand{a.Result, a.Pos, a.Cond})
		}
	}
	cands = append(cands, cand{nr.Result, nr.Pos, 0})
	for _, c := range cands {
		if c.res.Action == rules.Tunnel {
			return c.res, c.pos, c.cond
		}
	}
	if nr.Action == rules.Direct {
		return nr.Result, nr.Pos, 0
	}
	for _, c := range cands {
		if c.res.Action != rules.Block {
			return c.res, c.pos, c.cond
		}
	}
	c := cands[0]
	return c.res, c.pos, c.cond
}
