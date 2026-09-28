package stats

import (
	"strings"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/rules"
)

// Route is where a counted flow went.
type Route uint8

const (
	Tunnel Route = iota + 1
	Direct
	Block
)

// Flow is what the collector needs from one flow (see flowOf).
type Flow struct {
	App, AppName string // key (lower-case path | lower-case exe | "proxy:<id>" verbatim | ""), display name
	Domain       string // first name of the record or ""; the site key is derived from it (siteKey)
	Server       string // profile ID (tunnel only; "" = no server chosen)
	Group        string // group ID ("" none; tunnel only)
	Route        Route
	Failed       bool
	Failover     bool // tunnel only
	// ServerName, GroupName: the names stored with the rows (Collector.Names).
	ServerName, GroupName string
}

// proxyPrefix marks the records of local proxies (Path "proxy:<id>").
const proxyPrefix = "proxy:"

// flowOf converts a flow view. ok=false: never counted (service traffic:
// the engine's exclusions, DNS queries HyRoute intercepts). settled: see
// flows.View.Settled; an unknown route is never settled.
func flowOf(v flows.View) (f Flow, settled, ok bool) {
	if v.Excluded != "" || v.Stage == flows.StageDNS {
		return Flow{}, false, false
	}
	switch {
	case strings.HasPrefix(v.Path, proxyPrefix):
		f.App = v.Path // proxy IDs are case-sensitive
	case v.Path != "":
		f.App = strings.ToLower(v.Path) // Windows paths are not
	default:
		f.App = strings.ToLower(v.Process)
	}
	f.AppName = v.Process
	if i := strings.IndexByte(v.Domain, ','); i >= 0 {
		f.Domain = v.Domain[:i] // DNS names are joined with ","
	} else {
		f.Domain = v.Domain
	}
	switch v.Route {
	case "tunnel":
		f.Route = Tunnel
		f.Server, f.Group, f.Failover = v.Profile, v.Group, v.Failover
	case "direct":
		f.Route = Direct
	case "block":
		f.Route = Block
	default:
		return f, false, true
	}
	f.Failed = v.Failed()
	return f, v.Settled(), true
}

// siteKey is the site a domain counts under: the registrable domain of a
// valid host name (the grouping of rules' «Весь сайт» and of sticky
// groups), "" for no name, an IP literal or anything that is not a host
// name.
func siteKey(domain string) string {
	if n, ok := rules.HostName(strings.TrimSpace(domain)); ok {
		return rules.Site(n)
	}
	return ""
}
