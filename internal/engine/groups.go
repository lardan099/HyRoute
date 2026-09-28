package engine

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/relay"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

// Server groups: a Tunnel decision's target, or one of its fallbacks, may
// be a group, which resolves to one of its members when a new flow is
// decided (Core.pick). Without a group in the chain the resolution is the
// v1.0.0 one, bit for bit. A group with no usable member is refused like
// a server that is down, never sent direct.

// pick moves a Tunnel decision to the first target of its chain (the
// target, then the fallbacks) that can carry the flow, resolving a group
// to its member and committing the group's choice (round robin, current
// member, trial). With nothing usable it stays on the primary target,
// which refuses the flow. It is the only resolver of "which server carries
// this new flow"; the pick is returned for Abandon.
func (c *Core) pick(res rules.Result, udp bool, h groups.Hint) (rules.Result, groups.Pick) {
	return c.resolve(res, udp, h, true)
}

// peek is pick without any state change: "would it move?".
func (c *Core) peek(res rules.Result, udp bool, h groups.Hint) rules.Result {
	r, _ := c.resolve(res, udp, h, false)
	return r
}

// hasGroup reports a group anywhere in a Tunnel result's chain.
func hasGroup(res rules.Result) bool {
	return groups.IsGroupID(res.Profile) || slices.ContainsFunc(res.Fallback, groups.IsGroupID)
}

// resolve works in two phases: it peeks every entry of the chain (the
// first healthy one wins, else the first degraded one), then commits a
// choice on that one entry only. So a degraded group earlier in the chain
// never moves its state when a later target gets the flow.
func (c *Core) resolve(res rules.Result, udp bool, h groups.Hint, commit bool) (rules.Result, groups.Pick) {
	if res.NeedsDomain || res.Action != rules.Tunnel {
		return res, groups.Pick{}
	}
	if !hasGroup(res) {
		// The v1.0.0 path: the first usable server, else the primary one
		// (refused).
		if len(res.Fallback) == 0 || c.usable(res.Profile, udp) {
			return res, groups.Pick{}
		}
		for _, id := range res.Fallback {
			if c.usable(id, udp) {
				res.Profile = id
				res.Rule += " (fallback)"
				res.Failover = true
				return res, groups.Pick{}
			}
		}
		return res, groups.Pick{}
	}
	chain := append([]string{res.Profile}, res.Fallback...)
	// A flow the IPv6 block refuses anyway must not move group state.
	if h.IP.Is6() && !h.IP.Is4In6() && c.Opt.BlockIPv6Tunnel {
		commit = false
	}
	skip := map[int]bool{} // entries whose commit found nothing usable any more
	for {
		idx, deg := -1, -1
		var pk, dpk groups.Pick
		for i, t := range chain {
			if skip[i] {
				continue
			}
			p, ok := c.target(t, udp, h, false)
			if !ok {
				continue
			}
			if p.Healthy {
				idx, pk = i, p
				break
			}
			if deg < 0 {
				deg, dpk = i, p
			}
		}
		if idx < 0 {
			idx, pk = deg, dpk
		}
		if idx < 0 {
			return res, groups.Pick{} // nothing usable: the primary target refuses
		}
		if !commit || !groups.IsGroupID(chain[idx]) {
			return with(res, pk, idx), pk
		}
		// Choose decides again under the runtime's lock: it may return
		// another member than the peek did (a concurrent flow took the
		// trial); that is still the right entry of the chain.
		if p, ok := c.target(chain[idx], udp, h, true); ok {
			return with(res, p, idx), p
		}
		skip[idx] = true
	}
}

// with puts the pick of chain entry idx into res.
func with(res rules.Result, p groups.Pick, idx int) rules.Result {
	res.Profile, res.Group = p.Member, p.Group
	res.Failover = p.Failover || idx > 0
	if idx > 0 {
		res.Rule += " (fallback)"
	}
	return res
}

// target decides one chain entry: a server is itself (usable or not), a
// group asks its runtime (Peek/PeekUDP, or Choose/ChooseUDP to commit).
func (c *Core) target(t string, udp bool, h groups.Hint, commit bool) (groups.Pick, bool) {
	if !groups.IsGroupID(t) {
		return groups.Pick{Member: t, Healthy: true}, c.usable(t, udp)
	}
	if c.Groups == nil {
		return groups.Pick{}, false
	}
	usable := func(id string) bool { return c.usable(id, udp) }
	switch {
	case !commit && udp:
		return c.Groups.PeekUDP(t, h, usable)
	case !commit:
		return c.Groups.Peek(t, h, usable)
	case udp:
		return c.Groups.ChooseUDP(t, h, usable)
	}
	return c.Groups.Choose(t, h, usable)
}

// hint is what a group needs to know about a new flow: the program, the
// destination and its site. decided is a name seen for this very flow
// (the sniffed SNI/Host), never a DNS cache name: those are all taken
// from the cache (groups.SiteOf), so QUIC and the sniffed TCP of one site
// key alike. The zero Hint without a group in the chain: the no-group path
// costs nothing.
func (c *Core) hint(res rules.Result, proc *procinfo.Info, decided string, dst netip.Addr) groups.Hint {
	if res.NeedsDomain || res.Action != rules.Tunnel || !hasGroup(res) {
		return groups.Hint{}
	}
	h := groups.Hint{IP: dst}
	if proc != nil {
		h.App = strings.ToLower(proc.Path)
		if h.App == "" {
			h.App = strings.ToLower(proc.Name)
		}
	}
	h.Site = groups.SiteOf(decided, c.DNS.Names(dst))
	return h
}

// abandon releases the trial a refused flow's pick holds.
func (c *Core) abandon(pk groups.Pick) {
	if c.Groups != nil && pk.Member != "" {
		c.Groups.Abandon(pk)
	}
}

var errGroupUnavailable = errors.New("no server of the group is available")

// groupMiss is the tunnel of a group with no usable member: it carries
// nothing, and a flow refused through it counts for the group.
type groupMiss struct {
	rt *groups.Runtime
	id string
}

func (g groupMiss) Available() bool    { return false }
func (g groupMiss) UDPAvailable() bool { return false }
func (g groupMiss) Dial(context.Context, socks5.Addr) (net.Conn, error) {
	return nil, errGroupUnavailable
}
func (g groupMiss) UDPAssociate(context.Context) (*socks5.UDPAssoc, error) {
	return nil, errGroupUnavailable
}
func (g groupMiss) NoteRejected()            { g.rt.NoteRejected(g.id) }
func (g groupMiss) NoteTraffic(int64, int64) {}

// GroupMiss is the relay's tunnel for a target that stayed a known group
// (no member usable), nil otherwise (an unknown group: nothing to count).
func (c *Core) GroupMiss(id string) relay.Tunnel {
	if c.Groups == nil || !c.Groups.IsGroup(id) {
		return nil
	}
	return groupMiss{rt: c.Groups, id: id}
}
