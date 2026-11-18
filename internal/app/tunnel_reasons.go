package app

import (
	"slices"
	"sort"
	"strings"

	"github.com/lardan099/hyroute/internal/groups"
)

// TunnelReasons lists the assignments keeping a server in the routing session.
// A direct proxy target stays awake through its idle window.
func (c *Controller) TunnelReasons(id string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess == nil || id == "" {
		return nil
	}
	out := c.ruleUsesLocked(id)
	var listeners []string
	hasAwakeProxy := false
	groupProxies := map[string][]string{}
	for _, p := range c.proxies {
		if !p.Enabled {
			continue
		}
		target := c.proxyProfileLocked(p)
		if groups.IsGroupID(target) {
			groupProxies[target] = append(groupProxies[target], proxyLabel(p))
		} else if u := c.proxyAwake[id]; target == id && u != nil {
			hasAwakeProxy = true
			if u.listeners[p.ID] > 0 || u.open == 0 && u.lastListener == p.ID {
				listeners = append(listeners, proxyLabel(p))
			}
		}
	}
	if len(listeners) > 0 {
		source := "Локальный прокси · "
		if len(listeners) > 1 {
			source = "Локальные прокси · "
		}
		text := source + strings.Join(listeners, ", ")
		if c.proxyAwake[id].open == 0 {
			text += " (ожидание простоя)"
		}
		out = append(out, text)
	} else if hasAwakeProxy {
		// A previously routed target may already be in its idle window
		// before any listener uses it, or after its last listener is gone.
		out = append(out, "Ожидание простоя локального прокси")
	}
	// Use only groups the session starts, including their selected subset
	// for large subscriptions. Reading this view must never wake a proxy.
	set := *c.set
	set.Main = c.mainTargetLocked()
	targets := set.Profiles()
	for gid := range groupProxies {
		targets = append(targets, gid)
	}
	sort.Strings(targets)
	for _, gid := range slices.Compact(targets) {
		if !groups.IsGroupID(gid) {
			continue
		}
		g := c.groupLocked(gid)
		if g == nil || !slices.Contains(c.runMembersLocked(g), id) {
			continue
		}
		uses := c.ruleUsesLocked(gid)
		for _, name := range groupProxies[gid] {
			uses = append(uses, "локальный прокси «"+name+"»")
		}
		for _, use := range uses {
			out = append(out, "Группа «"+g.Name+"» · "+use)
		}
	}
	return out
}
