package tunnels

import (
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
)

type chainUpstream struct {
	*Endpoint
	manager *Manager
	rt      *groups.Runtime
	group   string
	test    bool
}

func (u chainUpstream) Available() bool {
	return u.rt.HasMember(u.group, u.ID) && u.manager.directUpstream(u.ID, u.test) == u.Endpoint && u.Endpoint.Available()
}

func (m *Manager) directUpstream(id string, test bool) *Endpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	up := m.eps[id]
	if up == nil && test {
		up = m.eps["test:"+id]
	}
	if up == nil || up.Profile.Via != "" {
		return nil
	}
	return up
}

func (m *Manager) upstream(p hysteria.Profile, test bool, tried map[string]bool) hysteria.Upstream {
	if p.Via == "" || p.Via == p.ID {
		return nil
	}
	if !groups.IsGroupID(p.Via) {
		if up := m.directUpstream(p.Via, test); up != nil {
			return up
		}
		return nil
	}
	rt := m.Groups
	if rt == nil {
		return nil
	}
	udp := !p.IsVLESS()
	usable := func(id string) bool {
		up := m.directUpstream(id, test)
		return up != nil && up.Available() && (!udp || up.UDPAvailable())
	}
	hint := groups.Hint{App: "hyroute:chain", Site: p.Host}
	pick := rt.Choose
	switch {
	case test && udp:
		pick = rt.PeekUDP
	case test:
		pick = rt.Peek
	case udp:
		pick = rt.ChooseUDP
	}
	selected, ok := pick(p.Via, hint, func(id string) bool { return !tried[id] && usable(id) })
	if !ok && len(tried) > 0 {
		// The current egress has tried every available first VPN.
		clear(tried)
		selected, ok = pick(p.Via, hint, usable)
	}
	if ok {
		// The egress core dials the SOCKS endpoint itself and cannot report a trial result.
		rt.Abandon(selected)
		if up := m.directUpstream(selected.Member, test); up != nil {
			tried[up.ID] = true
			return chainUpstream{Endpoint: up, manager: m, rt: rt, group: p.Via, test: test}
		}
	}
	return nil
}
