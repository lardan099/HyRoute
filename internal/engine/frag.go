package engine

import (
	"net/netip"
	"time"

	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/rules"
)

// IP fragments. Only the first fragment of a datagram has the transport
// header (ports), so the route is decided on it and the other fragments
// follow by (addresses, protocol, IP ID). A fragmented datagram can only
// go direct: the tunnel (SOCKS5 UDP) carries whole datagrams and a
// fragment of a Block or Tunnel datagram must not leave directly, so those
// are dropped. A fragment with no decided first fragment is dropped too.
// Fragments of other protocols (a large ping, IPsec ESP, GRE) are not
// routed and pass unchanged.

const (
	fragTTL = 30 * time.Second
	fragMax = 4096
)

type fragEntry struct {
	pass bool
	exp  time.Time
}

// fragOut handles an outbound fragment.
func (c *Core) fragOut(raw []byte, addr *divert.Address) {
	f, err := packet.ParseFragment(raw)
	if err != nil {
		c.Malformed.Add(1)
		return
	}
	if !f.Routable() || c.excluded(f.Dst) {
		// Protocols the engine does not route (ICMP, ESP, GRE...: their
		// whole packets are not captured either) go on unchanged.
		c.Inject(raw, addr)
		return
	}
	now := time.Now()
	fk := f.Key()
	if !f.HasPorts {
		c.mu.Lock()
		e, ok := c.frags[fk]
		c.mu.Unlock()
		switch {
		case ok && e.pass:
			c.Inject(raw, addr)
		case ok:
			c.FragDropped.Add(1)
		default:
			c.FragOrphan.Add(1) // first fragment not seen (or expired)
		}
		return
	}
	key := nat.FlowKey{Src: netip.AddrPortFrom(f.Src, f.SrcPort), Dst: netip.AddrPortFrom(f.Dst, f.DstPort)}
	route := c.fragRoute(f.Proto, key)
	pass := route == rules.Direct
	c.mu.Lock()
	if len(c.frags) >= fragMax {
		for k, e := range c.frags {
			if now.After(e.exp) {
				delete(c.frags, k)
			}
		}
		if len(c.frags) >= fragMax {
			clear(c.frags)
		}
	}
	c.frags[fk] = fragEntry{pass: pass, exp: now.Add(fragTTL)}
	c.mu.Unlock()
	if pass {
		c.Inject(raw, addr)
		return
	}
	c.FragDropped.Add(1)
	if n := c.FragDatagrams.Add(1); n <= 5 || n%100 == 0 {
		c.Log.Warn("fragmented datagram dropped: its route is not direct (the tunnel carries whole datagrams only)",
			"dst", key.Dst, "route", route.String(), "count", n)
	}
}

// fragRoute is the route of the flow a first fragment belongs to: an
// existing flow's route, or the rules. The owner is not waited for, but
// when no SOCKET event has named it yet the OS tables are asked at once,
// as the pending queue would: a program's rule must not miss the first
// datagram of its flow and let it go direct.
func (c *Core) fragRoute(proto uint8, key nat.FlowKey) rules.Action {
	c.mu.Lock()
	if proto == packet.ProtoUDP {
		if uf := c.udp[key]; uf != nil {
			c.mu.Unlock()
			return uf.route
		}
	} else if tf := c.tcp[key]; tf != nil {
		c.mu.Unlock()
		return rules.Direct
	}
	c.mu.Unlock()
	if proto == packet.ProtoTCP && c.NAT.LookupFlow(key) != nil {
		return rules.Tunnel // reflected flow
	}
	pid, known := c.Conns.Lookup(attrib.Key5{Proto: proto, Local: key.Src, Remote: key.Dst})
	if !known && c.OwnerFallback != nil {
		pid, known = c.OwnerFallback(proto, key.Src, key.Dst)
	}
	sub := rules.Subject{Proto: proto, Dst: key.Dst}
	if known {
		sub.Proc = c.Procs.Get(pid)
	}
	if res, ok := c.exclusion(pid, known, sub.Proc, proto, key.Dst); ok {
		return res.Action
	}
	set := c.Rules.Load()
	res := set.Evaluate(sub, c.packetNames(set, proto, key.Dst))
	if res.NeedsDomain {
		// Same as a whole UDP datagram with an unknown name (applyUDP).
		if c.Opt.BlockQUIC && key.Dst.Port() == 443 {
			return rules.Block
		}
		res = set.EvaluateNoDomain(sub)
	}
	return res.Action
}
