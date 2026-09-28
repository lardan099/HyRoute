//go:build windows

package session

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/dnsproxy"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// dns: DNS policies in a session. The resolver resolves tunnel names
// through the running profiles' Hysteria (SOCKS5 CONNECT to the DoH/DoT
// server) and direct names from HyRoute itself; the engine captures and
// answers.

// startDNS wires the resolver and the policy into the engine before it
// starts: capture is on from the first packet when a policy is set.
func (s *Session) startDNS(cfg Config) error {
	s.res = &dnsproxy.Resolver{
		TunnelDial: func(profile string) dnsproxy.Dialer {
			e := s.mgr.Get(profile)
			if e == nil || !e.Available() {
				return nil
			}
			return socksDialer(e)
		},
		Log:  cfg.Log,
		Name: cfg.ProfileName,
	}
	s.configureDNS(cfg.DNS)
	s.eng.Resolver = s.res
	s.eng.OwnName = cfg.OwnName
	if cfg.DNS != nil {
		s.eng.SysDNS.Refresh()
	}
	s.eng.DNSPol.Store(cfg.DNS)
	return s.eng.SetDNSCapture(cfg.DNS != nil)
}

// socksDialer dials through a profile's Hysteria: a host name goes to the
// server as a name (the server resolves it).
func socksDialer(e *tunnels.Endpoint) dnsproxy.Dialer {
	return func(ctx context.Context, host string, port uint16) (net.Conn, error) {
		dst := socks5.Addr{Port: port}
		if a, err := netip.ParseAddr(host); err == nil {
			dst.IP = a.Unmap()
		} else {
			dst.Host = host
		}
		return e.Dial(ctx, dst)
	}
}

// configureDNS gives the resolver the policy's servers (none: closed).
func (s *Session) configureDNS(p *dnspolicy.Policy) {
	if p == nil {
		s.res.Configure(dnspolicy.Spec{}, nil)
		return
	}
	var tunnel dnspolicy.Spec
	if p.Cfg.ByRules {
		tunnel = p.TunnelSpec
	}
	s.res.Configure(tunnel, p.DirectSpec)
}

// SetDNS replaces the DNS policy while the session runs. Turning it on,
// capture comes first (a failed filter swap changes nothing and is
// returned); turning it off, the policy goes first, then the DNS-mode
// connections are reset while the filter still reflects the resets, then
// the filter; turning on browser DoH blocking resets the browsers' open
// DoH connections.
func (s *Session) SetDNS(p *dnspolicy.Policy) error {
	old := s.eng.DNSPol.Load()
	switch {
	case old == nil && p == nil:
		return nil
	case old == nil:
		s.eng.SysDNS.Refresh()
		if err := s.eng.SetDNSCapture(true); err != nil {
			return err
		}
		s.configureDNS(p)
		s.eng.DNSPol.Store(p)
		if p.Cfg.BlockBrowserDoH {
			s.rel.AbortWhere(s.eng.DropDoH())
		}
		return nil
	case p == nil:
		s.eng.DNSPol.Store(nil)
		s.eng.AbortDNS()
		s.rel.AbortWhere(func(e *nat.Entry) bool { return e.Mode == nat.DNS })
		err := s.eng.SetDNSCapture(false)
		if err != nil {
			s.eng.Log.Warn("DNS capture not removed from the filter", "err", err)
		}
		s.configureDNS(nil)
		return err
	}
	s.configureDNS(p)
	s.eng.DNSPol.Store(p)
	if p.Cfg.BlockBrowserDoH && !old.Cfg.BlockBrowserDoH {
		s.rel.AbortWhere(s.eng.DropDoH())
	}
	return nil
}

// retainDNS closes the resolver's tunnel clients of profiles that stopped.
func (s *Session) retainDNS(profiles []hysteria.Profile) {
	ids := make([]string, len(profiles))
	for i, p := range profiles {
		ids[i] = p.ID
	}
	s.res.Retain(ids)
}

// DNSHealth lists the resolver's clients that are down.
func (s *Session) DNSHealth() []dnsproxy.Health {
	if s.res == nil {
		return nil
	}
	return s.res.Health(time.Now())
}

// PauseDNS sets the captive-portal pause (zero time: none).
func (s *Session) PauseDNS(until time.Time) {
	if s.eng == nil {
		return
	}
	if until.IsZero() {
		s.eng.DNSPauseUntil.Store(0)
		return
	}
	s.eng.DNSPauseUntil.Store(until.UnixNano())
}
