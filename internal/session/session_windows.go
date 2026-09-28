//go:build windows

package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/engine"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/fwrule"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/relay"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// relayWait bounds how long stopping waits for the relay's connection
// handlers. Once their connections are reset they finish at once, unless
// one waits for the NAT table's lock held by a packet loop the watchdog
// gave up on: the engine does not hang on that loop (see engine.Stop), so
// neither does the session.
const relayWait = 500 * time.Millisecond

type Session struct {
	eng  *engine.Engine
	rel  *relay.Server
	mgr  *tunnels.Manager
	stub *socks5.Server
	// unlock gives back the machine's single engine (engine.LockMachine).
	unlock func()
}

// Start brings everything up; on error nothing is left running.
func Start(cfg Config) (_ *Session, err error) {
	if cfg.Settings == nil || cfg.Rules == nil {
		return nil, errors.New("session: settings and rules are required")
	}
	log := cfg.Log
	s := &Session{}
	defer func() {
		if err != nil {
			s.Stop()
		}
	}()

	// One engine per machine, claimed before anything machine-wide
	// changes (the firewall rule names this copy's exe).
	if s.unlock, err = engine.LockMachine(); err != nil {
		return nil, err
	}

	if err := fwrule.Ensure(cfg.Exe); err != nil {
		log.Warn("firewall rule not ensured; reflected connections may be blocked", "err", err)
	}

	s.mgr = &tunnels.Manager{Log: log, OnStatus: cfg.OnStatus, LogLine: cfg.HysteriaLog}
	if cfg.Stub {
		s.stub = &socks5.Server{Username: "stub", Password: "stubpass"}
		if err := s.stub.Listen("127.0.0.1:0"); err != nil {
			return nil, fmt.Errorf("socks5 stub: %w", err)
		}
		c := socks5.Client{Server: s.stub.Addr(), Username: "stub", Password: "stubpass"}
		s.mgr.New = func(hysteria.Profile, tunnels.Hooks) tunnels.Runner { return &stubRunner{c: c} }
		log.Info("SOCKS5 stub listening (connects directly from this process)", "addr", s.stub.Addr())
	} else {
		s.mgr.New = RunnerFactory(cfg)
	}

	// The relay listens before the engine exists (the engine needs its
	// port): a connection that comes first has no NAT entry. Decide and
	// OnDone only follow an entry Lookup found.
	var engp atomic.Pointer[engine.Engine]
	s.rel = &relay.Server{
		Log: log,
		Lookup: func(peer netip.AddrPort) *nat.Entry {
			eng := engp.Load()
			if eng == nil {
				return nil
			}
			return eng.NAT.LookupReflect(peer.Addr(), peer.Port())
		},
		Decide: func(e *nat.Entry, domain string, src rules.DomainSource) rules.Result {
			return engp.Load().RelayDecide(e, domain, src)
		},
		Tunnel: func(profile string) relay.Tunnel {
			if e := s.mgr.Get(profile); e != nil {
				return e
			}
			return nil
		},
		OnDone:          func(r relay.Result) { engp.Load().RelayDone(r) },
		PreferRemoteDNS: cfg.Settings.RemoteDNS(),
		SniffTimeout:    cfg.Settings.SniffTimeout(),
	}
	if err := s.rel.Start(0); err != nil {
		return nil, fmt.Errorf("relay: %w", err)
	}
	log.Info("relay listening", "port", s.rel.Port())

	eng := engine.New(engine.Config{
		DLLDir: cfg.Dir,
		Tunnels: func(profile string) engine.Tunnel {
			if e := s.mgr.Get(profile); e != nil {
				return e
			}
			return nil
		},
		Log: log,
		// Runs before the filters go: the relay's sockets are reset now, so
		// no FIN, queued data or keepalive of theirs can leak to the real
		// remotes once diverting stops (see relay.Server.Abort).
		OnFail: func() {
			s.rel.Abort()
			if cfg.OnEngineFail != nil {
				cfg.OnEngineFail()
			}
		},
		Options: engine.Options{
			RelayPort:          s.rel.Port(),
			BlockQUIC:          cfg.Settings.QUICBlocked(),
			BlockIPv6Tunnel:    cfg.Settings.IPv6TunnelBlocked(),
			TCPOnly:            cfg.TCPOnly,
			ResetUnknownDomain: cfg.ResetUnknownDomain,
		},
	})
	eng.Rules.Swap(cfg.Rules)
	eng.OnDecision = cfg.OnDecision
	eng.Flows.OnClose = cfg.OnClose
	s.eng = eng
	engp.Store(eng)
	if err := eng.Start(); err != nil {
		return nil, err
	}
	// Every Hysteria reports its server IPs before its first packet; the
	// engine excludes the union.
	s.mgr.SetServerIPs = eng.SetServerIPs
	s.mgr.Sync(cfg.Profiles)
	return s, nil
}

// Stop resets the relayed connections while the filters still reflect the
// resets to the applications, then removes the filters (traffic goes
// direct at once) and stops every Hysteria. Closing the relay after the
// filters would send its FINs and queued data to the real remotes,
// outside the kill switch. The relay closes quickly: its dials are
// canceled and its connections reset; a handler stuck on the engine's
// locks is not waited for past relayWait.
func (s *Session) Stop() {
	if s.rel != nil {
		s.rel.CloseWait(relayWait)
	}
	if s.eng != nil {
		s.eng.Stop()
	}
	if s.mgr != nil {
		s.mgr.StopAll()
	}
	if s.stub != nil {
		s.stub.Close()
	}
	if s.unlock != nil {
		s.unlock()
	}
}

// ResetConnections resets the relayed connections while the filters, and
// the kill switch's pass, still let the resets reach the applications. A
// disconnect that keeps the kill switch block calls it before the pass
// goes: the block could drop them. Stop resets whatever came since.
func (s *Session) ResetConnections() {
	if s.rel != nil {
		s.rel.CloseWait(relayWait)
	}
	if s.eng != nil {
		s.eng.ResetConnections()
	}
}

// SetRules starts the profiles the new rules need, swaps the rule set (new
// flows use it) and stops the profiles no longer used.
func (s *Session) SetRules(set *rules.Set, profiles []hysteria.Profile) {
	s.mgr.Sync(profiles)
	s.eng.Rules.Swap(set)
}

func (s *Session) Flows() *flows.Registry { return s.eng.Flows }

// EngineFailed reports that the engine removed its filters (fail-open).
func (s *Session) EngineFailed() bool { return s.eng.Failed() }

// Tunnels lists the running profiles.
func (s *Session) Tunnels() []tunnels.Status { return s.mgr.Statuses() }

// Acquire returns a running endpoint for p (see tunnels.Manager.Acquire).
func (s *Session) Acquire(p hysteria.Profile) (*tunnels.Endpoint, func()) { return s.mgr.Acquire(p) }

// DNSSites returns the DNS cache names of an address grouped by site.
func (s *Session) DNSSites(ip netip.Addr) [][]string { return s.eng.DNS.Sites(ip) }

// Endpoint is a running profile's tunnel, or nil.
func (s *Session) Endpoint(profile string) *tunnels.Endpoint { return s.mgr.Get(profile) }

func (s *Session) Stats() Stats {
	e, r := s.eng, s.rel
	return Stats{
		Reflected:   e.Reflected.Load(),
		Passed:      e.Passed.Load(),
		Blocked:     e.Blocked.Load() + r.Blocked.Load(),
		Rejected:    e.Rejected.Load() + r.Rejected.Load(),
		Unknown:     e.Unknown.Load(),
		RelayTunnel: r.Tunneled.Load(),
		RelayDirect: r.Direct.Load(),
		UDPTunneled: e.UDPTunneled.Load(),
		UDPDropped:  e.UDPDropped.Load(),
		SYNRetries:  e.SYNRetries.Load(),
		FragDropped: e.FragDropped.Load(),
		Malformed:   e.Malformed.Load(),
		Panics:      e.Panics.Load(),
		DNSPairs:    e.DNS.Len(),
		NATEntries:  e.NAT.Len(),
		RelayPort:   int(r.Port()),
		Driver:      e.DriverVersion(),
	}
}

// stubRunner is a profile served by the in-process SOCKS5 stub.
type stubRunner struct {
	c  socks5.Client
	mu sync.Mutex
	up bool
}

func (r *stubRunner) Start() error { r.mu.Lock(); r.up = true; r.mu.Unlock(); return nil }
func (r *stubRunner) Stop()        { r.mu.Lock(); r.up = false; r.mu.Unlock() }
func (r *stubRunner) Status() hysteria.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.up {
		return hysteria.Status{State: hysteria.Connected, UDPEnabled: true}
	}
	return hysteria.Status{}
}
func (r *stubRunner) Available() bool    { return r.Status().State == hysteria.Connected }
func (r *stubRunner) UDPAvailable() bool { return r.Available() }
func (r *stubRunner) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	return r.c.Connect(ctx, dst)
}
func (r *stubRunner) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	return r.c.UDPAssociate(ctx)
}
func (r *stubRunner) SOCKS() socks5.Client { return r.c }
