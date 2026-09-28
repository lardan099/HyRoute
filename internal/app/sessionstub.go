package app

import (
	"net/netip"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// NopSession implements every Session method with zero values. Test
// doubles embed it and keep only the methods they customise, so a method
// added to Session (in the interface, here and in session.Session, in one
// block per feature) does not break them.
type NopSession struct{}

var _ Session = NopSession{}

func (NopSession) Stop()                                   {}
func (NopSession) ResetConnections()                       {}
func (NopSession) SetRules(*rules.Set, []hysteria.Profile) {}
func (NopSession) Flows() *flows.Registry                  { return nil }
func (NopSession) EngineFailed() bool                      { return false }
func (NopSession) Tunnels() []tunnels.Status               { return nil }

// Acquire returns no endpoint and a release that does nothing (callers
// always call it).
func (NopSession) Acquire(hysteria.Profile) (*tunnels.Endpoint, func()) { return nil, func() {} }
func (NopSession) DNSSites(netip.Addr) [][]string                       { return nil }
func (NopSession) Stats() session.Stats                                 { return session.Stats{} }
func (NopSession) Endpoint(string) *tunnels.Endpoint                    { return nil }

// groups

// ServerIPRoom has no room: a group check starts no temporary Hysteria.
func (NopSession) ServerIPRoom() int { return 0 }
