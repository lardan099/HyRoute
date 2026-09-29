//go:build windows

package main

import (
	"github.com/lardan099/hyroute/internal/app"
	"github.com/lardan099/hyroute/internal/dnspolicy"
)

// dns: «Настройки» → «DNS» and the captive-portal pause on Home.

// DNS returns the DNS settings and the servers the card offers.
func (g *GUI) DNS() app.DNSView { return g.ctl.DNS() }

// SaveDNS validates, stores and applies the DNS settings.
func (g *GUI) SaveDNS(c dnspolicy.Config) error { return g.ctl.SaveDNS(c) }

// PauseDNSTunnel lets tunnel names whose tunnel is down resolve as before
// for 5 minutes (a Wi-Fi login page).
func (g *GUI) PauseDNSTunnel() error { return g.ctl.PauseDNSTunnel() }

// CancelDNSPause ends that pause.
func (g *GUI) CancelDNSPause() { g.ctl.CancelDNSPause() }
