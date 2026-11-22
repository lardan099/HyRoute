package app

import (
	"context"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
)

// Sleep mode. A server that only local proxies use (no rule, fallback,
// the main target or a group sends traffic to it) runs only while its
// proxies do: it starts on a proxy's first connection and stops once no
// proxy connection went through it for proxySleepAfter. An idle server
// costs subscription traffic (VLESS checks, QUIC keepalives) and a
// process; with «Прокси для серверов» that is every server of a
// subscription. Groups do not sleep: their members also serve rules.

var (
	proxySleepAfter = 10 * time.Minute
	proxyWakeWait   = 20 * time.Second // the longest a connection waits for its server to start
)

// proxyUse is a server kept awake by proxies (c.proxyAwake, c.mu).
type proxyUse struct {
	last         time.Time      // the last proxy connection opened or closed
	open         int            // proxy connections open through it
	listeners    map[string]int // open connections by local proxy ID
	lastListener string         // the proxy that began the current idle window
}

// proxyWake marks profile id used by a proxy now and, when it sleeps,
// starts it and waits until it can carry traffic (or failed, ctx ended,
// proxyWakeWait passed). It returns the release of the connection that
// follows: call it once the connection closes (a no-op for groups).
func (c *Controller) proxyWake(ctx context.Context, s Session, id, listener string) (hold func()) {
	if groups.IsGroupID(id) || s == nil {
		return func() {}
	}
	c.mu.Lock()
	if c.sess != s {
		c.mu.Unlock()
		return func() {}
	}
	if c.proxyAwake == nil {
		c.proxyAwake = map[string]*proxyUse{}
	}
	u := c.proxyAwake[id]
	woke := u == nil
	if woke {
		u = &proxyUse{}
		c.proxyAwake[id] = u
	}
	u.last = time.Now()
	u.open++
	if u.listeners == nil {
		u.listeners = make(map[string]int)
	}
	u.listeners[listener]++
	wait := proxyWakeWait
	if p := c.profiles.Find(id); p != nil {
		wait = connectWait(*p, proxyWakeWait)
	}
	if woke && s.Endpoint(id) == nil {
		c.Log.Info("local proxy: starting its server", "profile", c.profileName(id))
		c.applyRoutingLocked()
	}
	c.mu.Unlock()
	release := sync.OnceFunc(func() {
		c.mu.Lock()
		u.open--
		u.listeners[listener]--
		if u.listeners[listener] == 0 {
			delete(u.listeners, listener)
		}
		u.lastListener = listener
		u.last = time.Now()
		c.mu.Unlock()
	})
	waitServer(ctx, s, id, wait)
	return release
}

// connectWait is how long server p may take to connect, base for
// Hysteria: Xray (VLESS) and AmneziaWG get 45 s to its 20, as «Проверить»
// gives them (the three tries of their start, hysteria/xray.go).
func connectWait(p hysteria.Profile, base time.Duration) time.Duration {
	if p.Probed() {
		return base * 9 / 4
	}
	return base
}

// waitServer waits until profile id runs and can carry traffic, or failed,
// at most wait.
func waitServer(ctx context.Context, s Session, id string, wait time.Duration) {
	deadline := time.Now().Add(wait)
	for {
		if ep := s.Endpoint(id); ep != nil && (ep.Available() || ep.Status().State == hysteria.Failed) {
			return
		}
		if time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// sleepProxies stops the proxy-only servers idle for proxySleepAfter
// (RunScheduler, every minute).
func (c *Controller) sleepProxies(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	slept := false
	for id, u := range c.proxyAwake {
		if u.open <= 0 && now.Sub(u.last) >= proxySleepAfter {
			delete(c.proxyAwake, id)
			slept = true
			c.Log.Info("local proxy: its server sleeps until the next connection", "profile", c.profileName(id))
		}
	}
	if slept {
		c.applyRoutingLocked()
	}
}
