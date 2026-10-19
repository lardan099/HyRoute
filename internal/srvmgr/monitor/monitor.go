// Package monitor samples the servers' CPU, memory, disk, load and network
// over SSH on a schedule and keeps the points (store.Metrics), checks
// the health of servers with Hysteria installed (health.go) and counts
// their traffic per user from the Hysteria stats API (traffic.go). It reads
// only (remote.ReadOnly, no sudo) and runs outside the job engine: a
// sample never waits for a job and never blocks one.
package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/quicprobe"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Store is what the collector reads and writes.
type Store interface {
	ListServers(ctx context.Context) ([]model.Server, error)
	ServerCredentials(ctx context.Context, id int64) ([]model.Credential, error)
	HostKey(ctx context.Context, serverID int64) (model.HostKey, error)
	SwapServerState(ctx context.Context, id int64, from []model.ServerState, state model.ServerState, at time.Time) (bool, error)
	Installation(ctx context.Context, serverID int64) (model.Installation, error)
	CurrentConfig(ctx context.Context, serverID int64) (model.ServerConfig, error)
	UnfinishedJobs(ctx context.Context) ([]model.Job, error)
	store.Metrics
	store.HealthChecks
	store.Traffic
}

// LinkChecker checks the cascade links that start at a server
// (cascade.Checker).
type LinkChecker interface {
	HasLinks(ctx context.Context, serverID int64) bool
	CheckLinks(ctx context.Context, entry model.Server, ex remote.Executor) (down string, err error)
	Prune(ctx context.Context, before time.Time) error
}

// Connector opens an SSH connection to a server (connect.Connector).
type Connector interface {
	Connect(ctx context.Context, serverID int64) (remote.Executor, error)
}

// Events hears what the rounds find (events.Watcher).
type Events interface {
	// Server: the status a round found on a server without a job:
	// healthy, degraded or offline, with the reason.
	Server(ctx context.Context, srv model.Server, status model.ServerState, reason string)
	// Disk: how full the root file system of a server is.
	Disk(ctx context.Context, srv model.Server, usedKiB, totalKiB uint64)
	// Network: whether the controller itself has network.
	Network(ctx context.Context, online bool)
}

// Collector samples every server with a trusted host key each Interval.
type Collector struct {
	Store Store
	Conn  Connector
	// Keys open config revisions (the port and obfs password of the UDP
	// check); nil: no UDP check.
	Keys *secrets.Keyring
	Log  *slog.Logger
	Now  func() time.Time
	// Interval between rounds (default 1 min), Timeout per server
	// (default 20 s), Parallel connections at most (default 4).
	Interval time.Duration
	Timeout  time.Duration
	Parallel int
	// KeepSamples (default 48 h) and KeepAverages (default 30 days);
	// KeepHealth (default 7 days); KeepTraffic (default 90 days).
	KeepSamples, KeepAverages, KeepHealth, KeepTraffic time.Duration
	// Probe checks a UDP port from the controller (quicprobe.Probe).
	Probe func(ctx context.Context, addr, salamander string) (time.Duration, error)
	// Links checks the cascade links that start at a server (nil: none);
	// LinkTimeout is the time added to such a server's round (default
	// 30 s).
	Links       LinkChecker
	LinkTimeout time.Duration
	// Online checks the controller's own network when no server of a
	// round answered (two servers or more); nil: never checked. Without
	// network the round changes no state and stores no health check.
	Online func(ctx context.Context) bool
	// Events hears statuses, disks and the controller's network (nil:
	// nobody).
	Events Events

	mu          sync.Mutex
	prev        map[int64]last
	traffic     map[int64]counters
	refused     map[int64]refusal
	lastCompact time.Time
	offline     bool // the last round found the controller without network
}

type last struct {
	s  remote.Sample
	at time.Time
}

// After a server refuses the SSH login the collector stops logging in to
// it: fail2ban and the like ban an address after a few failures, and the
// admin may share that address with the controller. It tries again as
// soon as the login data changes, otherwise after a pause that doubles
// with each refusal in a row, from authPause up to authPauseMax.
const (
	authPause    = 15 * time.Minute
	authPauseMax = 6 * time.Hour
)

// refusal is a server that refused the SSH login.
type refusal struct {
	login string    // the refused login data (loginKey)
	n     int       // refusals in a row
	until time.Time // no login before
}

// loginKey identifies a server's login data: the address, the user and
// the sealed credentials, sealed anew whenever the admin saves them. ""
// when they cannot be read.
func (c *Collector) loginKey(ctx context.Context, srv model.Server) string {
	creds, err := c.Store.ServerCredentials(ctx, srv.ID)
	if err != nil {
		return ""
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%d\x00%s\x00%s\x00", srv.Host, srv.SSHPort, srv.SSHUser, srv.AuthType)
	for _, cr := range creds {
		fmt.Fprintf(h, "%s\x00%x\x00", cr.Kind, cr.Sealed)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// paused reports whether the server refused the login data it has now and
// the pause after that has not run out.
func (c *Collector) paused(id int64, login string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.refused[id]
	if !ok {
		return false
	}
	if login != "" && login != r.login {
		delete(c.refused, id) // new login data: try it
		return false
	}
	return now.Before(r.until)
}

// refuse records a refused login and returns the pause before the next
// attempt.
func (c *Collector) refuse(id int64, login string, now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.refused[id]
	if login != r.login {
		r = refusal{login: login}
	}
	pause := min(authPause<<min(r.n, 8), authPauseMax)
	r.n++
	r.until = now.Add(pause)
	c.refused[id] = r
	return pause
}

// loggedIn forgets a server's refusals.
func (c *Collector) loggedIn(id int64) {
	c.mu.Lock()
	delete(c.refused, id)
	c.mu.Unlock()
}

// Paused are the servers the collector does not log in to now because
// they refused the login, with the time of the next attempt (unless the
// login data changes first).
func (c *Collector) Paused() map[int64]time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	out := map[int64]time.Time{}
	for id, r := range c.refused {
		if now().Before(r.until) {
			out[id] = r.until
		}
	}
	return out
}

// Offline reports whether the last round found the controller without
// network.
func (c *Collector) Offline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offline
}

func (c *Collector) defaults() {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Interval == 0 {
		c.Interval = time.Minute
	}
	if c.Timeout == 0 {
		c.Timeout = 20 * time.Second
	}
	if c.LinkTimeout == 0 {
		c.LinkTimeout = 30 * time.Second
	}
	if c.Parallel == 0 {
		c.Parallel = 4
	}
	if c.KeepSamples == 0 {
		c.KeepSamples = 48 * time.Hour
	}
	if c.KeepAverages == 0 {
		c.KeepAverages = 30 * 24 * time.Hour
	}
	if c.KeepHealth == 0 {
		c.KeepHealth = 7 * 24 * time.Hour
	}
	if c.KeepTraffic == 0 {
		c.KeepTraffic = 90 * 24 * time.Hour
	}
	if c.Probe == nil {
		c.Probe = quicprobe.Probe
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.prev == nil {
		c.prev = map[int64]last{}
	}
	if c.refused == nil {
		c.refused = map[int64]refusal{}
	}
	if c.traffic == nil {
		c.traffic = map[int64]counters{}
	}
}

// Run collects until ctx ends, the first round right away.
func (c *Collector) Run(ctx context.Context) {
	c.mu.Lock()
	c.defaults()
	c.mu.Unlock()
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		c.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round samples every server once and compacts the stored points every
// ten minutes.
func (c *Collector) Round(ctx context.Context) {
	c.mu.Lock()
	c.defaults()
	c.mu.Unlock()
	list, err := c.Store.ListServers(ctx)
	if err != nil {
		if ctx.Err() == nil {
			c.Log.Warn("monitor: list servers", "err", err)
		}
		return
	}
	// A job changes the server as it goes (restarts, ports): its health
	// is the job's business until it ends.
	busy := map[int64]bool{}
	if js, err := c.Store.UnfinishedJobs(ctx); err == nil {
		for _, j := range js {
			for _, s := range j.AllServers() {
				busy[s] = true
			}
		}
	} else if ctx.Err() == nil {
		c.Log.Warn("monitor: jobs", "err", err)
	}
	sem := make(chan struct{}, c.Parallel)
	var (
		wg    sync.WaitGroup
		vmu   sync.Mutex
		found []verdict
	)
	for _, srv := range list {
		if _, err := c.Store.HostKey(ctx, srv.ID); err != nil {
			continue // not trusted yet: no connection
		}
		login := c.loginKey(ctx, srv)
		if c.paused(srv.ID, login, c.Now()) {
			continue // it refused this login: no new attempt yet
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			v := c.collect(ctx, srv, busy[srv.ID], login)
			vmu.Lock()
			found = append(found, v)
			vmu.Unlock()
		}()
	}
	wg.Wait()
	// States are set once every server is done: when none answered, it
	// may be the controller that lost its network.
	if ctx.Err() == nil && !c.noNetwork(ctx, found) {
		for _, v := range found {
			c.apply(ctx, v)
		}
	}
	now := c.Now()
	c.mu.Lock()
	due := now.Sub(c.lastCompact) >= 10*time.Minute
	if due {
		c.lastCompact = now
	}
	c.mu.Unlock()
	if due {
		if err := c.Store.CompactMetrics(ctx, now, c.KeepSamples, c.KeepAverages); err != nil && ctx.Err() == nil {
			c.Log.Warn("monitor: compact", "err", err)
		}
		if err := c.Store.PruneHealth(ctx, now.Add(-c.KeepHealth)); err != nil && ctx.Err() == nil {
			c.Log.Warn("monitor: prune health", "err", err)
		}
		if err := c.Store.PruneTraffic(ctx, now.Add(-c.KeepTraffic)); err != nil && ctx.Err() == nil {
			c.Log.Warn("monitor: prune traffic", "err", err)
		}
		if c.Links != nil {
			if err := c.Links.Prune(ctx, now.Add(-c.KeepHealth)); err != nil && ctx.Err() == nil {
				c.Log.Warn("monitor: prune link checks", "err", err)
			}
		}
	}
}

// up are the states a sample may turn into Offline (and back): the
// others belong to jobs and the admin.
var up = []model.ServerState{model.StateHealthy, model.StateDegraded}

// netSign is what a server's answer says about the controller's own
// network.
type netSign int

const (
	netUnknown netSign = iota // no verdict (a local error, the round cut short)
	netDown                   // neither SSH nor UDP answered
	netUp                     // the server answered
)

// verdict is what a round found on one server. Round applies it once
// every server is done: when none of them answered, the controller
// itself may have lost its network, and then nothing is applied.
type verdict struct {
	srv model.Server
	net netSign
	// health is the check to store; the server's state follows it.
	health *model.Health
	// Without a health check: the state to swap to from the states in
	// from ("": none), and why (for the log).
	state model.ServerState
	from  []model.ServerState
	err   error
	// status and reason for Events ("": nothing to tell, the server had
	// a job or the login failed).
	status model.ServerState
	reason string
}

// collect samples one server; login is its loginKey. The state it found
// is in the verdict, not set yet.
func (c *Collector) collect(ctx context.Context, srv model.Server, busy bool, login string) (v verdict) {
	v.srv = srv
	// An entry of a cascade checks its links after its own health.
	timeout, links := c.Timeout, !busy && c.Links != nil && c.Links.HasLinks(ctx, srv.ID)
	if links {
		timeout += c.LinkTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// Servers with Hysteria get a health check; the UDP probe runs while
	// SSH connects.
	var hc *check
	if !busy {
		hc = c.startCheck(cctx, srv)
	}
	start := time.Now()
	ex, err := c.Conn.Connect(cctx, srv.ID)
	sshTook := time.Since(start)
	if err != nil {
		if ctx.Err() != nil {
			return verdict{srv: srv}
		}
		refused := errors.Is(err, remote.ErrAuthFailed)
		if refused {
			pause := c.refuse(srv.ID, login, c.Now())
			c.Log.Warn("monitor: the server refused the SSH login; next attempt when the login data changes or after a pause", "server", srv.Name, "pause", pause, "err", err)
		}
		var (
			unreachable *remote.UnreachableError
			changed     *remote.HostKeyChangedError
		)
		down := errors.As(err, &unreachable)
		if refused || errors.As(err, &changed) {
			v.net = netUp // it answered SSH
		}
		if hc != nil {
			h := hc.sshFailed(err, down)
			v.health, v.status, v.reason = &h, h.Status, h.Reason
			switch {
			case h.UDP == model.UDPOK:
				v.net = netUp
			case down:
				v.net = netDown
			}
			return v
		}
		switch {
		case down:
			v.net, v.state, v.from, v.err = netDown, model.StateOffline, up, err
			if !busy {
				v.status, v.reason = model.StateOffline, "SSH не отвечает."
			}
		case !refused:
			c.Log.Warn("monitor: connect", "server", srv.Name, "err", err)
		}
		return v
	}
	v.net = netUp
	c.loggedIn(srv.ID)
	defer ex.Close()
	// The timeout closes the connection too: a server that went silent
	// mid-command must not hold up the round, and with it every server.
	stop := context.AfterFunc(cctx, func() { ex.Close() })
	defer stop()
	ro := remote.ReadOnly(ex)
	if hc != nil {
		defer func() {
			h := hc.onServer(cctx, ro, sshTook)
			if links {
				// Over the connection itself: the check tunnels to the
				// entry's loopback.
				down, err := c.Links.CheckLinks(cctx, srv, ex)
				if err != nil && ctx.Err() == nil {
					c.Log.Warn("monitor: cascade links", "server", srv.Name, "err", err)
				}
				if down != "" && h.Status == model.StateHealthy {
					h.Status, h.Reason = model.StateDegraded, capitalize(down)
				}
			}
			v.health, v.status, v.reason = &h, h.Status, h.Reason
		}()
	}
	s, err := remote.ReadSample(cctx, ro)
	if err != nil {
		if ctx.Err() == nil {
			c.Log.Warn("monitor: sample", "server", srv.Name, "err", err)
		}
		return v
	}
	if c.Events != nil {
		c.Events.Disk(ctx, srv, s.DiskUsedKiB, s.DiskTotalKiB)
	}
	now := c.Now()
	c.mu.Lock()
	p, had := c.prev[srv.ID]
	c.prev[srv.ID] = last{s, now}
	c.mu.Unlock()
	var prev *remote.Sample
	if had {
		prev = &p.s
	}
	if err := c.Store.AddMetric(ctx, Point(srv.ID, now, s, prev, p.at)); err != nil && ctx.Err() == nil {
		c.Log.Warn("monitor: store", "server", srv.Name, "err", err)
		return v
	}
	// A job may be changing the config (and the secret): its servers are
	// read once it ends; the counters carry the traffic in between.
	if !busy {
		c.readTraffic(cctx, srv, ro)
	}
	if hc == nil && !busy {
		v.state, v.from, v.status = model.StateHealthy, []model.ServerState{model.StateOffline}, model.StateHealthy
	}
	return v
}

// noNetwork decides, after a round, whether the controller has network:
// when no server answered (two or more were tried) it asks Online. It
// tells Events what it learnt and reports a controller without network.
func (c *Collector) noNetwork(ctx context.Context, found []verdict) bool {
	tried, down := 0, 0
	for _, v := range found {
		switch v.net {
		case netDown:
			tried++
			down++
		case netUp:
			tried++
		}
	}
	online, known := true, tried > down
	if !known && down >= 2 && c.Online != nil {
		online, known = c.Online(ctx), true
		if ctx.Err() != nil {
			return true // stopping: nothing is applied
		}
	}
	if !known {
		return false
	}
	c.mu.Lock()
	was := c.offline
	c.offline = !online
	c.mu.Unlock()
	switch {
	case !online && !was:
		c.Log.Warn("monitor: no server answered and neither did the internet: the controller has no network; server states stay as they are", "servers", down)
	case online && was:
		c.Log.Info("monitor: the controller has network again")
	}
	if c.Events != nil {
		c.Events.Network(ctx, online)
	}
	return !online
}

// apply stores what a round found on a server and sets its state.
func (c *Collector) apply(ctx context.Context, v verdict) {
	switch {
	case v.health != nil:
		c.finish(ctx, v.srv, *v.health)
	case v.state != "":
		if ok, _ := c.Store.SwapServerState(ctx, v.srv.ID, v.from, v.state, c.Now()); ok {
			if v.state == model.StateOffline {
				c.Log.Warn("monitor: server unreachable", "server", v.srv.Name, "err", v.err)
			} else {
				c.Log.Info("monitor: server reachable again", "server", v.srv.Name)
			}
		}
	}
	if c.Events != nil && v.status != "" && ctx.Err() == nil {
		c.Events.Server(ctx, v.srv, v.status, v.reason)
	}
}

// Point turns a sample taken at at into a stored point; rates need the
// previous sample of the same boot (prev, taken at prevAt).
func Point(serverID int64, at time.Time, s remote.Sample, prev *remote.Sample, prevAt time.Time) model.Metric {
	const mib = 1024.0
	m := model.Metric{
		ServerID:     serverID,
		At:           at,
		MemUsedMiB:   float64(s.MemTotalKiB-min(s.MemAvailKiB, s.MemTotalKiB)) / mib,
		MemTotalMiB:  float64(s.MemTotalKiB) / mib,
		DiskUsedMiB:  float64(s.DiskUsedKiB) / mib,
		DiskTotalMiB: float64(s.DiskTotalKiB) / mib,
		Load1:        s.Load[0],
	}
	if prev == nil || s.UptimeSec < prev.UptimeSec {
		return m // no earlier sample, or a reboot in between
	}
	p := *prev
	if s.CPUTotal > p.CPUTotal && s.CPUBusy >= p.CPUBusy {
		cpu := 100 * float64(s.CPUBusy-p.CPUBusy) / float64(s.CPUTotal-p.CPUTotal)
		m.CPU = &cpu
	}
	if dt := at.Sub(prevAt).Seconds(); dt > 0 && s.RxBytes >= p.RxBytes && s.TxBytes >= p.TxBytes {
		rx, tx := float64(s.RxBytes-p.RxBytes)/dt, float64(s.TxBytes-p.TxBytes)/dt
		m.RxBps, m.TxBps = &rx, &tx
	}
	return m
}
