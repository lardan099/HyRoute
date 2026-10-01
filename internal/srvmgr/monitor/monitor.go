// Package monitor samples the servers' CPU, memory, disk, load and network
// over SSH on a schedule and keeps the points (store.Metrics), and checks
// the health of servers with Hysteria installed (health.go). It reads
// only (remote.ReadOnly, no sudo) and runs outside the job engine: a
// sample never waits for a job and never blocks one.
package monitor

import (
	"context"
	"errors"
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
	HostKey(ctx context.Context, serverID int64) (model.HostKey, error)
	SwapServerState(ctx context.Context, id int64, from []model.ServerState, state model.ServerState, at time.Time) (bool, error)
	Installation(ctx context.Context, serverID int64) (model.Installation, error)
	CurrentConfig(ctx context.Context, serverID int64) (model.ServerConfig, error)
	UnfinishedJobs(ctx context.Context) ([]model.Job, error)
	store.Metrics
	store.HealthChecks
}

// Connector opens an SSH connection to a server (connect.Connector).
type Connector interface {
	Connect(ctx context.Context, serverID int64) (remote.Executor, error)
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
	// KeepHealth (default 7 days).
	KeepSamples, KeepAverages, KeepHealth time.Duration
	// Probe checks a UDP port from the controller (quicprobe.Probe).
	Probe func(ctx context.Context, addr, salamander string) (time.Duration, error)

	mu          sync.Mutex
	prev        map[int64]last
	lastCompact time.Time
}

type last struct {
	s  remote.Sample
	at time.Time
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
	if c.Probe == nil {
		c.Probe = quicprobe.Probe
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.prev == nil {
		c.prev = map[int64]last{}
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
			busy[j.ServerID] = true
		}
	} else if ctx.Err() == nil {
		c.Log.Warn("monitor: jobs", "err", err)
	}
	sem := make(chan struct{}, c.Parallel)
	var wg sync.WaitGroup
	for _, srv := range list {
		if _, err := c.Store.HostKey(ctx, srv.ID); err != nil {
			continue // not trusted yet: no connection
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			c.collect(ctx, srv, busy[srv.ID])
		}()
	}
	wg.Wait()
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
	}
}

// up are the states a sample may turn into Offline (and back): the
// others belong to jobs and the admin.
var up = []model.ServerState{model.StateHealthy, model.StateDegraded}

func (c *Collector) collect(ctx context.Context, srv model.Server, busy bool) {
	cctx, cancel := context.WithTimeout(ctx, c.Timeout)
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
			return
		}
		var unreachable *remote.UnreachableError
		down := errors.As(err, &unreachable)
		if hc != nil {
			c.finish(ctx, srv, hc.sshFailed(err, down))
			return
		}
		if down {
			if ok, _ := c.Store.SwapServerState(ctx, srv.ID, up, model.StateOffline, c.Now()); ok {
				c.Log.Warn("monitor: server unreachable", "server", srv.Name, "err", err)
			}
		} else {
			c.Log.Warn("monitor: connect", "server", srv.Name, "err", err)
		}
		return
	}
	defer ex.Close()
	// The timeout closes the connection too: a server that went silent
	// mid-command must not hold up the round, and with it every server.
	stop := context.AfterFunc(cctx, func() { ex.Close() })
	defer stop()
	ro := remote.ReadOnly(ex)
	if hc != nil {
		defer func() { c.finish(ctx, srv, hc.onServer(cctx, ro, sshTook)) }()
	}
	s, err := remote.ReadSample(cctx, ro)
	if err != nil {
		if ctx.Err() == nil {
			c.Log.Warn("monitor: sample", "server", srv.Name, "err", err)
		}
		return
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
		return
	}
	if hc == nil && !busy {
		if ok, _ := c.Store.SwapServerState(ctx, srv.ID, []model.ServerState{model.StateOffline}, model.StateHealthy, now); ok {
			c.Log.Info("monitor: server reachable again", "server", srv.Name)
		}
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
