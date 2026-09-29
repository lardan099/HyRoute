package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/stats"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// Traffic statistics («Статистика», internal/stats): the collector, its
// goroutine (RunStats: sampler, flushes, compaction), the source of each
// session and the flow records of the local proxies.
//
// Locks: the collector's own lock is a leaf. Its I/O lock is never taken
// or waited for with a Controller lock held (lifeMu included): the
// Disconnect path only samples in memory and kicks RunStats, and the
// backup functions below are called with no Controller lock held.

const (
	statsSampleEvery = 5 * time.Second
	statsFlushEvery  = 5 * time.Minute
	statsCompactWait = time.Minute // first compaction after start: keep startup light
	statsEndWait     = time.Second // EndSession: longest wait for the statistics disk lock
)

// statLive is what the sampler needs from the current session; published
// atomically so that the sampler and EndSession never take c.mu.
type statLive struct {
	sess Session // Tunnels() for drop detection
	reg  *flows.Registry
	src  *stats.Source
}

type statsState struct {
	stats *stats.Collector // created in New; configured in Load
	// statLive: the current session's; stored and cleared in the c.mu
	// sections that set and clear c.sess.
	statLive   atomic.Pointer[statLive]
	statsFlush chan struct{}   // cap 1: «flush soon» (Disconnect, restore); drained by RunStats
	proxyFlows *flows.Registry // local proxy connections, controller lifetime
	proxySrc   *stats.Source
	statsOnce  sync.Once // loadStats: the first Load only (the collector is live after it)

	// Tests: statsTick replaces statsSampleEvery; statsUnlocked runs at
	// the start of the backup functions (they must hold no lock).
	statsTick     time.Duration
	statsUnlocked func()
}

func (c *Controller) initStats() {
	c.stats = stats.New(c.Log)
	c.stats.Names = c.statsName
	c.stats.LegacyProxy = c.statsLegacyProxy
	c.statsFlush = make(chan struct{}, 1)
	c.proxyFlows = flows.NewRegistry(256)
	c.proxySrc = c.stats.NewSource()
	c.proxyFlows.OnClose = c.proxySrc.Closed
}

// statsLegacyProxy maps the program name HyRoute 1.2.0 gave a local proxy
// in its statistics («Локальный прокси «имя»», «Локальный прокси :порт»)
// to that proxy's rows, when exactly one current proxy has that name.
// Called by the collector under its I/O lock (never with c.mu held: see
// the lock notes above).
func (c *Controller) statsLegacyProxy(name string) (key, label string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, p := range c.proxies {
		old := "Локальный прокси :" + strconv.Itoa(p.Port)
		if p.Name != "" {
			old = "Локальный прокси «" + p.Name + "»"
		}
		if old == name {
			key, label = proxyRecordPrefix+p.ID, proxyLabel(p)
			n++
		}
	}
	if n != 1 {
		return "", "", false
	}
	return key, label, true
}

// statsName is the current name of a server or group for the rows (""
// when unknown). Lock-free (see profileName).
func (c *Controller) statsName(id string) string {
	if n := c.profileName(id); n != id {
		return n
	}
	return ""
}

// loadStats attaches the files and reads the collection mode (the first
// Load, before RunStats starts; a later Load leaves the live collector
// alone: only the collector itself writes its files). It creates nothing.
func (c *Controller) loadStats() {
	c.statsOnce.Do(func() {
		c.stats.Log = c.Log
		if c.Store != nil {
			c.stats.Configure(c.Store.StatsFiles())
		}
	})
}

func (c *Controller) statsNow() time.Time {
	if c.stats.Now != nil {
		return c.stats.Now()
	}
	return time.Now()
}

// statsSource is the statistics source of a session that starts: the
// registry closes records into it.
func (c *Controller) statsSource(cfg *session.Config) *stats.Source {
	src := c.stats.NewSource()
	cfg.OnClose = src.Closed
	return src
}

// statsStartedLocked publishes the started session to the sampler (c.mu
// held, with c.sess).
func (c *Controller) statsStartedLocked(sess Session, src *stats.Source) {
	c.statLive.Store(&statLive{sess: sess, reg: sess.Flows(), src: src})
}

// statsStopped runs after the session stopped (lifeMu held): a last sample
// in memory (the engine does not close direct flows when it stops) and a
// kick; RunStats writes the files. No disk work under lifeMu.
func (c *Controller) statsStopped(live *statLive) {
	now := c.statsNow()
	if live != nil {
		live.src.Sample(now, live.reg)
	}
	c.proxySrc.Sample(now, c.proxyFlows)
	c.statsKick()
}

// statsShutdown writes the statistics at exit, after lifeMu was released.
func (c *Controller) statsShutdown() {
	now := c.statsNow()
	c.proxySrc.Sample(now, c.proxyFlows)
	if err := c.stats.Flush(now); err != nil {
		c.Log.Warn("stats: statistics not saved at exit", "err", err)
	}
}

// statsSessionEnd: Windows ends the session. No Controller lock (c.mu may
// be held for seconds by code waiting for Hysteria); at most statsEndWait
// for the disk lock, else the last minutes are lost as in a crash.
func (c *Controller) statsSessionEnd() {
	now := c.statsNow()
	if live := c.statLive.Load(); live != nil {
		live.src.Sample(now, live.reg)
	}
	c.proxySrc.Sample(now, c.proxyFlows)
	if err := c.stats.FlushWithin(now, statsEndWait); err != nil {
		c.Log.Warn("stats: statistics not saved at the end of the Windows session", "err", err)
	}
}

// statsKick asks RunStats to flush soon (never blocks).
func (c *Controller) statsKick() {
	select {
	case c.statsFlush <- struct{}{}:
	default:
	}
}

// sampleStats samples the session and the proxies; withServers also feeds
// the servers' statuses (drops; also in mode off and without a session,
// so that a later comparison is never with a stale state). No Controller
// lock.
func (c *Controller) sampleStats(now time.Time, withServers bool) {
	live := c.statLive.Load()
	if live != nil {
		live.src.Sample(now, live.reg)
	}
	if withServers {
		var list []stats.ServerState
		if live != nil {
			for _, t := range live.sess.Tunnels() {
				if !t.Test {
					list = append(list, serverState(t))
				}
			}
		}
		c.stats.ServerStates(now, list)
	}
	c.proxySrc.Sample(now, c.proxyFlows)
}

func serverState(t tunnels.Status) stats.ServerState {
	return stats.ServerState{ID: t.ID, Name: t.Name, Started: t.Started, Connected: t.State == "connected", Restarts: t.Restarts}
}

// RunStats is the statistics goroutine: a sample every 5 s; a flush every
// 5 minutes, on a day change and on a kick (Disconnect, restore); the
// compaction when due, after a flush, on this goroutine only (the first
// one a minute after the start); on ctx end a best-effort flush (the exit
// flush is Shutdown's).
func (c *Controller) RunStats(ctx context.Context) {
	start := c.statsNow()
	// The first flush also imports the statistics of HyRoute 1.2.0.
	if err := c.stats.Flush(start); err != nil {
		c.Log.Warn("stats: statistics not saved", "err", err)
	}
	every := statsSampleEvery
	if c.statsTick > 0 {
		every = c.statsTick
	}
	t := time.NewTicker(every)
	defer t.Stop()
	lastFlush := start
	var lastCompact time.Time
	// dayFlushed: the day whose change was flushed already. A failed
	// flush leaves the day changed (its delta goes back); it is retried
	// at the flush pace, not at every sample.
	dayFlushed := start.In(time.Local).Format("2006-01-02")
	flush := func(now time.Time, compact bool) {
		lastFlush = now
		if err := c.stats.Flush(now); err != nil {
			c.Log.Warn("stats: statistics not saved", "err", err)
		}
		// A failing compaction is retried at the flush pace too.
		if compact && now.Sub(start) >= statsCompactWait && c.stats.CompactDue(now) && now.Sub(lastCompact) >= statsFlushEvery {
			lastCompact = now
			if err := c.stats.Compact(now); err != nil {
				c.Log.Warn("stats: compaction not finished", "err", err)
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			now := c.statsNow()
			c.sampleStats(now, false)
			if err := c.stats.Flush(now); err != nil {
				c.Log.Warn("stats: statistics not saved", "err", err)
			}
			return
		case <-c.statsFlush:
			flush(c.statsNow(), true)
		case <-t.C:
			now := c.statsNow()
			c.sampleStats(now, true)
			due := now.Sub(start) >= statsCompactWait && c.stats.CompactDue(now) && now.Sub(lastCompact) >= statsFlushEvery
			day := now.In(time.Local).Format("2006-01-02")
			dayChange := day != dayFlushed && c.stats.DayChanged(now)
			if dayChange {
				dayFlushed = day
			}
			if now.Sub(lastFlush) >= statsFlushEvery || dayChange || due {
				flush(now, true)
			}
		}
	}
}

// Stats is the report of a period (today, yesterday, 7d, 30d, YYYY-MM)
// with the current names of servers, groups and proxies; a deleted one is
// marked gone (its stored name stays).
func (c *Controller) Stats(period string) (stats.Report, error) {
	rep, err := c.stats.Report(c.statsNow(), period)
	if err != nil {
		return rep, err
	}
	c.mu.Lock()
	for i := range rep.Servers {
		r := &rep.Servers[i]
		switch p := c.profiles.Find(r.Key); {
		case r.Key == "" || r.Key == stats.Others:
		case groups.IsGroupID(r.Key):
			// A group none of whose servers was usable.
			if g := c.groupLocked(r.Key); g != nil {
				r.Name = g.Name
			} else {
				r.Gone = true
			}
		case p != nil:
			r.Name = p.Name
		case r.Key == stubProfile && c.Base.Stub:
			r.Name = "stub"
		default:
			r.Gone = true
		}
	}
	for i := range rep.Groups {
		r := &rep.Groups[i]
		if r.Key == stats.Others {
			continue
		}
		if g := c.groupLocked(r.Key); g != nil {
			r.Name = g.Name
		} else {
			r.Gone = true
		}
	}
	for i := range rep.Apps {
		r := &rep.Apps[i]
		id, ok := strings.CutPrefix(r.Key, proxyRecordPrefix)
		if !ok {
			continue
		}
		r.Gone = true
		for _, p := range c.proxies {
			if p.ID == id { // proxy IDs are case-sensitive
				r.Name, r.Gone = proxyLabel(p), false
				break
			}
		}
	}
	c.mu.Unlock()
	rep.Mode = string(c.stats.Mode())
	return rep, nil
}

// ResetStats deletes every statistic («Сбросить статистику»).
func (c *Controller) ResetStats() error {
	if err := c.stats.Reset(c.statsNow()); err != nil {
		c.Log.Warn("stats: statistics not deleted completely", "err", err)
		return err
	}
	c.Log.Info("stats: statistics deleted")
	return nil
}

// SetStatsMode sets the collection mode: "" (all), "no-sites" or "off"
// (stats\mode.json; prefs.json is not involved).
func (c *Controller) SetStatsMode(mode string) error {
	m, err := stats.ParseMode(mode)
	if err != nil {
		return err
	}
	err = c.stats.SetMode(c.statsNow(), m)
	c.Log.Info("stats: collection mode set", "mode", m.Label())
	return err
}

// statsDiagLines is the diagnostics line: the mode and what is wrong with
// the files (file names only, never sites or programs).
func (c *Controller) statsDiagLines() []string {
	l := "   статистика: сбор " + c.stats.Mode().Label()
	if e := c.stats.StoreError(); e != "" {
		l += "; файлы: " + e
	}
	return []string{l}
}

// ---- backup (all four are called with no Controller lock held: they
// take the statistics' disk lock) ----

func (c *Controller) statsCheckUnlocked() {
	if c.statsUnlocked != nil {
		c.statsUnlocked()
	}
}

// StatsBackupInfo is the detail of the export dialog, from the files and
// the mode («с 12.07.2026 · 92 дня · сбор: всё»); empty: nothing to save.
func (c *Controller) StatsBackupInfo() (detail string, empty bool) {
	c.statsCheckUnlocked()
	return c.stats.Summary(c.statsNow())
}

// ExportStats flushes, then returns the section (≤ stats.MaxExport), its
// detail and whether the oldest days were left out for size.
func (c *Controller) ExportStats() (json.RawMessage, string, bool, error) {
	c.statsCheckUnlocked()
	return c.stats.Export(c.statsNow())
}

// CheckStatsImport validates a section completely without writing
// anything; the detail is for the preview.
func (c *Controller) CheckStatsImport(raw json.RawMessage) (string, error) {
	c.statsCheckUnlocked()
	return c.stats.CheckImport(c.statsNow(), raw)
}

// ReplaceStats validates again and replaces the statistics (files of a
// newer version and future ones kept, unflushed deltas kept, the stricter
// mode), then kicks RunStats to flush and compact.
func (c *Controller) ReplaceStats(raw json.RawMessage) error {
	c.statsCheckUnlocked()
	err := c.stats.Replace(c.statsNow(), raw)
	c.statsKick()
	return err
}

// ---- local proxies ----

// proxyRecordPrefix is the Path of a proxy's records: the statistics
// count them as the program «Прокси «имя»».
const proxyRecordPrefix = "proxy:"

// proxyLabel names a proxy in the statistics.
func proxyLabel(p store.LocalProxy) string {
	if p.Name != "" {
		return p.Name
	}
	return "порт " + strconv.Itoa(p.Port)
}

// proxyRecord opens the statistics record of a local proxy connection
// (proto 6) or UDP association (17) through profile (member of group
// when set). A refusal (outcome "rst: …") is closed at once: counted as
// a failed connection.
func (c *Controller) proxyRecord(p store.LocalProxy, proto uint8, dst socks5.Addr, profile, group string, failover bool, outcome string) *flows.Record {
	r := &flows.Record{Proto: proto, Process: proxyLabel(p), Path: proxyRecordPrefix + p.ID}
	if dst.Host == "" && dst.IP.IsValid() {
		r.Dst = netip.AddrPortFrom(dst.IP, dst.Port)
	}
	rec := c.proxyFlows.Open(r)
	rec.Set(func(f *flows.Fields) {
		f.Route, f.Profile, f.Group, f.Failover, f.Outcome = "tunnel", profile, group, failover, outcome
		f.DomainSrc = "proxy"
		if dst.Host != "" {
			f.Domain = rules.NormalizeDomain(dst.Host)
		}
	})
	if strings.HasPrefix(outcome, "rst: ") {
		c.proxyFlows.Close(rec, time.Now())
	}
	return rec
}

// proxyDialStopped: a local proxy's dial failed because the proxy is
// stopping (its context cancelled, not timed out). That is not a refusal
// of the server: neither the server's refusals nor the statistics count
// it, as the relay's «aborted: stopping».
func proxyDialStopped(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.Canceled)
}

// refusedVia is the server a refused group connection is counted under:
// the member chosen, or the group itself when none was usable (as the
// engine records it).
func refusedVia(pk groups.Pick, gid string) string {
	if pk.Member != "" {
		return pk.Member
	}
	return gid
}

// flowCloser closes a proxy's record once (a connection may be closed by
// both sides of a pipe).
type flowCloser struct {
	rec  *flows.Record
	reg  *flows.Registry
	once sync.Once
}

func (f *flowCloser) close() {
	if f == nil || f.rec == nil {
		return
	}
	f.once.Do(func() { f.reg.Close(f.rec, time.Now()) })
}
