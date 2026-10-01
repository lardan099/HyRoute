package monitor

import (
	"context"
	"errors"
	"fmt"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// The stats API counts bytes per user since Hysteria started. The
// collector keeps the last counters of each server and stores the growth
// per hour. The process is told by its MainPID and start time: after a
// restart the counters begin again at zero, so all of them is growth. The
// first read after the controller starts only sets the counters.

// counters are the last counters read from a server's stats API.
type counters struct {
	proc  string // the Hysteria process they belong to
	users map[string]remote.UserTraffic
}

// readTraffic reads the stats API of a server whose current config turns
// it on and stores the growth since the last read.
func (c *Collector) readTraffic(ctx context.Context, srv model.Server, ex remote.Executor) {
	in, err := c.Store.Installation(ctx, srv.ID)
	if err != nil {
		return
	}
	cfg := c.config(ctx, srv.ID)
	if cfg == nil || cfg.TrafficStats.Listen == "" {
		c.forget(srv.ID)
		return
	}
	u, err := remote.Unit(ctx, ex, in.Unit)
	if err != nil || u.ActiveState != "active" || u.MainPID == 0 {
		return // not running: nothing to read, the counters will restart
	}
	b, err := remote.ReadStats(ctx, ex, cfg.TrafficStats.Listen, cfg.TrafficStats.Secret, remote.StatsTraffic)
	if err == nil {
		var cur map[string]remote.UserTraffic
		if cur, err = remote.ParseTraffic(b); err == nil {
			err = c.addTraffic(ctx, srv.ID, fmt.Sprintf("%d@%d", u.MainPID, u.ActiveEnter), cur)
		}
	}
	if err != nil && ctx.Err() == nil {
		level := c.Log.Warn
		if errors.Is(err, remote.ErrStatsDown) {
			level = c.Log.Info // Hysteria starting, or an older one without the API
		}
		level("monitor: traffic stats", "server", srv.Name, "err", err)
	}
}

// addTraffic stores the growth of the counters cur of process proc.
func (c *Collector) addTraffic(ctx context.Context, serverID int64, proc string, cur map[string]remote.UserTraffic) error {
	c.mu.Lock()
	prev, had := c.traffic[serverID]
	c.traffic[serverID] = counters{proc, cur}
	c.mu.Unlock()
	if !had {
		return nil // only the counters: what came before is unknown
	}
	restarted := prev.proc != proc
	grow := map[string]model.TrafficHour{}
	for user, t := range cur {
		p := prev.users[user]
		if restarted || t.Tx < p.Tx || t.Rx < p.Rx {
			p = remote.UserTraffic{}
		}
		grow[user] = model.TrafficHour{Tx: int64(t.Tx - p.Tx), Rx: int64(t.Rx - p.Rx)}
	}
	return c.Store.AddTraffic(ctx, serverID, c.Now(), grow)
}

// forget drops a server's counters (stats off: the next start begins
// with fresh ones).
func (c *Collector) forget(serverID int64) {
	c.mu.Lock()
	delete(c.traffic, serverID)
	c.mu.Unlock()
}
