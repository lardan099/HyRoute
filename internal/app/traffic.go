package app

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/traffic"
)

// VPN traffic statistics (traffic.json): bytes per server and per program,
// never the sites. Live flows are sampled every trafficSample, and the file
// is written every trafficFlush and when routing stops.

var (
	trafficSample = 10 * time.Second
	trafficFlush  = time.Minute
)

type trafficState struct {
	once  sync.Once
	stats *traffic.Stats
	loop  sync.Once
}

func (c *Controller) trafficStats() *traffic.Stats {
	c.traffic.once.Do(func() {
		path := "" // no store: in memory only
		if c.Store != nil {
			path = filepath.Join(c.Store.Dir, "traffic.json")
		}
		c.traffic.stats = traffic.Open(path)
	})
	return c.traffic.stats
}

// noteTraffic counts tunneled bytes of a server and a program.
func (c *Controller) noteTraffic(profile, app string, sent, recv int64) {
	if profile == "" || profile == stubProfile {
		return
	}
	c.trafficStats().Add(profile, c.profileName(profile), app, sent, recv)
}

// startTrafficLoop samples the live flows while connected (started with the
// first session, runs until HyRoute exits).
func (c *Controller) startTrafficLoop() {
	c.traffic.loop.Do(func() {
		go func() {
			t := time.NewTicker(trafficSample)
			defer t.Stop()
			last := time.Now()
			for range t.C {
				c.sampleTraffic()
				if time.Since(last) >= trafficFlush {
					last = time.Now()
					c.flushTraffic()
				}
			}
		}()
	})
}

func (c *Controller) sampleTraffic() {
	c.mu.Lock()
	reg, live := c.lastFlows, c.sess != nil
	c.mu.Unlock()
	if live && reg != nil {
		reg.Sample()
	}
}

func (c *Controller) flushTraffic() {
	if err := c.trafficStats().Flush(); err != nil {
		c.Log.Warn("traffic statistics not saved", "err", err)
	}
}

// TrafficReport is the statistics for «Статистика»: period day | week |
// month | year.
func (c *Controller) TrafficReport(period string) traffic.Report {
	c.sampleTraffic()
	return c.trafficStats().Report(period, c.profileName)
}

// ClearTraffic forgets the statistics.
func (c *Controller) ClearTraffic() error {
	c.sampleTraffic() // what live flows moved so far is not counted again
	return c.trafficStats().Clear()
}
