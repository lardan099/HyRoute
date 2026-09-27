package app

import (
	"sort"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/procinfo"
)

// RunningApps lists running programs for the rule editor: those matching
// query (file name, description or path, any case; empty = all), windowed
// programs first, Windows' own last. Without all, background programs of
// Windows are left out. At most limit entries (0 = no limit).
func (c *Controller) RunningApps(query string, all bool, limit int) []procinfo.Running {
	list := c.runningList()
	q := strings.ToLower(strings.TrimSpace(query))
	q = strings.TrimSuffix(q, ".exe")
	type scored struct {
		r     procinfo.Running
		score int
	}
	var hits []scored
	for _, r := range list {
		name := strings.ToLower(r.Name)
		if name == "hysteria.exe" || strings.HasPrefix(name, "hyroute") {
			continue
		}
		if r.System && !r.Windowed && !all && q == "" {
			continue
		}
		stem := strings.TrimSuffix(name, ".exe")
		desc := strings.ToLower(r.Description)
		s := 0
		switch {
		case q == "":
		case strings.HasPrefix(stem, q):
			s = 30
		case strings.Contains(stem, q):
			s = 20
		case strings.Contains(desc, q):
			s = 15
		case strings.Contains(strings.ToLower(r.Path), q):
			s = 5
		default:
			continue
		}
		if r.Windowed {
			s += 10
		}
		if r.System {
			s -= 12
		}
		hits = append(hits, scored{r, s})
	}
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return strings.ToLower(hits[i].r.Name) < strings.ToLower(hits[j].r.Name)
	})
	out := make([]procinfo.Running, 0, len(hits))
	for _, h := range hits {
		if limit > 0 && len(out) == limit {
			break
		}
		out = append(out, h.r)
	}
	return out
}

// runningList snapshots processes at most every 2 s (typing asks often).
func (c *Controller) runningList() []procinfo.Running {
	if c.ListRunning == nil {
		return nil
	}
	c.runMu.Lock()
	defer c.runMu.Unlock()
	if c.runList == nil || time.Since(c.runAt) > 2*time.Second {
		c.runList, c.runAt = c.ListRunning(), time.Now()
	}
	return c.runList
}
