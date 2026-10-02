package geo

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// DefaultInterval is how often the controller looks for a newer release
// (Loyalsoldier publishes daily; Hysteria itself updates weekly).
const DefaultInterval = 7 * 24 * time.Hour

// ScheduleDB is what the schedule reads.
type ScheduleDB interface {
	ListServers(ctx context.Context) ([]model.Server, error)
	CurrentConfig(ctx context.Context, serverID int64) (model.ServerConfig, error)
	Installation(ctx context.Context, serverID int64) (model.Installation, error)
	ServerGeo(ctx context.Context, serverID int64) (model.ServerGeo, error)
}

// Scheduler keeps the databases fresh: once Interval has passed since the
// last look it downloads a newer release to the controller, and it queues
// the geo job (source auto) for the servers that are due. A failed job
// leaves the server's files as they were; the server is not tried again
// for the same release (until the controller restarts).
type Scheduler struct {
	Files    *Store
	Jobs     *Installer
	DB       ScheduleDB
	Keys     *secrets.Keyring
	Interval time.Duration // DefaultInterval if 0
	Tick     time.Duration // how often to look; an hour if 0
	Now      func() time.Time
	Log      *slog.Logger

	mu    sync.Mutex
	tried map[int64]string // server → release queued for it
}

func (s *Scheduler) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// Run looks every Tick until ctx ends.
func (s *Scheduler) Run(ctx context.Context) {
	tick := s.Tick
	if tick == 0 {
		tick = time.Hour
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		s.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Scheduler) log() *slog.Logger {
	if s.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Log
}

// Round is one look: a newer release when it is time, then the jobs. It
// returns the servers it queued a job for.
func (s *Scheduler) Round(ctx context.Context) []int64 {
	info, err := s.Files.Info()
	if err != nil || info.Release == "" {
		return nil // the first download is the admin's
	}
	interval := s.Interval
	if interval == 0 {
		interval = DefaultInterval
	}
	if s.now().Sub(info.CheckedAt) >= interval {
		next, changed, err := s.Files.Update(ctx)
		if err != nil {
			s.log().Warn("geo databases: no update", "err", err)
		} else {
			info = next
			if changed {
				s.log().Info("geo databases updated", "release", info.Release)
			}
		}
	}
	due, err := s.Due(ctx, info.Release)
	if err != nil {
		s.log().Warn("geo databases: servers not listed", "err", err)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tried == nil {
		s.tried = map[int64]string{}
	}
	var queued []int64
	for _, id := range due {
		if s.tried[id] == info.Release {
			continue
		}
		j, err := s.Jobs.Submit(ctx, id, SourceAuto, 0, 0)
		switch {
		case errors.Is(err, jobs.ErrBusy):
			continue // the next look
		case err != nil:
			s.log().Warn("geo databases: job not queued", "server", id, "err", err)
		default:
			s.log().Info("geo databases: job queued", "server", id, "job", j.ID, "release", info.Release)
			queued = append(queued, id)
		}
		s.tried[id] = info.Release
	}
	return queued
}

// Due are the servers to bring to release: HyRoute put databases there
// before, the config still reads them, and it has geo rules (or its rules
// are in a file HyRoute does not read).
func (s *Scheduler) Due(ctx context.Context, release string) ([]int64, error) {
	servers, err := s.DB.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	var due []int64
	for _, srv := range servers {
		g, err := s.DB.ServerGeo(ctx, srv.ID)
		if errors.Is(err, store.ErrNotFound) || err == nil && g.Release == release {
			continue
		} else if err != nil {
			return nil, err
		}
		if _, err := s.DB.Installation(ctx, srv.ID); err != nil {
			continue
		}
		cur, err := s.DB.CurrentConfig(ctx, srv.ID)
		if err != nil {
			continue
		}
		b, err := s.Keys.Open(cur.Sealed, model.ConfigContext(srv.ID, cur.Revision))
		if err != nil {
			continue
		}
		c, err := hyconfig.ParseServer(b)
		if err != nil || c.ACL.GeoIP != ServerDir+"/"+GeoIP || c.ACL.GeoSite != ServerDir+"/"+GeoSite {
			continue
		}
		if UsesGeo(c) || c.ACL.File != "" {
			due = append(due, srv.ID)
		}
	}
	return due, nil
}
