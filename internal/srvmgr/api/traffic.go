package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// trafficPeriods are the periods of the traffic page (hours are kept 90
// days).
var trafficPeriods = map[string]time.Duration{
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
	"90d": 90 * 24 * time.Hour,
}

type trafficHourJSON struct {
	Hour time.Time `json:"t"`
	Tx   int64     `json:"tx"`
	Rx   int64     `json:"rx"`
}

type userTrafficJSON struct {
	User string `json:"user"`
	Tx   int64  `json:"tx"`
	Rx   int64  `json:"rx"`
}

type trafficJSON struct {
	Period string    `json:"period"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	// Enabled: the current config turns the stats API on.
	Enabled bool `json:"enabled"`
	// Hours are the totals of all users per hour (hours without traffic
	// are left out), oldest first.
	Hours []trafficHourJSON `json:"hours"`
	// Users are the totals of the period per user, the busiest first.
	Users []userTrafficJSON `json:"users"`
}

// serverTraffic is the stored traffic of a server: ?period=24h … 90d.
func (s *server) serverTraffic(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	d, ok := trafficPeriods[period]
	if !ok {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "Период: 24h, 7d, 30d или 90d."})
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	to := time.Now().UTC()
	from := to.Add(-d).Truncate(time.Hour)
	hs, err := s.Store.Traffic(r.Context(), id, from, to.Add(time.Second))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := trafficJSON{Period: period, From: from, To: to, Hours: []trafficHourJSON{}, Users: []userTrafficJSON{}}
	if cfg, err := s.statsConfig(r.Context(), id); err == nil {
		out.Enabled = cfg.TrafficStats.Listen != ""
	}
	users := map[string]*userTrafficJSON{}
	for _, h := range hs {
		if n := len(out.Hours); n == 0 || !out.Hours[n-1].Hour.Equal(h.Hour) {
			out.Hours = append(out.Hours, trafficHourJSON{Hour: h.Hour})
		}
		last := &out.Hours[len(out.Hours)-1]
		last.Tx, last.Rx = last.Tx+h.Tx, last.Rx+h.Rx
		u := users[h.User]
		if u == nil {
			u = &userTrafficJSON{User: h.User}
			users[h.User] = u
		}
		u.Tx, u.Rx = u.Tx+h.Tx, u.Rx+h.Rx
	}
	for _, u := range users {
		out.Users = append(out.Users, *u)
	}
	slices.SortFunc(out.Users, func(a, b userTrafficJSON) int {
		if x, y := a.Tx+a.Rx, b.Tx+b.Rx; x != y {
			if x > y {
				return -1
			}
			return 1
		}
		return strings.Compare(a.User, b.User)
	})
	writeJSON(w, http.StatusOK, out)
}

// statsConfig is the server's current config (secrets and all).
func (s *server) statsConfig(ctx context.Context, id int64) (*hyconfig.Server, error) {
	_, b, err := s.editor().Current(ctx, id)
	if err != nil {
		return nil, err
	}
	return hyconfig.ParseServer(b)
}

var errStatsOff = &Error{Status: http.StatusConflict, Code: "stats_off", Message: "Статистика трафика выключена: включите её в редакторе конфига (флажок «Статистика трафика»)."}

func statsError(err error) error {
	switch {
	case errors.Is(err, remote.ErrNoCurl):
		return &Error{Status: http.StatusConflict, Code: "no_curl", Message: "На сервере нет curl: панель читает статистику Hysteria через него. Установите curl (apt install curl)."}
	case errors.Is(err, remote.ErrStatsDown):
		return &Error{Status: http.StatusConflict, Code: "stats_down", Message: "API статистики Hysteria не отвечает: служба остановлена или ещё запускается."}
	case errors.Is(err, remote.ErrStatsAuth):
		return &Error{Status: http.StatusConflict, Code: "stats_auth", Message: "API статистики Hysteria не принял секрет: конфиг на сервере отличается от того, что знает панель. Импортируйте сервер заново."}
	}
	return mapError(err)
}

// readLive asks the server's stats API for path over SSH.
func (s *server) readLive(w http.ResponseWriter, r *http.Request, path remote.StatsPath) ([]byte, bool) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return nil, false
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	cfg, err := s.statsConfig(r.Context(), id)
	if err != nil {
		s.fail(w, r, configError(err))
		return nil, false
	}
	ts := cfg.TrafficStats
	if ts.Listen == "" {
		writeError(w, errStatsOff)
		return nil, false
	}
	if _, err := remote.StatsURL(ts.Listen, path); err != nil {
		writeError(w, &Error{Status: http.StatusConflict, Code: "stats_exposed", Message: "API статистики в конфиге слушает не только 127.0.0.1, и панель к нему не обращается. Сохраните конфиг с флажком «Статистика трафика»: API перенесётся на 127.0.0.1.", Details: ts.Listen})
		return nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), statusTimeout)
	defer cancel()
	ex, err := s.Connect.Connect(ctx, id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return nil, false
	}
	defer ex.Close()
	b, err := remote.ReadStats(ctx, remote.ReadOnly(ex), ts.Listen, ts.Secret, path)
	if err != nil {
		s.fail(w, r, statsError(err))
		return nil, false
	}
	return b, true
}

type onlineJSON struct {
	User        string `json:"user"`
	Connections int    `json:"connections"`
}

// trafficOnline is who is online now (live, not stored).
func (s *server) trafficOnline(w http.ResponseWriter, r *http.Request) {
	b, ok := s.readLive(w, r, remote.StatsOnline)
	if !ok {
		return
	}
	m, err := remote.ParseOnline(b)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]onlineJSON, 0, len(m))
	for u, n := range m {
		out = append(out, onlineJSON{u, n})
	}
	slices.SortFunc(out, func(a, b onlineJSON) int { return strings.Compare(a.User, b.User) })
	writeJSON(w, http.StatusOK, map[string]any{"at": time.Now().UTC(), "users": out})
}

// maxStreams bounds the answer (a busy server has thousands).
const maxStreams = 500

// trafficStreams are the open streams with where they go: live only,
// never stored, for the roles that may change servers.
func (s *server) trafficStreams(w http.ResponseWriter, r *http.Request) {
	b, ok := s.readLive(w, r, remote.StatsStreams)
	if !ok {
		return
	}
	ss, err := remote.ParseStreams(b)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The busiest first.
	slices.SortFunc(ss, func(a, b remote.Stream) int {
		x, y := a.Tx+a.Rx, b.Tx+b.Rx
		switch {
		case x > y:
			return -1
		case x < y:
			return 1
		}
		return a.Since.Compare(b.Since)
	})
	total := len(ss)
	ss = ss[:min(total, maxStreams)]
	writeJSON(w, http.StatusOK, map[string]any{"at": time.Now().UTC(), "total": total, "streams": ss})
}
