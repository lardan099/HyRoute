package api

import (
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// periods the metrics page offers; up to two days are samples, longer
// ones 15-minute averages (the samples are gone by then).
var periods = map[string]time.Duration{
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
	"48h": 48 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

type pointJSON struct {
	At        time.Time `json:"t"`
	CPU       *float64  `json:"cpu"`
	MemUsed   float64   `json:"memUsed"`
	MemTotal  float64   `json:"memTotal"`
	DiskUsed  float64   `json:"diskUsed"`
	DiskTotal float64   `json:"diskTotal"`
	Load1     float64   `json:"load1"`
	Rx        *float64  `json:"rx"`
	Tx        *float64  `json:"tx"`
}

func toPoint(m model.Metric) pointJSON {
	return pointJSON{At: m.At, CPU: m.CPU, MemUsed: m.MemUsedMiB, MemTotal: m.MemTotalMiB, DiskUsed: m.DiskUsedMiB, DiskTotal: m.DiskTotalMiB, Load1: m.Load1, Rx: m.RxBps, Tx: m.TxBps}
}

type seriesJSON struct {
	Period string      `json:"period"`
	Step   int         `json:"step"` // 0: samples; else seconds per average
	From   time.Time   `json:"from"`
	To     time.Time   `json:"to"`
	Points []pointJSON `json:"points"`
}

// serverMetrics is the monitoring series of a server: ?period=1h … 30d.
func (s *server) serverMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "6h"
	}
	d, ok := periods[period]
	if !ok {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "Период: 1h, 6h, 24h, 48h, 7d или 30d."})
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	to := time.Now().UTC()
	from := to.Add(-d)
	step := 0
	if d > 48*time.Hour {
		step = model.MetricStep
	}
	ms, err := s.Store.Metrics(r.Context(), id, step, from, to.Add(time.Second))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := seriesJSON{Period: period, Step: step, From: from, To: to, Points: make([]pointJSON, 0, len(ms))}
	for _, m := range ms {
		out.Points = append(out.Points, toPoint(m))
	}
	writeJSON(w, http.StatusOK, out)
}

type latestJSON struct {
	ServerID int64 `json:"serverId"`
	pointJSON
}

// latestMetrics is the newest sample of every server in the caller's
// scope from the last five minutes (the Overview).
func (s *server) latestMetrics(w http.ResponseWriter, r *http.Request) {
	ms, err := s.Store.LatestMetrics(r.Context(), time.Now().Add(-5*time.Minute))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	set, err := s.scopeSet(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]latestJSON, 0, len(ms))
	for _, m := range ms {
		if !set.has(m.ServerID) {
			continue
		}
		out = append(out, latestJSON{ServerID: m.ServerID, pointJSON: toPoint(m)})
	}
	writeJSON(w, http.StatusOK, out)
}
