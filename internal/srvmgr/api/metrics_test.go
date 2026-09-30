package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func TestMetricsAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	now := time.Now().UTC().Truncate(time.Second)
	cpu := 12.5
	e.db.AddMetric(ctx, model.Metric{ServerID: srv.ID, At: now.Add(-3 * time.Hour), Load1: 1, MemTotalMiB: 1024})
	e.db.AddMetric(ctx, model.Metric{ServerID: srv.ID, At: now.Add(-time.Minute), CPU: &cpu, Load1: 2, MemTotalMiB: 1024})

	rec = owner.do("GET", "/api/v1/servers/"+id+"/metrics?period=1h", nil, nil)
	var s seriesJSON
	json.Unmarshal(rec.Body.Bytes(), &s)
	if rec.Code != 200 || s.Step != 0 || len(s.Points) != 1 || *s.Points[0].CPU != 12.5 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id+"/metrics", nil, nil) // 6h
	json.Unmarshal(rec.Body.Bytes(), &s)
	if rec.Code != 200 || s.Period != "6h" || len(s.Points) != 2 || s.Points[0].CPU != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id+"/metrics?period=30d", nil, nil)
	json.Unmarshal(rec.Body.Bytes(), &s)
	if rec.Code != 200 || s.Step != model.MetricStep {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/metrics?period=1y", nil, nil), http.StatusBadRequest, "bad_request")
	code(t, owner.do("GET", "/api/v1/servers/999/metrics", nil, nil), http.StatusNotFound, "not_found")

	rec = owner.do("GET", "/api/v1/metrics/latest", nil, nil)
	var latest []latestJSON
	json.Unmarshal(rec.Body.Bytes(), &latest)
	if rec.Code != 200 || len(latest) != 1 || latest[0].ServerID != srv.ID || latest[0].Load1 != 2 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
