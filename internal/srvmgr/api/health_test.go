package api

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func TestHealthAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)

	rec = owner.do("GET", "/api/v1/servers/"+id+"/health", nil, nil)
	var out serverHealthJSON
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.Latest != nil || len(out.Changes) != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	// healthy, healthy, degraded, degraded, healthy (oldest first)
	now := time.Now().Truncate(time.Second)
	for i, st := range []model.ServerState{model.StateHealthy, model.StateHealthy, model.StateDegraded, model.StateDegraded, model.StateHealthy} {
		h := model.Health{ServerID: srv.ID, At: now.Add(time.Duration(i-5) * time.Minute), Status: st, UDP: model.UDPOK}
		if st == model.StateDegraded {
			h.Reason, h.UDP = "UDP 443 не отвечает снаружи.", model.UDPNoAnswer
		}
		e.db.AddHealth(ctx, h)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id+"/health", nil, nil)
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.Latest == nil || out.Latest.Status != model.StateHealthy || len(out.Changes) != 3 ||
		out.Changes[1].Status != model.StateDegraded || out.Changes[2].Status != model.StateHealthy {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
