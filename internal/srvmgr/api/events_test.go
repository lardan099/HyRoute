package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Any logged-in user reads the events and the summary; nobody else.
func TestEventsAndAttention(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner := e.setupOwner()
	u := model.User{Username: "viewer", Role: model.RoleReadOnly, Scope: model.Scope{All: true}}
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	if err := e.db.CreateUser(ctx, &u); err != nil {
		t.Fatal(err)
	}
	viewer := e.login("viewer")

	s := model.Server{Name: "Alpha", Host: "198.51.100.9", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateOffline}
	if err := e.db.CreateServer(ctx, &s, nil); err != nil {
		t.Fatal(err)
	}
	bus := &events.Bus{Store: e.db}
	w := &events.Watcher{Bus: bus, Threshold: 1}
	w.Disk(ctx, s, 95, 100)
	w.Disk(ctx, s, 10, 100)
	w.Network(ctx, false)

	rec := viewer.do("GET", "/api/v1/events", nil, nil)
	var list []eventJSON
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list) != 2 || list[0].Kind != model.EventNetwork || list[1].ClosedAt == nil || list[1].CloseText == "" {
		t.Fatalf("events %d %s", rec.Code, rec.Body)
	}
	rec = viewer.do("GET", "/api/v1/events?open=1", nil, nil)
	if json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list) != 1 || list[0].ClosedAt != nil {
		t.Fatalf("open events %s", rec.Body)
	}
	code(t, e.client().do("GET", "/api/v1/events", nil, nil), http.StatusUnauthorized, "unauthorized")
	code(t, e.client().do("GET", "/api/v1/attention", nil, nil), http.StatusUnauthorized, "unauthorized")

	// Without a summary: an empty one.
	rec = owner.do("GET", "/api/v1/attention", nil, nil)
	var att attentionJSON
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &att) != nil || att.Items == nil || len(att.Items) != 0 || att.Network != nil {
		t.Fatalf("empty attention %d %s", rec.Code, rec.Body)
	}
	e.h = New(Deps{Store: e.db, Auth: e.auth, Attention: &events.Attention{Store: e.db, Monitoring: true, Now: time.Now}})
	rec = viewer.do("GET", "/api/v1/attention", nil, nil)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &att) != nil || att.Network == nil || !att.Monitoring || len(att.Items) != 1 ||
		att.Items[0].Kind != "server" || att.Items[0].Name != "Alpha" || att.Items[0].SubjectID != s.ID {
		t.Fatalf("attention %d %s", rec.Code, rec.Body)
	}
}
