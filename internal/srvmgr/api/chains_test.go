package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func TestChainsAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	var ids []int64
	for i, name := range []string{"Entry", "Exit"} {
		rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": name, "host": "192.0.2.9" + strconv.Itoa(i), "authType": "password", "password": fakeSSHPass}, nil)
		var srv serverJSON
		json.Unmarshal(rec.Body.Bytes(), &srv)
		if rec.Code != http.StatusCreated || srv.Role != model.RoleStandalone {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Meta: model.ConfigMeta{Auth: "password"}, Source: model.ConfigDeploy, At: time.Now()}
		e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) {
			return e.keys.Seal([]byte("auth: {type: password}"), model.ConfigContext(srv.ID, rev))
		})
		ids = append(ids, srv.ID)
	}
	// The role is no longer entered by hand.
	code(t, owner.do("PATCH", "/api/v1/servers/"+strconv.FormatInt(ids[0], 10), map[string]any{"name": "Entry", "host": "192.0.2.90", "authType": "password", "role": "exit"}, nil), http.StatusBadRequest, "bad_request")

	code(t, owner.do("POST", "/api/v1/chains", map[string]any{"name": "x", "nodes": []int64{ids[0]}}, nil), http.StatusBadRequest, "invalid")
	rec := owner.do("POST", "/api/v1/chains", map[string]any{"name": "Через Германию", "notes": "n", "nodes": ids}, nil)
	var ch chainJSON
	json.Unmarshal(rec.Body.Bytes(), &ch)
	if rec.Code != http.StatusCreated || ch.State != model.LinkNew || len(ch.Nodes) != 2 || ch.Nodes[0].Name != "Entry" || ch.Nodes[0].Role != model.RoleEntry ||
		ch.Nodes[1].Role != model.RoleExit || len(ch.Links) != 1 || ch.Links[0].From != ids[0] || ch.Links[0].To != ids[1] {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	id := strconv.FormatInt(ch.ID, 10)
	code(t, owner.do("POST", "/api/v1/chains", map[string]any{"name": "back", "nodes": []int64{ids[1], ids[0]}}, nil), http.StatusBadRequest, "invalid")

	// Roles show on the servers; a server of a chain is not deleted.
	rec = owner.do("GET", "/api/v1/servers/"+strconv.FormatInt(ids[1], 10), nil, nil)
	if !strings.Contains(rec.Body.String(), `"role":"exit"`) {
		t.Fatalf("exit role: %s", rec.Body)
	}
	code(t, owner.do("DELETE", "/api/v1/servers/"+strconv.FormatInt(ids[1], 10), nil, nil), http.StatusConflict, "chain_member")

	// Read-only sees chains, changes none.
	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	viewer := e.login("viewer")
	if rec = viewer.do("GET", "/api/v1/chains", nil, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Через Германию") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, viewer.do("PATCH", "/api/v1/chains/"+id, map[string]any{"name": "y"}, nil), http.StatusForbidden, "forbidden")
	code(t, viewer.do("DELETE", "/api/v1/chains/"+id, nil, nil), http.StatusForbidden, "forbidden")

	rec = owner.do("PATCH", "/api/v1/chains/"+id, map[string]any{"name": "DE", "notes": "заметка"}, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"DE"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec = owner.do("GET", "/api/v1/chains/"+id, nil, nil); !strings.Contains(rec.Body.String(), `"notes":"заметка"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/chains/999", nil, nil), http.StatusNotFound, "not_found")

	// Deployed: the job removes it (P3-02c), not DELETE.
	c, _ := e.db.ChainByID(ctx, ch.ID)
	l := c.Links[0]
	l.State = model.LinkActive
	e.db.UpdateLink(ctx, l)
	code(t, owner.do("DELETE", "/api/v1/chains/"+id, nil, nil), http.StatusConflict, "chain_deployed")
	l.State = model.LinkNew
	e.db.UpdateLink(ctx, l)
	if rec = owner.do("DELETE", "/api/v1/chains/"+id, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec = owner.do("GET", "/api/v1/servers/"+strconv.FormatInt(ids[1], 10), nil, nil); !strings.Contains(rec.Body.String(), `"role":"standalone"`) {
		t.Fatalf("role after delete: %s", rec.Body)
	}
}
