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
	code(t, owner.do("POST", "/api/v1/chains", map[string]any{"name": "x", "nodes": ids, "link": map[string]any{"checkTarget": "a;b:22"}}, nil), http.StatusBadRequest, "invalid")
	rec := owner.do("POST", "/api/v1/chains", map[string]any{"name": "Через Германию", "notes": "n", "nodes": ids, "link": map[string]any{"up": "50 mbps", "down": "100 mbps", "noUdp": true}}, nil)
	var ch chainJSON
	json.Unmarshal(rec.Body.Bytes(), &ch)
	if rec.Code != http.StatusCreated || ch.State != model.LinkNew || len(ch.Nodes) != 2 || ch.Nodes[0].Name != "Entry" || ch.Nodes[0].Role != model.RoleEntry ||
		ch.Nodes[1].Role != model.RoleExit || len(ch.Links) != 1 || ch.Links[0].From != ids[0] || ch.Links[0].To != ids[1] ||
		ch.Links[0].Params.Up != "50 mbps" || !ch.Links[0].Params.NoUDP {
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

	// Deploying the link is a job on both servers; it needs to know where
	// Hysteria is on them.
	code(t, owner.do("POST", "/api/v1/chains/"+id+"/link", nil, nil), http.StatusConflict, "no_installation")
	for _, sid := range ids {
		e.db.SetInstallation(ctx, model.Installation{ServerID: sid, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", At: time.Now()})
	}
	code(t, viewer.do("POST", "/api/v1/chains/"+id+"/link", nil, nil), http.StatusForbidden, "forbidden")
	rec = owner.do("POST", "/api/v1/chains/"+id+"/link", nil, nil)
	var job jobJSON
	json.Unmarshal(rec.Body.Bytes(), &job)
	if rec.Code != http.StatusAccepted || job.Kind != "link" || job.ServerID != ids[0] || len(job.Servers) != 1 || job.Servers[0] != ids[1] {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if sealed, _ := e.db.LinkSecrets(ctx, ch.ID, 0); len(sealed) == 0 {
		t.Fatal("no link secrets")
	}
	code(t, owner.do("POST", "/api/v1/chains/"+id+"/link", nil, nil), http.StatusConflict, "server_busy")
	code(t, owner.do("DELETE", "/api/v1/servers/"+strconv.FormatInt(ids[0], 10), nil, nil), http.StatusConflict, "server_busy")
	queued, _ := e.db.JobByID(ctx, job.ID)
	queued.State = model.JobFailed
	e.db.UpdateJob(ctx, queued)

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
