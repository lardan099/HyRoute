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
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
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
	if !strings.Contains(rec.Body.String(), `"chains":[{"id":`+id+`,"name":"Через Германию","state":"new"}]`) {
		t.Fatalf("server chains: %s", rec.Body)
	}
	if rec = owner.do("GET", "/api/v1/servers", nil, nil); !strings.Contains(rec.Body.String(), `"chains":[{"id":`+id+`,`) {
		t.Fatalf("servers: %s", rec.Body)
	}
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
	code(t, owner.do("POST", "/api/v1/chains/"+id+"/unlink", map[string]any{"delete": true}, nil), http.StatusConflict, "not_deployed")

	// Deployed: the job removes it (P3-02c), not DELETE.
	c, _ := e.db.ChainByID(ctx, ch.ID)
	l := c.Links[0]
	l.State = model.LinkLinking
	e.db.UpdateLink(ctx, l)
	code(t, owner.do("POST", "/api/v1/chains/"+id+"/check", nil, nil), http.StatusConflict, "chain_busy")
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

// A deployed chain is deleted without the server «Удалить каскад» could
// not reach: only by owners and admins, only after that failure, and the
// request is audited. The chain lists what stays on the server.
func TestChainForceDeleteAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	var u model.User
	u.Username, u.Role = "op", model.RoleOperator
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	op := e.login("op")
	var ids []int64
	for i, name := range []string{"Entry", "Exit"} {
		rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": name, "host": "192.0.2.6" + strconv.Itoa(i), "authType": "password", "password": fakeSSHPass}, nil)
		var srv serverJSON
		json.Unmarshal(rec.Body.Bytes(), &srv)
		c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Meta: model.ConfigMeta{Auth: "userpass"}, Source: model.ConfigDeploy, At: time.Now()}
		e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) {
			return e.keys.Seal([]byte("listen: :443\nauth:\n  type: userpass\n  userpass:\n    alice: fake-force-api\n"), model.ConfigContext(srv.ID, rev))
		})
		e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", At: time.Now()})
		ids = append(ids, srv.ID)
	}
	rec := owner.do("POST", "/api/v1/chains", map[string]any{"name": "DE", "nodes": ids}, nil)
	var ch chainJSON
	json.Unmarshal(rec.Body.Bytes(), &ch)
	id := strconv.FormatInt(ch.ID, 10)
	c, _ := e.db.ChainByID(ctx, ch.ID)
	l := c.Links[0]
	l.State = model.LinkActive
	e.db.UpdateLink(ctx, l)
	// The exit got the link's user when the link was deployed.
	user := cascade.User(ch.ID, 0)
	cx := model.ServerConfig{ServerID: ids[1], SHA256: "y", Meta: model.ConfigMeta{Auth: "userpass"}, Source: model.ConfigCascade, At: time.Now()}
	e.db.AddConfig(ctx, &cx, func(rev int) ([]byte, error) {
		return e.keys.Seal([]byte("listen: :443\nauth:\n  type: userpass\n  userpass:\n    alice: fake-force-api\n    "+user+": fake-link-api\n"), model.ConfigContext(ids[1], rev))
	})
	force := map[string]any{"delete": true, "force": true}

	// Not before «Удалить каскад» failed for want of the server.
	code(t, op.do("POST", "/api/v1/chains/"+id+"/unlink", force, nil), http.StatusForbidden, "forbidden")
	code(t, owner.do("POST", "/api/v1/chains/"+id+"/unlink", force, nil), http.StatusConflict, "servers_reached")
	rec = owner.do("POST", "/api/v1/chains/"+id+"/unlink", map[string]any{"delete": true}, nil)
	var job jobJSON
	json.Unmarshal(rec.Body.Bytes(), &job)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	failed, _ := e.db.JobByID(ctx, job.ID)
	failed.State, failed.CurrentStep = model.JobFailed, "connect"
	e.db.UpdateJob(ctx, failed)
	if rec = owner.do("GET", "/api/v1/chains/"+id, nil, nil); strings.Contains(rec.Body.String(), `"unreachable"`) {
		t.Fatalf("failed with both servers reached: %s", rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/chains/"+id+"/unlink", force, nil), http.StatusConflict, "servers_reached")
	e.db.SetJobData(ctx, job.ID, map[string]string{"unreached:" + strconv.FormatInt(ids[1], 10): "1"})

	rec = owner.do("GET", "/api/v1/chains/"+id, nil, nil)
	json.Unmarshal(rec.Body.Bytes(), &ch)
	if len(ch.Unreachable) != 1 || ch.Unreachable[0].ServerID != ids[1] || ch.Unreachable[0].Name != "Exit" || ch.Unreachable[0].Role != model.RoleExit ||
		len(ch.Unreachable[0].Left) != 1 || !strings.Contains(ch.Unreachable[0].Left[0], user+" в /etc/hysteria/config.yaml") {
		t.Fatalf("%s", rec.Body)
	}
	if rec = owner.do("GET", "/api/v1/chains", nil, nil); strings.Contains(rec.Body.String(), `"unreachable"`) {
		t.Fatalf("list: %s", rec.Body)
	}
	code(t, op.do("POST", "/api/v1/chains/"+id+"/unlink", force, nil), http.StatusForbidden, "forbidden")
	code(t, owner.do("POST", "/api/v1/chains/"+id+"/unlink", map[string]any{"force": true}, nil), http.StatusBadRequest, "bad_request")
	rec = owner.do("POST", "/api/v1/chains/"+id+"/unlink", force, nil)
	json.Unmarshal(rec.Body.Bytes(), &job)
	if rec.Code != http.StatusAccepted || job.Kind != "unlink" || !strings.Contains(string(job.Params), `"force":true`) || job.ServerID != ids[0] {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	as, _ := e.db.ListAudit(ctx, 5)
	if len(as) == 0 || as[0].Action != "chain_force_delete" || as[0].Target != "chain/"+id || !strings.Contains(as[0].Details, "«DE» без «Exit»") {
		t.Fatalf("audit %+v", as)
	}

	// Its retry is for owners and admins too.
	forced, _ := e.db.JobByID(ctx, job.ID)
	forced.State = model.JobFailed
	e.db.UpdateJob(ctx, forced)
	code(t, op.do("POST", "/api/v1/jobs/"+strconv.FormatInt(job.ID, 10)+"/retry", nil, nil), http.StatusForbidden, "forbidden")
	if rec = owner.do("POST", "/api/v1/jobs/"+strconv.FormatInt(job.ID, 10)+"/retry", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("owner retry: %d %s", rec.Code, rec.Body)
	}
}

// A deployed link shows its latest check, the chain the worst of them,
// and the exit's address out while the exit sends straight out.
func TestChainHealthAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	var ids []int64
	for i, name := range []string{"Entry", "Exit"} {
		rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": name, "host": "192.0.2.7" + strconv.Itoa(i), "authType": "password", "password": fakeSSHPass}, nil)
		var srv serverJSON
		json.Unmarshal(rec.Body.Bytes(), &srv)
		c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Meta: model.ConfigMeta{Auth: "password"}, Source: model.ConfigDeploy, At: time.Now()}
		e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) {
			return e.keys.Seal([]byte("listen: :443\nauth:\n  type: password\n  password: fake-health-api\n"), model.ConfigContext(srv.ID, rev))
		})
		ids = append(ids, srv.ID)
	}
	rec := owner.do("POST", "/api/v1/chains", map[string]any{"name": "DE", "nodes": ids}, nil)
	var ch chainJSON
	json.Unmarshal(rec.Body.Bytes(), &ch)
	id := strconv.FormatInt(ch.ID, 10)
	if ch.Health != "" || ch.Links[0].Check != nil || ch.Egress != "" {
		t.Fatalf("new chain: %s", rec.Body)
	}
	c, _ := e.db.ChainByID(ctx, ch.ID)
	l := c.Links[0]
	l.State = model.LinkActive
	e.db.UpdateLink(ctx, l)
	if err := e.db.AddHealth(ctx, model.Health{ServerID: ids[1], At: time.Now(), Status: model.StateHealthy, UDP: model.UDPOK, Egress: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	e.db.AddLinkCheck(ctx, model.LinkCheck{ChainID: ch.ID, At: time.Unix(1_700_000_000, 0), Status: model.StateOffline, Reason: "сервер выхода не отвечает"})
	e.db.AddLinkCheck(ctx, model.LinkCheck{ChainID: ch.ID, At: time.Unix(1_700_000_060, 0), Status: model.StateDegraded, Reason: "не открывает", HandshakeMillis: 40})

	rec = owner.do("GET", "/api/v1/chains/"+id, nil, nil)
	json.Unmarshal(rec.Body.Bytes(), &ch)
	if ch.Health != model.StateDegraded || ch.Links[0].Check == nil || ch.Links[0].Check.HandshakeMs != 40 || ch.Egress != "203.0.113.9" {
		t.Fatalf("%s", rec.Body)
	}
	rec = owner.do("GET", "/api/v1/chains/"+id+"/checks?idx=0", nil, nil)
	var checks []linkCheckJSON
	json.Unmarshal(rec.Body.Bytes(), &checks)
	if rec.Code != http.StatusOK || len(checks) != 2 || checks[0].Status != model.StateDegraded || checks[1].Status != model.StateOffline {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/chains/"+id+"/checks?idx=5", nil, nil), http.StatusNotFound, "not_found")

	// The exit sends through an outbound of its own: its address is not
	// the chain's egress.
	cx := model.ServerConfig{ServerID: ids[1], SHA256: "y", Source: model.ConfigEdit, At: time.Now()}
	e.db.AddConfig(ctx, &cx, func(rev int) ([]byte, error) {
		return e.keys.Seal([]byte("listen: :443\nauth:\n  type: password\n  password: fake-health-api\noutbounds:\n  - name: warp\n    type: socks5\n    socks5:\n      addr: 127.0.0.1:40000\n"), model.ConfigContext(ids[1], rev))
	})
	rec = owner.do("GET", "/api/v1/chains", nil, nil)
	var list []chainJSON
	json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].Egress != "" || list[0].Health != model.StateDegraded {
		t.Fatalf("%s", rec.Body)
	}
}

// A chain of three: the relay's role shows, one job deploys both links on
// all three servers, and the chain is taken off by one job too.
func TestChainThreeNodesAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	var ids []int64
	for i, name := range []string{"Entry", "Relay", "Exit"} {
		rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": name, "host": "192.0.2.4" + strconv.Itoa(i), "authType": "password", "password": fakeSSHPass}, nil)
		var srv serverJSON
		json.Unmarshal(rec.Body.Bytes(), &srv)
		c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Meta: model.ConfigMeta{Auth: "userpass"}, Source: model.ConfigDeploy, At: time.Now()}
		e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) {
			return e.keys.Seal([]byte("listen: :443\nauth:\n  type: userpass\n  userpass:\n    alice: fake-three-api\n"), model.ConfigContext(srv.ID, rev))
		})
		e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", At: time.Now()})
		ids = append(ids, srv.ID)
	}
	code(t, owner.do("POST", "/api/v1/chains", map[string]any{"name": "x", "nodes": []int64{ids[0], ids[1], ids[2], ids[0]}}, nil), http.StatusBadRequest, "invalid")
	rec := owner.do("POST", "/api/v1/chains", map[string]any{"name": "Через два", "nodes": ids}, nil)
	var ch chainJSON
	json.Unmarshal(rec.Body.Bytes(), &ch)
	if rec.Code != http.StatusCreated || len(ch.Nodes) != 3 || ch.Nodes[1].Role != model.RoleRelay || len(ch.Links) != 2 || ch.Links[1].From != ids[1] || ch.Links[1].To != ids[2] {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	id := strconv.FormatInt(ch.ID, 10)
	if rec = owner.do("GET", "/api/v1/servers/"+strconv.FormatInt(ids[1], 10), nil, nil); !strings.Contains(rec.Body.String(), `"role":"relay"`) {
		t.Fatalf("relay role: %s", rec.Body)
	}
	// The relay sends through this chain only.
	code(t, owner.do("POST", "/api/v1/chains", map[string]any{"name": "y", "nodes": []int64{ids[1], ids[0]}}, nil), http.StatusBadRequest, "invalid")

	rec = owner.do("POST", "/api/v1/chains/"+id+"/link", nil, nil)
	var job jobJSON
	json.Unmarshal(rec.Body.Bytes(), &job)
	if rec.Code != http.StatusAccepted || job.Kind != "link" || job.ServerID != ids[0] || len(job.Servers) != 2 || job.Servers[0] != ids[1] || job.Servers[1] != ids[2] || !strings.Contains(string(job.Params), `"hops"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for idx := range 2 {
		if sealed, _ := e.db.LinkSecrets(ctx, ch.ID, idx); len(sealed) == 0 {
			t.Fatalf("no secrets of link %d", idx)
		}
	}
	queued, _ := e.db.JobByID(ctx, job.ID)
	queued.State = model.JobFailed
	e.db.UpdateJob(ctx, queued)

	// Deployed: one unlink job on all three servers takes both links off.
	c, _ := e.db.ChainByID(ctx, ch.ID)
	for _, l := range c.Links {
		l.State = model.LinkActive
		e.db.UpdateLink(ctx, l)
	}
	rec = owner.do("POST", "/api/v1/chains/"+id+"/unlink", map[string]any{"delete": true}, nil)
	json.Unmarshal(rec.Body.Bytes(), &job)
	if rec.Code != http.StatusAccepted || job.Kind != "unlink" || job.ServerID != ids[0] || len(job.Servers) != 2 || !strings.Contains(string(job.Params), `"hops"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// The relay did not answer: the chain shows it as the relay, with
	// what the links left there (its config has neither the outbound nor
	// the user of the link before).
	failed, _ := e.db.JobByID(ctx, job.ID)
	failed.State, failed.CurrentStep = model.JobFailed, "connect"
	e.db.UpdateJob(ctx, failed)
	e.db.SetJobData(ctx, job.ID, map[string]string{"unreached:" + strconv.FormatInt(ids[1], 10): "1"})
	rec = owner.do("GET", "/api/v1/chains/"+id, nil, nil)
	json.Unmarshal(rec.Body.Bytes(), &ch)
	if len(ch.Unreachable) != 1 || ch.Unreachable[0].ServerID != ids[1] || ch.Unreachable[0].Role != model.RoleRelay || len(ch.Unreachable[0].Left) != 2 ||
		!strings.Contains(ch.Unreachable[0].Left[0], cascade.UnitName(ch.ID, 1)) {
		t.Fatalf("%s", rec.Body)
	}
	rec = owner.do("POST", "/api/v1/chains/"+id+"/unlink", map[string]any{"delete": true, "force": true}, nil)
	json.Unmarshal(rec.Body.Bytes(), &job)
	if rec.Code != http.StatusAccepted || !strings.Contains(string(job.Params), `"force":true`) || !strings.Contains(string(job.Params), `"hops"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
