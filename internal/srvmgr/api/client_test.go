package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/profile"
)

func TestClientProfileAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "NL", "host": "192.0.2.80", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/client", nil, nil), http.StatusNotFound, "no_config")

	cfg := []byte("listen: :443,20000-50000\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-client-api-pass\nobfs:\n  type: salamander\n  salamander:\n    password: fake-client-api-obfs\n")
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigImport, Meta: model.ConfigMeta{TLS: "acme", Ports: "443,20000-50000", SNI: "vpn.example.com"}, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(srv.ID, rev)) })

	rec = owner.do("GET", "/api/v1/servers/"+id+"/client", nil, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "fake-client-api") || !strings.Contains(rec.Body.String(), `"ports":"443,20000-50000"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id+"/client?reveal=1", nil, nil)
	var pr profile.Profile
	json.Unmarshal(rec.Body.Bytes(), &pr)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	hp, _, err := hysteria.ParseURI(pr.URI)
	if err != nil || hp.Auth != "fake-client-api-pass" || hp.Obfs.Password != "fake-client-api-obfs" || hp.Ports != "443,20000-50000" {
		t.Fatalf("%v %+v", err, hp)
	}
	audit, _ := e.db.ListAudit(ctx, 10)
	if len(audit) == 0 || audit[0].Action != "client.reveal" || audit[0].Target != "server/"+id || strings.Contains(audit[0].Details, "fake") {
		t.Fatalf("%+v", audit)
	}

	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	ro := e.login("viewer")
	if rec := ro.do("GET", "/api/v1/servers/"+id+"/client", nil, nil); rec.Code != 200 {
		t.Fatalf("read-only summary: %d", rec.Code)
	}
	code(t, ro.do("GET", "/api/v1/servers/"+id+"/client?reveal=1", nil, nil), http.StatusForbidden, "forbidden")
}
