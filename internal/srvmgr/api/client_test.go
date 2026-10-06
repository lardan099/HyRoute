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

// The user of a cascade link on its exit: listed apart, never revealed,
// and left out of a rotation of all users.
func TestClientLinkUserAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	ids := map[string]int64{}
	for _, name := range []string{"entry", "exit"} {
		rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": name, "host": name + ".example.com", "authType": "password", "password": fakeSSHPass}, nil)
		var srv serverJSON
		json.Unmarshal(rec.Body.Bytes(), &srv)
		ids[name] = srv.ID
	}
	ch := model.Chain{Name: "c", Nodes: []int64{ids["entry"], ids["exit"]}, Links: []model.ChainLink{{}}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := e.db.CreateChain(ctx, &ch, nil); err != nil {
		t.Fatal(err)
	}
	link := "link-" + strconv.FormatInt(ch.ID, 10) + "-0"
	exit, id := ids["exit"], strconv.FormatInt(ids["exit"], 10)
	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: userpass\n  userpass:\n    phone: fake-phone-pass\n    " + link + ": fake-link-pass\n")
	c := model.ServerConfig{ServerID: exit, SHA256: "x", Source: model.ConfigCascade, Meta: model.ConfigMeta{TLS: "acme", Ports: "443"}, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(exit, rev)) })

	rec := owner.do("GET", "/api/v1/servers/"+id+"/client", nil, nil)
	var sum profile.Summary
	json.Unmarshal(rec.Body.Bytes(), &sum)
	if rec.Code != 200 || strings.Join(sum.Users, ",") != "phone" || strings.Join(sum.Links, ",") != link {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/client/reveal", map[string]any{"user": link}, nil), http.StatusConflict, "link_user")
	rec = owner.do("POST", "/api/v1/servers/"+id+"/client/reveal", map[string]any{}, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "fake-link-pass") || !strings.Contains(rec.Body.String(), `"user":"phone"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	e.db.SetInstallation(ctx, model.Installation{ServerID: exit, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: exit, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	rec = owner.do("POST", "/api/v1/servers/"+id+"/config/rotate", map[string]any{"base": c.Revision, "auth": true}, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || !strings.Contains(string(j.Params), `"rotated":["user:phone"]`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

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
	// The old GET form reveals nothing.
	if rec := owner.do("GET", "/api/v1/servers/"+id+"/client?reveal=1", nil, nil); strings.Contains(rec.Body.String(), "fake-client-api") {
		t.Fatalf("GET revealed: %s", rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/client/reveal", map[string]any{}, map[string]string{"X-CSRF-Token": "forged"}), http.StatusForbidden, "csrf")
	rec = owner.do("POST", "/api/v1/servers/"+id+"/client/reveal", map[string]any{}, nil)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q", cc)
	}
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
	code(t, ro.do("POST", "/api/v1/servers/"+id+"/client/reveal", map[string]any{}, nil), http.StatusForbidden, "forbidden")
}
