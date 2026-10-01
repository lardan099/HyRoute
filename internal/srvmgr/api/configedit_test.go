package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func TestConfigEditAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/config/edit", nil, nil), http.StatusNotFound, "no_config")

	cfg := []byte("# hand-made\nlisten: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-edit-auth-pass\n")
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigImport, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(srv.ID, rev)) })

	rec = owner.do("GET", "/api/v1/servers/"+id+"/config/edit", nil, nil)
	var v apply.View
	json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != 200 || v.Revision != 1 || strings.Contains(rec.Body.String(), "fake-edit-auth-pass") || !strings.Contains(v.YAML, "# hand-made") || v.Fields.TLS != "acme" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	text := strings.Replace(v.YAML, "listen: :443", "listen: :8443", 1)
	rec = owner.do("POST", "/api/v1/servers/"+id+"/config/render", map[string]any{"revision": 1, "yaml": text}, nil)
	var ch apply.Check
	json.Unmarshal(rec.Body.Bytes(), &ch)
	if rec.Code != 200 || !ch.OK || ch.Fields.Listen != ":8443" || !apply.Changed(ch.Diff) || strings.Contains(rec.Body.String(), "fake-edit-auth-pass") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Fields from the structured editor.
	f := v.Fields
	f.BandwidthUp = "100 mbps"
	rec = owner.do("POST", "/api/v1/servers/"+id+"/config/render", map[string]any{"revision": 1, "yaml": v.YAML, "fields": f}, nil)
	json.Unmarshal(rec.Body.Bytes(), &ch)
	if rec.Code != 200 || !strings.Contains(ch.YAML, "up: 100 mbps") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/render", map[string]any{"revision": 1, "yaml": "listen: ["}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/render", map[string]any{"revision": 7, "yaml": v.YAML}, nil), http.StatusConflict, "config_changed")

	// Read-only users do not get the editor's text at all.
	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	ro := e.login("viewer")
	code(t, ro.do("GET", "/api/v1/servers/"+id+"/config/edit", nil, nil), http.StatusForbidden, "forbidden")
	code(t, ro.do("POST", "/api/v1/servers/"+id+"/config/render", map[string]any{"revision": 1, "yaml": v.YAML}, nil), http.StatusForbidden, "forbidden")
}

func TestConfigApplyAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-apply-api-pass\n")
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigImport, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(srv.ID, rev)) })
	rec = owner.do("GET", "/api/v1/servers/"+id+"/config/edit", nil, nil)
	var v apply.View
	json.Unmarshal(rec.Body.Bytes(), &v)
	good := map[string]any{"revision": 1, "yaml": strings.Replace(v.YAML, ":443", ":8443", 1)}

	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/apply", good, nil), http.StatusConflict, "no_installation")
	e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})

	rec = owner.do("POST", "/api/v1/servers/"+id+"/config/apply", map[string]any{"revision": 1, "yaml": strings.Replace(v.YAML, ":443", ":99999", 1)}, nil)
	code(t, rec, http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/apply", map[string]any{"revision": 1, "yaml": v.YAML}, nil), http.StatusBadRequest, "invalid")
	rec = owner.do("POST", "/api/v1/servers/"+id+"/config/apply", good, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || j.Kind != "apply" || strings.Contains(rec.Body.String(), "fake-apply-api-pass") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/apply", good, nil), http.StatusConflict, "server_busy")
}

func TestConfigHistoryAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	for i, cfg := range []string{
		"listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-history-pass-1\n",
		"listen: :8443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-history-pass-2\n",
	} {
		c := model.ServerConfig{ServerID: srv.ID, SHA256: "x" + strconv.Itoa(i), Source: model.ConfigEdit, By: ownerID(t, e), At: time.Now()}
		e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal([]byte(cfg), model.ConfigContext(srv.ID, rev)) })
	}

	rec = owner.do("GET", "/api/v1/servers/"+id+"/config/revisions", nil, nil)
	var revs []revisionJSON
	json.Unmarshal(rec.Body.Bytes(), &revs)
	if rec.Code != 200 || len(revs) != 2 || revs[0].Revision != 2 || !revs[0].Current || revs[1].Current || revs[0].By != "owner" || strings.Contains(rec.Body.String(), "fake-history") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id+"/config/revisions/1", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "listen: :443") || strings.Contains(rec.Body.String(), "fake-history") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/config/revisions/5", nil, nil), http.StatusNotFound, "no_revision")
	rec = owner.do("GET", "/api/v1/servers/"+id+"/config/compare?from=1&to=2", nil, nil)
	var cmp apply.Comparison
	json.Unmarshal(rec.Body.Bytes(), &cmp)
	if rec.Code != 200 || !apply.Changed(cmp.Diff) || len(cmp.Secrets) != 1 || strings.Contains(rec.Body.String(), "fake-history") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/servers/"+id+"/config/compare?from=1", nil, nil), http.StatusBadRequest, "bad_request")

	// Rolling back needs the installation; a stale base is refused.
	back := map[string]any{"base": 2, "revision": 1}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/rollback", back, nil), http.StatusConflict, "no_installation")
	e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/rollback", map[string]any{"base": 1, "revision": 1}, nil), http.StatusConflict, "config_changed")

	// Read-only: the history list, nothing else.
	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	ro := e.login("viewer")
	if rec := ro.do("GET", "/api/v1/servers/"+id+"/config/revisions", nil, nil); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, ro.do("GET", "/api/v1/servers/"+id+"/config/revisions/1", nil, nil), http.StatusForbidden, "forbidden")
	code(t, ro.do("GET", "/api/v1/servers/"+id+"/config/compare?from=1&to=2", nil, nil), http.StatusForbidden, "forbidden")
	code(t, ro.do("POST", "/api/v1/servers/"+id+"/config/rollback", back, nil), http.StatusForbidden, "forbidden")

	rec = owner.do("POST", "/api/v1/servers/"+id+"/config/rollback", back, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || j.Kind != "apply" || strings.Contains(rec.Body.String(), "fake-history") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func ownerID(t *testing.T, e *testEnv) int64 {
	t.Helper()
	u, err := e.db.UserByName(context.Background(), "owner")
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestRotateAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	cfg := "listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-rotate-pass-1\n"
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now(), Meta: model.ConfigMeta{TLS: "acme"}}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal([]byte(cfg), model.ConfigContext(srv.ID, rev)) })
	auth1 := map[string]any{"base": 1, "auth": true}

	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/rotate", auth1, nil), http.StatusConflict, "no_installation")
	e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/rotate", map[string]any{"base": 1}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/rotate", map[string]any{"base": 1, "cert": true}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/config/rotate", map[string]any{"base": 2, "auth": true}, nil), http.StatusConflict, "config_changed")

	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	code(t, e.login("viewer").do("POST", "/api/v1/servers/"+id+"/config/rotate", auth1, nil), http.StatusForbidden, "forbidden")

	rec = owner.do("POST", "/api/v1/servers/"+id+"/config/rotate", auth1, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || j.Kind != "apply" || !strings.Contains(string(j.Params), `"rotated":["auth"]`) || strings.Contains(rec.Body.String(), "fake-rotate") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

// The ports endpoint: the interval alone is saved at once; new ports
// start an apply job; bad values are refused; read-only may not.
func TestPortsAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	cfg := "listen: :443,20000-50000\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-ports-pass-1\n"
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now(), Meta: model.ConfigMeta{TLS: "acme"}}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal([]byte(cfg), model.ConfigContext(srv.ID, rev)) })
	same := map[string]any{"base": 1, "ports": []string{"443", "20000-50000"}, "hopInterval": 45}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/ports", same, nil), http.StatusConflict, "no_installation")
	e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})

	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	code(t, e.login("viewer").do("POST", "/api/v1/servers/"+id+"/ports", same, nil), http.StatusForbidden, "forbidden")

	for _, bad := range []map[string]any{
		{"base": 1, "ports": []string{"443"}, "hopInterval": 2},
		{"base": 1, "ports": []string{"443", "400-500"}},
		{"base": 1, "ports": []string{}},
	} {
		code(t, owner.do("POST", "/api/v1/servers/"+id+"/ports", bad, nil), http.StatusBadRequest, "invalid")
	}
	// The same ports and the same interval: nothing to do.
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/ports", map[string]any{"base": 1, "ports": []string{"443", "20000-50000"}}, nil), http.StatusBadRequest, "invalid")

	// Only the interval: saved, no job.
	rec = owner.do("POST", "/api/v1/servers/"+id+"/ports", same, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"job":null`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id, nil, nil)
	json.Unmarshal(rec.Body.Bytes(), &srv)
	if srv.HopInterval != 45 {
		t.Fatalf("interval %d", srv.HopInterval)
	}

	// New ports: an apply job.
	rec = owner.do("POST", "/api/v1/servers/"+id+"/ports", map[string]any{"base": 1, "ports": []string{"443", "30000-40000"}, "hopInterval": 45}, nil)
	var out struct {
		Job jobJSON `json:"job"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusAccepted || out.Job.Kind != "apply" || strings.Contains(rec.Body.String(), "fake-ports") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
