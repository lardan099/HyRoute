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
