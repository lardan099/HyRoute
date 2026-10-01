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

func TestPresetsAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "192.0.2.80", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	cfg := "listen: 192.0.2.80:443,20000-50000\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-presets-api-pass\nobfs:\n  type: salamander\n  salamander:\n    password: fake-presets-api-obfs\nbandwidth:\n  up: 300 mbps\n"
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal([]byte(cfg), model.ConfigContext(srv.ID, rev)) })

	code(t, owner.do("POST", "/api/v1/presets", map[string]any{"name": "x"}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/presets", map[string]any{"name": "x", "serverId": 999}, nil), http.StatusNotFound, "not_found")
	rec = owner.do("POST", "/api/v1/presets", map[string]any{"name": "Быстрый", "serverId": srv.ID}, nil)
	var p presetJSON
	json.Unmarshal(rec.Body.Bytes(), &p)
	if rec.Code != http.StatusCreated || strings.Join(p.Sections, ",") != "ports,obfs,speed" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for _, bad := range []string{"fake-presets", "192.0.2.80", "vpn.example.com"} {
		if strings.Contains(rec.Body.String(), bad) {
			t.Fatalf("preset has %q: %s", bad, rec.Body)
		}
	}
	id := strconv.FormatInt(p.ID, 10)

	// Read-only sees presets, changes none.
	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	viewer := e.login("viewer")
	if rec = viewer.do("GET", "/api/v1/presets", nil, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Быстрый") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, viewer.do("PATCH", "/api/v1/presets/"+id, map[string]any{"name": "y"}, nil), http.StatusForbidden, "forbidden")
	code(t, viewer.do("POST", "/api/v1/presets", map[string]any{"name": "y", "from": p.ID}, nil), http.StatusForbidden, "forbidden")

	code(t, owner.do("POST", "/api/v1/presets", map[string]any{"name": "быстрый", "from": p.ID}, nil), http.StatusBadRequest, "invalid")
	rec = owner.do("POST", "/api/v1/presets", map[string]any{"name": "Копия", "from": p.ID}, nil)
	var clone presetJSON
	json.Unmarshal(rec.Body.Bytes(), &clone)
	if rec.Code != http.StatusCreated || clone.Config != p.Config {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec = owner.do("PATCH", "/api/v1/presets/"+id, map[string]any{"name": "Очень быстрый"}, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Очень быстрый") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	rec = owner.do("GET", "/api/v1/presets/"+id+"/export", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") || !strings.Contains(rec.Body.String(), `"format": "hyroute-preset"`) {
		t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
	}
	var file map[string]any
	json.Unmarshal(rec.Body.Bytes(), &file)
	rec = owner.do("POST", "/api/v1/presets/import", file, nil)
	var imp presetJSON
	json.Unmarshal(rec.Body.Bytes(), &imp)
	if rec.Code != http.StatusCreated || imp.Name != "Очень быстрый (2)" || imp.Config != p.Config {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	file["version"] = 9
	code(t, owner.do("POST", "/api/v1/presets/import", file, nil), http.StatusBadRequest, "invalid")

	if rec = owner.do("DELETE", "/api/v1/presets/"+id, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/presets/"+id, nil, nil), http.StatusNotFound, "not_found")
}
