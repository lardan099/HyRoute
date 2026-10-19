package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	u.Username, u.Role, u.Scope = "viewer", model.RoleReadOnly, model.ScopeAll
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
	// The file comes as text: what is wrong with it is said by Import.
	imp := func(file any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(file)
		return owner.do("POST", "/api/v1/presets/import", map[string]any{"data": string(b)}, nil)
	}
	refused := func(rec *httptest.ResponseRecorder, msg string) {
		t.Helper()
		code(t, rec, http.StatusBadRequest, "invalid")
		if m := decodeError(t, rec).Message; !strings.Contains(m, msg) {
			t.Fatalf("message %q, want %q", m, msg)
		}
	}
	rec = owner.do("POST", "/api/v1/presets/import", map[string]any{"data": rec.Body.String()}, nil)
	var imported presetJSON
	json.Unmarshal(rec.Body.Bytes(), &imported)
	if rec.Code != http.StatusCreated || imported.Name != "Очень быстрый (2)" || imported.Config != p.Config {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var file map[string]any
	json.Unmarshal(owner.do("GET", "/api/v1/presets/"+id+"/export", nil, nil).Body.Bytes(), &file)
	// A rules file, a file of a later version, or not JSON at all.
	refused(imp(map[string]any{"format": "hyroute-routing", "version": 1, "acl": map[string]any{"rules": []any{}}}), "не файл пресета")
	refused(owner.do("POST", "/api/v1/presets/import", map[string]any{"data": "listen: :443"}, nil), "не файл пресета")
	file["version"] = 9
	file["later"] = true
	refused(imp(file), "версии 9")
	// A file over 1 MB is read (a preset with a big ACL); one over the
	// limit of preset files is refused by Import, and a body far over it
	// gets 413.
	file["notes"] = []string{strings.Repeat("x", 2<<20)}
	refused(imp(file), "версии 9")
	file["notes"] = []string{strings.Repeat("x", 5<<20)}
	refused(imp(file), "больше 4 МБ")
	file["notes"] = []string{strings.Repeat("x", 10<<20)}
	code(t, imp(file), http.StatusRequestEntityTooLarge, "too_large")
	// Escaping can double a file as a JSON string: a file just under the
	// limit full of quotes still gets to Import.
	delete(file, "later")
	file["version"] = 1
	file["notes"] = []string{strings.Repeat(`"`, (4<<20-len(p.Config))/2-1<<10)}
	if rec = imp(file); rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	if rec = owner.do("DELETE", "/api/v1/presets/"+id, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("GET", "/api/v1/presets/"+id, nil, nil), http.StatusNotFound, "not_found")
}

// A preset's sections over a server: the preview shows the diff, the
// apply starts the job; read-only may do neither.
func TestPresetApplyAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": "192.0.2.81", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	id := strconv.FormatInt(srv.ID, 10)
	cfg := "listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-preset-apply-pass\n"
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal([]byte(cfg), model.ConfigContext(srv.ID, rev)) })
	p := model.Preset{Name: "Быстрый", Config: "bandwidth:\n  up: 900 mbps\n", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	e.db.CreatePreset(ctx, &p)
	body := map[string]any{"base": 1, "preset": p.ID, "sections": []string{"speed"}}

	rec = owner.do("POST", "/api/v1/servers/"+id+"/preset/preview", body, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "900 mbps") || strings.Contains(rec.Body.String(), "fake-preset-apply") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/preset/preview", map[string]any{"base": 1, "preset": 999, "sections": []string{"speed"}}, nil), http.StatusNotFound, "no_preset")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/preset/preview", map[string]any{"base": 1, "preset": p.ID, "sections": []string{"acl"}}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/servers/"+id+"/preset/apply", body, nil), http.StatusConflict, "no_installation")

	e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	var u model.User
	u.Username, u.Role, u.Scope = "viewer", model.RoleReadOnly, model.ScopeAll
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(ctx, &u)
	code(t, e.login("viewer").do("POST", "/api/v1/servers/"+id+"/preset/apply", body, nil), http.StatusForbidden, "forbidden")

	rec = owner.do("POST", "/api/v1/servers/"+id+"/preset/apply", body, nil)
	var j jobJSON
	json.Unmarshal(rec.Body.Bytes(), &j)
	if rec.Code != http.StatusAccepted || j.Kind != "apply" || !strings.Contains(string(j.Params), `"preset":"Быстрый"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
