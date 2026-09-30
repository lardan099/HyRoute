package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

const fakeSSHPass = "fake-ssh-pass-for-api-test"

func TestServersCRUD(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	body := map[string]any{"name": "NL 1", "host": "nl.example.com", "authType": "password", "password": fakeSSHPass, "tags": []string{"nl"}, "country": "nl"}
	rec := owner.do("POST", "/api/v1/servers", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	if srv.ID == 0 || srv.Country != "NL" || srv.SSHPort != 22 || !srv.HasPassword {
		t.Fatalf("%+v", srv)
	}
	id := strconv.FormatInt(srv.ID, 10)
	for _, p := range []string{"/api/v1/servers", "/api/v1/servers/" + id} {
		rec := owner.do("GET", p, nil, nil)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), fakeSSHPass) || strings.Contains(rec.Body.String(), `"password":`) {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Body)
		}
	}
	// Validation errors name the field.
	rec = owner.do("POST", "/api/v1/servers", map[string]any{"name": "NL 1", "host": "x.example.com", "authType": "password", "password": "p1234"}, nil)
	code(t, rec, http.StatusBadRequest, "invalid")
	if decodeError(t, rec).Details != "name" {
		t.Fatalf("%s", rec.Body)
	}
	// PATCH without credentials keeps them.
	rec = owner.do("PATCH", "/api/v1/servers/"+id, map[string]any{"name": "NL main", "host": "nl.example.com", "authType": "password", "notes": "n"}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"hasPassword":true`) || !strings.Contains(rec.Body.String(), `"NL main"`) {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body)
	}
	if c, _ := e.servers.Credentials(context.Background(), srv.ID); c.Password != fakeSSHPass {
		t.Fatal("password lost on PATCH")
	}
	code(t, owner.do("GET", "/api/v1/servers/999", nil, nil), http.StatusNotFound, "not_found")
	code(t, owner.do("GET", "/api/v1/servers/abc", nil, nil), http.StatusNotFound, "not_found")
	if rec := owner.do("DELETE", "/api/v1/servers/"+id, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	code(t, owner.do("DELETE", "/api/v1/servers/"+id, nil, nil), http.StatusNotFound, "not_found")
}

func TestServersReadOnly(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	owner.do("POST", "/api/v1/servers", map[string]any{"name": "A", "host": "a.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var u model.User
	u.Username, u.Role = "viewer", model.RoleReadOnly
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(context.Background(), &u)
	ro := e.login("viewer")
	if rec := ro.do("GET", "/api/v1/servers", nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"A"`) {
		t.Fatalf("read-only list: %d %s", rec.Code, rec.Body)
	}
	code(t, ro.do("POST", "/api/v1/servers", map[string]any{"name": "B", "host": "b.example.com", "authType": "password", "password": fakeSSHPass}, nil), http.StatusForbidden, "forbidden")
	code(t, ro.do("DELETE", "/api/v1/servers/1", nil, nil), http.StatusForbidden, "forbidden")
	code(t, e.client().do("GET", "/api/v1/servers", nil, nil), http.StatusUnauthorized, "unauthorized")
}
