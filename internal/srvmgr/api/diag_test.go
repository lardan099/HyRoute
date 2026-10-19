package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/diag"
	"github.com/lardan099/hyroute/internal/srvmgr/diag/diagtest"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// diagEnv is an API with the diagnostic bundle over a database of
// canaries, and users of every role.
func diagEnv(t *testing.T) (*testEnv, map[model.Role]*client) {
	t.Helper()
	e := newEnv(t)
	users := map[model.Role]*client{model.RoleOwner: e.setupOwner()}
	seed := diagtest.Fill(t, e.db, e.keys)
	e.h = New(Deps{Store: e.db, Auth: e.auth, Keys: e.keys, Logs: seed.Logs,
		Diag: &diag.Builder{Store: e.db, Keys: e.keys, Logs: seed.Logs, Geo: e.geo, Version: "test",
			Settings: diag.Settings{Panel: true, Listen: diagtest.Listen, AllowedHosts: []string{diagtest.AllowedHost}, BackupKeep: 7, MasterKey: "file"}}})
	for _, r := range []model.Role{model.RoleAdmin, model.RoleOperator, model.RoleReadOnly} {
		u := model.User{Username: string(r), Role: r}
		u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
		if err := e.db.CreateUser(context.Background(), &u); err != nil {
			t.Fatal(err)
		}
		users[r] = e.login(string(r))
	}
	return e, users
}

func TestDiagBundle(t *testing.T) {
	e, users := diagEnv(t)
	for _, r := range []model.Role{model.RoleOwner, model.RoleAdmin} {
		c := users[r]
		rec := c.do("GET", "/api/v1/diag", nil, nil)
		var list diagJSON
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil {
			t.Fatalf("%s: list %d %s", r, rec.Code, rec.Body)
		}
		if !list.ControllerLog || list.Jobs != diag.DefaultJobs || list.Size == 0 || !strings.HasPrefix(list.Name, "hyroute-diag-") {
			t.Fatalf("%s: %+v", r, list)
		}
		rec = c.do("GET", "/api/v1/diag/bundle", nil, nil)
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/zip" || !strings.Contains(rec.Header().Get("Content-Disposition"), "hyroute-diag-") ||
			rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: download %d %v", r, rec.Code, rec.Header())
		}
		files := diagtest.Files(t, rec.Body.Bytes())
		diagtest.NoCanaries(t, files, append(slices.Clone(diagtest.Canaries), diagtest.KeyCanaries(bytes.Repeat([]byte{9}, 32))...)...)
		// The list before the download is the list of the download.
		var names []string
		for _, f := range list.Files {
			names = append(names, f.Name)
			if _, ok := files[f.Name]; !ok {
				t.Errorf("%s: %s listed, not in the bundle", r, f.Name)
			}
		}
		if len(files) != len(names) {
			t.Errorf("%s: %d files, %d listed: %v", r, len(files), len(names), names)
		}
	}
	audit, _ := e.db.ListAudit(context.Background(), 20)
	n := 0
	for _, a := range audit {
		if a.Action == "diag_downloaded" {
			n++
			if !strings.HasPrefix(a.Target, "diag/hyroute-diag-") || !strings.Contains(a.Details, "jobs=20") {
				t.Fatalf("audit %+v", a)
			}
		}
	}
	if n != 2 {
		t.Fatalf("%d downloads audited, want 2", n)
	}

	owner := users[model.RoleOwner]
	rec := owner.do("GET", "/api/v1/diag/bundle?jobs=1", nil, nil)
	var jobs []any
	if rec.Code != 200 || json.Unmarshal([]byte(diagtest.Files(t, rec.Body.Bytes())["jobs.json"]), &jobs) != nil || len(jobs) != 1 {
		t.Fatalf("jobs=1: %d %v", rec.Code, jobs)
	}
	for _, bad := range []string{"0", "201", "x"} {
		code(t, owner.do("GET", "/api/v1/diag?jobs="+bad, nil, nil), http.StatusBadRequest, "invalid")
	}
}

// readonly and operator get neither the list nor the bundle.
func TestDiagForbidden(t *testing.T) {
	e, users := diagEnv(t)
	for _, r := range []model.Role{model.RoleOperator, model.RoleReadOnly} {
		code(t, users[r].do("GET", "/api/v1/diag", nil, nil), http.StatusForbidden, "forbidden")
		code(t, users[r].do("GET", "/api/v1/diag/bundle", nil, nil), http.StatusForbidden, "forbidden")
	}
	audit, _ := e.db.ListAudit(context.Background(), 20)
	for _, a := range audit {
		if a.Action == "diag_downloaded" {
			t.Fatalf("a refused download audited: %+v", a)
		}
	}
	// A panel without the bundle.
	e.h = New(Deps{Store: e.db, Auth: e.auth, Keys: e.keys})
	code(t, users[model.RoleOwner].do("GET", "/api/v1/diag", nil, nil), http.StatusNotFound, "not_found")
}
