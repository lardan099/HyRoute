package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/backup"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
)

// backupEnv is an API with copies and the key check, its database bound
// to a master key (keyText) and users of every role.
func backupEnv(t *testing.T) (e *testEnv, keyText string, users map[model.Role]*client) {
	t.Helper()
	e = newEnv(t)
	ctx := context.Background()
	keyFile := filepath.Join(t.TempDir(), "master.key")
	if _, _, err := secrets.Open(ctx, func(string) string { return "" }, keyFile, e.db); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(keyFile)
	m := &backup.Manager{DB: e.db, Dir: filepath.Join(t.TempDir(), "backups"), Keep: 3}
	e.h = New(Deps{Store: e.db, Auth: e.auth, Keys: e.keys, Backups: m,
		KeyCheck: func(ctx context.Context, text string) (secrets.KeyReport, error) {
			return secrets.CheckKeyText(ctx, text, e.db)
		}})
	users = map[model.Role]*client{model.RoleOwner: e.setupOwner()}
	for _, r := range []model.Role{model.RoleAdmin, model.RoleOperator, model.RoleReadOnly} {
		u := model.User{Username: string(r), Role: r}
		u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
		if err := e.db.CreateUser(ctx, &u); err != nil {
			t.Fatal(err)
		}
		users[r] = e.login(string(r))
	}
	return e, string(b), users
}

func TestBackupsOwnerOnly(t *testing.T) {
	e, _, users := backupEnv(t)
	owner := users[model.RoleOwner]
	rec := owner.do("POST", "/api/v1/backups", nil, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	var info backup.Info
	json.Unmarshal(rec.Body.Bytes(), &info)
	rec = owner.do("GET", "/api/v1/backups", nil, nil)
	var list backupsJSON
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list.Items) != 1 || list.Items[0].Name != info.Name || list.Last.Name != info.Name {
		t.Fatalf("list %d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/backups/"+info.Name, nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), info.Name) || rec.Body.Len() != int(info.Size) {
		t.Fatalf("download %d %v %d", rec.Code, rec.Header(), rec.Body.Len())
	}
	audit, _ := e.db.ListAudit(context.Background(), 10)
	var actions []string
	for _, a := range audit {
		actions = append(actions, a.Action)
	}
	if !strings.Contains(strings.Join(actions, " "), "backup.download") || !strings.Contains(strings.Join(actions, " "), "backup.create") {
		t.Fatalf("audit %v", actions)
	}
	for _, bad := range []string{"..%2Fhyroute-server.db", "t.db", "hyroute-server-20990101-000000.db"} {
		code(t, owner.do("GET", "/api/v1/backups/"+bad, nil, nil), http.StatusNotFound, "")
	}
	for _, r := range []model.Role{model.RoleAdmin, model.RoleOperator, model.RoleReadOnly} {
		c := users[r]
		code(t, c.do("GET", "/api/v1/backups", nil, nil), http.StatusForbidden, "forbidden")
		code(t, c.do("POST", "/api/v1/backups", nil, nil), http.StatusForbidden, "forbidden")
		code(t, c.do("GET", "/api/v1/backups/"+info.Name, nil, nil), http.StatusForbidden, "forbidden")
	}
}

func TestMasterKeyCheck(t *testing.T) {
	e, keyText, users := backupEnv(t)
	other, _ := secrets.NewKeyText()
	check := func(c *client, key string) (int, keyCheckJSON) {
		rec := c.do("POST", "/api/v1/master-key/check", map[string]string{"key": key}, nil)
		var out keyCheckJSON
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	for _, r := range []model.Role{model.RoleOwner, model.RoleAdmin} {
		if st, out := check(users[r], keyText); st != 200 || !out.OK || len(out.Versions) != 1 || out.Versions[0].Status != secrets.KeyOK {
			t.Fatalf("%s, right key: %d %+v", r, st, out)
		}
		if st, out := check(users[r], other); st != 200 || out.OK || out.Versions[0].Status != secrets.KeyWrong {
			t.Fatalf("%s, other key: %d %+v", r, st, out)
		}
	}
	code(t, users[model.RoleOwner].do("POST", "/api/v1/master-key/check", map[string]string{"key": "not a key"}, nil), http.StatusBadRequest, "not_a_key")
	for _, r := range []model.Role{model.RoleOperator, model.RoleReadOnly} {
		code(t, users[r].do("POST", "/api/v1/master-key/check", map[string]string{"key": keyText}, nil), http.StatusForbidden, "forbidden")
	}
	// The audit says a check was made, never with the key.
	audit, _ := e.db.ListAudit(context.Background(), 50)
	n := 0
	secret := strings.TrimPrefix(strings.TrimSpace(keyText), "1:")
	for _, a := range audit {
		if a.Action == "master_key.check" {
			n++
		}
		if strings.Contains(a.Details+a.Target, secret[:16]) {
			t.Fatalf("the audit holds the key: %+v", a)
		}
	}
	if n != 4 {
		t.Fatalf("%d key checks audited, want 4", n)
	}
}
