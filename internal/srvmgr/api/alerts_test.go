package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/alerts"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// Fake channel secrets for these tests.
const (
	fakeBotToken = "987654321:fake-bot-token-for-api-tests-BBBBBBBB"
	fakeHookKey  = "fake-hook-key-for-api-tests-0042"
	fakeMailPass = "fake-mail-pass-for-api-tests-77"
)

// alertsEnv is an API with notification channels over a database at a
// known path, and users of every role.
func alertsEnv(t *testing.T) (*testEnv, string, map[model.Role]*client) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "t.db")
	db, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{8}, 32)})
	e := &testEnv{t: t, db: db, keys: keys, auth: auth.New(db)}
	e.auth.Params = auth.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	n := &alerts.Notifier{Store: db, Keys: keys, Timeout: 3 * time.Second}
	nctx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	n.Start(nctx)
	e.h = New(Deps{Store: db, Auth: e.auth, Keys: keys, Alerts: n})
	users := map[model.Role]*client{model.RoleOwner: e.setupOwner()}
	for _, r := range []model.Role{model.RoleAdmin, model.RoleOperator, model.RoleReadOnly} {
		u := model.User{Username: string(r), Role: r}
		u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
		if err := db.CreateUser(ctx, &u); err != nil {
			t.Fatal(err)
		}
		users[r] = e.login(string(r))
	}
	return e, path, users
}

// Owners and admins set up channels; nobody gets a secret back; the
// database holds them sealed only; the audit names the channel, not
// its secret.
func TestAlertChannelsAPI(t *testing.T) {
	e, path, users := alertsEnv(t)
	owner, admin := users[model.RoleOwner], users[model.RoleAdmin]
	var hits atomic.Int32
	var lastSig atomic.Value
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		ts, _ := strconv.ParseInt(r.Header.Get(alerts.HeaderTimestamp), 10, 64)
		lastSig.Store(r.Header.Get(alerts.HeaderSignature) == alerts.Sign(fakeHookKey, ts, b))
		if strings.Contains(string(b), "fail") {
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(hook.Close)

	for _, r := range []model.Role{model.RoleOperator, model.RoleReadOnly} {
		code(t, users[r].do("GET", "/api/v1/alerts/channels", nil, nil), http.StatusForbidden, "forbidden")
		code(t, users[r].do("POST", "/api/v1/alerts/channels", map[string]any{"name": "x", "kind": "webhook"}, nil), http.StatusForbidden, "forbidden")
	}

	create := func(c *client, body map[string]any) channelJSON {
		t.Helper()
		rec := c.do("POST", "/api/v1/alerts/channels", body, nil)
		var out channelJSON
		if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("create %d %s", rec.Code, rec.Body)
		}
		return out
	}
	tg := create(owner, map[string]any{"name": "Телеграм", "kind": "telegram", "settings": map[string]any{"chatId": "-100500"}, "secret": fakeBotToken,
		"events": []string{"server", "link"}, "quiet": map[string]string{"from": "23:00", "to": "07:00", "zone": "Europe/Moscow"}})
	wh := create(admin, map[string]any{"name": "Хук", "kind": "webhook", "settings": map[string]any{"url": hook.URL}, "secret": fakeHookKey})
	ml := create(owner, map[string]any{"name": "Почта", "kind": "smtp", "settings": map[string]any{"host": "smtp.example.com", "security": "starttls",
		"username": "bot", "from": "bot@example.com", "to": []string{"a@example.com"}}, "secret": fakeMailPass})
	if !tg.HasSecret || !tg.Enabled || len(tg.Events) != 2 || tg.Quiet.Zone != "Europe/Moscow" || !wh.HasSecret || string(wh.Settings) != `{"url":"`+hook.URL+`"}` {
		t.Fatalf("created %+v %+v", tg, wh)
	}
	code(t, owner.do("POST", "/api/v1/alerts/channels", map[string]any{"name": "Плохой", "kind": "telegram", "settings": map[string]any{"chatId": "1"}}, nil), http.StatusBadRequest, "invalid")

	// Keep the secret, change the rest; another kind is refused; a webhook
	// without its key is refused.
	rec := owner.do("PATCH", "/api/v1/alerts/channels/"+strconv.FormatInt(tg.ID, 10), map[string]any{"name": "Телеграм админов", "settings": map[string]any{"chatId": "-100501"}, "enabled": false}, nil)
	var upd channelJSON
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &upd) != nil || upd.Name != "Телеграм админов" || upd.Enabled || !upd.HasSecret || len(upd.Events) != 0 || upd.Quiet.From != "" {
		t.Fatalf("update %d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("PATCH", "/api/v1/alerts/channels/"+strconv.FormatInt(tg.ID, 10), map[string]any{"name": "x", "kind": "smtp", "settings": map[string]any{"chatId": "1"}}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("PATCH", "/api/v1/alerts/channels/"+strconv.FormatInt(wh.ID, 10), map[string]any{"name": "Хук", "settings": map[string]any{"url": hook.URL}, "clearSecret": true}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("PATCH", "/api/v1/alerts/channels/999", map[string]any{"name": "x"}, nil), http.StatusNotFound, "not_found")

	// The test goes now, signed with the stored key.
	rec = admin.do("POST", "/api/v1/alerts/channels/"+strconv.FormatInt(wh.ID, 10)+"/test", nil, nil)
	if rec.Code != 200 || hits.Load() != 1 || lastSig.Load() != true {
		t.Fatalf("test %d %s, %d hits", rec.Code, rec.Body, hits.Load())
	}
	rec = admin.do("PATCH", "/api/v1/alerts/channels/"+strconv.FormatInt(wh.ID, 10), map[string]any{"name": "fail", "settings": map[string]any{"url": hook.URL}}, nil)
	code(t, rec, 200, "")
	rec = admin.do("POST", "/api/v1/alerts/channels/"+strconv.FormatInt(wh.ID, 10)+"/test", nil, nil)
	code(t, rec, http.StatusBadGateway, "send_failed")
	code(t, users[model.RoleOperator].do("POST", "/api/v1/alerts/channels/"+strconv.FormatInt(wh.ID, 10)+"/test", nil, nil), http.StatusForbidden, "forbidden")

	rec = owner.do("GET", "/api/v1/alerts/channels", nil, nil)
	var list []channelJSON
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil || len(list) != 3 {
		t.Fatalf("list %d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("DELETE", "/api/v1/alerts/channels/"+strconv.FormatInt(ml.ID, 10), nil, nil), http.StatusNoContent, "")
	code(t, owner.do("DELETE", "/api/v1/alerts/channels/"+strconv.FormatInt(ml.ID, 10), nil, nil), http.StatusNotFound, "not_found")

	// No secret in any answer of the test, the audit or the database file.
	ctx := context.Background()
	audit, _ := e.db.ListAudit(ctx, 100)
	actions := map[string]int{}
	for _, a := range audit {
		actions[a.Action]++
		for _, s := range []string{fakeBotToken, fakeHookKey, fakeMailPass, "fake-bot-token"} {
			if strings.Contains(a.Details, s) || strings.Contains(a.Target, s) {
				t.Fatalf("a secret in the audit %+v", a)
			}
		}
	}
	if actions["alert_channel_created"] != 3 || actions["alert_channel_updated"] != 2 || actions["alert_channel_deleted"] != 1 || actions["alert_channel_tested"] != 2 {
		t.Fatalf("audit %v", actions)
	}
	for _, body := range []string{rec.Body.String(), owner.do("GET", "/api/v1/alerts/channels", nil, nil).Body.String()} {
		for _, s := range []string{fakeBotToken, fakeHookKey, fakeMailPass} {
			if strings.Contains(body, s) {
				t.Fatalf("a secret in an answer: %s", body)
			}
		}
	}
	e.db.Close()
	for _, f := range []string{path, path + "-wal"} {
		b, err := os.ReadFile(f)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		for _, s := range []string{fakeBotToken, fakeHookKey, fakeMailPass} {
			if bytes.Contains(b, []byte(s)) {
				t.Fatalf("%s holds a channel secret in the clear", filepath.Base(f))
			}
		}
	}
}
