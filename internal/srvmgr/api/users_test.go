package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// staff creates a user of each role but owner and logs them in.
func (e *testEnv) staff(owner *client) (admin, op, ro *client, ids map[string]int64) {
	e.t.Helper()
	ids = map[string]int64{}
	for _, u := range []struct{ name, role string }{{"admin", "admin"}, {"op", "operator"}, {"ro", "readonly"}} {
		rec := owner.do("POST", "/api/v1/users", map[string]string{"username": u.name, "password": pass, "role": u.role}, nil)
		if rec.Code != http.StatusCreated {
			e.t.Fatalf("create %s: %d %s", u.name, rec.Code, rec.Body)
		}
		var uj userJSON
		json.Unmarshal(rec.Body.Bytes(), &uj)
		ids[u.name] = uj.ID
	}
	return e.login("admin"), e.login("op"), e.login("ro"), ids
}

func userPath(id int64, rest string) string {
	return "/api/v1/users/" + strconv.FormatInt(id, 10) + rest
}

// Operators and read-only users manage nobody; admins do not touch the
// owner; the owner cannot lose the panel's last owner.
func TestUsersAPIRefusals(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	admin, op, ro, ids := e.staff(owner)
	ownerID := int64(1)
	for _, c := range []*client{op, ro} {
		for _, target := range []int64{ids["admin"], ids["op"], ids["ro"]} {
			code(t, c.do("PATCH", userPath(target, ""), map[string]any{"role": "readonly"}, nil), http.StatusForbidden, "forbidden")
			code(t, c.do("PATCH", userPath(target, ""), map[string]any{"disabled": true}, nil), http.StatusForbidden, "forbidden")
			code(t, c.do("POST", userPath(target, "/password"), map[string]any{"generate": true}, nil), http.StatusForbidden, "forbidden")
			code(t, c.do("POST", userPath(target, "/owner"), nil, nil), http.StatusForbidden, "forbidden")
			code(t, c.do("DELETE", userPath(target, ""), nil, nil), http.StatusForbidden, "forbidden")
		}
		code(t, c.do("GET", "/api/v1/audit", nil, nil), http.StatusForbidden, "forbidden")
	}
	code(t, admin.do("PATCH", userPath(ownerID, ""), map[string]any{"role": "admin"}, nil), http.StatusForbidden, "forbidden")
	code(t, admin.do("PATCH", userPath(ownerID, ""), map[string]any{"disabled": true}, nil), http.StatusForbidden, "forbidden")
	code(t, admin.do("POST", userPath(ownerID, "/password"), map[string]any{"generate": true}, nil), http.StatusForbidden, "forbidden")
	code(t, admin.do("DELETE", userPath(ownerID, ""), nil, nil), http.StatusForbidden, "forbidden")
	code(t, admin.do("PATCH", userPath(ids["ro"], ""), map[string]any{"role": "owner"}, nil), http.StatusForbidden, "forbidden")
	code(t, admin.do("POST", userPath(ids["ro"], "/owner"), nil, nil), http.StatusForbidden, "forbidden")

	code(t, owner.do("PATCH", userPath(ownerID, ""), map[string]any{"role": "admin"}, nil), http.StatusConflict, "last_owner")
	code(t, owner.do("PATCH", userPath(ownerID, ""), map[string]any{"disabled": true}, nil), http.StatusConflict, "self")
	code(t, owner.do("DELETE", userPath(ownerID, ""), nil, nil), http.StatusConflict, "self")
	code(t, owner.do("POST", userPath(ownerID, "/password"), map[string]any{"generate": true}, nil), http.StatusConflict, "self")
	code(t, owner.do("PATCH", userPath(999, ""), map[string]any{"role": "admin"}, nil), http.StatusNotFound, "not_found")
	code(t, owner.do("PATCH", userPath(ids["ro"], ""), map[string]any{"role": "root"}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("PATCH", userPath(ids["ro"], ""), map[string]any{}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", userPath(ids["ro"], "/password"), map[string]any{}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", userPath(ids["ro"], "/password"), map[string]any{"password": pass, "generate": true}, nil), http.StatusBadRequest, "invalid")

	// Handed over, the old owner is an admin and the new one is protected.
	rec := owner.do("POST", userPath(ids["ro"], "/owner"), nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"role":"owner"`) {
		t.Fatalf("hand over: %d %s", rec.Code, rec.Body)
	}
	if rec := owner.do("GET", "/api/v1/session", nil, nil); !strings.Contains(rec.Body.String(), `"role":"admin"`) {
		t.Fatalf("old owner: %s", rec.Body)
	}
	code(t, owner.do("PATCH", userPath(ids["ro"], ""), map[string]any{"disabled": true}, nil), http.StatusForbidden, "forbidden")
	code(t, ro.do("PATCH", userPath(ids["ro"], ""), map[string]any{"role": "admin"}, nil), http.StatusConflict, "last_owner")
}

// A reset, a change of one's password and a block end the sessions at
// once; a blocked user cannot log in.
func TestUsersAPISessionsEnd(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	_, _, ro, ids := e.staff(owner)
	ro2 := e.login("ro")

	rec := owner.do("POST", userPath(ids["ro"], "/password"), map[string]any{"generate": true}, nil)
	var gen struct{ Password string }
	json.Unmarshal(rec.Body.Bytes(), &gen)
	if rec.Code != http.StatusOK || len(gen.Password) < 20 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body)
	}
	for _, c := range []*client{ro, ro2} {
		code(t, c.do("GET", "/api/v1/session", nil, nil), http.StatusUnauthorized, "unauthorized")
	}
	code(t, e.client().do("POST", "/api/v1/session", map[string]string{"username": "ro", "password": pass}, nil), http.StatusUnauthorized, "bad_credentials")
	ro = e.client()
	if rec := ro.do("POST", "/api/v1/session", map[string]string{"username": "ro", "password": gen.Password}, nil); rec.Code != http.StatusOK {
		t.Fatalf("login with the generated password: %d", rec.Code)
	}
	// A typed one: nothing returned.
	if rec := owner.do("POST", userPath(ids["op"], "/password"), map[string]any{"password": "a typed password 1"}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("typed reset: %d %s", rec.Code, rec.Body)
	}

	// One's own password, read-only users included.
	other := e.client()
	other.do("POST", "/api/v1/session", map[string]string{"username": "ro", "password": gen.Password}, nil)
	rec = ro.do("POST", "/api/v1/session/password", map[string]string{"current": "wrong password", "password": "my new password 1"}, nil)
	code(t, rec, http.StatusBadRequest, "invalid")
	if decodeError(t, rec).Details != "current" {
		t.Fatalf("%s", rec.Body)
	}
	old := *ro.cookie
	rec = ro.do("POST", "/api/v1/session/password", map[string]string{"current": gen.Password, "password": "my new password 1"}, nil)
	if rec.Code != http.StatusOK || ro.cookie == nil || ro.cookie.Value == old.Value {
		t.Fatalf("change: %d %s", rec.Code, rec.Body)
	}
	if rec := ro.do("GET", "/api/v1/session", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("new session: %d", rec.Code)
	}
	code(t, other.do("GET", "/api/v1/session", nil, nil), http.StatusUnauthorized, "unauthorized")
	stale := e.client()
	stale.cookie = &old
	code(t, stale.do("GET", "/api/v1/session", nil, nil), http.StatusUnauthorized, "unauthorized")

	// Block: the session ends at once, no login until unblocked.
	if rec := owner.do("PATCH", userPath(ids["ro"], ""), map[string]any{"disabled": true}, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"disabled":true`) {
		t.Fatalf("block: %d %s", rec.Code, rec.Body)
	}
	code(t, ro.do("GET", "/api/v1/servers", nil, nil), http.StatusUnauthorized, "unauthorized")
	code(t, e.client().do("POST", "/api/v1/session", map[string]string{"username": "ro", "password": "my new password 1"}, nil), http.StatusUnauthorized, "bad_credentials")
	owner.do("PATCH", userPath(ids["ro"], ""), map[string]any{"disabled": false}, nil)
	e.client().do("POST", "/api/v1/session", map[string]string{"username": "ro", "password": "my new password 1"}, nil)

	// The list shows the last login.
	var us []userJSON
	json.Unmarshal(owner.do("GET", "/api/v1/users", nil, nil).Body.Bytes(), &us)
	for _, u := range us {
		if u.LastLoginAt == nil || !u.LastLoginAt.Equal(e.clock) {
			t.Fatalf("%s: last login %v", u.Username, u.LastLoginAt)
		}
	}
	// Deleted, the user and its sessions are gone.
	if rec := owner.do("DELETE", userPath(ids["ro"], ""), nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	code(t, e.client().do("POST", "/api/v1/session", map[string]string{"username": "ro", "password": "my new password 1"}, nil), http.StatusUnauthorized, "bad_credentials")
}

// A live stream ends as soon as its user is blocked, not at the next
// keepalive.
func TestStreamEndsWhenBlocked(t *testing.T) {
	sseKeepalive = time.Hour
	t.Cleanup(func() { sseKeepalive = 20 * time.Second })
	e := newEnv(t)
	release := make(chan struct{})
	defer close(release)
	var broken atomic.Bool
	e.jobs.Register(demoKind(release, &broken))
	owner := e.setupOwner()
	_, _, ro, ids := e.staff(owner)
	e.runJobs()
	j, _ := e.jobs.Submit(context.Background(), "demo", 0, nil, nil, 1)
	e.waitJob(j.ID, model.JobInstalling)

	ts := httptest.NewServer(e.h)
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/jobs/"+strconv.FormatInt(j.ID, 10)+"/events", nil)
	req.AddCookie(ro.cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	closed := make(chan struct{})
	go func() { io.Copy(io.Discard, res.Body); close(closed) }()
	// Other users' sessions ending does not end it.
	e.login("op").do("DELETE", "/api/v1/session", nil, nil)
	select {
	case <-closed:
		t.Fatal("the stream ended while its session holds")
	case <-time.After(300 * time.Millisecond):
	}
	code(t, owner.do("PATCH", userPath(ids["ro"], ""), map[string]any{"disabled": true}, nil), http.StatusOK, "")
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream outlived the block")
	}
}

type auditPageJSON struct {
	Entries []auditJSON
	Next    int64
}

// The audit listing filters by user, action, target and period, pages,
// and never shows a password: they are seeded through the real actions.
func TestAuditAPI(t *testing.T) {
	e := newEnv(t)
	const canary = "canary-pw-Xq71-for-audit"
	owner := e.setupOwner()
	start := e.clock
	rec := owner.do("POST", "/api/v1/users", map[string]string{"username": "helper", "password": canary + "1", "role": "admin"}, nil)
	var helper userJSON
	json.Unmarshal(rec.Body.Bytes(), &helper)
	e.client().do("POST", "/api/v1/session", map[string]string{"username": "helper", "password": canary + "x"}, nil)
	h := e.client()
	if rec := h.do("POST", "/api/v1/session", map[string]string{"username": "helper", "password": canary + "1"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("login: %d", rec.Code)
	}
	h.do("POST", "/api/v1/session/password", map[string]string{"current": canary + "y", "password": canary + "2"}, nil)
	code(t, h.do("POST", "/api/v1/session/password", map[string]string{"current": canary + "1", "password": canary + "2"}, nil), http.StatusOK, "")
	e.clock = e.clock.Add(time.Hour)
	later := e.clock
	owner.do("POST", userPath(helper.ID, "/password"), map[string]any{"password": canary + "3"}, nil)
	rec = owner.do("POST", userPath(helper.ID, "/password"), map[string]any{"generate": true}, nil)
	var gen struct{ Password string }
	json.Unmarshal(rec.Body.Bytes(), &gen)
	owner.do("PATCH", userPath(helper.ID, ""), map[string]any{"role": "operator"}, nil)
	// A server with a canary SSH password and a job queued on it.
	rec = owner.do("POST", "/api/v1/servers", map[string]any{"name": "NL", "host": "192.0.2.10", "authType": "password", "password": canary + "4"}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	e.db.SetHostKey(context.Background(), model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	rec = owner.do("POST", "/api/v1/servers/"+strconv.FormatInt(srv.ID, 10)+"/deploy", map[string]any{"tls": "self-signed", "port": 443}, nil)
	var job jobJSON
	json.Unmarshal(rec.Body.Bytes(), &job)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("deploy: %d %s", rec.Code, rec.Body)
	}

	list := func(q url.Values) auditPageJSON {
		t.Helper()
		rec := owner.do("GET", "/api/v1/audit?"+q.Encode(), nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%v: %d %s", q, rec.Code, rec.Body)
		}
		for _, s := range []string{canary, gen.Password} {
			if strings.Contains(rec.Body.String(), s) {
				t.Fatalf("a password in the audit: %s", rec.Body)
			}
		}
		var p auditPageJSON
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	actions := func(p auditPageJSON) []string {
		var out []string
		for _, x := range p.Entries {
			out = append(out, x.Action)
		}
		return out
	}

	all := list(url.Values{"limit": {"200"}})
	if all.Next != 0 || len(all.Entries) < 11 {
		t.Fatalf("all: %d entries, next %d", len(all.Entries), all.Next)
	}
	byHelper := list(url.Values{"user": {strconv.FormatInt(helper.ID, 10)}})
	if got := actions(byHelper); !slices.Equal(got, []string{"user_password_changed", "password_change_failed", "login"}) {
		t.Fatalf("by helper: %v", got)
	}
	if byHelper.Entries[0].User != "helper" {
		t.Fatalf("user name: %+v", byHelper.Entries[0])
	}
	resets := list(url.Values{"action": {"user_password_reset"}})
	if got := actions(resets); len(got) != 2 || resets.Entries[0].Details != "helper (сгенерирован)" || resets.Entries[1].Details != "helper" {
		t.Fatalf("resets: %+v", resets.Entries)
	}
	if got := actions(list(url.Values{"action": {"login,login_failed"}})); !slices.Equal(got, []string{"login", "login_failed"}) {
		t.Fatalf("logins: %v", got)
	}
	onHelper := list(url.Values{"target": {"user/" + strconv.FormatInt(helper.ID, 10)}})
	if got := actions(onHelper); !slices.Equal(got, []string{"user_role_changed", "user_password_reset", "user_password_reset", "user_password_changed", "password_change_failed", "user_created"}) {
		t.Fatalf("on helper: %v", got)
	}
	if onHelper.Entries[0].Object != "helper" || onHelper.Entries[0].Details != "helper: admin → operator" {
		t.Fatalf("%+v", onHelper.Entries[0])
	}
	servers := list(url.Values{"target": {"server/"}})
	if got := actions(servers); !slices.Equal(got, []string{"job_submitted", "server_created"}) {
		t.Fatalf("servers: %v", got)
	}
	if x := servers.Entries[0]; x.Object != "NL" || x.Details != "job="+strconv.FormatInt(job.ID, 10)+" kind=deploy" || x.User != "owner" {
		t.Fatalf("job entry: %+v", x)
	}
	// The auth clock moved an hour between the two groups of actions.
	period := list(url.Values{"from": {start.Format(time.RFC3339)}, "to": {later.Format(time.RFC3339)}})
	if got := actions(period); !slices.Equal(got, []string{"user_password_changed", "password_change_failed", "login", "login_failed", "user_created", "setup"}) {
		t.Fatalf("period: %v", got)
	}
	code(t, owner.do("GET", "/api/v1/audit?from=yesterday", nil, nil), http.StatusBadRequest, "invalid")

	// Pages of 5 cover the whole log once, newest first.
	var ids []int64
	for before := int64(0); ; {
		q := url.Values{"limit": {"5"}}
		if before != 0 {
			q.Set("before", strconv.FormatInt(before, 10))
		}
		p := list(q)
		if len(p.Entries) > 5 {
			t.Fatalf("page of %d", len(p.Entries))
		}
		for _, x := range p.Entries {
			ids = append(ids, x.ID)
		}
		if p.Next == 0 {
			break
		}
		before = p.Next
	}
	var want []int64
	for _, x := range all.Entries {
		want = append(want, x.ID)
	}
	if !slices.Equal(ids, want) {
		t.Fatalf("pages %v, want %v", ids, want)
	}
}
