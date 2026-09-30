package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/connect"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

const pass = "correct horse battery"

type testEnv struct {
	t       *testing.T
	h       http.Handler
	db      *sqlite.DB
	auth    *auth.Service
	servers *servers.Service
	connect *connect.Connector
	jobs    *jobs.Engine
	keys    *secrets.Keyring
	clock   time.Time
}

func newEnv(t *testing.T) *testEnv {
	db := openDB(t)
	e := &testEnv{t: t, db: db, clock: time.Unix(1_700_000_000, 0)}
	e.auth = auth.New(db)
	e.auth.Params = auth.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	e.auth.Now = func() time.Time { return e.clock }
	keys, err := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	e.servers = servers.New(db, keys)
	e.connect = connect.New(e.servers, db, redact.New())
	e.connect.Timeout = 5 * time.Second
	e.jobs = jobs.New(db, keys, redact.New(), e.connect, nil)
	e.jobs.Poll = 20 * time.Millisecond
	e.jobs.Register(deploy.Kind(deploy.Deps{Store: db, Keys: keys, Resolver: &hyrelease.Resolver{}}))
	e.keys = keys
	e.h = New(Deps{Store: db, Auth: e.auth, Servers: e.servers, Connect: e.connect, Jobs: e.jobs,
		Deploy: &deploy.Submitter{Store: db, Keys: keys, Jobs: e.jobs}})
	return e
}

// client is a browser: it keeps the session cookie and the CSRF token.
type client struct {
	e      *testEnv
	cookie *http.Cookie
	csrf   string
	ip     string
}

func (e *testEnv) client() *client { return &client{e: e, ip: "127.0.0.1"} }

func (c *client) do(method, path string, body any, hdr map[string]string) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, path, &buf)
	r.RemoteAddr = c.ip + ":50000"
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	c.e.h.ServeHTTP(rec, r)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == cookieName {
			if ck.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = ck
			}
		}
	}
	var sj sessionJSON
	if json.Unmarshal(rec.Body.Bytes(), &sj) == nil && sj.CSRFToken != "" {
		c.csrf = sj.CSRFToken
	}
	return rec
}

func (e *testEnv) setupOwner() *client {
	e.t.Helper()
	tok, err := e.auth.PrepareSetup(context.Background())
	if err != nil || tok == "" {
		e.t.Fatal(tok, err)
	}
	c := e.client()
	rec := c.do("POST", "/api/v1/setup", map[string]string{"token": tok, "username": "owner", "password": pass}, nil)
	if rec.Code != http.StatusCreated || c.cookie == nil || c.csrf == "" {
		e.t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	return c
}

func (e *testEnv) login(user string) *client {
	e.t.Helper()
	c := e.client()
	rec := c.do("POST", "/api/v1/session", map[string]string{"username": user, "password": pass}, nil)
	if rec.Code != 200 {
		e.t.Fatalf("login %s: %d %s", user, rec.Code, rec.Body)
	}
	return c
}

func code(t *testing.T, rec *httptest.ResponseRecorder, status int, errCode string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body)
	}
	if errCode != "" && decodeError(t, rec).Code != errCode {
		t.Fatalf("code %q, want %q", decodeError(t, rec).Code, errCode)
	}
}

func TestSetupFlow(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	rec := c.do("GET", "/api/v1/setup", nil, nil)
	if !strings.Contains(rec.Body.String(), `"needed":true`) {
		t.Fatalf("%s", rec.Body)
	}
	owner := e.setupOwner()
	if !owner.cookie.HttpOnly || owner.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags: %+v", owner.cookie)
	}
	if owner.cookie.Secure {
		t.Fatal("Secure cookie over plain HTTP on loopback would not come back")
	}
	rec = c.do("GET", "/api/v1/setup", nil, nil)
	if !strings.Contains(rec.Body.String(), `"needed":false`) {
		t.Fatalf("%s", rec.Body)
	}
	// First run cannot be repeated, whatever token is sent.
	rec = e.client().do("POST", "/api/v1/setup", map[string]string{"token": "anything", "username": "evil", "password": pass}, nil)
	code(t, rec, http.StatusConflict, "setup_done")
	if n, _ := e.db.CountUsers(context.Background()); n != 1 {
		t.Fatalf("%d users", n)
	}
	// The session works.
	rec = owner.do("GET", "/api/v1/session", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"role":"owner"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestSetupNeedsToken(t *testing.T) {
	e := newEnv(t)
	e.auth.PrepareSetup(context.Background())
	rec := e.client().do("POST", "/api/v1/setup", map[string]string{"token": "guess", "username": "owner", "password": pass}, nil)
	code(t, rec, http.StatusForbidden, "bad_setup_token")
	rec = e.client().do("POST", "/api/v1/setup", map[string]string{"username": "owner"}, map[string]string{"Content-Type": "text/plain"})
	code(t, rec, http.StatusUnsupportedMediaType, "bad_content_type")
}

func TestLoginErrorsAndRateLimit(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	c := e.client()
	rec := c.do("POST", "/api/v1/session", map[string]string{"username": "owner", "password": "wrong password"}, nil)
	code(t, rec, http.StatusUnauthorized, "bad_credentials")
	if c.cookie != nil {
		t.Fatal("cookie set on a failed login")
	}
	for i := 0; i < 5; i++ {
		c.do("POST", "/api/v1/session", map[string]string{"username": "owner", "password": "wrong password"}, nil)
	}
	rec = c.do("POST", "/api/v1/session", map[string]string{"username": "owner", "password": pass}, nil)
	code(t, rec, http.StatusTooManyRequests, "rate_limited")
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	e.clock = e.clock.Add(10 * time.Minute)
	e.login("owner")
}

func TestSessionRequired(t *testing.T) {
	e := newEnv(t)
	e.setupOwner()
	c := e.client()
	for _, p := range []string{"/api/v1/session", "/api/v1/sessions", "/api/v1/users"} {
		code(t, c.do("GET", p, nil, nil), http.StatusUnauthorized, "unauthorized")
	}
	c.cookie = &http.Cookie{Name: cookieName, Value: "forged"}
	code(t, c.do("GET", "/api/v1/session", nil, nil), http.StatusUnauthorized, "unauthorized")
	// Health, setup status and login need no session.
	if rec := c.do("GET", "/api/v1/health", nil, nil); rec.Code != 200 {
		t.Fatalf("health %d", rec.Code)
	}
}

func TestExpiredAndRevokedSessions(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	e.clock = e.clock.Add(e.auth.IdleTimeout + time.Minute)
	code(t, owner.do("GET", "/api/v1/session", nil, nil), http.StatusUnauthorized, "unauthorized")
	if owner.cookie != nil {
		t.Fatal("dead session cookie not cleared")
	}

	a := e.login("owner")
	b := e.login("owner")
	var list []sessionInfoJSON
	json.Unmarshal(a.do("GET", "/api/v1/sessions", nil, nil).Body.Bytes(), &list)
	if len(list) != 2 {
		t.Fatalf("%d sessions", len(list))
	}
	var other int64
	for _, s := range list {
		if !s.Current {
			other = s.ID
		}
	}
	if rec := a.do("DELETE", "/api/v1/sessions/"+strconv.FormatInt(other, 10), nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body)
	}
	code(t, b.do("GET", "/api/v1/session", nil, nil), http.StatusUnauthorized, "unauthorized")
	// Logout: the old cookie, sent again, is refused.
	old := *a.cookie
	if rec := a.do("DELETE", "/api/v1/session", nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if a.cookie != nil {
		t.Fatal("logout did not clear the cookie")
	}
	a.cookie = &old
	code(t, a.do("GET", "/api/v1/session", nil, nil), http.StatusUnauthorized, "unauthorized")
}

func TestCSRF(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	body := map[string]string{"username": "viewer", "password": pass, "role": "readonly"}
	saved := owner.csrf
	owner.csrf = ""
	code(t, owner.do("POST", "/api/v1/users", body, nil), http.StatusForbidden, "csrf")
	owner.csrf = "wrong"
	code(t, owner.do("POST", "/api/v1/users", body, nil), http.StatusForbidden, "csrf")
	owner.csrf = saved
	code(t, owner.do("POST", "/api/v1/users", body, map[string]string{"Origin": "https://evil.example"}), http.StatusForbidden, "csrf")
	code(t, owner.do("POST", "/api/v1/users", body, map[string]string{"Sec-Fetch-Site": "cross-site"}), http.StatusForbidden, "csrf")
	// Cross-site login attempts are refused too (login CSRF).
	code(t, e.client().do("POST", "/api/v1/session", map[string]string{"username": "owner", "password": pass}, map[string]string{"Sec-Fetch-Site": "cross-site"}), http.StatusForbidden, "csrf")
	rec := owner.do("POST", "/api/v1/users", body, map[string]string{"Origin": "http://example.com", "Sec-Fetch-Site": "same-origin"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("same-origin create: %d %s", rec.Code, rec.Body)
	}
}

func TestReadOnlyCannotWrite(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	rec := owner.do("POST", "/api/v1/users", map[string]string{"username": "viewer", "password": pass, "role": "readonly"}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	ro := e.login("viewer")
	if rec := ro.do("GET", "/api/v1/users", nil, nil); rec.Code != 200 {
		t.Fatalf("read-only cannot read: %d", rec.Code)
	}
	code(t, ro.do("POST", "/api/v1/users", map[string]string{"username": "x", "password": pass, "role": "readonly"}, nil), http.StatusForbidden, "forbidden")
	code(t, ro.do("GET", "/api/v1/sessions?all=1", nil, nil), http.StatusForbidden, "forbidden")
	// But a read-only user can log out.
	if rec := ro.do("DELETE", "/api/v1/session", nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("read-only logout: %d %s", rec.Code, rec.Body)
	}
	// An operator is not an admin: no user management.
	var u model.User
	u.Username, u.Role = "op", model.RoleOperator
	u.PasswordHash, _ = auth.HashPassword(pass, e.auth.Params)
	e.db.CreateUser(context.Background(), &u)
	op := e.login("op")
	code(t, op.do("POST", "/api/v1/users", map[string]string{"username": "y", "password": pass, "role": "readonly"}, nil), http.StatusForbidden, "forbidden")
}

func TestSecureCookieBehindProxy(t *testing.T) {
	e := newEnv(t)
	e.h = New(Deps{Store: e.db, Auth: e.auth, Servers: e.servers, TrustProxy: true})
	c := e.setupOwner()
	if c.cookie.Secure {
		t.Fatal("plain HTTP without a proxy header got a Secure cookie")
	}
	c2 := e.client()
	c2.do("POST", "/api/v1/session", map[string]string{"username": "owner", "password": pass}, map[string]string{"X-Forwarded-Proto": "https"})
	if c2.cookie == nil || !c2.cookie.Secure {
		t.Fatalf("HTTPS proxy: cookie %+v", c2.cookie)
	}
	// The header is ignored from a non-loopback peer.
	c3 := e.client()
	c3.ip = "203.0.113.5"
	c3.do("POST", "/api/v1/session", map[string]string{"username": "owner", "password": pass}, map[string]string{"X-Forwarded-Proto": "https"})
	if c3.cookie == nil || c3.cookie.Secure {
		t.Fatalf("untrusted peer: cookie %+v", c3.cookie)
	}
}
