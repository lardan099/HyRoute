package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// brokenStore fails SchemaVersion, as a database with a disk error would.
type brokenStore struct {
	*sqlite.DB
	err error
}

func (b brokenStore) SchemaVersion(context.Context) (int, error) { return 0, b.err }

func openDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

var testUI = fstest.MapFS{
	"index.html":       {Data: []byte("<!doctype html><title>admin</title>")},
	"assets/app-1.js":  {Data: []byte("console.log(1)")},
	"assets/app-1.css": {Data: []byte("body{}")},
}

func do(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) Error {
	t.Helper()
	var body struct{ Error Error }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not a JSON error: %q", rec.Body.String())
	}
	if body.Error.Code == "" || body.Error.Message == "" {
		t.Fatalf("error without code or message: %q", rec.Body.String())
	}
	return body.Error
}

func TestHealth(t *testing.T) {
	db := openDB(t)
	h := New(Deps{Store: db, Version: "v1.2.3"})
	wantVersion, _ := db.SchemaVersion(context.Background())
	rec := do(h, "GET", "/api/v1/health")
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]any
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "ok" || body["version"] != "v1.2.3" || body["schemaVersion"] != float64(wantVersion) {
		t.Fatalf("%v", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("API responses must not be cached")
	}
}

func TestHealthDBDown(t *testing.T) {
	h := New(Deps{Store: brokenStore{DB: openDB(t), err: errors.New("disk I/O error")}})
	rec := do(h, "GET", "/api/v1/health")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", rec.Code)
	}
	e := decodeError(t, rec)
	if e.Code != "db_unavailable" || !strings.Contains(e.Details, "disk I/O") {
		t.Fatalf("%+v", e)
	}
}

func TestUnknownAPIIsJSON404(t *testing.T) {
	h := New(Deps{Store: openDB(t), UI: testUI})
	for _, p := range []string{"/api/v1/nope", "/api/v2/health"} {
		rec := do(h, "GET", p)
		if rec.Code != 404 {
			t.Fatalf("%s: status %d", p, rec.Code)
		}
		if decodeError(t, rec).Code != "not_found" {
			t.Fatalf("%s: %q", p, rec.Body.String())
		}
	}
	// A wrong method on a known route is not answered with the UI.
	rec := do(h, "POST", "/api/v1/health")
	if rec.Code == 200 || strings.Contains(rec.Body.String(), "<title>") {
		t.Fatalf("POST health: %d %q", rec.Code, rec.Body.String())
	}
}

func TestUIServingAndFallback(t *testing.T) {
	h := New(Deps{Store: openDB(t), UI: testUI})
	for _, p := range []string{"/", "/servers", "/deployments/42"} {
		rec := do(h, "GET", p)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<title>admin</title>") {
			t.Fatalf("%s: %d %q", p, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-cache" {
			t.Fatalf("%s: index must be revalidated", p)
		}
	}
	rec := do(h, "GET", "/assets/app-1.js")
	if rec.Code != 200 || rec.Body.String() != "console.log(1)" {
		t.Fatalf("asset: %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatal("hashed assets should be cached")
	}
	if rec := do(h, "POST", "/servers"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST to UI: %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := New(Deps{Store: openDB(t), UI: testUI})
	for _, p := range []string{"/", "/api/v1/health"} {
		rec := do(h, "GET", p)
		for _, k := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
			if rec.Header().Get(k) == "" {
				t.Errorf("%s: no %s", p, k)
			}
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: CSP allows framing", p)
		}
	}
}

func TestErrorDetailsRedacted(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, Errorf(http.StatusBadGateway, "ssh", "Сервер недоступен.", errors.New("dial: password=fake-secret-value hysteria2://fake@h:1")))
	if strings.Contains(rec.Body.String(), "fake-secret-value") || strings.Contains(rec.Body.String(), "fake@h") {
		t.Fatalf("secret in API error: %s", rec.Body)
	}
}

func TestPanicBecomesInternalError(t *testing.T) {
	s := &server{Deps: Deps{Log: slog.New(slog.DiscardHandler)}}
	h := s.recoverPanics(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := do(h, "GET", "/api/v1/x")
	if rec.Code != 500 {
		t.Fatalf("status %d", rec.Code)
	}
	e := decodeError(t, rec)
	if e.Code != "internal" || strings.Contains(rec.Body.String(), "boom") {
		t.Fatalf("panic text leaked or wrong code: %q", rec.Body.String())
	}
}

func TestBodyTimeout(t *testing.T) {
	bodyTimeout = 300 * time.Millisecond
	t.Cleanup(func() { bodyTimeout = time.Minute })
	e := newEnv(t)
	ts := httptest.NewServer(e.h)
	defer ts.Close()

	// A promised body that never comes: the public login and a route that
	// answers 401 without reading it both let the connection go.
	for _, path := range []string{"/api/v1/session", "/api/v1/servers"} {
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{", path, ts.Listener.Addr())
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		resp, err := io.ReadAll(c)
		c.Close()
		if err != nil {
			t.Fatalf("%s: connection held: %v (%q)", path, err, resp)
		}
		if !bytes.HasPrefix(resp, []byte("HTTP/1.1 4")) {
			t.Fatalf("%s: %q", path, resp)
		}
	}

	// Once the body is in, a request that runs longer keeps its context
	// (a whole-request ReadTimeout would end it).
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		time.Sleep(3 * bodyTimeout)
		if err := r.Context().Err(); err != nil {
			t.Errorf("request context: %v", err)
		}
		w.Write([]byte("ok"))
	}))
	ts2 := httptest.NewServer(h)
	defer ts2.Close()
	resp, err := http.Post(ts2.URL, "application/json", strings.NewReader(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "ok" {
		t.Fatalf("long request: %d %q", resp.StatusCode, b)
	}
}

// On a loopback address without a proxy only loopback names are served:
// another name pointed at 127.0.0.1 is refused before any handler.
func TestLoopbackHost(t *testing.T) {
	db := openDB(t)
	get := func(d Deps, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/v1/health", nil)
		r.Host = host
		r.RemoteAddr = "127.0.0.1:50000"
		rec := httptest.NewRecorder()
		New(d).ServeHTTP(rec, r)
		return rec
	}
	d := Deps{Store: db, Loopback: true}
	for _, host := range []string{"127.0.0.1:8480", "localhost:8480", "LOCALHOST", "[::1]:8480", "127.0.0.1"} {
		if rec := get(d, host); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", host, rec.Code, rec.Body)
		}
	}
	for _, host := range []string{"attacker.example:8480", "attacker.example", "localhost.attacker.example:8480", "203.0.113.5:8480", ""} {
		rec := get(d, host)
		if rec.Code != http.StatusMisdirectedRequest || decodeError(t, rec).Code != "bad_host" {
			t.Fatalf("%s: %d %s", host, rec.Code, rec.Body)
		}
	}
	// A reverse proxy passes the public name; an address beyond loopback
	// is not checked.
	for _, d := range []Deps{{Store: db, Loopback: true, TrustProxy: true}, {Store: db}} {
		if rec := get(d, "panel.example.com"); rec.Code != http.StatusOK {
			t.Fatalf("%+v: %d %s", d, rec.Code, rec.Body)
		}
	}
}
