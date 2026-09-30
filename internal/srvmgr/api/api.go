// Package api is the HTTP layer of the server manager: /api/v1 handlers,
// middleware and the embedded admin UI. Handlers parse requests, check
// permissions and call the services; they hold no business logic.
package api

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"runtime/debug"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/connect"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Deps is what the API needs.
type Deps struct {
	Store   store.Store
	Auth    *auth.Service
	Servers *servers.Service
	Connect *connect.Connector
	Jobs    *jobs.Engine
	Log     *slog.Logger
	Version string
	// TrustProxy: believe X-Forwarded-For/-Proto from a reverse proxy on
	// a loopback address.
	TrustProxy bool
	// OnSetupDone runs after the first owner is created (main removes the
	// setup token file).
	OnSetupDone func()
	// UI is the built admin app (a directory with index.html); nil
	// serves no UI.
	UI fs.FS
}

type server struct {
	Deps
}

// New returns the HTTP handler of the controller.
func New(d Deps) http.Handler {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	s := &server{Deps: d}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/setup", s.public(s.getSetup))
	mux.HandleFunc("POST /api/v1/setup", s.public(s.postSetup))
	mux.HandleFunc("POST /api/v1/session", s.public(s.postSession))
	mux.HandleFunc("GET /api/v1/session", s.authed(anyRole, s.getSession))
	mux.HandleFunc("DELETE /api/v1/session", s.authed(ownSession, s.deleteSession))
	mux.HandleFunc("GET /api/v1/sessions", s.authed(anyRole, s.listSessions))
	mux.HandleFunc("DELETE /api/v1/sessions/{id}", s.authed(ownSession, s.revokeSession))
	mux.HandleFunc("GET /api/v1/users", s.authed(anyRole, s.listUsers))
	mux.HandleFunc("POST /api/v1/users", s.authed(manageUsers, s.createUser))
	mux.HandleFunc("GET /api/v1/servers", s.authed(anyRole, s.listServers))
	mux.HandleFunc("POST /api/v1/servers", s.authed(anyRole, s.createServer))
	mux.HandleFunc("GET /api/v1/servers/{id}", s.authed(anyRole, s.getServer))
	mux.HandleFunc("PATCH /api/v1/servers/{id}", s.authed(anyRole, s.updateServer))
	mux.HandleFunc("DELETE /api/v1/servers/{id}", s.authed(anyRole, s.deleteServer))
	mux.HandleFunc("POST /api/v1/servers/{id}/check", s.authed(anyRole, s.checkServer))
	mux.HandleFunc("POST /api/v1/servers/{id}/host-key", s.authed(anyRole, s.trustHostKey))
	mux.HandleFunc("POST /api/v1/servers/{id}/preflight", s.authed(anyRole, s.startPreflight))
	mux.HandleFunc("GET /api/v1/jobs", s.authed(anyRole, s.listJobs))
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.authed(anyRole, s.getJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}/logs", s.authed(anyRole, s.jobLogs))
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.authed(anyRole, s.jobEvents))
	mux.HandleFunc("POST /api/v1/jobs/{id}/retry", s.authed(anyRole, s.retryJob))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeError(w, errNotFound) })
	if d.UI != nil {
		mux.Handle("/", uiHandler(d.UI))
	}
	return s.recoverPanics(s.logRequests(securityHeaders(limitBody(mux))))
}

// fail answers with err; an error that is not an *Error is logged here
// (the client only sees a generic internal error).
func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var e *Error
	if !errors.As(err, &e) {
		s.Log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	}
	writeError(w, err)
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.SchemaVersion(r.Context())
	if err != nil {
		s.Log.Error("health: database", "err", err)
		writeError(w, Errorf(http.StatusServiceUnavailable, "db_unavailable", "База данных controller недоступна.", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"version":       s.Version,
		"schemaVersion": v,
	})
}

// uiHandler serves the admin app; paths that are not files get
// index.html (the app routes on the client).
func uiHandler(ui fs.FS) http.Handler {
	files := http.FileServerFS(ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, &Error{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed", Message: "Метод не поддерживается."})
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if st, err := fs.Stat(ui, p); err != nil || st.IsDir() {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "assets/") {
			// Vite names assets by content hash.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

// securityHeaders: the admin loads only its own scripts and styles and is
// never framed.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// maxBody bounds request bodies: the API takes small JSON documents
// (a Hysteria config is a few KB).
const maxBody = 1 << 20

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Flush keeps server-sent events working through the wrapper.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests logs API requests (not UI files): method, path without the
// query (it may carry tokens), status and duration.
func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		s.Log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "ms", time.Since(start).Milliseconds())
	})
}

func (s *server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				s.Log.Error("panic in handler", "path", r.URL.Path, "panic", v, "stack", string(debug.Stack()))
				writeError(w, errInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
