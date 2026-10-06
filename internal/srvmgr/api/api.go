// Package api is the HTTP layer of the server manager: /api/v1 handlers,
// middleware and the embedded admin UI. Handlers parse requests, check
// permissions and call the services; they hold no business logic.
package api

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"path"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/connect"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/logbuf"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
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
	Deploy  *deploy.Submitter
	Apply   *apply.Applier
	// Cascade deploys cascade links (P3-02).
	Cascade *cascade.Linker
	// Geo are the controller's geo databases (P3-07), GeoJobs puts them
	// on servers.
	Geo     *geo.Store
	GeoJobs *geo.Installer
	// Keys open config revisions (the passwords journals are redacted
	// with).
	Keys *secrets.Keyring
	// Logs are the controller\'s latest log records (the Logs page).
	Logs    *logbuf.Buffer
	Log     *slog.Logger
	Version string
	// TrustProxy: believe X-Forwarded-For/-Proto/-Host from a reverse
	// proxy on a loopback address.
	TrustProxy bool
	// Loopback: the controller listens on a loopback address. Without a
	// reverse proxy (TrustProxy) it then answers only requests that name
	// it so (see loopbackHost).
	Loopback bool
	// OnSetupDone runs after the first owner is created (main removes the
	// setup token file).
	OnSetupDone func()
	// UI is the built admin app (a directory with index.html); nil
	// serves no UI.
	UI fs.FS
	// Streams ends the live event streams (job events, the Hysteria
	// journal) when it is done: main cancels it when shutdown starts, so
	// they do not hold Shutdown while other requests finish. nil: a
	// stream ends with its request only.
	Streams context.Context
}

type server struct {
	Deps
	ssh          sshLimits
	originWarned atomic.Int64 // unix time of the last warnOrigin line
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
	mux.HandleFunc("POST /api/v1/servers/{id}/deploy", s.authed(anyRole, s.startDeploy))
	mux.HandleFunc("POST /api/v1/servers/{id}/import", s.authed(anyRole, s.startImport))
	mux.HandleFunc("POST /api/v1/servers/{id}/maintain", s.authed(anyRole, s.startMaintain))
	mux.HandleFunc("GET /api/v1/servers/{id}/config", s.authed(anyRole, s.currentConfig))
	mux.HandleFunc("GET /api/v1/servers/{id}/config/edit", s.authed(writers, s.editConfig))
	mux.HandleFunc("GET /api/v1/servers/{id}/client", s.authed(anyRole, s.clientProfile))
	mux.HandleFunc("POST /api/v1/servers/{id}/client/reveal", s.authed(anyRole, s.revealClient))
	mux.HandleFunc("POST /api/v1/servers/{id}/config/render", s.authed(anyRole, s.renderConfig))
	mux.HandleFunc("POST /api/v1/servers/{id}/config/apply", s.authed(anyRole, s.applyConfig))
	mux.HandleFunc("GET /api/v1/servers/{id}/metrics", s.authed(anyRole, s.serverMetrics))
	mux.HandleFunc("GET /api/v1/metrics/latest", s.authed(anyRole, s.latestMetrics))
	mux.HandleFunc("GET /api/v1/servers/{id}/health", s.authed(anyRole, s.serverHealth))
	mux.HandleFunc("GET /api/v1/servers/{id}/traffic", s.authed(anyRole, s.serverTraffic))
	mux.HandleFunc("GET /api/v1/servers/{id}/traffic/online", s.authed(anyRole, s.trafficOnline))
	mux.HandleFunc("GET /api/v1/servers/{id}/traffic/streams", s.authed(writers, s.trafficStreams))
	mux.HandleFunc("GET /api/v1/servers/{id}/config/revisions", s.authed(anyRole, s.configRevisions))
	mux.HandleFunc("GET /api/v1/servers/{id}/config/revisions/{rev}", s.authed(writers, s.configRevision))
	mux.HandleFunc("GET /api/v1/servers/{id}/config/compare", s.authed(writers, s.compareConfigs))
	mux.HandleFunc("POST /api/v1/servers/{id}/config/rollback", s.authed(anyRole, s.rollbackConfig))
	mux.HandleFunc("POST /api/v1/servers/{id}/config/rotate", s.authed(anyRole, s.rotateConfig))
	mux.HandleFunc("POST /api/v1/servers/{id}/ports", s.authed(anyRole, s.setPorts))
	mux.HandleFunc("GET /api/v1/servers/{id}/tuning", s.authed(anyRole, s.getTuning))
	mux.HandleFunc("POST /api/v1/servers/{id}/tuning", s.authed(anyRole, s.startTuning))
	mux.HandleFunc("GET /api/v1/presets", s.authed(anyRole, s.listPresets))
	mux.HandleFunc("POST /api/v1/presets", s.authed(anyRole, s.createPreset))
	mux.HandleFunc("POST /api/v1/presets/import", s.authed(anyRole, s.importPreset))
	mux.HandleFunc("GET /api/v1/presets/{id}", s.authed(anyRole, s.getPreset))
	mux.HandleFunc("PATCH /api/v1/presets/{id}", s.authed(anyRole, s.renamePreset))
	mux.HandleFunc("DELETE /api/v1/presets/{id}", s.authed(anyRole, s.deletePreset))
	mux.HandleFunc("GET /api/v1/presets/{id}/export", s.authed(anyRole, s.exportPreset))
	mux.HandleFunc("POST /api/v1/servers/{id}/preset/preview", s.authed(anyRole, s.presetPreview))
	mux.HandleFunc("POST /api/v1/servers/{id}/preset/apply", s.authed(anyRole, s.presetApply))
	mux.HandleFunc("GET /api/v1/servers/{id}/routing", s.authed(writers, s.getRouting))
	mux.HandleFunc("POST /api/v1/servers/{id}/routing/preview", s.authed(anyRole, s.previewRouting))
	mux.HandleFunc("POST /api/v1/servers/{id}/routing/apply", s.authed(anyRole, s.applyRouting))
	mux.HandleFunc("POST /api/v1/servers/{id}/routing/check", s.authed(anyRole, s.checkRouting))
	mux.HandleFunc("GET /api/v1/servers/{id}/routing/export", s.authed(writers, s.exportRouting))
	mux.HandleFunc("GET /api/v1/servers/{id}/routing/file", s.authed(writers, s.routingFile))
	mux.HandleFunc("POST /api/v1/routing/import", s.authed(anyRole, s.importRouting))
	mux.HandleFunc("GET /api/v1/routing/templates", s.authed(anyRole, s.routingTemplates))
	mux.HandleFunc("GET /api/v1/chain-templates", s.authed(anyRole, s.chainTemplates))
	mux.HandleFunc("POST /api/v1/chain-templates/import", s.authed(anyRole, s.importChainTemplate))
	mux.HandleFunc("GET /api/v1/chains/{id}/template", s.authed(writers, s.chainTemplate))
	mux.HandleFunc("GET /api/v1/geo", s.authed(anyRole, s.geoInfo))
	mux.HandleFunc("POST /api/v1/geo/update", s.authed(anyRole, s.geoUpdate))
	mux.HandleFunc("GET /api/v1/geo/categories", s.authed(anyRole, s.geoCategories))
	mux.HandleFunc("GET /api/v1/servers/{id}/geo", s.authed(anyRole, s.serverGeo))
	mux.HandleFunc("POST /api/v1/servers/{id}/geo", s.authed(anyRole, s.installGeo))
	mux.HandleFunc("GET /api/v1/chains", s.authed(anyRole, s.listChains))
	mux.HandleFunc("POST /api/v1/chains", s.authed(anyRole, s.createChain))
	mux.HandleFunc("GET /api/v1/chains/{id}", s.authed(anyRole, s.getChain))
	mux.HandleFunc("PATCH /api/v1/chains/{id}", s.authed(anyRole, s.updateChain))
	mux.HandleFunc("DELETE /api/v1/chains/{id}", s.authed(anyRole, s.deleteChain))
	mux.HandleFunc("POST /api/v1/chains/{id}/link", s.authed(anyRole, s.linkChain))
	mux.HandleFunc("POST /api/v1/chains/{id}/unlink", s.authed(anyRole, s.unlinkChain))
	mux.HandleFunc("GET /api/v1/chains/{id}/checks", s.authed(anyRole, s.chainChecks))
	mux.HandleFunc("POST /api/v1/chains/{id}/check", s.authed(anyRole, s.checkChain))
	mux.HandleFunc("GET /api/v1/servers/{id}/status", s.authed(anyRole, s.serviceStatus))
	mux.HandleFunc("POST /api/v1/servers/{id}/service/{action}", s.authed(anyRole, s.serviceAction))
	mux.HandleFunc("GET /api/v1/servers/{id}/journal", s.authed(anyRole, s.journal))
	mux.HandleFunc("GET /api/v1/jobs", s.authed(anyRole, s.listJobs))
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.authed(anyRole, s.getJob))
	mux.HandleFunc("GET /api/v1/jobs/{id}/logs", s.authed(anyRole, s.jobLogs))
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.authed(anyRole, s.jobEvents))
	mux.HandleFunc("POST /api/v1/jobs/{id}/retry", s.authed(anyRole, s.retryJob))
	mux.HandleFunc("GET /api/v1/logs", s.authed(anyRole, s.logs))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeError(w, errNotFound) })
	if d.UI != nil {
		mux.Handle("/", uiHandler(d.UI))
	}
	return s.recoverPanics(s.logRequests(securityHeaders(s.loopbackHost(limitBody(mux)))))
}

var errBadHost = &Error{Status: http.StatusMisdirectedRequest, Code: "bad_host", Message: "Панель на этом адресе открывается только как localhost, 127.0.0.1 или [::1]: откройте её по такому адресу."}

// loopbackHost: a controller on a loopback address without a proxy
// answers only localhost, 127.0.0.1 and [::1]. Another name pointed at
// 127.0.0.1 (DNS rebinding) would make a page of another site
// same-origin with the admin: it could read the API and spend the login
// limits of the owner's own address.
func (s *server) loopbackHost(next http.Handler) http.Handler {
	if !s.Loopback || s.TrustProxy {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if !strings.EqualFold(host, "localhost") && !isLoopback(host) {
			writeError(w, errBadHost)
			return
		}
		next.ServeHTTP(w, r)
	})
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

// maxRoutingBody bounds the bodies of the routing editor and of the
// config editor: a draft of a 1 MB ACL (acl.file moved into the config)
// is a few times larger as JSON, and the config editor carries the config
// with it.
const maxRoutingBody = 6 << 20

// bodyTimeout bounds the time a body takes to arrive (a few MB fit even
// on a slow link). The server has no ReadTimeout, it would end event
// streams, so without it a body that never comes holds its connection
// forever.
var bodyTimeout = time.Minute

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			limit := int64(maxBody)
			if strings.Contains(r.URL.Path, "/routing") || strings.HasPrefix(r.URL.Path, "/api/v1/chain-templates/") ||
				strings.HasSuffix(r.URL.Path, "/config/render") || strings.HasSuffix(r.URL.Path, "/config/apply") {
				limit = maxRoutingBody
			} else if r.URL.Path == "/api/v1/presets/import" {
				limit = maxPresetBody
			}
			if r.ContentLength != 0 {
				// It also covers the rest of a body the handler did not
				// read: net/http reads it after the handler. Once the body
				// is in, the deadline no longer matters (HTTP/1 lifts it,
				// HTTP/2 applies it to the body only).
				http.NewResponseController(w).SetReadDeadline(time.Now().Add(bodyTimeout))
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
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
