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

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/alerts"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/backup"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/connect"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/diag"
	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/logbuf"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
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
	// Logs are the controller's latest log records (the Logs page).
	Logs    *logbuf.Buffer
	Log     *slog.Logger
	Version string
	// TrustProxy: believe X-Forwarded-For/-Proto/-Host from a reverse
	// proxy on a loopback address.
	TrustProxy bool
	// Loopback: the controller listens on a loopback address. Without a
	// reverse proxy (TrustProxy) it then answers only requests that name
	// it so (see hostCheck).
	Loopback bool
	// AllowedHosts (-allowed-host): the names besides the loopback ones
	// the panel answers to, in every mode; empty: the check above only.
	AllowedHosts []string
	// OnSetupDone runs after the first owner is created (main removes the
	// setup token file).
	OnSetupDone func()
	// UI is the built admin app (a directory with index.html); nil
	// serves no UI.
	UI fs.FS
	// Backups are the copies of the database (nil: none).
	Backups *backup.Manager
	// KeyCheck tries a copy of the master key against the database (nil:
	// not offered).
	KeyCheck func(ctx context.Context, text string) (secrets.KeyReport, error)
	// Diag builds the diagnostic bundle (nil: not offered).
	Diag *diag.Builder
	// Attention is the summary «Требует внимания» (nil: an empty one).
	Attention *events.Attention
	// Alerts sends notifications through the channels (nil: channels are
	// stored, but nothing sends, and there is no test).
	Alerts *alerts.Notifier
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
	for _, rt := range s.routes() {
		mux.HandleFunc(rt.pattern, s.guard(rt.rule, rt.h))
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeError(w, errNotFound) })
	if d.UI != nil {
		mux.Handle("/", uiHandler(d.UI))
	}
	return s.recoverPanics(s.logRequests(securityHeaders(s.hostCheck(limitBody(mux)))))
}

// route is an endpoint of the API and what it needs from the caller.
type route struct {
	pattern string
	rule    rule
	h       http.HandlerFunc
}

// routes is every endpoint of the API (P4-04): each one declares who may
// call it (access.go): public, signedIn, or need(permission, finders) —
// the permission of the role and how the servers of the request are found
// (global: none; onServer, onChain, onJob: the {id} of the path; body*: a
// field of the body). Nothing is registered on the mux but through this
// table: TestRoutesDeclared fails otherwise, and TestRoleRouteMatrix checks
// every route for every role.
func (s *server) routes() []route {
	return []route{
		{"GET /api/v1/health", public, s.health},
		{"GET /api/v1/setup", public, s.getSetup},
		{"POST /api/v1/setup", public, s.postSetup},
		{"POST /api/v1/session", public, s.postSession},
		{"GET /api/v1/session", signedIn, s.getSession},
		{"DELETE /api/v1/session", signedIn, s.deleteSession},
		{"GET /api/v1/sessions", signedIn, s.listSessions},
		{"DELETE /api/v1/sessions/{id}", signedIn, s.revokeSession},
		{"GET /api/v1/users", signedIn, s.listUsers},
		{"GET /api/v1/roles", signedIn, s.listRoles},
		{"POST /api/v1/users", need(model.PermUsers, global), s.createUser},
		{"POST /api/v1/session/password", signedIn, s.changePassword},
		{"PATCH /api/v1/users/{id}", need(model.PermUsers, global), s.updateUser},
		{"DELETE /api/v1/users/{id}", need(model.PermUsers, global), s.deleteUser},
		{"POST /api/v1/users/{id}/password", need(model.PermUsers, global), s.resetPassword},
		{"POST /api/v1/users/{id}/owner", ownerOnly(need(model.PermUsers, global)), s.transferOwner},
		{"GET /api/v1/audit", need(model.PermUsers, global), s.listAudit},
		{"GET /api/v1/servers", need(model.PermView, global), s.listServers},
		{"POST /api/v1/servers", need(model.PermDeploy, bodyTags), s.createServer},
		{"GET /api/v1/servers/{id}", need(model.PermView, onServer), s.getServer},
		{"PATCH /api/v1/servers/{id}", need(model.PermCredentials, onServer, bodyTags), s.updateServer},
		{"DELETE /api/v1/servers/{id}", need(model.PermDeploy, onServer), s.deleteServer},
		{"POST /api/v1/servers/{id}/check", need(model.PermCredentials, onServer), s.checkServer},
		{"POST /api/v1/servers/{id}/host-key", need(model.PermCredentials, onServer), s.trustHostKey},
		{"POST /api/v1/servers/{id}/preflight", need(model.PermDeploy, onServer), s.startPreflight},
		{"POST /api/v1/servers/{id}/deploy", need(model.PermDeploy, onServer, bodyVia), s.startDeploy},
		{"POST /api/v1/servers/{id}/import", need(model.PermDeploy, onServer), s.startImport},
		{"POST /api/v1/servers/{id}/maintain", need(model.PermDeploy, onServer, bodyVia), s.startMaintain},
		{"GET /api/v1/servers/{id}/config", need(model.PermView, onServer), s.currentConfig},
		{"GET /api/v1/servers/{id}/config/edit", need(model.PermConfig, onServer), s.editConfig},
		{"GET /api/v1/servers/{id}/client", need(model.PermView, onServer), s.clientProfile},
		{"POST /api/v1/servers/{id}/client/reveal", need(model.PermClientsReveal, onServer), s.revealClient},
		{"POST /api/v1/servers/{id}/clients", need(model.PermClientsManage, onServer), s.addClient},
		{"POST /api/v1/servers/{id}/clients/remove", need(model.PermClientsManage, onServer), s.removeClient},
		{"POST /api/v1/servers/{id}/clients/password", need(model.PermClientsManage, onServer), s.clientPassword},
		{"POST /api/v1/servers/{id}/config/render", need(model.PermConfig, onServer), s.renderConfig},
		{"POST /api/v1/servers/{id}/config/apply", need(model.PermConfig, onServer), s.applyConfig},
		{"GET /api/v1/servers/{id}/metrics", need(model.PermView, onServer), s.serverMetrics},
		{"GET /api/v1/metrics/latest", need(model.PermView, global), s.latestMetrics},
		{"GET /api/v1/servers/{id}/health", need(model.PermView, onServer), s.serverHealth},
		{"GET /api/v1/servers/{id}/traffic", need(model.PermView, onServer), s.serverTraffic},
		{"GET /api/v1/servers/{id}/traffic/online", need(model.PermView, onServer), s.trafficOnline},
		{"GET /api/v1/servers/{id}/traffic/streams", need(model.PermConfig, onServer), s.trafficStreams},
		{"GET /api/v1/servers/{id}/config/revisions", need(model.PermView, onServer), s.configRevisions},
		{"GET /api/v1/servers/{id}/config/revisions/{rev}", need(model.PermConfig, onServer), s.configRevision},
		{"GET /api/v1/servers/{id}/config/compare", need(model.PermConfig, onServer), s.compareConfigs},
		{"POST /api/v1/servers/{id}/config/rollback", need(model.PermConfig, onServer), s.rollbackConfig},
		{"POST /api/v1/servers/{id}/config/rotate", need(model.PermConfig, onServer), s.rotateConfig},
		{"POST /api/v1/servers/{id}/ports", need(model.PermConfig, onServer), s.setPorts},
		{"GET /api/v1/servers/{id}/tuning", need(model.PermView, onServer), s.getTuning},
		{"POST /api/v1/servers/{id}/tuning", need(model.PermConfig, onServer), s.startTuning},
		{"GET /api/v1/presets", need(model.PermView, global), s.listPresets},
		{"POST /api/v1/presets", need(model.PermPresets, bodyServerID), s.createPreset},
		{"POST /api/v1/presets/import", need(model.PermPresets, global), s.importPreset},
		{"GET /api/v1/presets/{id}", need(model.PermView, global), s.getPreset},
		{"PATCH /api/v1/presets/{id}", need(model.PermPresets, global), s.renamePreset},
		{"DELETE /api/v1/presets/{id}", need(model.PermPresets, global), s.deletePreset},
		{"GET /api/v1/presets/{id}/export", need(model.PermView, global), s.exportPreset},
		{"POST /api/v1/servers/{id}/preset/preview", need(model.PermConfig, onServer), s.presetPreview},
		{"POST /api/v1/servers/{id}/preset/apply", need(model.PermConfig, onServer), s.presetApply},
		{"GET /api/v1/servers/{id}/routing", need(model.PermConfig, onServer), s.getRouting},
		{"POST /api/v1/servers/{id}/routing/preview", need(model.PermConfig, onServer), s.previewRouting},
		{"POST /api/v1/servers/{id}/routing/apply", need(model.PermConfig, onServer), s.applyRouting},
		{"POST /api/v1/servers/{id}/routing/check", need(model.PermConfig, onServer), s.checkRouting},
		{"POST /api/v1/servers/{id}/routing/services", need(model.PermConfig, onServer), s.routingServices},
		{"POST /api/v1/servers/{id}/routing/services/build", need(model.PermConfig, onServer), s.buildRoutingServices},
		{"GET /api/v1/servers/{id}/routing/export", need(model.PermConfig, onServer), s.exportRouting},
		{"GET /api/v1/servers/{id}/routing/file", need(model.PermConfig, onServer), s.routingFile},
		{"POST /api/v1/routing/import", need(model.PermConfig, global), s.importRouting},
		{"GET /api/v1/routing/templates", need(model.PermView, global), s.routingTemplates},
		{"GET /api/v1/chain-templates", need(model.PermView, global), s.chainTemplates},
		{"POST /api/v1/chain-templates/import", need(model.PermChains, global), s.importChainTemplate},
		{"GET /api/v1/chains/{id}/template", need(model.PermChains, onChain), s.chainTemplate},
		{"GET /api/v1/geo", need(model.PermView, global), s.geoInfo},
		{"POST /api/v1/geo/update", need(model.PermConfig, global), s.geoUpdate},
		{"GET /api/v1/geo/categories", need(model.PermView, global), s.geoCategories},
		{"GET /api/v1/servers/{id}/geo", need(model.PermView, onServer), s.serverGeo},
		{"POST /api/v1/servers/{id}/geo", need(model.PermConfig, onServer, bodyVia), s.installGeo},
		{"GET /api/v1/chains", need(model.PermView, global), s.listChains},
		{"POST /api/v1/chains", need(model.PermChains, bodyNodes), s.createChain},
		{"GET /api/v1/chains/{id}", need(model.PermView, onChain), s.getChain},
		{"PATCH /api/v1/chains/{id}", need(model.PermChains, onChain), s.updateChain},
		{"DELETE /api/v1/chains/{id}", need(model.PermChains, onChain), s.deleteChain},
		{"POST /api/v1/chains/{id}/link", need(model.PermChains, onChain), s.linkChain},
		{"POST /api/v1/chains/{id}/unlink", need(model.PermChains, onChain), s.unlinkChain},
		{"GET /api/v1/chains/{id}/checks", need(model.PermView, onChain), s.chainChecks},
		{"POST /api/v1/chains/{id}/check", need(model.PermChains, onChain), s.checkChain},
		{"POST /api/v1/chains/{id}/route", need(model.PermConfig, onChain), s.routeChain},
		{"GET /api/v1/servers/{id}/status", need(model.PermView, onServer), s.serviceStatus},
		{"POST /api/v1/servers/{id}/service/{action}", need(model.PermService, onServer), s.serviceAction},
		{"GET /api/v1/servers/{id}/journal", need(model.PermView, onServer), s.journal},
		{"GET /api/v1/jobs", need(model.PermView, global), s.listJobs},
		{"GET /api/v1/jobs/{id}", need(model.PermView, onJob), s.getJob},
		{"GET /api/v1/jobs/{id}/logs", need(model.PermView, onJob), s.jobLogs},
		{"GET /api/v1/jobs/{id}/events", need(model.PermView, onJob), s.jobEvents},
		{"POST /api/v1/jobs/{id}/retry", retryRule, s.retryJob},
		{"GET /api/v1/logs", need(model.PermView, global), s.logs},
		{"GET /api/v1/backups", ownerOnly(need(model.PermSettings, global)), s.listBackups},
		{"POST /api/v1/backups", ownerOnly(need(model.PermSettings, global)), s.createBackup},
		{"GET /api/v1/backups/{name}", ownerOnly(need(model.PermSettings, global)), s.downloadBackup},
		{"POST /api/v1/master-key/check", need(model.PermSettings, global), s.checkMasterKey},
		{"GET /api/v1/diag", need(model.PermSettings, global), s.diagFiles},
		{"GET /api/v1/diag/bundle", need(model.PermSettings, global), s.diagBundle},
		{"GET /api/v1/events", need(model.PermView, global), s.listEvents},
		{"GET /api/v1/attention", need(model.PermView, global), s.attention},
		{"GET /api/v1/alerts/channels", need(model.PermSettings, global), s.listChannels},
		{"POST /api/v1/alerts/channels", need(model.PermSettings, global), s.createChannel},
		{"PATCH /api/v1/alerts/channels/{id}", need(model.PermSettings, global), s.updateChannel},
		{"DELETE /api/v1/alerts/channels/{id}", need(model.PermSettings, global), s.deleteChannel},
		{"POST /api/v1/alerts/channels/{id}/test", need(model.PermSettings, global), s.testChannel},
	}
}

// hostCheck answers only requests that name the panel as it is meant to
// be reached. Another name pointed at its address (DNS rebinding) would
// make a page of another site same-origin with the admin: it could read
// the API and spend the login limits of the owner's own address.
//   - With -allowed-host: the loopback names and those, in every mode.
//     Behind a trusted proxy the name the browser used is
//     X-Forwarded-Host when the proxy sets it (a proxy that rewrites Host).
//   - Without: on a loopback address and no proxy, the loopback names
//     only (localhost, 127.0.0.1, [::1]); otherwise nothing is checked.
func (s *server) hostCheck(next http.Handler) http.Handler {
	if len(s.AllowedHosts) == 0 && (!s.Loopback || s.TrustProxy) {
		return next
	}
	names := []string{"localhost", "127.0.0.1", "[::1]"}
	for _, h := range s.AllowedHosts {
		names = append(names, h)
	}
	bad := &Error{Status: http.StatusMisdirectedRequest, Code: "bad_host",
		Message: "Панель открывается только по адресам " + strings.Join(names, ", ") + ": откройте её по такому адресу."}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if s.fromProxy(r) {
			if f := r.Header.Get("X-Forwarded-Host"); f != "" {
				host, _, _ = strings.Cut(f, ",")
			}
		}
		if !s.allowedHost(strings.TrimSpace(host)) {
			writeError(w, bad)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allowedHost: host (with a port or not) is a loopback name or one of
// AllowedHosts.
func (s *server) allowedHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), ".")
	if strings.EqualFold(host, "localhost") || isLoopback(host) {
		return true
	}
	for _, a := range s.AllowedHosts {
		if strings.EqualFold(host, a) {
			return true
		}
	}
	return false
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
// index.html (the app routes on the client), except under assets/.
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
		st, err := fs.Stat(ui, p)
		found := err == nil && !st.IsDir()
		switch {
		case strings.HasPrefix(p, "assets/") && found:
			// Vite names assets by content hash.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		case strings.HasPrefix(p, "assets/"):
			// An asset of another build: index.html cached under its name
			// would break the page once that build is served again.
			w.Header().Set("Cache-Control", "no-cache")
			http.NotFound(w, r)
			return
		default:
			w.Header().Set("Cache-Control", "no-cache")
			if !found {
				r = r.Clone(r.Context())
				r.URL.Path = "/"
			}
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

// maxConfigBody bounds the config editor's bodies: they carry a config of
// up to hyconfig.MaxServerConfig as a JSON string, which escaping may make
// twice as long.
const maxConfigBody = 2*hyconfig.MaxServerConfig + 1<<20

// bodyTimeout bounds the time a body takes to arrive (a few MB fit even
// on a slow link). The server has no ReadTimeout, it would end event
// streams, so without it a body that never comes holds its connection
// forever.
var bodyTimeout = time.Minute

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			limit := int64(maxBody)
			if strings.HasSuffix(r.URL.Path, "/config/render") || strings.HasSuffix(r.URL.Path, "/config/apply") {
				limit = maxConfigBody
			} else if strings.Contains(r.URL.Path, "/routing") || strings.HasPrefix(r.URL.Path, "/api/v1/chain-templates/") {
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
