// hyroute-server is the HyRoute Server Manager controller: it deploys,
// imports and maintains Hysteria 2 servers over SSH and serves the web
// admin. See docs/SERVER_MANAGER_ARCHITECTURE.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/api"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/config"
	"github.com/lardan099/hyroute/internal/srvmgr/connect"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/importer"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/logbuf"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
	admin "github.com/lardan099/hyroute/web/admin"
)

// version is stamped at build time (-X main.version=…).
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stderr, nil); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "hyroute-server:", err)
		os.Exit(1)
	}
}

// run starts the controller and blocks until ctx is done, then shuts down
// gracefully. ready, if not nil, receives the listening address.
func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, ready chan<- string) error {
	cfg, err := config.Load(args, getenv, stderr)
	if err != nil {
		return err
	}
	red := redact.New()
	logs := logbuf.New(2000, slog.LevelInfo)
	log := newLogger(stderr, cfg.LogLevel, red, logs)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	keys, src, err := secrets.Load(getenv, cfg.MasterKeyFile)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	switch src {
	case secrets.Created:
		log.Warn("created a new master key: back it up, stored credentials cannot be decrypted without it", "file", cfg.MasterKeyFile)
	case secrets.FromEnv:
		log.Info("master key from the environment", "version", keys.Current())
	default:
		log.Info("master key from file", "file", cfg.MasterKeyFile, "version", keys.Current())
	}
	db, err := sqlite.Open(ctx, cfg.DBPath())
	if err != nil {
		return fmt.Errorf("database %s: %w", cfg.DBPath(), err)
	}
	defer db.Close()

	authSvc := auth.New(db)
	tokenFile := filepath.Join(cfg.DataDir, "setup-token")
	if err := prepareSetup(ctx, authSvc, tokenFile, log); err != nil {
		return err
	}
	go cleanupSessions(ctx, authSvc, log)
	inventory := servers.New(db, keys)
	conn := connect.New(inventory, db, red)
	engine := jobs.New(db, keys, red, conn, log)
	engine.Register(preflight.Kind())
	engine.Register(deploy.Kind(deploy.Deps{Store: db, Keys: keys, Resolver: &hyrelease.Resolver{}}))
	engine.Register(importer.Kind(importer.Deps{Store: db, Keys: keys}))
	engine.Register(service.Kind(service.Deps{Store: db, Keys: keys}))
	jobsCtx, stopJobs := context.WithCancel(context.WithoutCancel(ctx))
	jobsDone := make(chan struct{})
	go func() {
		engine.Run(jobsCtx)
		close(jobsDone)
	}()
	defer func() {
		// Jobs stop after the HTTP server: a stopped job is recovered on
		// the next start.
		stopJobs()
		<-jobsDone
	}()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	if !cfg.Loopback() {
		log.Warn("the admin listens beyond this machine: put it behind a TLS reverse proxy or reach it through an SSH tunnel", "listen", cfg.Listen)
	}
	// Requests get a context that ends when shutdown starts: live event
	// streams return instead of holding Shutdown for its whole timeout.
	baseCtx, endRequests := context.WithCancel(context.WithoutCancel(ctx))
	defer endRequests()
	srv := &http.Server{
		BaseContext: func(net.Listener) context.Context { return baseCtx },
		Handler: api.New(api.Deps{
			Store:      db,
			Auth:       authSvc,
			Servers:    inventory,
			Connect:    conn,
			Jobs:       engine,
			Deploy:     &deploy.Submitter{Store: db, Keys: keys, Jobs: engine},
			Keys:       keys,
			Logs:       logs,
			Log:        log,
			Version:    version,
			TrustProxy: cfg.TrustProxy,
			UI:         admin.FS(),
			OnSetupDone: func() {
				os.Remove(tokenFile)
				log.Info("owner created, setup token removed")
			},
		}),
		// No ReadTimeout/WriteTimeout: live logs are long-lived event
		// streams. Bodies are bounded by size in the API instead.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("hyroute-server started", "version", version, "listen", ln.Addr().String(), "data", cfg.DataDir)
	if ready != nil {
		ready <- ln.Addr().String()
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	endRequests()
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Warn("shutdown", "err", err)
	}
	return nil
}

// prepareSetup issues the one-time setup token while there are no users.
// It goes to a 0600 file (the log names the file, not the token), so only
// someone with access to the machine can create the first owner. A
// leftover file is removed once setup is done.
func prepareSetup(ctx context.Context, a *auth.Service, tokenFile string, log *slog.Logger) error {
	tok, err := a.PrepareSetup(ctx)
	if err != nil {
		return err
	}
	if tok == "" {
		os.Remove(tokenFile)
		return nil
	}
	os.Remove(tokenFile) // a stale file of another owner or mode
	f, err := os.OpenFile(tokenFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("setup token file: %w", err)
	}
	_, err = f.WriteString(tok + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("setup token file: %w", err)
	}
	log.Warn("no administrator yet: open the admin and create the owner with the setup token from this file", "file", tokenFile)
	return nil
}

// cleanupSessions drops long-ended sessions every hour.
func cleanupSessions(ctx context.Context, a *auth.Service, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if err := a.Cleanup(ctx); err != nil && ctx.Err() == nil {
			log.Warn("session cleanup", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// newLogger writes text logs to w and keeps the latest in buf for the
// Logs page; every record passes through red first.
func newLogger(w io.Writer, level string, red *redact.Redactor, buf *logbuf.Buffer) *slog.Logger {
	var l slog.Level
	l.UnmarshalText([]byte(level))
	return slog.New(red.Handler(slog.NewMultiHandler(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l}), buf.Handler())))
}
