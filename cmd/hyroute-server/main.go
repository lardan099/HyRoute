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
	"syscall"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/api"
	"github.com/lardan099/hyroute/internal/srvmgr/config"
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
	log := newLogger(stderr, cfg.LogLevel)
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	db, err := sqlite.Open(ctx, cfg.DBPath())
	if err != nil {
		return fmt.Errorf("database %s: %w", cfg.DBPath(), err)
	}
	defer db.Close()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	if !cfg.Loopback() {
		log.Warn("the admin listens beyond this machine: put it behind a TLS reverse proxy or reach it through an SSH tunnel", "listen", cfg.Listen)
	}
	srv := &http.Server{
		Handler: api.New(api.Deps{Store: db, Log: log, Version: version, UI: admin.FS()}),
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
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		log.Warn("shutdown", "err", err)
	}
	return nil
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var l slog.Level
	l.UnmarshalText([]byte(level))
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: l}))
}
