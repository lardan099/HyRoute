// Package config reads the hyroute-server configuration: command-line flags
// override HYROUTE_SERVER_* environment variables, which override defaults.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config is the controller configuration.
type Config struct {
	// Listen is the HTTP address. The default is loopback only: access
	// from outside goes through an SSH tunnel or a TLS reverse proxy.
	Listen string
	// DataDir holds the database, the master key file and the setup token.
	DataDir string
	// MasterKeyFile is used when HYROUTE_MASTER_KEY is not set.
	MasterKeyFile string
	// TrustProxy makes the controller believe X-Forwarded-Proto and
	// X-Forwarded-For from a reverse proxy on a loopback address.
	TrustProxy bool
	// LogLevel is debug, info, warn or error.
	LogLevel string
}

// DefaultListen is the address used when none is given.
const DefaultListen = "127.0.0.1:8480"

// DBPath is the SQLite database file.
func (c Config) DBPath() string { return filepath.Join(c.DataDir, "hyroute-server.db") }

// DefaultDataDir is the data directory for this OS.
func DefaultDataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "HyRoute Server")
		}
		return `C:\ProgramData\HyRoute Server`
	}
	return "/var/lib/hyroute-server"
}

// Load parses args (without the program name) on top of the environment.
// Usage and errors go to out.
func Load(args []string, getenv func(string) string, out io.Writer) (Config, error) {
	env := func(k, def string) string {
		if v := strings.TrimSpace(getenv("HYROUTE_SERVER_" + k)); v != "" {
			return v
		}
		return def
	}
	fs := flag.NewFlagSet("hyroute-server", flag.ContinueOnError)
	fs.SetOutput(out)
	var c Config
	fs.StringVar(&c.Listen, "listen", env("LISTEN", DefaultListen), "HTTP address (env HYROUTE_SERVER_LISTEN)")
	fs.StringVar(&c.DataDir, "data-dir", env("DATA_DIR", DefaultDataDir()), "data directory (env HYROUTE_SERVER_DATA_DIR)")
	fs.StringVar(&c.MasterKeyFile, "master-key-file", env("MASTER_KEY_FILE", ""), "master key file, when HYROUTE_MASTER_KEY is not set (default <data-dir>/master.key)")
	trust := env("TRUST_PROXY", "false")
	fs.BoolVar(&c.TrustProxy, "trust-proxy", trust == "1" || strings.EqualFold(trust, "true"), "trust X-Forwarded-* from a reverse proxy on loopback (env HYROUTE_SERVER_TRUST_PROXY)")
	fs.StringVar(&c.LogLevel, "log-level", env("LOG_LEVEL", "info"), "debug, info, warn or error (env HYROUTE_SERVER_LOG_LEVEL)")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if c.MasterKeyFile == "" {
		c.MasterKeyFile = filepath.Join(c.DataDir, "master.key")
	}
	return c, c.validate()
}

func (c Config) validate() error {
	if _, port, err := net.SplitHostPort(c.Listen); err != nil || port == "" {
		return fmt.Errorf("listen %q: want host:port", c.Listen)
	}
	if c.DataDir == "" {
		return errors.New("data-dir is empty")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log-level %q: want debug, info, warn or error", c.LogLevel)
	}
	return nil
}

// Loopback reports whether Listen accepts connections only from this
// machine. An empty host or 0.0.0.0 listens on every interface.
func (c Config) Loopback() bool {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
