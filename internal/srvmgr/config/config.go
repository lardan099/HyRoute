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
	"time"
)

// Config is the controller configuration.
type Config struct {
	// Listen is the HTTP address. The default is loopback only: access
	// from outside goes through an SSH tunnel or a TLS reverse proxy.
	Listen string
	// TLSCert and TLSKey are PEM files: set, the admin is served over
	// HTTPS (the files are read again when they change).
	TLSCert, TLSKey string
	// InsecureHTTP allows plaintext HTTP on an address reachable from the
	// network. Without it, a non-loopback Listen needs TLS.
	InsecureHTTP bool
	// DataDir holds the database, the master key file and the setup token.
	DataDir string
	// MasterKeyFile is used when HYROUTE_MASTER_KEY is not set.
	MasterKeyFile string
	// TrustProxy makes the controller believe X-Forwarded-Proto,
	// X-Forwarded-For and X-Forwarded-Host from a reverse proxy on a
	// loopback address.
	TrustProxy bool
	// LogLevel is debug, info, warn or error.
	LogLevel string
	// MonitorInterval is how often servers are sampled (0: never).
	MonitorInterval time.Duration
	// GeoInterval is how often the geo databases are updated (0: never).
	GeoInterval time.Duration
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
	fs.StringVar(&c.TLSCert, "tls-cert", env("TLS_CERT", ""), "TLS certificate chain (PEM) to serve HTTPS (env HYROUTE_SERVER_TLS_CERT)")
	fs.StringVar(&c.TLSKey, "tls-key", env("TLS_KEY", ""), "TLS private key (PEM) (env HYROUTE_SERVER_TLS_KEY)")
	fs.BoolVar(&c.InsecureHTTP, "insecure-http", isTrue(env("INSECURE_HTTP", "")), "allow plaintext HTTP on an address reachable from the network (env HYROUTE_SERVER_INSECURE_HTTP)")
	fs.BoolVar(&c.TrustProxy, "trust-proxy", isTrue(env("TRUST_PROXY", "")), "trust X-Forwarded-* from a reverse proxy on loopback (env HYROUTE_SERVER_TRUST_PROXY)")
	fs.DurationVar(&c.MonitorInterval, "monitor-interval", envDuration(getenv("HYROUTE_SERVER_MONITOR_INTERVAL"), time.Minute), "how often to sample the servers' CPU, memory, disk and network; 0 turns it off (env HYROUTE_SERVER_MONITOR_INTERVAL)")
	fs.DurationVar(&c.GeoInterval, "geo-interval", envDuration(getenv("HYROUTE_SERVER_GEO_INTERVAL"), 7*24*time.Hour), "how often to look for newer geo databases and put them on the servers that use HyRoute's; 0 turns it off (env HYROUTE_SERVER_GEO_INTERVAL)")
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

func isTrue(v string) bool { return v == "1" || strings.EqualFold(v, "true") }

// envDuration is v as a duration, def when empty or unreadable (the flag
// check reports nothing for the env, so a typo keeps the default).
func envDuration(v string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
		return d
	}
	return def
}

// TLS reports whether the admin is served over HTTPS.
func (c Config) TLS() bool { return c.TLSCert != "" }

func (c Config) validate() error {
	if _, port, err := net.SplitHostPort(c.Listen); err != nil || port == "" {
		return fmt.Errorf("listen %q: want host:port", c.Listen)
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls-cert and tls-key go together")
	}
	if !c.Loopback() && !c.TLS() && !c.InsecureHTTP {
		return fmt.Errorf("listen %s is reachable from the network, and passwords and sessions would cross it in plaintext: "+
			"serve HTTPS with -tls-cert and -tls-key, or keep the admin on 127.0.0.1 behind a TLS reverse proxy or an SSH tunnel "+
			"(-insecure-http allows plaintext anyway, for a network you trust)", c.Listen)
	}
	if c.DataDir == "" {
		return errors.New("data-dir is empty")
	}
	if c.MonitorInterval != 0 && c.MonitorInterval < 10*time.Second {
		return fmt.Errorf("monitor-interval %s: at least 10s, or 0 to turn monitoring off", c.MonitorInterval)
	}
	if c.GeoInterval < 0 {
		return fmt.Errorf("geo-interval %s: a positive duration, or 0 to turn the geo schedule off", c.GeoInterval)
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
