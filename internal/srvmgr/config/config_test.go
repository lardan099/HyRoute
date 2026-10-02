package config

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(nil, env(nil), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != DefaultListen || !c.Loopback() {
		t.Fatalf("listen %q loopback %v", c.Listen, c.Loopback())
	}
	if c.MasterKeyFile != filepath.Join(c.DataDir, "master.key") {
		t.Fatalf("master key file %q", c.MasterKeyFile)
	}
	if c.TrustProxy || c.LogLevel != "info" || c.MonitorInterval != time.Minute {
		t.Fatalf("%+v", c)
	}
}

func TestFlagsOverrideEnv(t *testing.T) {
	e := env(map[string]string{
		"HYROUTE_SERVER_LISTEN":      "0.0.0.0:9000",
		"HYROUTE_SERVER_DATA_DIR":    "/srv/a",
		"HYROUTE_SERVER_TRUST_PROXY": "true",
		"HYROUTE_SERVER_LOG_LEVEL":   "debug",
		"HYROUTE_SERVER_TLS_CERT":    "/srv/a/cert.pem",
		"HYROUTE_SERVER_TLS_KEY":     "/srv/a/key.pem",
	})
	c, err := Load([]string{"-listen", "127.0.0.1:9100"}, e, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:9100" || c.DataDir != "/srv/a" || !c.TrustProxy || c.LogLevel != "debug" {
		t.Fatalf("%+v", c)
	}
	c, err = Load(nil, e, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.Loopback() || !c.TLS() || c.TLSKey != "/srv/a/key.pem" {
		t.Fatalf("%+v", c)
	}
}

// The admin is not served in plaintext beyond this machine unless asked.
func TestPlaintextBeyondLoopback(t *testing.T) {
	for _, l := range []string{"0.0.0.0:8480", ":8480", "192.0.2.5:8480", "[::]:8480"} {
		if _, err := Load([]string{"-listen", l}, env(nil), io.Discard); err == nil || !strings.Contains(err.Error(), "-tls-cert") {
			t.Errorf("%s: %v", l, err)
		}
		if c, err := Load([]string{"-listen", l, "-insecure-http"}, env(nil), io.Discard); err != nil || !c.InsecureHTTP {
			t.Errorf("%s -insecure-http: %v", l, err)
		}
		if _, err := Load([]string{"-listen", l}, env(map[string]string{"HYROUTE_SERVER_INSECURE_HTTP": "1"}), io.Discard); err != nil {
			t.Errorf("%s with the env: %v", l, err)
		}
	}
	for _, l := range []string{"127.0.0.1:8480", "localhost:8480", "[::1]:8480"} {
		if _, err := Load([]string{"-listen", l}, env(nil), io.Discard); err != nil {
			t.Errorf("%s: %v", l, err)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	for _, args := range [][]string{
		{"-listen", "8480"},
		{"-log-level", "loud"},
		{"-data-dir", ""},
		{"-tls-cert", "/a/cert.pem"},
		{"-monitor-interval", "5s"},
		{"-tls-key", "/a/key.pem"},
		{"extra"},
	} {
		if _, err := Load(args, env(nil), io.Discard); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}

func TestMonitorInterval(t *testing.T) {
	c, err := Load([]string{"-monitor-interval", "0"}, env(nil), io.Discard)
	if err != nil || c.MonitorInterval != 0 {
		t.Fatalf("off: %v %v", c.MonitorInterval, err)
	}
	c, err = Load(nil, env(map[string]string{"HYROUTE_SERVER_MONITOR_INTERVAL": "5m"}), io.Discard)
	if err != nil || c.MonitorInterval != 5*time.Minute {
		t.Fatalf("env: %v %v", c.MonitorInterval, err)
	}
}

func TestGeoInterval(t *testing.T) {
	c, err := Load(nil, env(nil), io.Discard)
	if err != nil || c.GeoInterval != 7*24*time.Hour {
		t.Fatalf("default: %v %v", c.GeoInterval, err)
	}
	c, err = Load([]string{"-geo-interval", "0"}, env(nil), io.Discard)
	if err != nil || c.GeoInterval != 0 {
		t.Fatalf("off: %v %v", c.GeoInterval, err)
	}
	c, err = Load(nil, env(map[string]string{"HYROUTE_SERVER_GEO_INTERVAL": "24h"}), io.Discard)
	if err != nil || c.GeoInterval != 24*time.Hour {
		t.Fatalf("env: %v %v", c.GeoInterval, err)
	}
}
