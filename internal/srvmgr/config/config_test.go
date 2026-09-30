package config

import (
	"io"
	"path/filepath"
	"testing"
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
	if c.TrustProxy || c.LogLevel != "info" {
		t.Fatalf("%+v", c)
	}
}

func TestFlagsOverrideEnv(t *testing.T) {
	e := env(map[string]string{
		"HYROUTE_SERVER_LISTEN":      "0.0.0.0:9000",
		"HYROUTE_SERVER_DATA_DIR":    "/srv/a",
		"HYROUTE_SERVER_TRUST_PROXY": "true",
		"HYROUTE_SERVER_LOG_LEVEL":   "debug",
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
	if c.Loopback() {
		t.Fatal("0.0.0.0 is not loopback")
	}
}

func TestLoadErrors(t *testing.T) {
	for _, args := range [][]string{
		{"-listen", "8480"},
		{"-log-level", "loud"},
		{"-data-dir", ""},
		{"extra"},
	} {
		if _, err := Load(args, env(nil), io.Discard); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
