package diag_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/diag"
	"github.com/lardan099/hyroute/internal/srvmgr/diag/diagtest"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// canaryDB is a database with the canaries of diagtest and the master key
// they are sealed with.
func canaryDB(t *testing.T) (*sqlite.DB, *secrets.Keyring, []byte, diagtest.Seed) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key := make([]byte, 32)
	rand.Read(key)
	keys, err := secrets.NewKeyring(map[uint32][]byte{1: key})
	if err != nil {
		t.Fatal(err)
	}
	return db, keys, key, diagtest.Fill(t, db, keys)
}

func build(t *testing.T, b *diag.Builder) (*diag.Bundle, map[string]string) {
	t.Helper()
	bundle, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := bundle.WriteZip(&buf); err != nil {
		t.Fatal(err)
	}
	return bundle, diagtest.Files(t, buf.Bytes())
}

func TestBundleHasNoCanaries(t *testing.T) {
	db, keys, key, seed := canaryDB(t)
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	b := &diag.Builder{Store: db, Keys: keys, Logs: seed.Logs, Version: "test",
		Settings: diag.Settings{Panel: true, Listen: diagtest.Listen, AllowedHosts: []string{diagtest.AllowedHost}, BackupKeep: 7, MasterKey: "file"},
		Now:      func() time.Time { return at }}
	bundle, files := build(t, b)

	var names []string
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	want := []string{"README.txt", "chains.json", "configs.json", "controller.log", "jobs.json", "jobs/000001-preflight.log", "jobs/000002-deploy.log",
		"jobs/000003-link.log", "manifest.json", "servers.json", "settings.json", "version.json"}
	if !slices.Equal(names, want) {
		t.Fatalf("files %v, want %v", names, want)
	}
	if bundle.Name() != "hyroute-diag-20261008-120000.zip" {
		t.Fatalf("name %q", bundle.Name())
	}

	// No canary in any file, nor the master key or a sealed value.
	values := append(slices.Clone(diagtest.Canaries), diagtest.KeyCanaries(key)...)
	creds, _ := db.ServerCredentials(context.Background(), seed.Server)
	for _, c := range creds {
		values = append(values, base64.StdEncoding.EncodeToString(c.Sealed)[:24])
	}
	diagtest.NoCanaries(t, files, values...)

	// One name, one pseudonym, in every file that names it.
	var servers []struct {
		ID         int64
		Name, Host string
	}
	if err := json.Unmarshal([]byte(files["servers.json"]), &servers); err != nil {
		t.Fatal(err)
	}
	var name, host string
	for _, s := range servers {
		if s.ID == seed.Server {
			name, host = s.Name, s.Host
		}
	}
	if name != "server-1" || host != "host-1" {
		t.Fatalf("server %q at %q", name, host)
	}
	for _, f := range []string{"servers.json", "configs.json", "chains.json", "jobs.json", "jobs/000002-deploy.log", "controller.log"} {
		if !strings.Contains(files[f], name) {
			t.Errorf("%s does not name %s:\n%s", f, name, files[f])
		}
	}
	for _, f := range []string{"servers.json", "jobs.json", "jobs/000002-deploy.log", "controller.log"} {
		if !strings.Contains(files[f], host) {
			t.Errorf("%s does not name %s:\n%s", f, host, files[f])
		}
	}
	if !strings.Contains(files["jobs/000002-deploy.log"], "Не удалось подключиться к серверу server-1.") ||
		!strings.Contains(files["controller.log"], `server="server-1"`) ||
		!strings.Contains(files["jobs.json"], `"errorMessage": "Не удалось подключиться к серверу server-1."`) {
		t.Errorf("the name is not replaced the same way:\n%s\n%s", files["jobs/000002-deploy.log"], files["controller.log"])
	}

	// What the bundle is for is in it.
	for f, parts := range map[string][]string{
		"servers.json":  {`"os": "Ubuntu 22.04.3 LTS"`, `"state": "degraded"`, `"sshUser": "user-1"`, `"version": "v2.6.0"`, `"status": "degraded"`},
		"configs.json":  {`"authType": "userpass"`, `"users": 2`, `"aclRules": 2`, `"obfs": "salamander"`, `"lint": [`},
		"chains.json":   {`"state": "new"`, `"status": "offline"`, `"localPort": 20000`},
		"settings.json": {`"keyVersion": 1`, `"dataVersions": [`, `"allowedHosts": [`},
		"version.json":  {`"schema": `, `"source": "panel"`},
		"manifest.json": {`"name": "controller.log"`},
	} {
		for _, part := range parts {
			if !strings.Contains(files[f], part) {
				t.Errorf("%s has no %s:\n%s", f, part, files[f])
			}
		}
	}

	// The same database makes the same bundle: the list before the
	// download is the list of the download.
	again, files2 := build(t, b)
	if !slices.Equal(bundle.Entries(), again.Entries()) {
		t.Fatalf("entries differ:\n%v\n%v", bundle.Entries(), again.Entries())
	}
	for n, d := range files {
		if files2[n] != d {
			t.Errorf("%s differs between two builds", n)
		}
	}
}

// Without a log buffer (the maintenance command) the bundle is the same
// but for controller.log.
func TestBundleWithoutLogBuffer(t *testing.T) {
	db, keys, _, seed := canaryDB(t)
	at := time.Now()
	panel := &diag.Builder{Store: db, Keys: keys, Logs: seed.Logs, Version: "test", Now: func() time.Time { return at }}
	cmd := &diag.Builder{Store: db, Keys: keys, Version: "test", Now: func() time.Time { return at }}
	_, withLog := build(t, panel)
	_, without := build(t, cmd)
	if _, ok := without["controller.log"]; ok {
		t.Fatal("controller.log without a buffer")
	}
	for n, d := range withLog {
		if n == "controller.log" || n == "manifest.json" || n == "README.txt" {
			continue
		}
		if without[n] != d {
			t.Errorf("%s differs", n)
		}
	}
	if len(without) != len(withLog)-1 {
		t.Fatalf("%d files, want %d", len(without), len(withLog)-1)
	}
	if !strings.Contains(without["version.json"], `"source": "command"`) {
		t.Fatalf("%s", without["version.json"])
	}
}

// The bundle carries the logs of the latest jobs only.
func TestBundleJobs(t *testing.T) {
	db, keys, _, _ := canaryDB(t)
	_, files := build(t, &diag.Builder{Store: db, Keys: keys, Jobs: 1})
	var jobs []struct {
		ID   int64
		Kind string
	}
	json.Unmarshal([]byte(files["jobs.json"]), &jobs)
	if len(jobs) != 1 || jobs[0].Kind != "link" {
		t.Fatalf("%+v", jobs)
	}
	if _, ok := files["jobs/000003-link.log"]; !ok || files["jobs/000002-deploy.log"] != "" {
		t.Fatalf("logs %v", files)
	}
	// The OS still comes from the last preflight, whatever its age.
	if !strings.Contains(files["servers.json"], "Ubuntu 22.04.3 LTS") {
		t.Fatal(files["servers.json"])
	}
	if _, err := (&diag.Builder{Store: db, Keys: keys}).Build(context.Background()); err != nil {
		t.Fatal(err)
	}
}
