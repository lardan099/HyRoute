package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/diag"
	"github.com/lardan099/hyroute/internal/srvmgr/diag/diagtest"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// hyroute-server diag builds, while the controller runs, the bundle the
// panel gives, without the log buffer, and changes nothing.
func TestToolDiag(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := runOnce(dir); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == "HYROUTE_SERVER_DATA_DIR" {
			return dir
		}
		return ""
	}
	ctx := context.Background()
	keyFile := filepath.Join(dir, "master.key")
	keys, _, err := secrets.Load(getenv, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	keyText, _ := os.ReadFile(keyFile)
	db, err := sqlite.Open(ctx, filepath.Join(dir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	seed := diagtest.Fill(t, db, keys)
	db.Close()

	// The controller runs.
	runCtx, cancel := context.WithCancel(ctx)
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() { done <- run(runCtx, []string{"-listen", "127.0.0.1:0"}, getenv, io.Discard, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("not started")
	}
	file := filepath.Join(t.TempDir(), "diag.zip")
	out, err := runCmd(t, dir, "diag", "-out", file)
	cancel()
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, file) || !strings.Contains(out, "Журнала панели в этом пакете нет") || !strings.Contains(out, "servers.json") {
		t.Fatalf("output %q", out)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(file); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode())
		}
	}
	files := diagtest.Files(t, b)
	var values []string
	values = append(values, diagtest.Canaries...)
	for _, l := range strings.Split(string(keyText), "\n") {
		if _, k, ok := strings.Cut(strings.TrimSpace(l), ":"); ok {
			values = append(values, k)
		}
	}
	diagtest.NoCanaries(t, files, values...)
	if !strings.Contains(files["version.json"], `"source": "command"`) || !strings.Contains(files["settings.json"], `"panel": false`) {
		t.Fatalf("%s\n%s", files["version.json"], files["settings.json"])
	}

	// The panel's bundle of the same database has the same files and the
	// log buffer besides.
	db, err = sqlite.OpenExisting(ctx, filepath.Join(dir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	bundle, err := (&diag.Builder{Store: db, Keys: keys, Logs: seed.Logs, Version: version, Settings: diag.Settings{Panel: true}}).Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	bundle.WriteZip(&buf)
	panel := diagtest.Files(t, buf.Bytes())
	var want, got []string
	for n := range panel {
		if n != "controller.log" {
			want = append(want, n)
		}
	}
	for n := range files {
		got = append(got, n)
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("files %v, the panel's %v", got, want)
	}
	for _, n := range got {
		if strings.HasPrefix(n, "jobs") || n == "servers.json" || n == "configs.json" || n == "chains.json" {
			if files[n] != panel[n] {
				t.Errorf("%s differs from the panel's:\n%s\n%s", n, files[n], panel[n])
			}
		}
	}
	// It wrote nothing: no audit of the download.
	if audit, _ := db.ListAudit(ctx, 50); slices.ContainsFunc(audit, func(a model.AuditEntry) bool { return strings.HasPrefix(a.Action, "diag") }) {
		t.Fatal("the command wrote to the audit")
	}

	if _, err := runCmd(t, dir, "diag", "-out", file); err == nil || !strings.Contains(err.Error(), "уже есть") {
		t.Fatalf("over an existing file: %v", err)
	}
	if _, err := runCmd(t, dir, "diag", "-jobs", "0", "-out", file+"2"); err == nil {
		t.Fatal("-jobs 0")
	}
}
