package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/backup"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// runCmd runs a maintenance command on dataDir and returns its output.
func runCmd(t *testing.T, dataDir string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	env := toolEnv{
		getenv: func(k string) string {
			if k == "HYROUTE_SERVER_DATA_DIR" {
				return dataDir
			}
			return ""
		},
		stdin:  strings.NewReader(""),
		stdout: &out,
		stderr: io.Discard,
	}
	err := runTool(context.Background(), args[0], args[1:], env)
	return out.String(), err
}

// addUser gives the database of dataDir a user: it is in use then.
func addUser(t *testing.T, dataDir, name string) {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(dataDir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	u := model.User{Username: name, PasswordHash: "h", Role: model.RoleOwner, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := db.CreateUser(context.Background(), &u); err != nil {
		t.Fatal(err)
	}
}

func hasUser(t *testing.T, dataDir, name string) bool {
	t.Helper()
	db, err := sqlite.OpenExisting(context.Background(), filepath.Join(dataDir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.UserByName(context.Background(), name)
	return err == nil
}

// A copy restored into another data directory with the same master key
// starts there; a copy is not restored under a running controller, nor
// over a database in use without -force.
func TestToolBackupRestore(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := runOnce(src); err != nil {
		t.Fatal(err)
	}
	addUser(t, src, "alice")

	out, err := runCmd(t, src, "backup")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, filepath.Join(src, "backups")) || !strings.Contains(out, "Мастер-ключа в копии нет") {
		t.Fatalf("backup output %q", out)
	}
	file := filepath.Join(t.TempDir(), "copy.db")
	if _, err := runCmd(t, src, "backup", "-out", file); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(file); err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("copy file %v %v", st, err)
		}
	}
	if _, err := runCmd(t, src, "backup", "-out", file); err == nil {
		t.Fatal("backup over an existing file")
	}

	dst := filepath.Join(t.TempDir(), "dst")
	os.MkdirAll(dst, 0o700)
	key, _ := os.ReadFile(filepath.Join(src, "master.key"))
	os.WriteFile(filepath.Join(dst, "master.key"), key, 0o600)
	out, err = runCmd(t, dst, "restore", file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "восстановлена") {
		t.Fatalf("restore output %q", out)
	}
	if !hasUser(t, dst, "alice") {
		t.Fatal("the restored database has no user")
	}
	if err := runOnce(dst); err != nil {
		t.Fatalf("the controller does not start on the restored database: %v", err)
	}

	// In use now: no restore without -force; with it, the old one is kept.
	addUser(t, dst, "bob")
	if _, err := runCmd(t, dst, "restore", file); !errors.Is(err, backup.ErrInUse) {
		t.Fatalf("over a database in use: %v", err)
	}
	if !hasUser(t, dst, "bob") {
		t.Fatal("the database in use changed")
	}
	out, err = runCmd(t, dst, "restore", "-force", file)
	if err != nil {
		t.Fatal(err)
	}
	if hasUser(t, dst, "bob") || !strings.Contains(out, ".before-restore-") {
		t.Fatalf("-force: %q", out)
	}

	// A running controller holds the data directory.
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	done := make(chan error, 1)
	env := func(k string) string {
		if k == "HYROUTE_SERVER_DATA_DIR" {
			return dst
		}
		return ""
	}
	go func() { done <- run(ctx, []string{"-listen", "127.0.0.1:0"}, env, io.Discard, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("not started")
	}
	_, err = runCmd(t, dst, "restore", "-force", file)
	cancel()
	<-done
	if err == nil || !strings.Contains(err.Error(), "остановите службу") {
		t.Fatalf("restore under a running controller: %v", err)
	}
}

func TestToolVersionAndHelp(t *testing.T) {
	out, err := runCmd(t, t.TempDir(), "version")
	if err != nil || !strings.Contains(out, "hyroute-server") || !strings.Contains(out, "схема базы") {
		t.Fatalf("version %q %v", out, err)
	}
	out, err = runCmd(t, t.TempDir(), "help")
	if err != nil || !strings.Contains(out, "restore") || !strings.Contains(out, "backup") {
		t.Fatalf("help %q %v", out, err)
	}
	// run hands a first argument that is not a flag to the commands.
	if err := run(context.Background(), []string{"frobnicate"}, func(string) string { return "" }, io.Discard, nil); err == nil || !strings.Contains(err.Error(), "help") {
		t.Fatalf("unknown command: %v", err)
	}
	if _, err := runCmd(t, filepath.Join(t.TempDir(), "none"), "backup"); err == nil {
		t.Fatal("backup without a data directory")
	}
}
