package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// runCmdIn is runCmd with stdin.
func runCmdIn(t *testing.T, dataDir, stdin string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	env := toolEnv{
		getenv: func(k string) string {
			if k == "HYROUTE_SERVER_DATA_DIR" {
				return dataDir
			}
			return ""
		},
		stdin:  strings.NewReader(stdin),
		stdout: &out,
		stderr: io.Discard,
	}
	err := runTool(context.Background(), args[0], args[1:], env)
	return out.String(), err
}

// withUser is a used data directory with the user alice logged in once;
// it returns the session token.
func withUser(t *testing.T) (dir, token string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "data")
	if err := runOnce(dir); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.Open(context.Background(), filepath.Join(dir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := auth.New(db)
	a.Params = auth.Params{Memory: 64, Time: 1, Threads: 1, KeyLen: 32, SaltLen: 16}
	u := model.User{Username: "alice", Role: model.RoleOwner, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	u.PasswordHash, _ = auth.HashPassword("old password 1", a.Params)
	if err := db.CreateUser(context.Background(), &u); err != nil {
		t.Fatal(err)
	}
	iss, err := a.Login(context.Background(), "alice", "old password 1", auth.Meta{IP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	return dir, iss.Token
}

func loginAs(t *testing.T, dir, user, password string) error {
	t.Helper()
	db, err := sqlite.OpenExisting(context.Background(), filepath.Join(dir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = auth.New(db).Login(context.Background(), user, password, auth.Meta{IP: "127.0.0.2"})
	return err
}

func sessionLives(t *testing.T, dir, token string) bool {
	t.Helper()
	db, err := sqlite.OpenExisting(context.Background(), filepath.Join(dir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = auth.New(db).Authenticate(context.Background(), token)
	return err == nil
}

func TestToolResetPassword(t *testing.T) {
	dir, token := withUser(t)
	if !sessionLives(t, dir, token) {
		t.Fatal("no session to begin with")
	}
	_, err := runCmdIn(t, dir, "", "reset-password", "bob")
	if !errors.Is(err, auth.ErrNoUser) || !strings.Contains(err.Error(), "alice") {
		t.Fatalf("unknown user: %v", err)
	}
	if _, err := runCmdIn(t, dir, "short\n", "reset-password", "-password-stdin", "alice"); err == nil {
		t.Fatal("a short password was taken")
	}

	out, err := runCmdIn(t, dir, "brand new password\r\n", "reset-password", "-password-stdin", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "brand new password") {
		t.Fatalf("the typed password is printed: %q", out)
	}
	if sessionLives(t, dir, token) {
		t.Fatal("the old session lives on")
	}
	if err := loginAs(t, dir, "alice", "brand new password"); err != nil {
		t.Fatalf("login with the new password: %v", err)
	}
	if err := loginAs(t, dir, "alice", "old password 1"); err == nil {
		t.Fatal("the old password still works")
	}

	// A made password is shown once and works.
	out, err = runCmdIn(t, dir, "", "reset-password", "alice")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`показывается\): (\S+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no password in %q", out)
	}
	if err := loginAs(t, dir, "alice", m[1]); err != nil {
		t.Fatalf("login with the made password: %v", err)
	}
	db, _ := sqlite.OpenExisting(context.Background(), filepath.Join(dir, "hyroute-server.db"))
	defer db.Close()
	audit, _ := db.ListAudit(context.Background(), 50)
	resets := 0
	for _, a := range audit {
		if a.Action == "user.password_reset" && a.Target == "alice" {
			resets++
		}
		if strings.Contains(a.Details, m[1]) || strings.Contains(a.Details, "brand new") {
			t.Fatalf("the audit holds the password: %+v", a)
		}
	}
	if resets != 2 {
		t.Fatalf("%d resets audited, want 2", resets)
	}
}

// After rekey -rotate the old key version can go from the key file and
// the controller still starts and opens its values; without rekey it
// would not.
func TestToolRekey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := runOnce(dir); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "master.key")
	v1, _ := os.ReadFile(keyFile)
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(dir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	keys, _, err := secrets.Load(func(string) string { return "" }, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srv := model.Server{Name: "a", Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	err = db.CreateServer(ctx, &srv, func(id int64) ([]model.Credential, error) {
		s, err := keys.SealString("canary-ssh-password", model.CredContext(id, model.CredSSHPassword))
		return []model.Credential{{Kind: model.CredSSHPassword, Sealed: s}}, err
	})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}

	// Under a running controller rekey refuses.
	runCtx, cancel := context.WithCancel(ctx)
	ready, done := make(chan string, 1), make(chan error, 1)
	env := func(k string) string {
		if k == "HYROUTE_SERVER_DATA_DIR" {
			return dir
		}
		return ""
	}
	go func() { done <- run(runCtx, []string{"-listen", "127.0.0.1:0"}, env, io.Discard, ready) }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	}
	_, err = runCmd(t, dir, "rekey", "-rotate")
	cancel()
	<-done
	if err == nil || !strings.Contains(err.Error(), "остановите службу") {
		t.Fatalf("rekey under a running controller: %v", err)
	}

	out, err := runCmd(t, dir, "rekey", "-rotate")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "версия 2") || !strings.Contains(out, "Перешифровано значений: 1") || !strings.Contains(out, "Версии 1 базе больше не нужны") {
		t.Fatalf("rekey output %q", out)
	}
	both, _ := os.ReadFile(keyFile)
	if !strings.HasPrefix(string(both), string(v1)) || strings.Count(string(both), "\n") != 2 {
		t.Fatalf("key file after -rotate: the old line must stay, one line added: %d lines", strings.Count(string(both), "\n"))
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(keyFile); st.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode %v", st.Mode().Perm())
		}
	}
	// A second run has nothing to do.
	if out, err := runCmd(t, dir, "rekey"); err != nil || !strings.Contains(out, "Перешифровано значений: 0") {
		t.Fatalf("second rekey %q %v", out, err)
	}

	// Only version 2 left: the controller starts and the credential opens.
	onlyV2 := strings.SplitAfterN(string(both), "\n", 2)[1]
	if err := os.WriteFile(keyFile, []byte(onlyV2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runOnce(dir); err != nil {
		t.Fatalf("start with version 2 only: %v", err)
	}
	keys2, _, err := secrets.Load(func(string) string { return "" }, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	db, err = sqlite.OpenExisting(ctx, filepath.Join(dir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	creds, _ := db.ServerCredentials(ctx, srv.ID)
	if p, err := keys2.OpenString(creds[0].Sealed, model.CredContext(srv.ID, model.CredSSHPassword)); err != nil || p != "canary-ssh-password" {
		t.Fatalf("credential after rekey: %q %v", p, err)
	}
	if strings.Contains(out, "canary") {
		t.Fatal("rekey printed a secret")
	}
}

// Without rekey the old version is still needed: the control for
// TestToolRekey.
func TestOldVersionNeededWithoutRekey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := runOnce(dir); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "master.key")
	keys, _, _ := secrets.Load(func(string) string { return "" }, keyFile)
	db, err := sqlite.Open(context.Background(), filepath.Join(dir, "hyroute-server.db"))
	if err != nil {
		t.Fatal(err)
	}
	srv := model.Server{Name: "a", Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	db.CreateServer(context.Background(), &srv, func(id int64) ([]model.Credential, error) {
		s, err := keys.SealString("x", model.CredContext(id, model.CredSSHPassword))
		return []model.Credential{{Kind: model.CredSSHPassword, Sealed: s}}, err
	})
	db.Close()
	if _, err := secrets.AddVersion(keyFile, keys); err != nil {
		t.Fatal(err)
	}
	if err := runOnce(dir); err != nil {
		t.Fatal(err)
	}
	both, _ := os.ReadFile(keyFile)
	os.WriteFile(keyFile, []byte(strings.SplitAfterN(string(both), "\n", 2)[1]), 0o600)
	if err := runOnce(dir); !errors.Is(err, secrets.ErrKeyMismatch) {
		t.Fatalf("version 1 dropped without rekey: %v", err)
	}
}

func TestToolDoctor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := runOnce(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := runCmd(t, dir, "backup"); err != nil {
		t.Fatal(err)
	}
	out, err := runCmd(t, dir, "doctor")
	if err != nil {
		t.Fatalf("healthy: %v\n%s", err, out)
	}
	if !strings.Contains(out, "целостность базы") || !strings.Contains(out, "открывает данные базы") || strings.Contains(out, "ОШИБКА") {
		t.Fatalf("healthy output %q", out)
	}

	// Another key.
	keyFile := filepath.Join(dir, "master.key")
	key, _ := os.ReadFile(keyFile)
	other, _ := secrets.NewKeyText()
	os.WriteFile(keyFile, []byte(other), 0o600)
	if out, err := runCmd(t, dir, "doctor"); err == nil || !strings.Contains(out, "не подходит") {
		t.Fatalf("another key: %v\n%s", err, out)
	}
	os.WriteFile(keyFile, key, 0o600)

	// A damaged database.
	dbPath := filepath.Join(dir, "hyroute-server.db")
	b, _ := os.ReadFile(dbPath)
	for i := 4096; i < len(b); i++ {
		b[i] ^= 0x5a
	}
	os.WriteFile(dbPath, b, 0o600)
	if out, err := runCmd(t, dir, "doctor"); err == nil || !strings.Contains(out, "ОШИБКА") {
		t.Fatalf("damaged database: %v\n%s", err, out)
	}
}

// doctor finds a database file others can read.
func TestToolDoctorPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := runOnce(dir); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "hyroute-server.db")
	openToOthers(t, dbPath)
	out, err := runCmd(t, dir, "doctor")
	if err == nil || !strings.Contains(out, "ОШИБКА") || !strings.Contains(out, "hyroute-server.db") {
		t.Fatalf("open database file: %v\n%s", err, out)
	}
}
