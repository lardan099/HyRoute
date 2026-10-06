package connect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// Fake credentials for the in-process server.
const fakePass = "fake-ssh-pass-connect"

type env struct {
	srv  *sshtest.Server
	db   *sqlite.DB
	inv  *servers.Service
	conn *Connector
	red  *redact.Redactor
	id   int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{3}, 32)})
	e := &env{srv: sshtest.Start(t, "deploy", fakePass), db: db, inv: servers.New(db, keys), red: redact.New()}
	e.srv.SetExec(fakeLinux(true))
	admin := model.User{Username: "admin", PasswordHash: "x", Role: model.RoleOwner}
	if err := db.CreateUser(context.Background(), &admin); err != nil || admin.ID != 1 {
		t.Fatal(admin.ID, err)
	}
	e.conn = New(e.inv, db, e.red)
	e.conn.Timeout = 5 * time.Second
	pw := fakePass
	info, err := e.inv.Create(context.Background(), 1, servers.Input{Name: "test", Host: e.srv.Host, SSHPort: e.srv.Port, SSHUser: "deploy", AuthType: model.AuthPassword, Password: &pw})
	if err != nil {
		t.Fatal(err)
	}
	e.id = info.ID
	return e
}

// fakeLinux answers the probe like a Debian box; sudo works or not.
func fakeLinux(sudo bool) sshtest.ExecFunc {
	return func(_ context.Context, line string, _ io.Reader, out, errw io.Writer) int {
		isSudo := strings.HasPrefix(line, "sudo -n -- ")
		line = strings.TrimPrefix(line, "sudo -n -- ")
		switch strings.TrimPrefix(line, "env LC_ALL=C LANG=C ") {
		case "id -un":
			fmt.Fprintln(out, "deploy")
		case "id -u":
			fmt.Fprintln(out, "1000")
		case "uname -n":
			fmt.Fprintln(out, "vps1")
		case "uname -sr":
			fmt.Fprintln(out, "Linux 6.1.0-18-amd64")
		case "uname -m":
			fmt.Fprintln(out, "x86_64")
		case "true":
			if isSudo && !sudo {
				fmt.Fprintln(errw, "sudo: a password is required")
				return 1
			}
		default:
			return 127
		}
		return 0
	}
}

func TestFirstConnectNeedsConfirmation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, err := e.conn.Check(ctx, e.id)
	var unknown *remote.HostKeyUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("first connect: %v", err)
	}
	want := ssh.FingerprintSHA256(e.srv.HostKey())
	if unknown.Fingerprint != want || !strings.HasPrefix(want, "SHA256:") {
		t.Fatalf("fingerprint %q, want %q", unknown.Fingerprint, want)
	}
	if n := e.srv.AuthAttempts.Load(); n != 0 {
		t.Fatalf("credentials offered to an untrusted server (%d attempts)", n)
	}
	if _, err := e.conn.Trust(ctx, 1, e.id, "SHA256:somethingelse", false); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("wrong fingerprint trusted: %v", err)
	}
	hk, err := e.conn.Trust(ctx, 1, e.id, want, false)
	if err != nil || hk.Fingerprint != want {
		t.Fatalf("%+v %v", hk, err)
	}
	if n := e.srv.AuthAttempts.Load(); n != 0 {
		t.Fatalf("trusting sent credentials (%d attempts)", n)
	}
	p, err := e.conn.Check(ctx, e.id)
	if err != nil || p.User != "deploy" || !p.Sudo || p.Arch != "x86_64" {
		t.Fatalf("%+v %v", p, err)
	}
	// The password is known to the redactor from now on.
	if got := e.red.String("echo " + fakePass); strings.Contains(got, fakePass) {
		t.Fatalf("password not registered: %q", got)
	}
	info, _ := e.inv.Get(ctx, e.id)
	if info.HostKey == nil || info.HostKey.TrustedBy != 1 {
		t.Fatalf("%+v", info.HostKey)
	}
}

func TestChangedHostKeyBlocks(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	old := ssh.FingerprintSHA256(e.srv.HostKey())
	if _, err := e.conn.Trust(ctx, 1, e.id, old, false); err != nil {
		t.Fatal(err)
	}
	e.srv.SetHostKey(sshtest.NewSigner(t)) // reinstalled, or someone in the middle
	newFP := ssh.FingerprintSHA256(e.srv.HostKey())
	attempts := e.srv.AuthAttempts.Load()

	_, err := e.conn.Check(ctx, e.id)
	var changed *remote.HostKeyChangedError
	if !errors.As(err, &changed) || changed.OldFingerprint != old || changed.Fingerprint != newFP {
		t.Fatalf("changed key: %v", err)
	}
	if e.srv.AuthAttempts.Load() != attempts {
		t.Fatal("credentials offered to a server with a changed key")
	}
	// Plain trust does not silently replace.
	if _, err := e.conn.Trust(ctx, 1, e.id, newFP, false); !errors.As(err, &changed) {
		t.Fatalf("trust without replace: %v", err)
	}
	if _, err := e.conn.Check(ctx, e.id); !errors.As(err, &changed) {
		t.Fatal("still blocked until an explicit re-trust")
	}
	if _, err := e.conn.Trust(ctx, 1, e.id, newFP, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.conn.Check(ctx, e.id); err != nil {
		t.Fatalf("after re-trust: %v", err)
	}
	es, _ := e.db.ListAudit(ctx, 5)
	found := false
	for _, a := range es {
		if a.Action == "host_key_replaced" && strings.Contains(a.Details, old) && strings.Contains(a.Details, newFP) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit of the re-trust: %+v", es)
	}
}

func TestWrongCredentialsAndNoSudo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	e := newEnv(t)
	ctx := context.Background()
	e.conn.Trust(ctx, 1, e.id, ssh.FingerprintSHA256(e.srv.HostKey()), false)

	e.srv.SetExec(fakeLinux(false))
	p, err := e.conn.Check(ctx, e.id)
	if !errors.Is(err, remote.ErrSudoRequired) || p.User != "deploy" || p.Sudo {
		t.Fatalf("no sudo: %+v %v", p, err)
	}

	wrong := "wrong-password"
	e.inv.Update(ctx, 1, e.id, servers.Input{Name: "test", Host: e.srv.Host, SSHPort: e.srv.Port, SSHUser: "deploy", AuthType: model.AuthPassword, Password: &wrong})
	if _, err := e.conn.Check(ctx, e.id); !errors.Is(err, remote.ErrAuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestUnreachable(t *testing.T) {
	e := newEnv(t)
	e.srv.Close()
	_, err := e.conn.Trust(context.Background(), 1, e.id, "SHA256:x", false)
	var ue *remote.UnreachableError
	if !errors.As(err, &ue) {
		t.Fatalf("%v", err)
	}
}
