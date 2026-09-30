package sshexec

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
)

// Fake credentials for the in-process server.
const fakePass = "fake-ssh-pass-sshexec"

func needShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the test server runs commands with /bin/sh")
	}
}

func trust(k ssh.PublicKey) func(ssh.PublicKey) error {
	return func(got ssh.PublicKey) error {
		if !bytes.Equal(got.Marshal(), k.Marshal()) {
			return &remote.HostKeyChangedError{Fingerprint: ssh.FingerprintSHA256(got)}
		}
		return nil
	}
}

func dial(t *testing.T, srv *sshtest.Server, a Auth) *Client {
	t.Helper()
	c, err := Dial(context.Background(), Target{Host: srv.Host, Port: srv.Port, User: srv.User}, a, Options{HostKey: trust(srv.HostKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRunAndArgs(t *testing.T) {
	needShell(t)
	srv := sshtest.Start(t, "tester", fakePass)
	c := dial(t, srv, Auth{Password: fakePass})
	ctx := context.Background()

	res, err := c.Run(ctx, remote.Cmd{Args: []string{"printf", "%s|", "$(id)", "a b", "it's", "x;y"}})
	if err != nil || res.ExitCode != 0 || string(res.Stdout) != "$(id)|a b|it's|x;y|" {
		t.Fatalf("%q %d %v", res.Stdout, res.ExitCode, err)
	}
	res, err = c.Run(ctx, remote.Cmd{Args: []string{"sh", "-c", "echo oops >&2; exit 3"}})
	if err != nil || res.ExitCode != 3 || strings.TrimSpace(string(res.Stderr)) != "oops" {
		t.Fatalf("%q %d %v", res.Stderr, res.ExitCode, err)
	}
	res, _ = c.Run(ctx, remote.Cmd{Args: []string{"cat"}, Stdin: []byte("from stdin")})
	if string(res.Stdout) != "from stdin" {
		t.Fatalf("stdin: %q", res.Stdout)
	}
	// The line carries the fixed locale and sudo without prompts.
	c.Run(ctx, remote.Cmd{Args: []string{"true"}, Sudo: true})
	lines := srv.Lines()
	if last := lines[len(lines)-1]; last != "sudo -n -- env LC_ALL=C LANG=C true" {
		t.Fatalf("line %q", last)
	}
}

func TestProbe(t *testing.T) {
	needShell(t)
	srv := sshtest.Start(t, "tester", fakePass)
	c := dial(t, srv, Auth{Password: fakePass})
	p, err := remote.RunProbe(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if p.User == "" || p.Arch == "" || !strings.HasPrefix(p.Kernel, "Linux") || !p.Privileged() {
		t.Fatalf("%+v", p)
	}
}

func TestFiles(t *testing.T) {
	needShell(t)
	srv := sshtest.Start(t, "tester", fakePass)
	c := dial(t, srv, Auth{Password: fakePass})
	ctx := context.Background()
	dir := t.TempDir()
	target := filepath.Join(dir, "config.yaml")
	os.WriteFile(target, []byte("old\n"), 0o644)

	data := bytes.Repeat([]byte("listen: :443\n"), 5000)
	if err := c.WriteFile(ctx, target, data, remote.FileSpec{Mode: 0o640}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("written %d bytes, %v", len(got), err)
	}
	if st, _ := os.Stat(target); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*hyroute-new")); len(left) != 0 {
		t.Fatalf("staged file left: %v", left)
	}
	for _, sudo := range []bool{false, true} {
		b, err := c.ReadFile(ctx, target, sudo)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("read (sudo %v): %d bytes, %v", sudo, len(b), err)
		}
	}
	for _, sudo := range []bool{false, true} {
		if _, err := c.ReadFile(ctx, filepath.Join(dir, "missing"), sudo); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("missing file (sudo %v): %v", sudo, err)
		}
	}
	if err := c.WriteFile(ctx, "relative/path", data, remote.FileSpec{Mode: 0o600}); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestStreamAndCancel(t *testing.T) {
	needShell(t)
	srv := sshtest.Start(t, "tester", fakePass)
	c := dial(t, srv, Auth{Password: fakePass})
	var got []string
	err := c.Stream(context.Background(), remote.Cmd{Args: []string{"printf", "a\\nb\\nc\\n"}}, func(l string) { got = append(got, l) })
	if err != nil || strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("%q %v", got, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c.Run(ctx, remote.Cmd{Args: []string{"sleep", "10"}}); err == nil {
		t.Fatal("cancelled run returned no error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancel did not stop the run")
	}
}

func TestKeyAuth(t *testing.T) {
	needShell(t)
	srv := sshtest.Start(t, "tester", "")
	user, priv := sshtest.NewUserKey(t)
	srv.AuthorizedKey = user.PublicKey()
	c := dial(t, srv, Auth{Key: priv})
	if res, err := c.Run(context.Background(), remote.Cmd{Args: []string{"true"}}); err != nil || !res.OK() {
		t.Fatal(err)
	}
}

func TestAuthFailedAndUnreachable(t *testing.T) {
	srv := sshtest.Start(t, "tester", fakePass)
	_, err := Dial(context.Background(), Target{Host: srv.Host, Port: srv.Port, User: "tester"}, Auth{Password: "wrong"}, Options{HostKey: trust(srv.HostKey())})
	if !errors.Is(err, remote.ErrAuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	_, err = Dial(context.Background(), Target{Host: "127.0.0.1", Port: port, User: "x"}, Auth{Password: "x"}, Options{HostKey: trust(srv.HostKey()), Timeout: 2 * time.Second})
	var ue *remote.UnreachableError
	if !errors.As(err, &ue) {
		t.Fatalf("closed port: %v", err)
	}
}

// A host key check that fails aborts the handshake before any credential
// is offered.
func TestHostKeyRejectedBeforeAuth(t *testing.T) {
	srv := sshtest.Start(t, "tester", fakePass)
	unknown := func(k ssh.PublicKey) error {
		return &remote.HostKeyUnknownError{KeyType: k.Type(), Fingerprint: ssh.FingerprintSHA256(k)}
	}
	_, err := Dial(context.Background(), Target{Host: srv.Host, Port: srv.Port, User: "tester"}, Auth{Password: fakePass}, Options{HostKey: unknown})
	var hk *remote.HostKeyUnknownError
	if !errors.As(err, &hk) || hk.Fingerprint != ssh.FingerprintSHA256(srv.HostKey()) {
		t.Fatalf("%v", err)
	}
	if n := srv.AuthAttempts.Load(); n != 0 {
		t.Fatalf("%d auth attempts reached an untrusted server", n)
	}
	if _, err := Dial(context.Background(), Target{Host: srv.Host, Port: srv.Port, User: "tester"}, Auth{Password: fakePass}, Options{}); err == nil {
		t.Fatal("dial without a host key check allowed")
	}
}
