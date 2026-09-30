package fake

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

func TestFakeRulesAndRecords(t *testing.T) {
	ctx := context.Background()
	f := New()
	f.On("id", "-un").Reply("deploy\n", 0)
	f.On("id", "-u").Reply("1000\n", 0)
	f.On("hostname").Reply("vps\n", 0)
	f.On("uname", "-sr").Reply("Linux 6.1.0\n", 0)
	f.On("uname", "-m").Reply("x86_64\n", 0)
	f.On("true").Fail("sudo: a password is required", 1)
	p, err := remote.RunProbe(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if p.User != "deploy" || p.Root || p.Sudo || p.Arch != "x86_64" {
		t.Fatalf("%+v", p)
	}
	if cs := f.Commands(); len(cs) != 6 || cs[5] != "true" {
		t.Fatalf("%q", cs)
	}
	// Newest rule wins; Times limits it.
	f.On("true").Reply("", 0).Times(1)
	if r, _ := f.Run(ctx, remote.Cmd{Args: []string{"true"}}); !r.OK() {
		t.Fatal("newest rule not used")
	}
	if r, _ := f.Run(ctx, remote.Cmd{Args: []string{"true"}}); r.OK() {
		t.Fatal("used-up rule still answers")
	}
	if r, _ := f.Run(ctx, remote.Cmd{Args: []string{"reboot"}}); r.ExitCode != 127 {
		t.Fatal("unmatched command must fail")
	}
}

func TestFakeFiles(t *testing.T) {
	ctx := context.Background()
	f := New()
	f.SetFile("/etc/hysteria/config.yaml", []byte("listen: :443\n"))
	b, err := f.ReadFile(ctx, "/etc/hysteria/config.yaml", true)
	if err != nil || string(b) != "listen: :443\n" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := f.ReadFile(ctx, "/missing", false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%v", err)
	}
	f.ReadOnly = true
	if err := f.WriteFile(ctx, "/etc/x", []byte("y"), remote.FileSpec{Mode: 0o600}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only write: %v", err)
	}
	if len(f.Writes()) != 1 {
		t.Fatal("attempted write not recorded")
	}
	f.ReadOnly = false
	f.WriteFile(ctx, "/etc/x", []byte("y"), remote.FileSpec{Mode: 0o600})
	if b, ok := f.File("/etc/x"); !ok || string(b) != "y" {
		t.Fatal("write not stored")
	}
}
