package remote_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

func TestTempDir(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("mktemp").Reply("/tmp/hyroute.Ab3dEf7hIj\n", 0)
	d, err := remote.TempDir(ctx, ex, true)
	if err != nil || d != "/tmp/hyroute.Ab3dEf7hIj" {
		t.Fatalf("%q %v", d, err)
	}
	ex.On("rm").Reply("", 0)
	if err := remote.RemoveTempDir(ctx, ex, d, true); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/", "/tmp", "/tmp/hyroute.", "/etc/hysteria", "/tmp/hyroute.Ab3dEf7hIj/..", "/tmp/hyroute.Ab3dEf7hIj/x"} {
		if err := remote.RemoveTempDir(ctx, ex, bad, true); err == nil {
			t.Errorf("removed %q", bad)
		}
	}
	if got := ex.Commands(); !slices.Equal(got, []string{"mktemp -d /tmp/hyroute.XXXXXXXXXX", "rm -rf -- /tmp/hyroute.Ab3dEf7hIj"}) {
		t.Fatalf("%q", got)
	}
	// mktemp printing something odd is not trusted as a path to delete later.
	ex = fake.New()
	ex.On("mktemp").Reply("/\n", 0)
	if _, err := remote.TempDir(ctx, ex, true); err == nil {
		t.Fatal("odd mktemp output accepted")
	}
}

func TestFileSHA256(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	sum := strings.Repeat("ab", 32)
	ex.On("sha256sum", "--", "/usr/local/bin/hysteria").Reply(sum+"  /usr/local/bin/hysteria\n", 0)
	ex.On("sha256sum", "--", "/nope").Fail("sha256sum: /nope: No such file or directory", 1)
	ex.On("sha256sum", "--", "/denied").Fail("sha256sum: /denied: Permission denied", 1)
	ex.On("sha256sum", "--", "/odd").Reply("hello\n", 0)
	if got, err := remote.FileSHA256(ctx, ex, "/usr/local/bin/hysteria", true); err != nil || got != sum {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := remote.FileSHA256(ctx, ex, "/nope", true); err != nil || got != "" {
		t.Fatalf("missing: %q %v", got, err)
	}
	for _, p := range []string{"/denied", "/odd", "relative"} {
		if _, err := remote.FileSHA256(ctx, ex, p, true); err == nil {
			t.Errorf("%s: no error", p)
		}
	}
}

func TestInstallFile(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("install").Reply("", 0)
	ex.On("mv").Reply("", 0)
	if err := remote.InstallFile(ctx, ex, "/tmp/hyroute.abcdefghij/hysteria", "/usr/local/bin/hysteria", 0o755, "", "", true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"install -m 0755 -o root -g root -- /tmp/hyroute.abcdefghij/hysteria /usr/local/bin/hysteria.hyroute-new",
		"mv -fT -- /usr/local/bin/hysteria.hyroute-new /usr/local/bin/hysteria",
	}
	if got := ex.Commands(); !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	for _, c := range ex.Calls() {
		if !c.Sudo {
			t.Fatalf("not as root: %+v", c)
		}
	}
	if err := remote.InstallFile(ctx, ex, "/a", "/b", 0o640, "root; reboot", "hysteria", true); err == nil {
		t.Fatal("bad owner accepted")
	}
	if err := remote.MakeDir(ctx, ex, "/etc/hysteria", 0o750, "root", "hysteria", false); err != nil {
		t.Fatal(err)
	}
	if got := ex.Commands(); got[len(got)-1] != "install -d -m 0750 -o root -g hysteria -- /etc/hysteria" {
		t.Fatalf("%q", got)
	}
}

func TestSetOwnerMode(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("chown").Reply("", 0)
	ex.On("chmod").Reply("", 0)
	if err := remote.SetOwnerMode(ctx, ex, "/etc/hysteria/config.yaml", 0o640, "", "hysteria", true); err != nil {
		t.Fatal(err)
	}
	want := []string{"chown -- root:hysteria /etc/hysteria/config.yaml", "chmod -- 0640 /etc/hysteria/config.yaml"}
	if got := ex.Commands(); !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	for _, bad := range [][2]string{{"/x", "root:root"}, {"relative", "root"}} {
		if err := remote.SetOwnerMode(ctx, ex, bad[0], 0o600, bad[1], "", true); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	ex.On("chown").Reply("", 1)
	if err := remote.SetOwnerMode(ctx, ex, "/x", 0o600, "", "", true); err == nil {
		t.Fatal("failed chown passed")
	}
}

func TestDownloadRejects(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	for _, u := range []string{"http://github.com/x", "https://x/a b", "https://x/'$(id)'", "file:///etc/passwd"} {
		if err := remote.Download(ctx, ex, u, "/tmp/x", true); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if len(ex.Calls()) != 0 {
		t.Fatal("ran something")
	}
}
