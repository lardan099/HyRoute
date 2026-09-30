package remote_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

func TestReadOnly(t *testing.T) {
	ctx := context.Background()
	inner := fake.New()
	inner.On().Reply("", 0) // everything succeeds underneath
	inner.SetFile("/etc/hysteria/config.yaml", []byte("listen: :443\n"))
	ex := remote.ReadOnly(inner)

	allowed := [][]string{
		{"id", "-un"}, {"hostname"}, {"uname", "-m"}, {"true"},
		{"test", "-e", "/etc/hysteria"},
		{"stat", "-L", "-c", "%a %U %G %s", "--", "/etc/hysteria/config.yaml"},
		{"cat", "--", "/etc/hysteria/config.yaml"},
		{"sha256sum", "--", "/usr/local/bin/hysteria"},
		{"ss", "-Hlntup"},
		{"ps", "-o", "unit=", "-p", "4242"},
		{"systemctl", "show", "--no-pager", "-p", "LoadState", "--", "hysteria-server.service"},
		{"systemctl", "list-units", "--no-pager", "--no-legend", "--plain", "--type=service", "--all", "--", "hysteria*"},
		{"systemctl", "is-enabled", "--", "hysteria-server.service"},
		{"journalctl", "-u", "hysteria-server.service", "-n", "50", "--no-pager", "-o", "cat"},
		{"/usr/local/bin/hysteria", "version"},
		{"sh", "-c", `command -v "$1" >/dev/null 2>&1`, "sh", "curl"},
		{"getent", "passwd", "hysteria"},
	}
	for _, a := range allowed {
		if _, err := ex.Run(ctx, remote.Cmd{Args: a, Sudo: true}); err != nil {
			t.Errorf("%q refused: %v", a, err)
		}
	}
	refused := [][]string{
		{"rm", "-rf", "/"}, {"mv", "a", "b"}, {"install", "-m", "0644", "a", "b"}, {"useradd", "x"},
		{"hostname", "evil"}, {"systemctl", "restart", "--", "hysteria-server.service"},
		{"systemctl", "stop", "hysteria-server.service"}, {"systemctl", "daemon-reload"},
		{"systemctl", "show", "--kill-who=all"}, {"ss", "-K", "dst", "192.0.2.1"},
		{"journalctl", "--vacuum-size=1K"}, {"journalctl", "--rotate"},
		{"sh", "-c", "rm -rf /"}, {"curl", "-o", "/usr/local/bin/hysteria", "https://example.com"},
		{"hysteria", "version"}, {"/usr/local/bin/hysteria", "server"}, {"/tmp/x", "version"},
		{"stat", "--printf=%n", "/"}, {"ufw", "allow", "443/udp"}, {},
		{"getent", "hosts", "example.com"}, {"getent", "passwd", "-s", "x"},
	}
	for _, a := range refused {
		if _, err := ex.Run(ctx, remote.Cmd{Args: a}); !errors.Is(err, remote.ErrNotReadOnly) {
			t.Errorf("%q not refused: %v", a, err)
		}
		if err := ex.Stream(ctx, remote.Cmd{Args: a}, func(string) {}); !errors.Is(err, remote.ErrNotReadOnly) {
			t.Errorf("%q streamed: %v", a, err)
		}
	}
	if err := ex.WriteFile(ctx, "/etc/hysteria/config.yaml", []byte("x"), remote.FileSpec{Mode: 0o600}); !errors.Is(err, remote.ErrNotReadOnly) {
		t.Fatalf("write: %v", err)
	}
	if b, err := ex.ReadFile(ctx, "/etc/hysteria/config.yaml", true); err != nil || string(b) != "listen: :443\n" {
		t.Fatalf("read: %q %v", b, err)
	}
	if len(inner.Writes()) != 0 {
		t.Fatal("a write reached the server")
	}
	for _, c := range inner.Commands() {
		for _, a := range refused {
			if len(a) > 0 && c == strings.Join(a, " ") {
				t.Fatalf("refused command ran: %s", c)
			}
		}
	}
}

func TestStat(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("stat", "-L", "-c", "%a %U %G %s", "--", "/etc/hysteria/config.yaml").Reply("644 root root 812\n", 0)
	ex.On("stat", "-L", "-c", "%a %U %G %s", "--", "/nope").Fail("stat: cannot statx '/nope': No such file or directory", 1)
	ex.On("stat", "-L", "-c", "%a %U %G %s", "--", "/odd").Reply("rw- root\n", 0)
	fi, ok, err := remote.Stat(ctx, ex, "/etc/hysteria/config.yaml", true)
	if err != nil || !ok || fi.Mode != 0o644 || fi.Owner != "root" || fi.Group != "root" || fi.Size != 812 {
		t.Fatalf("%+v %v %v", fi, ok, err)
	}
	if _, ok, err := remote.Stat(ctx, ex, "/nope", true); ok || err != nil {
		t.Fatalf("missing: %v %v", ok, err)
	}
	if _, _, err := remote.Stat(ctx, ex, "/odd", true); err == nil {
		t.Fatal("odd output accepted")
	}
	if _, _, err := remote.Stat(ctx, ex, "relative", true); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestServiceUnitsAndUnitOfPID(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("systemctl", "list-units").Reply("hysteria-server@main.service loaded active running Hysteria Server Service (main.yaml)\nhysteria-server.service loaded inactive dead Hysteria Server Service (config.yaml)\n", 0)
	ex.On("systemctl", "list-unit-files").Reply("hysteria-server.service enabled enabled\nhysteria-server@.service disabled enabled\nhysteria-extra.service disabled enabled\n", 0)
	got, err := remote.ServiceUnits(ctx, ex, "hysteria*")
	if err != nil || !slices.Equal(got, []string{"hysteria-server@main.service", "hysteria-server.service", "hysteria-extra.service"}) {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := remote.ServiceUnits(ctx, ex, "a b; rm"); err == nil {
		t.Fatal("bad pattern accepted")
	}
	ex.On("ps", "-o", "unit=", "-p", "4242").Reply("hy2.service\n", 0)
	ex.On("ps", "-o", "unit=", "-p", "7").Reply("-\n", 0)
	if u, err := remote.UnitOfPID(ctx, ex, 4242); err != nil || u != "hy2.service" {
		t.Fatalf("%q %v", u, err)
	}
	if u, err := remote.UnitOfPID(ctx, ex, 7); err != nil || u != "" {
		t.Fatalf("no unit: %q %v", u, err)
	}
}
