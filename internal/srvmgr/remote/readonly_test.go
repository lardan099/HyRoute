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
		{"sh", "-c", `PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"; command -v "$1" >/dev/null 2>&1`, "sh", "ss"},
		{"getent", "passwd", "hysteria"},
		{"df", "-Pk", "/"}, {"nproc"},
		{"head", "-n", "200", "--", "/proc/stat", "/proc/meminfo"},
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
		{"sh", "-c", `PATH=/tmp; command -v "$1" >/dev/null 2>&1`, "sh", "ss"},
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

func TestUnitStatusAndSystem(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	ex.On("systemctl", "show").Reply("LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nNRestarts=2\nMemoryCurrent=25165824\nActiveEnterTimestampMonotonic=1500000000\nUnitFileState=enabled\n", 0)
	u, err := remote.Unit(ctx, ex, "hysteria-server.service")
	if err != nil || u.SubState != "running" || u.MainPID != 4242 || u.NRestarts != 2 || u.MemoryCurrent != 24<<20 || u.ActiveEnter != 1_500_000_000 {
		t.Fatalf("%+v %v", u, err)
	}
	ex.On("systemctl", "show").Reply("LoadState=loaded\nActiveState=inactive\nMainPID=0\nMemoryCurrent=[not set]\nActiveEnterTimestampMonotonic=0\n", 0)
	if u, _ := remote.Unit(ctx, ex, "hysteria-server.service"); u.MemoryCurrent != 0 || u.MainPID != 0 {
		t.Fatalf("%+v", u)
	}
	ex.SetFile("/proc/uptime", []byte("3600.52 7000.10\n"))
	ex.SetFile("/proc/loadavg", []byte("0.15 0.10 0.05 1/123 4567\n"))
	if up, err := remote.Uptime(ctx, ex); err != nil || up != 3600.52 {
		t.Fatalf("%v %v", up, err)
	}
	if l, err := remote.LoadAverage(ctx, ex); err != nil || l != [3]float64{0.15, 0.10, 0.05} {
		t.Fatalf("%v %v", l, err)
	}
}

func TestJournal(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	lines := []string{
		`{"__REALTIME_TIMESTAMP":"1790000000000000","PRIORITY":"6","MESSAGE":"2026-09-21T10:13:20Z\tINFO\tserver up and running\t{\"listen\": \":443\"}"}`,
		`{"__REALTIME_TIMESTAMP":"1790000001000000","PRIORITY":"3","MESSAGE":[104,105,255]}`,
		`-- No entries --`,
		`{"__REALTIME_TIMESTAMP":"1790000002000000"}`,
	}
	ex.On("journalctl", "-u", "hysteria-server.service", "-n", "50", "--no-pager", "-o", "json", "--output-fields=MESSAGE,PRIORITY").Reply(strings.Join(lines, "\n")+"\n", 0)
	es, err := remote.JournalEntries(ctx, remote.ReadOnly(ex), "hysteria-server.service", 50, true)
	if err != nil || len(es) != 2 {
		t.Fatalf("%+v %v", es, err)
	}
	if es[0].Priority != 6 || !strings.Contains(es[0].Message, "server up and running") || es[0].Time.Unix() != 1_790_000_000 {
		t.Fatalf("%+v", es[0])
	}
	if es[1].Priority != 3 || es[1].Message != "hi�" {
		t.Fatalf("%+v", es[1])
	}
	ex.On("journalctl", "-u", "hysteria-server.service", "-n", "10").Lines(lines...)
	var got []remote.JournalEntry
	err = remote.JournalFollow(ctx, remote.ReadOnly(ex), "hysteria-server.service", 10, false, func(e remote.JournalEntry) { got = append(got, e) })
	if err != nil || len(got) != 2 {
		t.Fatalf("%d %v", len(got), err)
	}
	if !slices.Contains(ex.Commands(), "journalctl -u hysteria-server.service -n 10 --no-pager -o json --output-fields=MESSAGE,PRIORITY -f") {
		t.Fatalf("%q", ex.Commands())
	}
	if _, err := remote.JournalEntries(ctx, ex, "bad unit", 10, false); err == nil {
		t.Fatal("bad unit accepted")
	}
}
