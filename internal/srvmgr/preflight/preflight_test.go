package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

const osDebian12 = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
ID=debian
`

const osUbuntu2204 = `PRETTY_NAME="Ubuntu 22.04.4 LTS"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
`

const osAlpine = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.19.1
PRETTY_NAME="Alpine Linux v3.19"
`

// server scripts a typical VPS.
type server struct {
	os       string
	arch     string
	github   string // curl http code
	ss       string
	ufw      bool
	hysteria bool
}

func (s server) fake() *fake.Executor {
	f := fake.New()
	f.SetFile("/etc/os-release", []byte(s.os))
	f.SetFile("/proc/meminfo", []byte("MemTotal:        1015800 kB\nMemFree:          200000 kB\nMemAvailable:     700000 kB\n"))
	f.On("test", "-e", "/run/systemd/system").Reply("", 0)
	f.On("test", "-e", StdBinary).Fail("", 1)
	f.On("nproc").Reply("2\n", 0)
	f.On("df", "-Pk").Reply("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 20511312 3000000 16448592 16% /\n", 0)
	f.On("getent", "hosts", "github.com").Reply("140.82.121.3 github.com\n", 0)
	// command -v: ufw and curl exist, nothing else.
	f.On("sh", "-c").Do(func(c remote.Cmd) (remote.Result, error) {
		switch c.Args[len(c.Args)-1] {
		case "curl", "ss":
			return remote.Result{}, nil
		case "ufw":
			if s.ufw {
				return remote.Result{}, nil
			}
		}
		return remote.Result{ExitCode: 1}, nil
	})
	f.On("ufw", "status").Reply("Status: active\n", 0)
	f.On("curl").Reply(s.github, 0)
	f.On("ss", "-Hlntup").Reply(s.ss, 0)
	f.On("systemctl", "show").Reply("LoadState=not-found\nActiveState=inactive\nFragmentPath=\nExecStart=\nUser=\n", 0)
	if s.hysteria {
		f.On("systemctl", "show").Reply("LoadState=loaded\nActiveState=active\nFragmentPath=/etc/systemd/system/hysteria-server.service\nExecStart={ path=/usr/local/bin/hysteria ; argv[]=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml }\nUser=hysteria\nMainPID=900\n", 0)
		f.On("test", "-e", StdBinary).Reply("", 0)
		f.On(StdBinary, "version").Reply("Version:\tv2.12.3\nBuildDate:\t2025-01-01\n", 0)
	}
	f.RootPaths()
	return f
}

var rootProbe = remote.Probe{User: "root", Root: true, Sudo: true, Kernel: "Linux 6.1.0", Arch: "x86_64", Hostname: "vps"}

func level(r Report, id string) Level {
	for _, c := range r.Checks {
		if c.ID == id {
			return c.Level
		}
	}
	return ""
}

func TestDebianReady(t *testing.T) {
	s := server{os: osDebian12, github: "200", ufw: true, ss: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"}
	f := s.fake()
	r, err := Run(context.Background(), f, rootProbe, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Blocked {
		t.Fatalf("blocked: %+v", r.Checks)
	}
	if r.OSID != "debian" || r.HysteriaArch != "amd64" || !r.Systemd || r.MemoryMiB != 991 || r.CPUs != 2 || r.Firewall != "ufw" || !r.GitHub || r.Hysteria.Installed {
		t.Fatalf("%+v", r)
	}
	for _, id := range []string{"os", "arch", "systemd", "memory", "disk", "firewall", "github", "hysteria", "port", "privileges"} {
		if level(r, id) != OK {
			t.Errorf("%s: %s", id, level(r, id))
		}
	}
	// Preflight only reads: no writes, and root needs no sudo.
	if len(f.Writes()) != 0 {
		t.Fatalf("writes: %+v", f.Writes())
	}
	for _, c := range f.Calls() {
		if c.Sudo {
			t.Fatalf("sudo as root: %v", c.Args)
		}
	}
}

func TestUbuntuWithSudo(t *testing.T) {
	s := server{os: osUbuntu2204, github: "200", ufw: true}
	f := s.fake()
	p := remote.Probe{User: "deploy", Sudo: true, Kernel: "Linux 5.15", Arch: "aarch64"}
	r, err := Run(context.Background(), f, p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Blocked || r.HysteriaArch != "arm64" || level(r, "os") != OK {
		t.Fatalf("%+v", r.Checks)
	}
	sudoed := map[string]bool{}
	for _, c := range f.Calls() {
		if c.Sudo {
			sudoed[c.Args[0]] = true
		}
	}
	if !sudoed["ufw"] || !sudoed["ss"] {
		t.Fatalf("privileged reads without sudo: %v", sudoed)
	}
}

func TestUnsupportedOS(t *testing.T) {
	f := server{os: osAlpine, github: "200"}.fake()
	f.On("test", "-e", "/run/systemd/system").Fail("", 1)
	f.On("systemctl").Fail("System has not been booted with systemd as init system (PID 1).", 1)
	r, err := Run(context.Background(), f, rootProbe, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Blocked || level(r, "os") != Fail || level(r, "systemd") != Fail {
		t.Fatalf("%+v", r.Checks)
	}
	p := rootProbe
	p.Arch = "sparc64"
	r, _ = Run(context.Background(), server{os: osDebian12, github: "200"}.fake(), p, Options{})
	if level(r, "arch") != Fail {
		t.Fatalf("unknown arch: %+v", r.Checks)
	}
}

func TestBusyPort(t *testing.T) {
	ss := "udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:((\"caddy\",pid=812,fd=9))\n" +
		"tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=700,fd=6))\n"
	r, err := Run(context.Background(), server{os: osDebian12, github: "200", ss: ss}.fake(), rootProbe, Options{UDPPort: 443, TCPPorts: []int{80}})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Blocked || len(r.Ports) != 2 || r.Ports[0].Process != "caddy" {
		t.Fatalf("%+v %+v", r.Checks, r.Ports)
	}
	// Another port is free.
	r, _ = Run(context.Background(), server{os: osDebian12, github: "200", ss: ss}.fake(), rootProbe, Options{UDPPort: 8443})
	if r.Blocked {
		t.Fatalf("%+v", r.Checks)
	}
}

// A program listening on IPv4 and IPv6 (nginx: listen 80; listen [::]:80;)
// is one check, not two identical ones.
func TestBusyPortDualStack(t *testing.T) {
	ss := "tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=700,fd=6))\n" +
		"tcp LISTEN 0 511 [::]:80 [::]:* users:((\"nginx\",pid=700,fd=7))\n" +
		"udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:((\"caddy\",pid=812,fd=9))\n" +
		"udp UNCONN 0 0 [::]:443 [::]:* users:((\"caddy\",pid=812,fd=10))\n" +
		"udp UNCONN 0 0 [::1]:443 [::]:* users:((\"unbound\",pid=900,fd=4))\n"
	r, err := Run(context.Background(), server{os: osDebian12, github: "200", ss: ss}.fake(), rootProbe, Options{UDPPort: 443, TCPPorts: []int{80}})
	if err != nil {
		t.Fatal(err)
	}
	var titles []string
	seen := map[string]bool{}
	for _, c := range r.Checks {
		if c.ID != "port" {
			continue
		}
		if seen[c.Title] {
			t.Fatalf("duplicate check %q: %+v", c.Title, r.Checks)
		}
		seen[c.Title] = true
		titles = append(titles, c.Title)
	}
	if !r.Blocked || len(titles) != 3 || len(r.Ports) != 3 {
		t.Fatalf("%q %+v", titles, r.Ports)
	}
}

func TestNoGitHub(t *testing.T) {
	r, err := Run(context.Background(), server{os: osDebian12, github: "000"}.fake(), rootProbe, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.GitHub || level(r, "github") != Warn || r.Blocked {
		t.Fatalf("no github must warn, not block: %+v", r.Checks)
	}
}

func TestExistingHysteria(t *testing.T) {
	ss := "udp UNCONN 0 0 *:443 *:* users:((\"hysteria\",pid=900,fd=7))\n"
	r, err := Run(context.Background(), server{os: osDebian12, github: "200", ss: ss, hysteria: true}.fake(), rootProbe, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Hysteria.Installed || r.Hysteria.Version != "v2.12.3" || !r.Hysteria.Active || level(r, "hysteria") != Warn || level(r, "port") != Warn || r.Blocked {
		t.Fatalf("%+v %+v", r.Hysteria, r.Checks)
	}

	// The standard service runs a program by another name: still the
	// installed Hysteria, which a deploy replaces or imports.
	r, err = Run(context.Background(), server{os: osDebian12, github: "200", ss: strings.ReplaceAll(ss, `"hysteria"`, `"hy2"`), hysteria: true}.fake(), rootProbe, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if level(r, "port") != Warn || r.Blocked {
		t.Fatalf("standard service as hy2: %+v", r.Checks)
	}

	// Another Hysteria holds the port (its own unit, a container): the
	// standard service is not it, or there is none.
	other := "udp UNCONN 0 0 *:443 *:* users:((\"hysteria\",pid=777,fd=7))\n"
	for _, std := range []bool{true, false} {
		r, err := Run(context.Background(), server{os: osDebian12, github: "200", ss: other, hysteria: std}.fake(), rootProbe, Options{UDPPort: 443})
		if err != nil {
			t.Fatal(err)
		}
		if level(r, ForeignPortCheck) != Fail || !r.Blocked {
			t.Fatalf("standard service %v: %+v", std, r.Checks)
		}
	}
}

type fakeConnector struct{ f *fake.Executor }

func (c fakeConnector) Connect(context.Context, int64) (remote.Executor, error) { return c.f, nil }

// The preflight job stores the report and logs the checks.
func TestPreflightJob(t *testing.T) {
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{2}, 32)})
	f := server{os: osDebian12, github: "000", ufw: true}.fake()
	f.On("id", "-un").Reply("root\n", 0)
	f.On("id", "-u").Reply("0\n", 0)
	f.On("uname", "-n").Reply("vps\n", 0)
	f.On("uname", "-sr").Reply("Linux 6.1.0\n", 0)
	f.On("uname", "-m").Reply("x86_64\n", 0)
	eng := jobs.New(db, keys, nil, fakeConnector{f}, nil)
	eng.Poll = 10 * time.Millisecond
	eng.Register(Kind())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx)
	srv := model.Server{Name: "s", Host: "h.example", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	db.CreateServer(ctx, &srv, nil)
	j, err := eng.Submit(ctx, JobKind, srv.ID, Options{UDPPort: 443}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		if j, _ = db.JobByID(ctx, j.ID); j.State.Terminal() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if j.State != model.JobCompleted {
		t.Fatalf("%s %s %s", j.State, j.ErrorMessage, j.ErrorDetails)
	}
	var r Report
	if err := json.Unmarshal([]byte(j.Data["report"]), &r); err != nil || r.OSID != "debian" || r.GitHub {
		t.Fatalf("report %q %v", j.Data["report"], err)
	}
	ls, _ := db.JobLogs(ctx, j.ID, 0, 0)
	var all strings.Builder
	for _, l := range ls {
		all.WriteString(l.Message + "\n")
	}
	if !strings.Contains(all.String(), "GitHub недоступен") || !strings.Contains(all.String(), "Препятствий для развёртывания нет") {
		t.Fatalf("log:\n%s", all.String())
	}
	if !f.Closed() {
		t.Fatal("connection left open")
	}
}

func TestNoSS(t *testing.T) {
	f := server{os: osDebian12, github: "200"}.fake()
	f.On("sh", "-c").Do(func(c remote.Cmd) (remote.Result, error) {
		if c.Args[len(c.Args)-1] == "curl" {
			return remote.Result{}, nil
		}
		return remote.Result{ExitCode: 1}, nil
	})
	r, err := Run(context.Background(), f, rootProbe, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if level(r, UncheckedPortCheck) != Warn || level(r, "port") != "" || r.Blocked {
		t.Fatalf("%+v", r.Checks)
	}
}

func check(r Report, id string) Check {
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	return Check{}
}

// A last rule that rejects everything (Oracle Cloud) is a closed firewall,
// as a drop policy is.
func TestFirewallFinalReject(t *testing.T) {
	for _, tc := range []struct {
		rules, title string
		level        Level
	}{
		{"-P INPUT ACCEPT\n-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT\n-A INPUT -j REJECT --reject-with icmp-host-prohibited\n", "последним правилом", Warn},
		{"-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n", "с запретом по умолчанию", Warn},
		{"-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n", "не ограничены", OK},
	} {
		f := server{os: osUbuntu2204, github: "200"}.fake()
		f.On("sh", "-c").Do(func(c remote.Cmd) (remote.Result, error) {
			switch c.Args[len(c.Args)-1] {
			case "curl", "ss", "iptables":
				return remote.Result{}, nil
			}
			return remote.Result{ExitCode: 1}, nil
		})
		f.On("iptables", "-S", "INPUT").Reply(tc.rules, 0)
		r, err := Run(context.Background(), f, rootProbe, Options{})
		if err != nil {
			t.Fatal(err)
		}
		c := check(r, "firewall")
		if c.Level != tc.level || !strings.Contains(c.Title, tc.title) || r.Blocked {
			t.Errorf("%q: %+v", tc.rules, c)
		}
	}
}
