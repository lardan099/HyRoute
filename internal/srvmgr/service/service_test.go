package service

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

var now = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

var std = model.Installation{Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", Managed: true}

const config = `listen: :443,20000-50000
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: fake-auth-secret-1234
obfs:
  type: salamander
  salamander:
    password: fake-obfs-secret-5678
trafficStats:
  listen: 127.0.0.1:9999
  secret: fake-stats-secret-90
`

// server is a fake machine with a Hysteria service whose state the
// systemctl actions change.
type server struct {
	*fake.Executor
	mu    sync.Mutex
	state string
	// broken: the service dies right after it starts.
	broken bool
}

func newServer() *server {
	s := &server{Executor: fake.New(), state: "active"}
	s.On("id", "-un").Reply("root\n", 0)
	s.On("id", "-u").Reply("0\n", 0)
	s.On("hostname").Reply("vps\n", 0)
	s.On("uname", "-sr").Reply("Linux 6.8.0\n", 0)
	s.On("uname", "-m").Reply("x86_64\n", 0)
	s.On("systemctl", "show").Do(func(remote.Cmd) (remote.Result, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		out := "LoadState=loaded\nActiveState=" + s.state + "\nSubState=running\nMainPID=4242\nNRestarts=1\nMemoryCurrent=31457280\nActiveEnterTimestampMonotonic=3000000000\nUnitFileState=enabled\n"
		if s.state != "active" {
			out = "LoadState=loaded\nActiveState=" + s.state + "\nSubState=dead\nMainPID=0\nNRestarts=1\nMemoryCurrent=[not set]\nActiveEnterTimestampMonotonic=0\nUnitFileState=enabled\n"
		}
		return remote.Result{Stdout: []byte(out)}, nil
	})
	s.On("systemctl", "is-active").Do(func(remote.Cmd) (remote.Result, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		code := 0
		if s.state != "active" {
			code = 3
		}
		return remote.Result{Stdout: []byte(s.state + "\n"), ExitCode: code}, nil
	})
	for _, a := range []string{"start", "restart", "stop"} {
		a := a
		s.On("systemctl", a).Do(func(remote.Cmd) (remote.Result, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			switch {
			case a == "stop":
				s.state = "inactive"
			case s.broken:
				s.state = "failed"
			default:
				s.state = "active"
			}
			return remote.Result{}, nil
		})
	}
	s.On("journalctl").Reply("server up and running\nconfig: auth password fake-auth-secret-1234 rejected\nfatal: obfs fake-obfs-secret-5678\n", 0)
	s.SetFile("/proc/uptime", []byte("3100.40 6000.00\n"))
	s.SetFile("/proc/loadavg", []byte("0.20 0.10 0.05 1/100 999\n"))
	s.SetFile("/proc/meminfo", []byte("MemTotal:        2048000 kB\nMemAvailable:    1024000 kB\n"))
	s.On("nproc").Reply("2\n", 0)
	s.On("df").Reply("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 20000000 5000000 15360000 25% /\n", 0)
	s.On("/usr/local/bin/hysteria", "version").Reply("Version:\tv2.12.3\n", 0)
	s.RootPaths()
	s.On("ss").Reply("udp UNCONN 0 0 *:443 *:* users:((\"hysteria\",pid=4242,fd=7))\ntcp LISTEN 0 4096 *:22 *:* users:((\"sshd\",pid=1,fd=3))\n", 0)
	return s
}

func TestReadStatus(t *testing.T) {
	s := newServer()
	st, err := Read(context.Background(), remote.ReadOnly(s), std, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Active || st.State != "active" || st.SubState != "running" || !st.Enabled || st.PID != 4242 || st.Restarts != 1 || st.MemoryMiB != 30 ||
		st.UptimeSec != 100 || st.Version != "v2.12.3" || len(st.Ports) != 1 || st.Ports[0] != 443 {
		t.Fatalf("%+v", st)
	}
	sys := st.System
	if sys.UptimeSec != 3100 || sys.Load[0] != 0.2 || sys.CPUs != 2 || sys.MemTotalMiB != 2000 || sys.MemAvailMiB != 1000 || sys.DiskFreeMiB != 15000 {
		t.Fatalf("%+v", sys)
	}
	if len(s.Writes()) != 0 {
		t.Fatal("status wrote")
	}
	s.mu.Lock()
	s.state = "failed"
	s.mu.Unlock()
	st, _ = Read(context.Background(), remote.ReadOnly(s), std, false, now)
	if st.Active || st.UptimeSec != 0 || st.PID != 0 {
		t.Fatalf("stopped: %+v", st)
	}
	s.On("systemctl", "show").Reply("LoadState=not-found\n", 0)
	var nie *NotInstalledError
	if _, err := Read(context.Background(), remote.ReadOnly(s), std, false, now); !errors.As(err, &nie) {
		t.Fatalf("gone unit: %v", err)
	}
}

type harness struct {
	t      *testing.T
	db     *sqlite.DB
	keys   *secrets.Keyring
	eng    *jobs.Engine
	server int64
}

type conn struct{ s *server }

func (c conn) Connect(context.Context, int64) (remote.Executor, error) { return open{c.s}, nil }

type open struct{ *server }

func (open) Close() error { return nil }

func newHarness(t *testing.T, s *server) *harness {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{3}, 32)})
	srv := model.Server{Name: "s", Host: "192.0.2.40", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	db.CreateServer(ctx, &srv, nil)
	eng := jobs.New(db, keys, redact.New(), conn{s}, nil)
	eng.Poll = 10 * time.Millisecond
	eng.Register(Kind(Deps{Store: db, Keys: keys, Wait: 300 * time.Millisecond, Poll: 20 * time.Millisecond}))
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { eng.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &harness{t: t, db: db, keys: keys, eng: eng, server: srv.ID}
}

func (h *harness) install() {
	ctx := context.Background()
	in := std
	in.ServerID, in.At = h.server, now
	h.db.SetInstallation(ctx, in)
	c := model.ServerConfig{ServerID: h.server, SHA256: "x", Source: model.ConfigDeploy, At: now}
	h.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return h.keys.Seal([]byte(config), model.ConfigContext(h.server, rev)) })
}

func (h *harness) run(a remote.ServiceAction) (model.Job, string) {
	h.t.Helper()
	j, err := h.eng.Submit(context.Background(), JobKind, h.server, Params{Action: a}, nil, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	for i := 0; i < 500 && !j.State.Terminal(); i++ {
		time.Sleep(10 * time.Millisecond)
		j, _ = h.db.JobByID(context.Background(), j.ID)
	}
	ls, _ := h.db.JobLogs(context.Background(), j.ID, 0, 0)
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Message + "\n")
	}
	return j, b.String()
}

func TestServiceJob(t *testing.T) {
	s := newServer()
	h := newHarness(t, s)
	if j, _ := h.run(remote.ServiceRestart); j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "разверните её или импортируйте") {
		t.Fatalf("no installation: %s %s", j.State, j.ErrorMessage)
	}
	h.install()
	for _, c := range []struct {
		a     remote.ServiceAction
		state model.ServerState
	}{{remote.ServiceRestart, model.StateHealthy}, {remote.ServiceStop, model.StateDegraded}, {remote.ServiceStart, model.StateHealthy}} {
		j, log := h.run(c.a)
		if j.State != model.JobCompleted {
			t.Fatalf("%s: %s %s\n%s", c.a, j.State, j.ErrorMessage, log)
		}
		time.Sleep(30 * time.Millisecond) // the Finished hook
		if srv, _ := h.db.ServerByID(context.Background(), h.server); srv.State != c.state {
			t.Fatalf("%s: server %s", c.a, srv.State)
		}
	}
	if !strings.Contains(strings.Join(s.Commands(), "\n"), "systemctl restart -- hysteria-server.service") {
		t.Fatalf("%q", s.Commands())
	}

	// A service that dies on start: the journal is in the log, redacted
	// with the passwords of the server's config.
	s.mu.Lock()
	s.broken = true
	s.mu.Unlock()
	j, log := h.run(remote.ServiceRestart)
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "failed") || !strings.Contains(log, "fatal: obfs") {
		t.Fatalf("%s %s\n%s", j.State, j.ErrorMessage, log)
	}
	for _, secret := range []string{"fake-auth-secret-1234", "fake-obfs-secret-5678"} {
		if strings.Contains(log, secret) {
			t.Fatalf("secret %s in the log:\n%s", secret, log)
		}
	}
	if _, err := h.eng.Submit(context.Background(), JobKind, h.server, Params{Action: "reboot"}, nil, 0); !errors.Is(err, ErrBadAction) {
		t.Fatalf("bad action: %v", err)
	}
}

func TestConfigSecrets(t *testing.T) {
	c, err := hyconfig.ParseServer([]byte(config + "---\n"))
	if err == nil {
		t.Fatal("multi-document config accepted")
	}
	c, _ = hyconfig.ParseServer([]byte(config))
	got := ConfigSecrets(c)
	for _, want := range []string{"fake-auth-secret-1234", "fake-obfs-secret-5678", "fake-stats-secret-90"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("%s not among the secrets", want)
		}
	}
	u, _ := hyconfig.ParseServer([]byte("auth:\n  type: userpass\n  userpass:\n    alice: fake-alice-pass\n"))
	if s := ConfigSecrets(u); !strings.Contains(strings.Join(s, ","), "fake-alice-pass") {
		t.Fatal("userpass passwords missed")
	}
	r, _ := hyconfig.ParseServer([]byte("listen: realm://fake-realm-token@realm.example.com/fake\n"))
	if s := ConfigSecrets(r); !slices.Contains(s, "fake-realm-token") {
		t.Fatalf("the Realms token missed: %q", s)
	}
}

func TestMakeEntry(t *testing.T) {
	r := redact.New()
	r.Add("fake-auth-secret-1234")
	at := time.Unix(1_790_000_000, 0).UTC()
	cases := []struct {
		in    remote.JournalEntry
		level string
		msg   string
	}{
		{remote.JournalEntry{Time: at, Priority: 6, Message: "2026-09-21T10:13:20Z\tINFO\tserver up and running\t{\"listen\": \":443\"}"}, "info", `server up and running  {"listen": ":443"}`},
		{remote.JournalEntry{Priority: 6, Message: "2026-09-21T10:13:20Z\tWARN\tclient auth failed\t{\"auth\": \"fake-auth-secret-1234\"}"}, "warn", `client auth failed  {"auth": "[REDACTED]"}`},
		{remote.JournalEntry{Priority: 6, Message: "2026-09-21T10:13:20Z\tFATAL\tfailed to load server config\t{\"error\": \"password fake-auth-secret-1234 too short\"}"}, "error", `failed to load server config  {"error": "password [REDACTED] too short"}`},
		{remote.JournalEntry{Priority: 3, Message: "Main process exited, code=exited, status=1/FAILURE"}, "error", "Main process exited, code=exited, status=1/FAILURE"},
		{remote.JournalEntry{Priority: 6, Message: "link hysteria2://fake-auth-secret-1234@192.0.2.1:443/"}, "info", "link hysteria2://[REDACTED]"},
	}
	for _, c := range cases {
		e := MakeEntry(c.in, r)
		if e.Level != c.level || e.Message != c.msg || !e.Time.Equal(c.in.Time) {
			t.Errorf("%q: %+v", c.in.Message, e)
		}
	}
}
