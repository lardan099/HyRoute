package importer

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

type conn struct{ m *machine }

// Connect gives every job the same machine; a job closing its connection
// does not close the machine.
func (c conn) Connect(context.Context, int64) (remote.Executor, error) { return open{c.m}, nil }

type open struct{ *machine }

func (open) Close() error { return nil }

type env struct {
	t      *testing.T
	db     *sqlite.DB
	keys   *secrets.Keyring
	eng    *jobs.Engine
	server int64
}

func newEnv(t *testing.T, m *machine) *env {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{5}, 32)})
	srv := model.Server{Name: "imported", Host: "192.0.2.20", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	if err := db.CreateServer(ctx, &srv, nil); err != nil {
		t.Fatal(err)
	}
	m.On("id", "-un").Reply("root\n", 0)
	m.On("id", "-u").Reply("0\n", 0)
	m.On("hostname").Reply("vps\n", 0)
	m.On("uname", "-sr").Reply("Linux 6.8.0\n", 0)
	m.On("uname", "-m").Reply("x86_64\n", 0)
	eng := jobs.New(db, keys, redact.New(), conn{m}, nil)
	eng.Poll = 10 * time.Millisecond
	eng.Register(Kind(Deps{Store: db, Keys: keys, Now: func() time.Time { return now }}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { eng.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &env{t: t, db: db, keys: keys, eng: eng, server: srv.ID}
}

func (e *env) run() model.Job {
	e.t.Helper()
	j, err := e.eng.Submit(context.Background(), JobKind, e.server, struct{}{}, nil, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		j, _ = e.db.JobByID(context.Background(), j.ID)
		if j.State.Terminal() {
			time.Sleep(20 * time.Millisecond) // the Finished hook
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatalf("job stuck in %s", j.State)
	return j
}

func (e *env) steps(id int64) map[string]model.StepState {
	rows, _ := e.db.JobSteps(context.Background(), id)
	out := map[string]model.StepState{}
	for _, r := range rows {
		out[r.Name] = r.State
	}
	return out
}

func TestImportJob(t *testing.T) {
	ctx := context.Background()
	m := official()
	e := newEnv(t, m)
	j := e.run()
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s %s", j.State, j.ErrorMessage, j.ErrorDetails)
	}
	if len(m.Writes()) != 0 {
		t.Fatalf("import wrote to the server: %v", m.Writes())
	}
	for _, c := range m.Commands() {
		for _, bad := range []string{"systemctl restart", "systemctl stop", "systemctl start", "mv ", "rm ", "install ", "chmod", "useradd"} {
			if strings.HasPrefix(c, bad) {
				t.Fatalf("import ran %q", c)
			}
		}
	}
	cur, err := e.db.CurrentConfig(ctx, e.server)
	if err != nil || cur.Revision != 1 || cur.Source != model.ConfigImport || cur.Meta.TLS != "acme" || cur.JobID != j.ID {
		t.Fatalf("%+v %v", cur, err)
	}
	plain, err := e.keys.Open(cur.Sealed, model.ConfigContext(e.server, 1))
	if err != nil || string(plain) != officialConfig {
		t.Fatalf("stored config: %v", err)
	}
	in, err := e.db.Installation(ctx, e.server)
	if err != nil || in.Managed || in.Unit != "hysteria-server.service" || in.Config != "/etc/hysteria/config.yaml" || in.User != "hysteria" || in.Version != "v2.6.0" {
		t.Fatalf("%+v %v", in, err)
	}
	if s, _ := e.db.ServerByID(ctx, e.server); s.State != model.StateNeedsAttention {
		t.Fatalf("state %s", s.State)
	}
	if !strings.Contains(j.Data["report"], `"config-readable"`) || strings.Contains(j.Data["report"], "fake-official-pass") {
		t.Fatalf("report: %s", j.Data["report"])
	}
	logs, _ := e.db.JobLogs(ctx, j.ID, 0, 0)
	for _, l := range logs {
		if strings.Contains(l.Message, "fake-official-pass") {
			t.Fatalf("password in the log: %s", l.Message)
		}
	}

	// Again, unchanged: nothing new.
	j = e.run()
	if j.State != model.JobCompleted || e.steps(j.ID)["save"] != model.StepSkipped {
		t.Fatalf("%s %v", j.State, e.steps(j.ID))
	}
	if cs, _ := e.db.ListConfigs(ctx, e.server); len(cs) != 1 {
		t.Fatalf("%d revisions", len(cs))
	}

	// The config changed on the server: a new revision.
	m.SetFile("/etc/hysteria/config.yaml", []byte(strings.Replace(officialConfig, "fake-official-pass", "fake-changed-pass-1", 1)))
	m.modes["/etc/hysteria/config.yaml"] = "640 root hysteria"
	if j = e.run(); j.State != model.JobCompleted {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if cur, _ := e.db.CurrentConfig(ctx, e.server); cur.Revision != 2 {
		t.Fatalf("revision %d", cur.Revision)
	}
	if s, _ := e.db.ServerByID(ctx, e.server); s.State != model.StateHealthy {
		t.Fatalf("state %s with only notes", s.State)
	}
}

func TestImportKeepsDeployedInstallationManaged(t *testing.T) {
	ctx := context.Background()
	m := official()
	e := newEnv(t, m)
	e.db.SetInstallation(ctx, model.Installation{ServerID: e.server, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", User: "hysteria", Managed: true, At: now})
	if j := e.run(); j.State != model.JobCompleted {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if in, _ := e.db.Installation(ctx, e.server); !in.Managed {
		t.Fatal("an installation HyRoute deployed became foreign")
	}
}

func TestImportConfigChangedMeanwhile(t *testing.T) {
	m := official()
	// The admin edits the config right after the import read it.
	m.On("stat").Do(func(c remote.Cmd) (remote.Result, error) {
		m.SetFile("/etc/hysteria/config.yaml", []byte(officialConfig+"# edited\n"))
		return remote.Result{Stdout: []byte("640 root hysteria 100\n")}, nil
	})
	e := newEnv(t, m)
	j := e.run()
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "изменился") {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if _, err := e.db.CurrentConfig(context.Background(), e.server); err == nil {
		t.Fatal("a config was saved")
	}
	if s, _ := e.db.ServerByID(context.Background(), e.server); s.State != model.StateNew {
		t.Fatalf("state %s after a failed import", s.State)
	}
}
