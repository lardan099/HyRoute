package apply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
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
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

const cfgPath = "/etc/hysteria/config.yaml"

const deployed = `listen: :443
acme:
  domains:
    - vpn.example.com
auth:
  type: password
  password: fake-apply-auth-pass
masquerade:
  type: proxy
  proxy:
    url: https://www.example.com
    rewriteHost: true
`

// vps is a server with Hysteria: restart runs the config on disk, and a
// config with "crash: true" (unknown to HyRoute, fatal to this Hysteria)
// makes the service fail.
type vps struct {
	mu     sync.Mutex
	files  map[string][]byte
	modes  map[string]string
	state  string
	port   int
	cmds   []string
	writes []remote.FileSpec
	ufw    map[string]bool // ufw rules ("8443/udp"); nil: no ufw
	bad    string          // a config containing it makes the service fail
	noSS   bool            // no ss (iproute2) on the server
}

func newVPS() *vps {
	v := &vps{files: map[string][]byte{cfgPath: []byte(deployed)}, modes: map[string]string{cfgPath: "640 root hysteria"}}
	v.start()
	return v
}

func (v *vps) start() {
	c, err := hyconfig.ParseServer(v.files[cfgPath])
	if err != nil || hyconfig.HasErrors(c.Validate()) || strings.Contains(string(v.files[cfgPath]), "crash: true") || (v.bad != "" && strings.Contains(string(v.files[cfgPath]), v.bad)) {
		v.state, v.port = "failed", 0
		return
	}
	l, _ := hyconfig.ParseListen(c.Listen)
	v.state, v.port = "active", l.First
}

func res(out string) remote.Result { return remote.Result{Stdout: []byte(out)} }

func (v *vps) Run(ctx context.Context, cmd remote.Cmd) (remote.Result, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	a := cmd.Args
	line := strings.Join(a, " ")
	v.cmds = append(v.cmds, line)
	last := a[len(a)-1]
	switch {
	case line == "id -un":
		return res("root\n"), nil
	case line == "id -u":
		return res("0\n"), nil
	case a[0] == "hostname":
		return res("vps\n"), nil
	case line == "uname -sr":
		return res("Linux 6.8.0\n"), nil
	case line == "uname -m":
		return res("x86_64\n"), nil
	case a[0] == "sha256sum":
		b, ok := v.files[last]
		if !ok {
			return remote.Result{ExitCode: 1, Stderr: []byte("No such file")}, nil
		}
		s := sha256.Sum256(b)
		return res(hex.EncodeToString(s[:]) + "  " + last + "\n"), nil
	case a[0] == "cp":
		v.files[last] = append([]byte(nil), v.files[a[len(a)-2]]...)
		v.modes[last] = v.modes[a[len(a)-2]]
		return res(""), nil
	case a[0] == "mv":
		src := a[len(a)-2]
		b, ok := v.files[src]
		if !ok {
			return remote.Result{ExitCode: 1, Stderr: []byte("mv: cannot stat")}, nil
		}
		v.files[last] = b
		delete(v.files, src)
		return res(""), nil
	case a[0] == "rm":
		delete(v.files, last)
		return res(""), nil
	case a[0] == "stat":
		b, ok := v.files[last]
		if !ok {
			return remote.Result{ExitCode: 1, Stderr: []byte("No such file")}, nil
		}
		return res(fmt.Sprintf("%s %d\n", v.modes[last], len(b))), nil
	case strings.HasPrefix(line, "systemctl is-active"):
		code := 0
		if v.state != "active" {
			code = 3
		}
		return remote.Result{Stdout: []byte(v.state + "\n"), ExitCode: code}, nil
	case strings.HasPrefix(line, "systemctl restart"):
		v.start()
		return res(""), nil
	case strings.HasPrefix(line, "systemctl stop"):
		v.state, v.port = "inactive", 0
		return res(""), nil
	case a[0] == "ss" && v.noSS:
		return remote.Result{ExitCode: 127, Stderr: []byte("env: 'ss': No such file or directory")}, nil
	case a[0] == "ss":
		if v.state == "active" {
			return res(fmt.Sprintf("udp UNCONN 0 0 *:%d *:* users:((\"hysteria\",pid=4242,fd=7))\n", v.port)), nil
		}
		return res(""), nil
	case a[0] == "sh" && last == "ufw" && v.ufw != nil:
		return res(""), nil
	case line == "ufw status" && v.ufw != nil:
		return res("Status: active\n"), nil
	case line == "ufw show added" && v.ufw != nil:
		out := "Added user rules (see 'ufw status' for running firewall):\n"
		for _, r := range v.rulesLocked() {
			out += "ufw allow " + r + "\n"
		}
		return res(out), nil
	case len(a) == 3 && a[0] == "ufw" && a[1] == "allow" && v.ufw != nil:
		v.ufw[last] = true
		return res("Rule added\n"), nil
	case strings.HasPrefix(line, "ufw --force delete allow ") && v.ufw != nil:
		delete(v.ufw, last)
		return res("Rule deleted\n"), nil
	case a[0] == "journalctl":
		return res("FATAL failed to load config: unknown field crash (auth fake-apply-auth-pass)\n"), nil
	}
	return remote.Result{ExitCode: 127, Stderr: []byte("vps: unknown command " + line)}, nil
}

func (v *vps) rulesLocked() []string {
	var out []string
	for r := range v.ufw {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

func (v *vps) rules() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.rulesLocked()
}

func (v *vps) Stream(context.Context, remote.Cmd, func(string)) error {
	return errors.New("no streams")
}

func (v *vps) ReadFile(_ context.Context, p string, _ bool) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	b, ok := v.files[p]
	if !ok {
		return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
	}
	return append([]byte(nil), b...), nil
}

func (v *vps) WriteFile(_ context.Context, p string, data []byte, f remote.FileSpec) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.files[p] = append([]byte(nil), data...)
	v.modes[p] = fmt.Sprintf("%o %s %s", f.Mode.Perm(), f.Owner, f.Group)
	v.writes = append(v.writes, f)
	return nil
}

func (v *vps) Close() error { return nil }

func (v *vps) file() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return string(v.files[cfgPath])
}

// service is the state of the service and the port Hysteria listens on.
func (v *vps) service() (string, int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.state, v.port
}

// has reports whether the server has the file.
func (v *vps) has(p string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.files[p]
	return ok
}

type conn struct{ v *vps }

func (c conn) Connect(context.Context, int64) (remote.Executor, error) { return c.v, nil }

type harness struct {
	t      *testing.T
	db     *sqlite.DB
	keys   *secrets.Keyring
	app    *Applier
	stop   func() // stops the controller of app
	v      *vps
	server int64
}

func newHarness(t *testing.T) *harness {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{4}, 32)})
	srv := model.Server{Name: "s", Host: "192.0.2.50", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	db.CreateServer(ctx, &srv, nil)
	db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: cfgPath, Unit: "hysteria-server.service", User: "hysteria", Version: "v2.12.3", Managed: true, At: time.Now()})
	s := sha256.Sum256([]byte(deployed))
	c := model.ServerConfig{ServerID: srv.ID, SHA256: hex.EncodeToString(s[:]), Source: model.ConfigDeploy, At: time.Now()}
	db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(deployed), model.ConfigContext(srv.ID, rev)) })

	v := newVPS()
	h := &harness{t: t, db: db, keys: keys, v: v, server: srv.ID}
	h.app, h.stop = h.controller(db, conn{v})
	return h
}

// controller starts a controller process on the harness's database (st
// is how it sees the database) with connections from c. stop ends it as
// a dying process: the running step sees its context cancelled.
func (h *harness) controller(st interface {
	Store
	store.Jobs
}, c jobs.Connector) (app *Applier, stop func()) {
	eng := jobs.New(st, h.keys, redact.New(), c, nil)
	eng.Poll = 10 * time.Millisecond
	app = New(Deps{Store: st, Keys: h.keys, Jobs: eng, VerifyTimeout: 200 * time.Millisecond, Poll: 10 * time.Millisecond})
	eng.Register(app.Kind())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { eng.Run(ctx); close(done) }()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	h.t.Cleanup(stop)
	return app, stop
}

// edit is the editor's text: the current config masked, changed by fn.
func (h *harness) edit(fn func(string) string) string {
	v, err := (&Editor{Store: h.db, Keys: h.keys}).Open(context.Background(), h.server)
	if err != nil {
		h.t.Fatal(err)
	}
	return fn(v.YAML)
}

func (h *harness) wait(j model.Job) (model.Job, string) {
	h.t.Helper()
	for i := 0; i < 500 && !j.State.Terminal(); i++ {
		time.Sleep(10 * time.Millisecond)
		j, _ = h.db.JobByID(context.Background(), j.ID)
	}
	time.Sleep(20 * time.Millisecond) // the Finished hook
	ls, _ := h.db.JobLogs(context.Background(), j.ID, 0, 0)
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Message + "\n")
	}
	return j, b.String()
}

func (h *harness) state() model.ServerState {
	s, _ := h.db.ServerByID(context.Background(), h.server)
	return s.State
}

func TestApply(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	text := h.edit(func(s string) string { return strings.Replace(s, "listen: :443", "listen: :8443", 1) })
	j, err := h.app.Submit(ctx, h.server, 1, text, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(j.Params), "fake-apply") {
		t.Fatalf("secret in params: %s", j.Params)
	}
	j, log := h.wait(j)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	c, _ := hyconfig.ParseServer([]byte(h.v.file()))
	if c.Listen != ":8443" || c.Auth.Password != "fake-apply-auth-pass" || h.v.state != "active" || h.v.port != 8443 {
		t.Fatalf("server: %s %d\n%s", h.v.state, h.v.port, h.v.file())
	}
	if _, ok := h.v.files[cfgPath+Backup]; ok {
		t.Fatal("backup left behind")
	}
	if len(h.v.writes) != 1 || h.v.writes[0].Mode != 0o640 || h.v.writes[0].Group != "hysteria" {
		t.Fatalf("written with %+v", h.v.writes)
	}
	cur, _ := h.db.CurrentConfig(ctx, h.server)
	if cur.Revision != 2 || cur.Source != model.ConfigEdit || cur.Meta.Ports != "8443" || cur.Meta.TLS != "acme" || cur.JobID != j.ID {
		t.Fatalf("%+v", cur)
	}
	if strings.Contains(log, "fake-apply-auth-pass") || h.state() != model.StateHealthy {
		t.Fatalf("state %s\n%s", h.state(), log)
	}

	// The same text again: nothing to apply.
	var fe *model.FieldError
	text = h.edit(func(s string) string { return s })
	if _, err := h.app.Submit(ctx, h.server, 2, text, nil, 0); !errors.As(err, &fe) || !strings.Contains(fe.Msg, "Изменений нет") {
		t.Fatalf("%v", err)
	}
	// From an old revision: the editor is stale.
	var stale *StaleError
	if _, err := h.app.Submit(ctx, h.server, 1, text, nil, 0); !errors.As(err, &stale) || stale.Current != 2 {
		t.Fatalf("%v", err)
	}
}

func TestInvalidConfigRefusedBeforeInstall(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	text := h.edit(func(s string) string { return strings.Replace(s, "listen: :443", "listen: :99999", 1) })
	var fe *model.FieldError
	if _, err := h.app.Submit(ctx, h.server, 1, text, nil, 0); !errors.As(err, &fe) || !strings.Contains(fe.Msg, "listen") {
		t.Fatalf("%v", err)
	}
	// A job that gets an invalid config anyway (queued by an older
	// controller, say) stops before writing anything.
	bad := strings.Replace(deployed, "listen: :443", "listen: :99999", 1)
	s := sha256.Sum256([]byte(bad))
	cur, _ := h.db.CurrentConfig(ctx, h.server)
	j, err := h.app.x.Jobs.Submit(ctx, JobKind, h.server, Params{Base: 1, BaseSHA256: cur.SHA256, SHA256: hex.EncodeToString(s[:])}, map[string]string{SecretConfig: bad}, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, _ = h.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "validate" || len(h.v.writes) != 0 || h.v.file() != deployed {
		t.Fatalf("%s at %s: %s", j.State, j.CurrentStep, j.ErrorMessage)
	}
	for _, c := range h.v.cmds {
		if strings.HasPrefix(c, "systemctl restart") || strings.HasPrefix(c, "cp ") {
			t.Fatalf("ran %q", c)
		}
	}
}

func TestServiceFailsRollsBack(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	text := h.edit(func(s string) string { return s + "crash: true\n" })
	j, err := h.app.Submit(ctx, h.server, 1, text, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "verify" || !strings.Contains(j.ErrorMessage, "Прежний конфиг возвращается") {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if h.v.file() != deployed || h.v.state != "active" || h.v.port != 443 {
		t.Fatalf("not rolled back: %s %d\n%s", h.v.state, h.v.port, h.v.file())
	}
	if _, ok := h.v.files[cfgPath+Backup]; ok {
		t.Fatal("backup left after the rollback")
	}
	if !strings.Contains(log, "FATAL failed to load config") || strings.Contains(log, "fake-apply-auth-pass") || !strings.Contains(log, "Прежний конфиг возвращён") {
		t.Fatalf("log:\n%s", log)
	}
	if cur, _ := h.db.CurrentConfig(ctx, h.server); cur.Revision != 1 {
		t.Fatalf("a failed config was saved as revision %d", cur.Revision)
	}
	if h.state() != model.StateHealthy {
		t.Fatalf("state %s after a clean rollback", h.state())
	}
}

func TestConfigChangedOnServer(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	text := h.edit(func(s string) string { return strings.Replace(s, "listen: :443", "listen: :8443", 1) })
	h.v.files[cfgPath] = []byte(deployed + "# edited over SSH\n")
	j, err := h.app.Submit(ctx, h.server, 1, text, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, _ = h.wait(j)
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "Импортируйте сервер заново") || len(h.v.writes) != 0 {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
}

// A port change opens the new port before the restart and closes the one
// HyRoute opened earlier after the new config works; the admin's rules
// stay, and a failed apply closes what it opened.
func TestApplyFirewall(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.v.mu.Lock()
	h.v.ufw = map[string]bool{"443/udp": true} // the admin's
	h.v.mu.Unlock()
	fwOf := func() model.Firewall {
		in, _ := h.db.Installation(ctx, h.server)
		return in.Firewall
	}
	apply := func(base int, fn func(string) string) (model.Job, string) {
		t.Helper()
		j, err := h.app.Submit(ctx, h.server, base, h.edit(fn), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		return h.wait(j)
	}

	j, log := apply(1, func(s string) string { return strings.Replace(s, "listen: :443", "listen: :8443", 1) })
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if r := h.v.rules(); !slices.Equal(r, []string{"443/udp", "8443/udp"}) {
		t.Fatalf("rules %q\n%s", r, log)
	}
	if fw := fwOf(); fw != (model.Firewall{Tool: "ufw", Ports: "8443/udp"}) {
		t.Fatalf("recorded %+v", fw)
	}
	// ACME ports of the old config were there already: not touched.
	if slices.ContainsFunc(h.v.cmds, func(c string) bool { return strings.Contains(c, "/tcp") }) {
		t.Fatalf("ran %q", h.v.cmds)
	}

	// A failed apply to 9443 closes 9443 again.
	j, log = apply(2, func(s string) string {
		return strings.Replace(s, "listen: :8443", "listen: :9443", 1) + "crash: true\n"
	})
	if j.State != model.JobFailed || !slices.Contains(h.v.cmds, "ufw allow 9443/udp") {
		t.Fatalf("%s\n%s", j.State, log)
	}
	if r := h.v.rules(); !slices.Equal(r, []string{"443/udp", "8443/udp"}) {
		t.Fatalf("rules after the rollback %q\n%s", r, log)
	}
	if fw := fwOf(); fw != (model.Firewall{Tool: "ufw", Ports: "8443/udp"}) {
		t.Fatalf("recorded %+v", fw)
	}

	// Back to 443: the admin's rule serves it, HyRoute's 8443 is closed.
	j, log = apply(2, func(s string) string { return strings.Replace(s, "listen: :8443", "listen: :443", 1) })
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if r := h.v.rules(); !slices.Equal(r, []string{"443/udp"}) {
		t.Fatalf("rules %q\n%s", r, log)
	}
	if fw := fwOf(); fw != (model.Firewall{Tool: "ufw"}) {
		t.Fatalf("recorded %+v", fw)
	}
}

// Without ss the port cannot be checked: a service that stays active is
// trusted, as in the deploy, both for an edit and for a rollback to a
// revision; a config Hysteria rejects is still rolled back.
func TestApplyWithoutSS(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.v.mu.Lock()
	h.v.noSS = true
	h.v.mu.Unlock()
	j, err := h.app.Submit(ctx, h.server, 1, h.edit(func(s string) string { return strings.Replace(s, "listen: :443", "listen: :8443", 1) }), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if st, port := h.v.service(); j.State != model.JobCompleted || !strings.Contains(log, "нет ss") || st != "active" || port != 8443 {
		t.Fatalf("%s: %s, service %s %d\n%s", j.State, j.ErrorMessage, st, port, log)
	}

	j, err = h.app.Rollback(ctx, h.server, 2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j, log = h.wait(j); j.State != model.JobCompleted || h.v.file() != deployed {
		t.Fatalf("rollback to revision 1: %s: %s\n%s", j.State, j.ErrorMessage, log)
	}

	j, err = h.app.Submit(ctx, h.server, 3, h.edit(func(s string) string { return s + "crash: true\n" }), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log = h.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "verify" {
		t.Fatalf("a failing config passed: %s at %s\n%s", j.State, j.CurrentStep, log)
	}
	h.back(log)
}
