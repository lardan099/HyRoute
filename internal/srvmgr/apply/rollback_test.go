package apply

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

var errDead = errors.New("the controller died")

// rigged is the server through a connection whose commands hook sees
// first: an error from it is what the command returns.
type rigged struct {
	*vps
	hook func(line string) error
}

func (r rigged) Run(ctx context.Context, cmd remote.Cmd) (remote.Result, error) {
	if err := r.hook(strings.Join(cmd.Args, " ")); err != nil {
		return remote.Result{}, err
	}
	return r.vps.Run(ctx, cmd)
}

type riggedConn struct{ r rigged }

func (c riggedConn) Connect(context.Context, int64) (remote.Executor, error) { return c.r, nil }

// dying is the database as a controller sees it that died when dead was
// set: nothing it writes after that lands.
type dying struct {
	*sqlite.DB
	dead *atomic.Bool
}

func (d dying) UpdateJob(ctx context.Context, j model.Job) error {
	if d.dead.Load() {
		return errDead
	}
	return d.DB.UpdateJob(ctx, j)
}

func (d dying) UpdateJobStep(ctx context.Context, s model.JobStep) error {
	if d.dead.Load() {
		return errDead
	}
	return d.DB.UpdateJobStep(ctx, s)
}

func (d dying) SetJobData(ctx context.Context, id int64, data map[string]string) error {
	if d.dead.Load() {
		return errDead
	}
	return d.DB.SetJobData(ctx, id, data)
}

func (d dying) AppendJobLog(ctx context.Context, l *model.JobLog) error {
	if d.dead.Load() {
		return errDead
	}
	return d.DB.AppendJobLog(ctx, l)
}

func (d dying) ClaimJob(ctx context.Context, id int64, owner string, until time.Time) (bool, error) {
	if d.dead.Load() {
		return false, errDead
	}
	return d.DB.ClaimJob(ctx, id, owner, until)
}

func (d dying) ExtendLease(ctx context.Context, id int64, owner string, until time.Time) error {
	if d.dead.Load() {
		return errDead
	}
	return d.DB.ExtendLease(ctx, id, owner, until)
}

func (d dying) SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error {
	if d.dead.Load() {
		return errDead
	}
	return d.DB.SetServerState(ctx, id, state, at)
}

func (d dying) SetFirewall(ctx context.Context, id int64, fw model.Firewall) error {
	if d.dead.Load() {
		return errDead
	}
	return d.DB.SetFirewall(ctx, id, fw)
}

func (d dying) AddConfig(ctx context.Context, c *model.ServerConfig, seal func(int) ([]byte, error)) error {
	if d.dead.Load() {
		return errDead
	}
	return d.DB.AddConfig(ctx, c, seal)
}

// back checks that the server runs the deployed config again, with no
// copy left behind.
func (h *harness) back(log string) {
	h.t.Helper()
	if st, port := h.v.service(); h.v.file() != deployed || st != "active" || port != 443 {
		h.t.Fatalf("the previous config is not back: %s %d\n%s\n%s", st, port, h.v.file(), log)
	}
	if h.v.has(cfgPath + Backup) {
		h.t.Fatalf("copy left behind\n%s", log)
	}
	if strings.Contains(log, "оставлен как есть") {
		h.t.Fatalf("the rollback found no copy:\n%s", log)
	}
}

// The controller dies in the middle of a rollback, after the config came
// back and before the service was restarted with it. The next controller
// finishes the rollback instead of applying the config again, and a retry
// after that rolls back to the previous config again.
func TestRollbackInterruptedByRestart(t *testing.T) {
	h := newHarness(t)
	h.stop() // this test runs its own controllers
	ctx := context.Background()
	var dead atomic.Bool
	var restarts atomic.Int32
	// The rollback's restart of the service is where the controller dies.
	first := rigged{h.v, func(line string) error {
		if dead.Load() {
			return errDead
		}
		if strings.HasPrefix(line, "systemctl restart") {
			if restarts.Add(1) == 2 {
				dead.Store(true)
				return errDead
			}
		}
		return nil
	}}
	app, stop := h.controller(dying{h.db, &dead}, riggedConn{first})
	j, err := app.Submit(ctx, h.server, 1, h.edit(func(s string) string { return s + "crash: true\n" }), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500 && !dead.Load(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	j, _ = h.db.JobByID(ctx, j.ID)
	if st, _ := h.v.service(); !dead.Load() || j.State != model.JobRollingBack || h.v.file() != deployed || st != "failed" {
		t.Fatalf("before the restart: dead %v, job %s, service %s\n%s", dead.Load(), j.State, st, h.v.file())
	}

	app, _ = h.controller(h.db, conn{h.v})
	j, log := h.wait(j)
	if j.State != model.JobFailed || !strings.Contains(log, "Откат продолжается") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	h.back(log)
	if n := len(h.v.writes); n != 1 {
		t.Fatalf("the config was written %d times: the recovery went forward\n%s", n, log)
	}
	if h.state() != model.StateHealthy {
		t.Fatalf("state %s after the rollback", h.state())
	}

	if j, err = app.x.Jobs.Retry(ctx, j.ID, 1); err != nil {
		t.Fatal(err)
	}
	j, log = h.wait(j)
	if j.State != model.JobFailed || j.Attempt != 2 || len(h.v.writes) != 2 {
		t.Fatalf("retry: %s attempt %d, %d writes: %s\n%s", j.State, j.Attempt, len(h.v.writes), j.ErrorMessage, log)
	}
	h.back(log)
}

// The service does not restart in the rollback (it fails once); a retry
// checks the server again and installs with a fresh copy of the previous
// config, so its rollback brings that config back.
func TestRetryAfterFailedRollback(t *testing.T) {
	h := newHarness(t)
	h.stop()
	ctx := context.Background()
	var restarts atomic.Int32
	app, _ := h.controller(h.db, riggedConn{rigged{h.v, func(line string) error {
		if strings.HasPrefix(line, "systemctl restart") {
			if restarts.Add(1) == 2 {
				return errors.New("connection reset by peer")
			}
		}
		return nil
	}}})
	j, err := app.Submit(ctx, h.server, 1, h.edit(func(s string) string { return s + "crash: true\n" }), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobFailed || !strings.Contains(log, "Откат не удался") || h.state() != model.StateNeedsAttention || h.v.file() != deployed {
		t.Fatalf("%s, server %s: %s\n%s", j.State, h.state(), j.ErrorMessage, log)
	}
	rows, _ := h.db.JobSteps(ctx, j.ID)
	if rows[2].Name != "prepare" || rows[2].State != model.StepDone {
		t.Fatalf("prepare is %+v: the retry would not start at the install", rows[2])
	}

	if j, err = app.x.Jobs.Retry(ctx, j.ID, 1); err != nil {
		t.Fatal(err)
	}
	j, log = h.wait(j)
	if j.State != model.JobFailed || j.Attempt != 2 {
		t.Fatalf("retry: %s attempt %d: %s\n%s", j.State, j.Attempt, j.ErrorMessage, log)
	}
	h.back(log)
	if h.state() != model.StateHealthy {
		t.Fatalf("state %s after a clean rollback", h.state())
	}
}

// The config fails and is rolled back; the admin then edits the file
// over SSH. A retry checks the file again and stops before writing: the
// edit stays, and nothing is rolled back.
func TestRetryChecksConfigAgain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	j, err := h.app.Submit(ctx, h.server, 1, h.edit(func(s string) string { return s + "crash: true\n" }), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "verify" {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	h.back(log)
	edited := deployed + "# edited over SSH\n"
	h.v.mu.Lock()
	h.v.files[cfgPath] = []byte(edited)
	h.v.mu.Unlock()

	if j, err = h.app.x.Jobs.Retry(ctx, j.ID, 1); err != nil {
		t.Fatal(err)
	}
	j, log = h.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "validate" || !strings.Contains(j.ErrorMessage, "Импортируйте сервер заново") {
		t.Fatalf("retry: %s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if h.v.file() != edited || len(h.v.writes) != 1 || strings.Contains(log, "Откат не удался") {
		t.Fatalf("the edit is gone (%d writes):\n%s\n%s", len(h.v.writes), h.v.file(), log)
	}
	if h.state() != model.StateHealthy {
		t.Fatalf("state %s", h.state())
	}
}
