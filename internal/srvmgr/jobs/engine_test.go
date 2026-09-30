package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// A fake secret made for these tests.
const fakeSecret = "fake-job-secret-Zq81"

type harness struct {
	t    *testing.T
	db   *sqlite.DB
	keys *secrets.Keyring
	eng  *Engine
	stop context.CancelFunc
	done chan struct{}
}

func newHarness(t *testing.T, db *sqlite.DB, kinds ...*Kind) *harness {
	t.Helper()
	if db == nil {
		var err error
		db, err = sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
	}
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{5}, 32)})
	h := &harness{t: t, db: db, keys: keys}
	h.eng = New(db, keys, redact.New(), nil, nil)
	h.eng.Poll = 20 * time.Millisecond
	for _, k := range kinds {
		h.eng.Register(k)
	}
	return h
}

func (h *harness) start() {
	ctx, cancel := context.WithCancel(context.Background())
	h.stop, h.done = cancel, make(chan struct{})
	go func() {
		h.eng.Run(ctx)
		close(h.done)
	}()
	h.t.Cleanup(h.kill)
}

// kill stops the engine as a dying process would: whatever runs is
// interrupted mid-step.
func (h *harness) kill() {
	if h.stop == nil {
		return
	}
	h.stop()
	<-h.done
	h.stop = nil
}

func (h *harness) wait(id int64, want ...model.JobState) model.Job {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := h.db.JobByID(context.Background(), id)
		if err != nil {
			h.t.Fatal(err)
		}
		for _, w := range want {
			if j.State == w {
				return j
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	j, _ := h.db.JobByID(context.Background(), id)
	h.t.Fatalf("job %d is %s, want %v (%s %s)", id, j.State, want, j.ErrorMessage, j.ErrorDetails)
	return j
}

func (h *harness) steps(id int64) []model.StepState {
	rows, _ := h.db.JobSteps(context.Background(), id)
	out := make([]model.StepState, len(rows))
	for i, r := range rows {
		out[i] = r.State
	}
	return out
}

func (h *harness) logText(id int64) string {
	ls, _ := h.db.JobLogs(context.Background(), id, 0, 0)
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Message + "\n")
	}
	return b.String()
}

// counters count runs per step name.
type counters struct {
	mu sync.Mutex
	m  map[string]int
}

func (c *counters) inc(n string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int{}
	}
	c.m[n]++
	return c.m[n]
}

func (c *counters) get(n string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[n]
}

func simpleKind(name string, steps ...Step) *Kind {
	return &Kind{Name: name, Steps: func(json.RawMessage) ([]Step, error) { return steps, nil }}
}

func TestSuccessfulJob(t *testing.T) {
	var c counters
	k := simpleKind("demo",
		Step{Name: "connect", Phase: model.JobConnecting, Run: func(_ context.Context, env *Env) error { c.inc("connect"); env.Set("arch", "amd64"); return nil }},
		Step{Name: "install", Phase: model.JobInstalling, Run: func(_ context.Context, env *Env) error {
			c.inc("install")
			if env.Get("arch") != "amd64" {
				return errors.New("data from the earlier step lost")
			}
			env.Logf("installed for %s", env.Get("arch"))
			return nil
		}},
		Step{Name: "verify", Phase: model.JobVerifying, Run: func(context.Context, *Env) error { c.inc("verify"); return nil }},
	)
	h := newHarness(t, nil, k)
	h.start()
	j, err := h.eng.Submit(context.Background(), "demo", 0, map[string]string{"x": "y"}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	j = h.wait(j.ID, model.JobCompleted)
	if j.Data["arch"] != "amd64" || j.StartedAt.IsZero() || j.FinishedAt.IsZero() || j.LeaseOwner != "" {
		t.Fatalf("%+v", j)
	}
	if got := h.steps(j.ID); got[0] != model.StepDone || got[2] != model.StepDone {
		t.Fatalf("steps %v", got)
	}
	if !strings.Contains(h.logText(j.ID), "installed for amd64") {
		t.Fatalf("log: %s", h.logText(j.ID))
	}
	if c.get("install") != 1 {
		t.Fatal("step ran twice")
	}
}

func TestFailureRetryFromSafeStep(t *testing.T) {
	var c counters
	var broken atomic.Bool
	broken.Store(true)
	k := simpleKind("demo",
		Step{Name: "connect", Phase: model.JobConnecting, Run: func(context.Context, *Env) error { c.inc("connect"); return nil }},
		Step{Name: "download", Phase: model.JobDownloading, Safe: true, Run: func(context.Context, *Env) error { c.inc("download"); return nil }},
		Step{Name: "install", Phase: model.JobInstalling, Run: func(context.Context, *Env) error {
			c.inc("install")
			if broken.Load() {
				return Fail("Не удалось установить Hysteria.", errors.New("disk full"))
			}
			return nil
		}},
		Step{Name: "verify", Phase: model.JobVerifying, Run: func(context.Context, *Env) error { c.inc("verify"); return nil }},
	)
	h := newHarness(t, nil, k)
	h.start()
	j, _ := h.eng.Submit(context.Background(), "demo", 0, nil, nil, 0)
	j = h.wait(j.ID, model.JobFailed)
	if j.ErrorMessage != "Не удалось установить Hysteria." || !strings.Contains(j.ErrorDetails, "disk full") || j.CurrentStep != "install" {
		t.Fatalf("%+v", j)
	}
	if got := h.steps(j.ID); got[2] != model.StepFailed || got[3] != model.StepPending {
		t.Fatalf("steps %v", got)
	}
	if _, err := h.eng.Retry(context.Background(), j.ID+100, 1); err == nil {
		t.Fatal("retry of a missing job")
	}
	broken.Store(false)
	if _, err := h.eng.Retry(context.Background(), j.ID, 1); err != nil {
		t.Fatal(err)
	}
	j = h.wait(j.ID, model.JobCompleted)
	if j.Attempt != 2 {
		t.Fatalf("attempt %d", j.Attempt)
	}
	// Resumed at the safe "download" step: connect did not run again.
	if c.get("connect") != 1 || c.get("download") != 2 || c.get("install") != 2 || c.get("verify") != 1 {
		t.Fatalf("runs %v", c.m)
	}
	if _, err := h.eng.Retry(context.Background(), j.ID, 1); !errors.Is(err, ErrNotRetryable) {
		t.Fatalf("retry of a completed job: %v", err)
	}
}

func TestRollbackOnStartFailure(t *testing.T) {
	var undone []string
	var mu sync.Mutex
	undo := func(name string) func(context.Context, *Env) error {
		return func(context.Context, *Env) error { mu.Lock(); undone = append(undone, name); mu.Unlock(); return nil }
	}
	k := simpleKind("demo",
		Step{Name: "install", Phase: model.JobInstalling, Run: func(context.Context, *Env) error { return nil }, Undo: undo("install")},
		Step{Name: "configure", Phase: model.JobConfiguring, Done: func(context.Context, *Env) (bool, error) { return true, nil }, Run: func(context.Context, *Env) error { return nil }, Undo: undo("configure")},
		Step{Name: "start", Phase: model.JobStarting, Run: func(context.Context, *Env) error {
			return Fail("Сервис не запустился.", errors.New("exit 1"))
		}},
	)
	h := newHarness(t, nil, k)
	h.start()
	j, _ := h.eng.Submit(context.Background(), "demo", 0, nil, nil, 0)
	j = h.wait(j.ID, model.JobFailed)
	got := h.steps(j.ID)
	// The skipped step was already in place: it is not ours to undo.
	if got[0] != model.StepRolledBack || got[1] != model.StepSkipped || got[2] != model.StepFailed {
		t.Fatalf("steps %v", got)
	}
	if len(undone) != 1 || undone[0] != "install" {
		t.Fatalf("undone %v", undone)
	}
	if !strings.Contains(h.logText(j.ID), "Откат") {
		t.Fatal("rollback not logged")
	}
}

// The controller dies in the middle of a step; the next process checks the
// actual state through Recover instead of continuing blindly.
func TestRecoveryAfterKilledProcess(t *testing.T) {
	var c counters
	entered := make(chan struct{}, 1)
	var recovered atomic.Int32
	mk := func(block bool) *Kind {
		return &Kind{
			Name: "demo",
			Steps: func(json.RawMessage) ([]Step, error) {
				return []Step{
					{Name: "connect", Phase: model.JobConnecting, Run: func(context.Context, *Env) error { c.inc("connect"); return nil }},
					{Name: "install", Phase: model.JobInstalling, Safe: true, Run: func(ctx context.Context, env *Env) error {
						if c.inc("install") == 1 && block {
							entered <- struct{}{}
							<-ctx.Done() // the process dies here
							return ctx.Err()
						}
						return nil
					}},
					{Name: "verify", Phase: model.JobVerifying, Run: func(context.Context, *Env) error { c.inc("verify"); return nil }},
				}, nil
			},
			Recover: func(ctx context.Context, env *Env) (Resolution, error) {
				recovered.Add(1)
				return ResolveRetry, nil
			},
		}
	}
	h1 := newHarness(t, nil, mk(true))
	h1.start()
	j, _ := h1.eng.Submit(context.Background(), "demo", 0, nil, nil, 0)
	<-entered
	h1.kill()
	j, _ = h1.db.JobByID(context.Background(), j.ID)
	if j.State != model.JobInstalling || j.LeaseOwner == "" {
		t.Fatalf("after the kill: %+v", j)
	}

	h2 := newHarness(t, h1.db, mk(false))
	h2.start()
	j = h2.wait(j.ID, model.JobCompleted)
	if recovered.Load() != 1 {
		t.Fatal("recovery check did not run")
	}
	if c.get("connect") != 1 || c.get("install") != 2 || c.get("verify") != 1 {
		t.Fatalf("runs %v", c.m)
	}
	if !strings.Contains(h2.logText(j.ID), "перезапущен") {
		t.Fatalf("log: %s", h2.logText(j.ID))
	}
}

func TestRecoveryWithoutCheckFails(t *testing.T) {
	entered := make(chan struct{}, 1)
	k := simpleKind("demo", Step{Name: "install", Phase: model.JobInstalling, Run: func(ctx context.Context, env *Env) error {
		entered <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}})
	h1 := newHarness(t, nil, k)
	h1.start()
	j, _ := h1.eng.Submit(context.Background(), "demo", 0, nil, nil, 0)
	<-entered
	h1.kill()
	h2 := newHarness(t, h1.db, simpleKind("demo", Step{Name: "install", Phase: model.JobInstalling, Run: func(context.Context, *Env) error { return nil }}))
	h2.start()
	j = h2.wait(j.ID, model.JobFailed)
	if !strings.Contains(j.ErrorMessage, "перезапуском controller") {
		t.Fatalf("%+v", j)
	}
}

func TestSecretsNotInJobLog(t *testing.T) {
	k := simpleKind("demo",
		Step{Name: "use", Phase: model.JobConfiguring, Run: func(_ context.Context, env *Env) error {
			env.Logf("configuring with auth %s", env.Secret("auth"))
			env.Warnf("echo from server: password=%s", env.Secret("auth"))
			return Fail("Сервер отклонил конфиг.", errors.New("hysteria: bad auth "+env.Secret("auth")))
		}},
	)
	h := newHarness(t, nil, k)
	h.start()
	j, err := h.eng.Submit(context.Background(), "demo", 0, nil, map[string]string{"auth": fakeSecret}, 0)
	if err != nil {
		t.Fatal(err)
	}
	j = h.wait(j.ID, model.JobFailed)
	if strings.Contains(h.logText(j.ID), fakeSecret) || strings.Contains(j.ErrorDetails, fakeSecret) {
		t.Fatalf("secret in the job log or error:\n%s\n%s", h.logText(j.ID), j.ErrorDetails)
	}
	rows, _ := h.db.JobSteps(context.Background(), j.ID)
	if strings.Contains(rows[0].Error, fakeSecret) {
		t.Fatal("secret in the step error")
	}
	if strings.Contains(string(j.Params), fakeSecret) {
		t.Fatal("secret in the params")
	}
	sealed, _ := h.db.JobSecret(context.Background(), j.ID)
	if bytes.Contains(sealed, []byte(fakeSecret)) {
		t.Fatal("secret not sealed")
	}
}

func TestOneJobPerServerAndEvents(t *testing.T) {
	release := make(chan struct{})
	k := simpleKind("demo", Step{Name: "wait", Phase: model.JobInstalling, Run: func(context.Context, *Env) error { <-release; return nil }})
	h := newHarness(t, nil, k)
	ctx := context.Background()
	srv := model.Server{Name: "s", Host: "h.example", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	if err := h.db.CreateServer(ctx, &srv, nil); err != nil {
		t.Fatal(err)
	}
	j1, err := h.eng.Submit(ctx, "demo", srv.ID, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.Submit(ctx, "demo", srv.ID, nil, nil, 0); !errors.Is(err, ErrBusy) {
		t.Fatalf("second job on a busy server: %v", err)
	}
	if _, err := h.eng.Submit(ctx, "nope", srv.ID, nil, nil, 0); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("unknown kind: %v", err)
	}
	evs, cancel := h.eng.Subscribe(j1.ID)
	defer cancel()
	h.start()
	close(release)
	h.wait(j1.ID, model.JobCompleted)
	var sawLog, sawDone bool
	timeout := time.After(2 * time.Second)
	for !(sawLog && sawDone) {
		select {
		case ev := <-evs:
			if ev.Type == "log" {
				sawLog = true
			}
			if ev.Type == "job" && ev.Job.State == model.JobCompleted {
				sawDone = true
			}
		case <-timeout:
			t.Fatalf("events: log %v done %v", sawLog, sawDone)
		}
	}
	if _, err := h.eng.Submit(ctx, "demo", srv.ID, nil, nil, 0); err != nil {
		t.Fatalf("new job after the first finished: %v", err)
	}
}
