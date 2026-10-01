package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// serverDialer records which servers were dialed.
type serverDialer struct {
	mu    sync.Mutex
	dials []int64
}

func (d *serverDialer) Connect(_ context.Context, id int64) (remote.Executor, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials = append(d.dials, id)
	return &link{}, nil
}

func (d *serverDialer) count(id int64) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, s := range d.dials {
		if s == id {
			n++
		}
	}
	return n
}

// on is a step or an Undo that runs a command on server *id of the job.
func on(id *int64, c *counters, name string) func(context.Context, *Env) error {
	return func(ctx context.Context, env *Env) error {
		ex, err := env.ExecOn(ctx, *id)
		if err != nil {
			return err
		}
		c.inc(name)
		_, err = ex.Run(ctx, remote.Cmd{Args: []string{name}})
		return err
	}
}

// A job on two servers keeps both busy while it runs and has a
// connection to each; it shows in the history of both.
func TestJobOnTwoServers(t *testing.T) {
	release := make(chan struct{})
	var c counters
	var a, b, other int64
	k := simpleKind("pair",
		Step{Name: "first", Phase: model.JobConfiguring, Safe: true, Run: on(&a, &c, "a")},
		Step{Name: "second", Phase: model.JobInstalling, Run: func(ctx context.Context, env *Env) error {
			if err := on(&b, &c, "b")(ctx, env); err != nil {
				return err
			}
			if _, err := env.ExecOn(ctx, other); err == nil {
				return errors.New("a server outside the job was reached")
			}
			<-release
			return nil
		}},
	)
	h := newHarness(t, nil, k, workKind(nil))
	d := &serverDialer{}
	h.eng.Connect = d
	a, b, other = h.newServer(), h.newServer(), h.newServer()
	h.start()
	ctx := context.Background()
	j, err := h.eng.SubmitOn(ctx, "pair", []int64{a, b}, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j.ServerID != a || !slices.Equal(j.Servers, []int64{b}) {
		t.Fatalf("servers %d %v", j.ServerID, j.Servers)
	}
	h.wait(j.ID, model.JobInstalling)
	for _, s := range []int64{a, b} {
		if _, err := h.eng.Submit(ctx, "demo", s, nil, nil, 0); !errors.Is(err, ErrBusy) {
			t.Fatalf("second job on server %d: %v", s, err)
		}
		if err := h.db.DeleteServer(ctx, s); !errors.Is(err, store.ErrBusy) {
			t.Fatalf("delete server %d: %v", s, err)
		}
		js, _ := h.db.ListJobs(ctx, model.JobFilter{ServerID: s})
		if len(js) != 1 || js[0].ID != j.ID || !slices.Equal(js[0].Servers, []int64{b}) {
			t.Fatalf("history of %d: %+v", s, js)
		}
	}
	if _, err := h.eng.Submit(ctx, "demo", other, nil, nil, 0); err != nil {
		t.Fatalf("a job on another server: %v", err)
	}
	close(release)
	h.wait(j.ID, model.JobCompleted)
	if d.count(a) != 1 || d.count(b) != 1 || d.count(other) != 0 || c.get("a") != 1 || c.get("b") != 1 {
		t.Fatalf("dials %v, runs %v", d.dials, c.m)
	}
}

// A failed step on one server rolls back the steps on both, over new
// connections.
func TestRollbackOnTwoServers(t *testing.T) {
	var c counters
	var a, b int64
	k := simpleKind("pair",
		Step{Name: "on a", Phase: model.JobConfiguring, Run: on(&a, &c, "a"), Undo: on(&a, &c, "undo a")},
		Step{Name: "on b", Phase: model.JobInstalling, Run: on(&b, &c, "b"), Undo: on(&b, &c, "undo b")},
		Step{Name: "start", Phase: model.JobStarting, Run: func(context.Context, *Env) error { return Fail("Не запустилось.", nil) }},
	)
	h := newHarness(t, nil, k)
	d := &serverDialer{}
	h.eng.Connect = d
	a, b = h.newServer(), h.newServer()
	h.start()
	j, err := h.eng.SubmitOn(context.Background(), "pair", []int64{a, b}, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	h.wait(j.ID, model.JobFailed)
	if c.get("undo a") != 1 || c.get("undo b") != 1 {
		t.Fatalf("undone %v", c.m)
	}
	if d.count(a) != 2 || d.count(b) != 2 {
		t.Fatalf("the rollback did not dial both servers again: %v", d.dials)
	}
}

// A restart in the middle of the rollback of a job on two servers: the
// new controller finishes it on both.
func TestRecoveryFinishesRollbackOnTwoServers(t *testing.T) {
	var c counters
	var a, b int64
	k := &Kind{
		Name: "pair",
		Steps: func(json.RawMessage) ([]Step, error) {
			return []Step{
				{Name: "on a", Phase: model.JobConfiguring, Run: on(&a, &c, "a"), Undo: on(&a, &c, "undo a")},
				{Name: "on b", Phase: model.JobInstalling, Run: on(&b, &c, "b"), Undo: on(&b, &c, "undo b")},
				{Name: "start", Phase: model.JobStarting, Run: func(context.Context, *Env) error { return nil }},
			}, nil
		},
		Recover: func(context.Context, *Env) (Resolution, error) { return ResolveRetry, nil },
	}
	h := newHarness(t, nil, k)
	d := &serverDialer{}
	h.eng.Connect = d
	a, b = h.newServer(), h.newServer()
	ctx := context.Background()
	j, err := h.eng.SubmitOn(ctx, "pair", []int64{a, b}, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := h.db.JobSteps(ctx, j.ID)
	for i, st := range []model.StepState{model.StepDone, model.StepDone, model.StepFailed} {
		rows[i].State = st
		h.db.UpdateJobStep(ctx, rows[i])
	}
	j.State, j.CurrentStep, j.LeaseOwner, j.LeaseUntil = model.JobRollingBack, "start", "dead-process", time.Now().Add(time.Minute)
	h.db.UpdateJob(ctx, j)
	h.start()
	h.wait(j.ID, model.JobFailed)
	if c.get("undo a") != 1 || c.get("undo b") != 1 || c.get("a") != 0 || c.get("b") != 0 {
		t.Fatalf("runs %v", c.m)
	}
	if d.count(a) != 1 || d.count(b) != 1 {
		t.Fatalf("dials %v", d.dials)
	}
}

// A failed job on two servers is retried only while it is the newest job
// of both.
func TestRetryOfJobOnTwoServers(t *testing.T) {
	h := newHarness(t, nil, workKind(nil))
	h.start()
	ctx := context.Background()
	a, b := h.newServer(), h.newServer()
	j, err := h.eng.SubmitOn(ctx, "demo", []int64{a, b}, failing, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	h.wait(j.ID, model.JobFailed)
	newer, _ := h.eng.Submit(ctx, "demo", b, nil, nil, 0)
	h.wait(newer.ID, model.JobCompleted)
	if _, err := h.eng.Retry(ctx, j.ID, 1); !errors.Is(err, ErrStale) {
		t.Fatalf("retry after a newer job on the second server: %v", err)
	}
	j2, _ := h.eng.SubmitOn(ctx, "demo", []int64{a, b}, failing, nil, 0)
	h.wait(j2.ID, model.JobFailed)
	if j2, err = h.eng.Retry(ctx, j2.ID, 1); err != nil {
		t.Fatalf("retry of the newest job of both: %v", err)
	}
	h.wait(j2.ID, model.JobFailed)
}

// Queued jobs that share a server never run together, whichever server
// they share.
func TestJobsSharingAServerTakeTurns(t *testing.T) {
	var running, most atomic.Int32
	work := Step{Name: "work", Phase: model.JobInstalling, Run: func(context.Context, *Env) error {
		n := running.Add(1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		time.Sleep(50 * time.Millisecond)
		running.Add(-1)
		return nil
	}}
	h := newHarness(t, nil, simpleKind("demo", work))
	ctx := context.Background()
	a, b := h.newServer(), h.newServer()
	pair, _ := h.eng.SubmitOn(ctx, "demo", []int64{a, b}, nil, nil, 0)
	pair.State = model.JobFailed
	h.db.UpdateJob(ctx, pair)
	single, err := h.eng.Submit(ctx, "demo", b, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	pair.State = model.JobQueued
	h.db.UpdateJob(ctx, pair)
	h.start()
	h.wait(pair.ID, model.JobCompleted)
	h.wait(single.ID, model.JobCompleted)
	if most.Load() != 1 {
		t.Fatalf("%d jobs on server %d at once", most.Load(), b)
	}
}
