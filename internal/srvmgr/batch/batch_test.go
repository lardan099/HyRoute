package batch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// gate is the work of the fake jobs: each waits until its server is let
// through, and the gate notes which servers ran at the same time.
type gate struct {
	mu      sync.Mutex
	open    map[int64]chan struct{}
	closed  map[chan struct{}]bool
	fail    map[int64]bool
	running map[int64]bool
	most    int
	// together are the servers that ran at once, each time one started.
	together [][]int64
	started  []int64
}

func newGate() *gate {
	return &gate{open: map[int64]chan struct{}{}, closed: map[chan struct{}]bool{}, fail: map[int64]bool{}, running: map[int64]bool{}}
}

func (g *gate) ch(id int64) chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.open[id]
	if !ok {
		c = make(chan struct{})
		g.open[id] = c
	}
	return c
}

// let lets the jobs of a server finish (with a failure if it fails), now
// and later.
func (g *gate) let(id int64) {
	c := g.ch(id)
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed[c] {
		g.closed[c] = true
		close(c)
	}
}

// hold makes the next job of a server wait again.
func (g *gate) hold(id int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.open[id] = make(chan struct{})
}

func (g *gate) setFail(id int64, fail bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fail[id] = fail
}

// seen is what ran: the servers in the order their jobs started, and
// the most that ran at once.
func (g *gate) seen() (started []int64, most int, together [][]int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.started), g.most, slices.Clone(g.together)
}

func (g *gate) enter(id int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.running[id] = true
	g.started = append(g.started, id)
	var now []int64
	for s := range g.running {
		now = append(now, s)
	}
	slices.Sort(now)
	g.together = append(g.together, now)
	g.most = max(g.most, len(now))
}

func (g *gate) leave(id int64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.running, id)
}

func (g *gate) isRunning(id int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.running[id]
}

// kind is the fake job of the tuning action: no server is touched.
func (g *gate) kind() *jobs.Kind {
	return &jobs.Kind{Name: JobKind(model.BatchTuning),
		Steps: func(json.RawMessage) ([]jobs.Step, error) {
			return []jobs.Step{{Name: "work", Phase: model.JobConfiguring, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error {
				g.enter(env.ServerID)
				defer g.leave(env.ServerID)
				select {
				case <-g.ch(env.ServerID):
				case <-ctx.Done():
					return ctx.Err()
				}
				g.mu.Lock()
				fail := g.fail[env.ServerID]
				g.mu.Unlock()
				if fail {
					return jobs.Fail("Не удалось.", nil)
				}
				return nil
			}}}, nil
		},
		Recover: func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
	}
}

// queuer queues the fake job; some servers have nothing to change or
// refuse the action.
type queuer struct {
	eng       *jobs.Engine
	mu        sync.Mutex
	unchanged map[int64]bool
	refuse    map[int64]bool
	calls     []int64
}

func (q *queuer) set(m map[int64]bool, id int64, v bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	m[id] = v
}

func (q *queuer) count() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.calls)
}

func (q *queuer) Queue(ctx context.Context, b model.Batch, server, actor int64) (model.Job, string, error) {
	q.mu.Lock()
	q.calls = append(q.calls, server)
	un, ref := q.unchanged[server], q.refuse[server]
	q.mu.Unlock()
	if un {
		return model.Job{}, "", &Unchanged{"Изменений нет."}
	}
	if ref {
		return model.Job{}, "", &model.FieldError{Field: "config", Msg: "Конфиг не разобрать."}
	}
	j, err := q.eng.Submit(ctx, JobKind(b.Action), server, struct{}{}, nil, actor)
	return j, "", err
}

type harness struct {
	t      *testing.T
	db     *sqlite.DB
	keys   *secrets.Keyring
	gate   *gate
	q      *queuer
	eng    *jobs.Engine
	run    *Runner
	owner  int64
	stops  []func()
	engCtx context.CancelFunc
	engEnd chan struct{}
	runCtx context.CancelFunc
	runEnd chan struct{}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{5}, 32)})
	h := &harness{t: t, db: db, keys: keys, gate: newGate()}
	h.owner = h.user("owner", model.RoleOwner, model.ScopeAll)
	h.start()
	t.Cleanup(h.kill)
	return h
}

// start runs a new engine and a new runner on the database, as a
// controller process does.
func (h *harness) start() {
	h.eng = jobs.New(h.db, h.keys, redact.New(), nil, nil)
	h.eng.Poll, h.eng.Workers = 10*time.Millisecond, 20
	h.eng.Register(h.gate.kind())
	if h.q == nil {
		h.q = &queuer{unchanged: map[int64]bool{}, refuse: map[int64]bool{}}
	}
	h.q.eng = h.eng
	h.run = New(h.db, h.q, nil)
	h.run.Poll = 10 * time.Millisecond
	h.eng.OnEnd = h.run.JobEnded
	ctx, cancel := context.WithCancel(context.Background())
	h.engCtx, h.engEnd = cancel, make(chan struct{})
	go func() { h.eng.Run(ctx); close(h.engEnd) }()
	rctx, rcancel := context.WithCancel(context.Background())
	h.runCtx, h.runEnd = rcancel, make(chan struct{})
	go func() { h.run.Run(rctx); close(h.runEnd) }()
}

// kill stops the runner and the engine as a dying process would.
func (h *harness) kill() {
	if h.runCtx == nil {
		return
	}
	h.runCtx()
	<-h.runEnd
	h.engCtx()
	<-h.engEnd
	h.runCtx = nil
}

func (h *harness) user(name string, role model.Role, sc model.Scope) int64 {
	h.t.Helper()
	u := model.User{Username: name, PasswordHash: "x", Role: role, Scope: sc, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := h.db.CreateUser(context.Background(), &u); err != nil {
		h.t.Fatal(err)
	}
	return u.ID
}

func (h *harness) servers(names ...string) []int64 {
	h.t.Helper()
	var ids []int64
	for _, n := range names {
		s := model.Server{Name: n, Tags: []string{n}, Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateHealthy}
		if err := h.db.CreateServer(context.Background(), &s, nil); err != nil {
			h.t.Fatal(err)
		}
		ids = append(ids, s.ID)
	}
	return ids
}

func (h *harness) create(by int64, parallel int, servers ...int64) model.Batch {
	h.t.Helper()
	b := model.Batch{Action: model.BatchTuning, Params: json.RawMessage(`{"keys":["net.core.rmem_max"]}`), Parallel: parallel, CreatedBy: by}
	for _, s := range servers {
		b.Items = append(b.Items, model.BatchItem{ServerID: s})
	}
	b, err := h.run.Create(context.Background(), b)
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

func (h *harness) batch(id int64) model.Batch {
	b, err := h.db.BatchByID(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

// wait waits until ok holds for the batch.
func (h *harness) wait(id int64, what string, ok func(b model.Batch) bool) model.Batch {
	h.t.Helper()
	for i := 0; i < 1000; i++ {
		if b := h.batch(id); ok(b) {
			return b
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("batch %d: never %s: %+v", id, what, h.batch(id))
	return model.Batch{}
}

func (h *harness) waitState(id int64, s model.BatchState) model.Batch {
	h.t.Helper()
	return h.wait(id, string(s), func(b model.Batch) bool { return b.State == s })
}

// waitRunning waits until the jobs of the servers run.
func (h *harness) waitRunning(ids ...int64) {
	h.t.Helper()
	for i := 0; i < 1000; i++ {
		all := true
		for _, id := range ids {
			all = all && h.gate.isRunning(id)
		}
		if all {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("jobs of %v never ran (started %v)", ids, h.started())
}

func (h *harness) started() []int64    { s, _, _ := h.gate.seen(); return s }
func (h *harness) most() int           { _, m, _ := h.gate.seen(); return m }
func (h *harness) together() [][]int64 { _, _, t := h.gate.seen(); return t }

// settle gives the runner time to start what it would.
func (h *harness) settle() { time.Sleep(100 * time.Millisecond) }

func states(b model.Batch) []model.BatchItemState {
	var out []model.BatchItemState
	for _, it := range b.Items {
		out = append(out, it.State)
	}
	return out
}

// A canary that fails starts no other job: the rest are skipped and the
// batch has failed.
func TestCanaryFailureStopsBatch(t *testing.T) {
	h := newHarness(t)
	ids := h.servers("a", "b", "c", "d")
	b := h.create(h.owner, 3, ids...)
	h.waitRunning(ids[0])
	h.settle()
	if len(h.started()) != 1 {
		t.Fatalf("started with the canary: %v", h.started())
	}
	h.gate.setFail(ids[0], true)
	h.gate.let(ids[0])
	got := h.waitState(b.ID, model.BatchFailed)
	if !slices.Equal(states(got), []model.BatchItemState{model.ItemFailed, model.ItemSkipped, model.ItemSkipped, model.ItemSkipped}) ||
		got.Stop != model.StopFailed || !got.Items[0].Canary || got.Items[0].Message != "Не удалось." || got.FinishedAt.IsZero() {
		t.Fatalf("%+v", got)
	}
	h.settle()
	if len(h.started()) != 1 || h.q.count() != 1 {
		t.Fatalf("other jobs: %v %v", h.started(), h.q.count())
	}
}

// After the canary, at most Parallel jobs of the batch run at once; one
// that changes nothing does not count as the canary.
func TestParallelLimit(t *testing.T) {
	h := newHarness(t)
	ids := h.servers("a", "b", "c", "d", "e", "f", "g", "h")
	h.q.set(h.q.unchanged, ids[0], true)
	b := h.create(h.owner, 3, ids...)
	h.waitRunning(ids[1])
	h.settle()
	if got := h.batch(b.ID); got.Items[0].State != model.ItemUnchanged || got.Items[0].Canary || !got.Items[1].Canary || len(h.started()) != 1 {
		t.Fatalf("canary: %+v %v", got.Items, h.started())
	}
	h.gate.let(ids[1])
	h.waitRunning(ids[2], ids[3], ids[4])
	h.settle()
	if h.most() != 3 || len(h.started()) != 4 {
		t.Fatalf("most %d, started %v", h.most(), h.started())
	}
	for _, id := range ids[2:] {
		h.gate.let(id)
	}
	got := h.waitState(b.ID, model.BatchCompleted)
	if h.most() != 3 || len(h.started()) != 7 || got.Stop != model.StopNone {
		t.Fatalf("most %d, started %v, %+v", h.most(), h.started(), got)
	}
	for _, it := range got.Items[1:] {
		if it.State != model.ItemCompleted || it.JobID == 0 {
			t.Fatalf("%+v", it)
		}
	}
}

// The servers of one cascade never run jobs of batches at the same time,
// also when they are in two batches.
func TestCascadeNotAtOnce(t *testing.T) {
	h := newHarness(t)
	ids := h.servers("c", "entry", "relay", "exit", "x")
	chain := model.Chain{Name: "k", Nodes: []int64{ids[1], ids[2], ids[3]}, Links: []model.ChainLink{{}, {}}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := h.db.CreateChain(context.Background(), &chain, nil); err != nil {
		t.Fatal(err)
	}
	b := h.create(h.owner, 10, ids[0], ids[1], ids[2], ids[4])
	other := h.create(h.owner, 10, ids[3])
	h.waitRunning(ids[0])
	h.gate.let(ids[0])
	// Each round lets every running job finish.
	for i := 0; i < 20 && (!h.batch(b.ID).State.Terminal() || !h.batch(other.ID).State.Terminal()); i++ {
		h.settle()
		for _, id := range ids[1:] {
			if h.gate.isRunning(id) {
				h.gate.let(id)
			}
		}
	}
	h.waitState(b.ID, model.BatchCompleted)
	h.waitState(other.ID, model.BatchCompleted)
	chained := map[int64]bool{ids[1]: true, ids[2]: true, ids[3]: true}
	for _, now := range h.together() {
		n := 0
		for _, s := range now {
			if chained[s] {
				n++
			}
		}
		if n > 1 {
			t.Fatalf("cascade servers at once: %v (all: %v)", now, h.together())
		}
	}
	if len(h.started()) != 5 {
		t.Fatalf("started %v", h.started())
	}
}

// Stopping a batch skips what has not started and leaves the running
// jobs alone: they finish, and the batch ends stopped.
func TestStopLeavesRunningJobs(t *testing.T) {
	h := newHarness(t)
	ids := h.servers("a", "b", "c", "d", "e")
	b := h.create(h.owner, 2, ids...)
	h.waitRunning(ids[0])
	h.gate.let(ids[0])
	h.waitRunning(ids[1], ids[2])
	got, err := h.run.Stop(context.Background(), b.ID, h.owner)
	if err != nil || got.State != model.BatchStopping || got.Stop != model.StopUser || got.StoppedBy != h.owner {
		t.Fatalf("%+v %v", got, err)
	}
	if !slices.Equal(states(got), []model.BatchItemState{model.ItemCompleted, model.ItemRunning, model.ItemRunning, model.ItemSkipped, model.ItemSkipped}) {
		t.Fatalf("%v", states(got))
	}
	if _, err := h.run.Stop(context.Background(), b.ID, h.owner); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("stop twice: %v", err)
	}
	h.settle()
	if !h.gate.isRunning(ids[1]) || !h.gate.isRunning(ids[2]) || len(h.started()) != 3 {
		t.Fatalf("the running jobs: %v", h.started())
	}
	h.gate.let(ids[1])
	h.gate.let(ids[2])
	got = h.waitState(b.ID, model.BatchStopped)
	if !slices.Equal(states(got), []model.BatchItemState{model.ItemCompleted, model.ItemCompleted, model.ItemCompleted, model.ItemSkipped, model.ItemSkipped}) {
		t.Fatalf("%v", states(got))
	}
	for _, j := range []int64{got.Items[1].JobID, got.Items[2].JobID} {
		if job, _ := h.db.JobByID(context.Background(), j); job.State != model.JobCompleted {
			t.Fatalf("job %d: %s", j, job.State)
		}
	}
}

// «Повторить неудачные» is a new batch over the failed and skipped
// servers, the canary first again; a batch is retried once, and only
// when it has ended.
func TestRetryFailed(t *testing.T) {
	h := newHarness(t)
	ids := h.servers("a", "b", "c", "d")
	h.q.set(h.q.refuse, ids[2], true)
	b := h.create(h.owner, 1, ids...)
	if _, err := h.run.Retry(context.Background(), b.ID, h.owner); !errors.Is(err, ErrNotFinished) {
		t.Fatalf("running: %v", err)
	}
	h.waitRunning(ids[0])
	h.gate.let(ids[0])
	h.waitRunning(ids[1])
	h.gate.setFail(ids[1], true)
	h.gate.let(ids[1])
	got := h.waitState(b.ID, model.BatchFailed)
	if !slices.Equal(states(got), []model.BatchItemState{model.ItemCompleted, model.ItemFailed, model.ItemSkipped, model.ItemSkipped}) {
		t.Fatalf("%v", states(got))
	}

	h.gate.setFail(ids[1], false)
	h.gate.hold(ids[1])
	again, err := h.run.Retry(context.Background(), b.ID, h.owner)
	if err != nil || again.RetryOf != b.ID || !slices.Equal(again.Servers(), ids[1:]) || again.Parallel != 1 || again.Action != b.Action {
		t.Fatalf("%+v %v", again, err)
	}
	if _, err := h.run.Retry(context.Background(), b.ID, h.owner); !errors.Is(err, ErrRetried) {
		t.Fatalf("twice: %v", err)
	}
	if first := h.batch(b.ID); first.RetriedBy != again.ID {
		t.Fatalf("retried by %d", first.RetriedBy)
	}
	// b is the canary again; c refuses the action: a failure that stops
	// the batch before d.
	h.waitRunning(ids[1])
	h.gate.let(ids[1])
	got = h.waitState(again.ID, model.BatchFailed)
	if !slices.Equal(states(got), []model.BatchItemState{model.ItemCompleted, model.ItemFailed, model.ItemSkipped}) || got.Items[1].Message != "Конфиг не разобрать." || got.Items[1].JobID != 0 {
		t.Fatalf("%+v", got.Items)
	}
	h.q.set(h.q.refuse, ids[2], false)
	third, err := h.run.Retry(context.Background(), again.ID, h.owner)
	if err != nil || !slices.Equal(third.Servers(), ids[2:]) {
		t.Fatalf("%+v %v", third, err)
	}
	h.waitRunning(ids[2])
	h.gate.let(ids[2])
	h.waitRunning(ids[3])
	h.gate.let(ids[3])
	h.waitState(third.ID, model.BatchCompleted)
	if _, err := h.run.Retry(context.Background(), third.ID, h.owner); !errors.Is(err, ErrNothingToRetry) {
		t.Fatalf("nothing: %v", err)
	}
}

// A batch in progress goes on after a controller restart: the job the
// restart cut short is recovered by the engine, and the new runner starts
// the rest from the database. An item recorded as starting finds its job
// if it was queued, and starts again if not.
func TestResumeAfterRestart(t *testing.T) {
	h := newHarness(t)
	ids := h.servers("a", "b", "c", "d")
	b := h.create(h.owner, 3, ids[0], ids[1])
	h.waitRunning(ids[0])
	h.kill()
	if got := h.batch(b.ID); got.State != model.BatchRunning || got.Items[0].State != model.ItemRunning {
		t.Fatalf("%+v", got)
	}

	// Two items a restart caught between the record and the job: c's job
	// was queued, d's was not.
	other := h.create(h.owner, 3, ids[2], ids[3])
	ctx := context.Background()
	j, err := h.eng.Submit(ctx, JobKind(model.BatchTuning), ids[2], struct{}{}, nil, h.owner)
	if err != nil {
		t.Fatal(err)
	}
	other = h.batch(other.ID)
	at := j.CreatedAt.Add(-time.Second)
	other.Items[0].State, other.Items[0].At = model.ItemStarting, at
	other.Items[1].State, other.Items[1].At = model.ItemStarting, at
	if err := h.db.SaveBatch(ctx, other); err != nil {
		t.Fatal(err)
	}

	h.start()
	h.waitRunning(ids[0])
	h.gate.let(ids[0])
	h.waitRunning(ids[1])
	h.gate.let(ids[1])
	got := h.waitState(b.ID, model.BatchCompleted)
	if got.Items[0].JobID == 0 || got.Items[1].State != model.ItemCompleted {
		t.Fatalf("%+v", got.Items)
	}
	h.waitRunning(ids[2])
	if adopted := h.batch(other.ID); adopted.Items[0].JobID != j.ID {
		t.Fatalf("c: %+v", adopted.Items[0])
	}
	h.gate.let(ids[2])
	h.waitRunning(ids[3])
	h.gate.let(ids[3])
	got = h.waitState(other.ID, model.BatchCompleted)
	if got.Items[1].JobID == 0 || got.Items[1].JobID == j.ID {
		t.Fatalf("d: %+v", got.Items[1])
	}
}

// The author's right is checked for every job as it is then: a demoted
// author's batch stops, and so does one whose next server left their
// scope.
func TestAuthorRightsRechecked(t *testing.T) {
	h := newHarness(t)
	ids := h.servers("a", "b", "c")
	op := h.user("op", model.RoleOperator, model.Scope{Tags: []string{"a", "b", "c"}})
	b := h.create(op, 1, ids...)
	h.waitRunning(ids[0])
	ctx := context.Background()
	change := func(f func(u *model.User)) {
		t.Helper()
		err := h.db.ChangeUsers(ctx, time.Now(), func(all []model.User) ([]model.User, []int64, error) {
			for _, u := range all {
				if u.ID == op {
					f(&u)
					return []model.User{u}, nil, nil
				}
			}
			return nil, nil, errors.New("no op")
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	change(func(u *model.User) { u.Scope = model.Scope{Tags: []string{"a", "c"}} })
	h.gate.let(ids[0])
	got := h.waitState(b.ID, model.BatchStopped)
	if got.Stop != model.StopDenied || !slices.Equal(states(got), []model.BatchItemState{model.ItemCompleted, model.ItemSkipped, model.ItemSkipped}) ||
		got.Items[1].Message == got.Items[2].Message {
		t.Fatalf("%+v", got)
	}

	change(func(u *model.User) { u.Scope = model.Scope{Tags: []string{"a", "b", "c"}} })
	next := h.create(op, 1, ids[1], ids[2])
	h.waitRunning(ids[1])
	change(func(u *model.User) { u.Role = model.RoleReadOnly })
	h.gate.let(ids[1])
	got = h.waitState(next.ID, model.BatchStopped)
	if got.Stop != model.StopDenied || !slices.Equal(states(got), []model.BatchItemState{model.ItemCompleted, model.ItemSkipped}) {
		t.Fatalf("%+v", got)
	}
	if len(h.started()) != 2 {
		t.Fatalf("started %v", h.started())
	}
}

// A server with another job waits: the batch goes on with the others
// and comes back to it.
func TestBusyServerWaits(t *testing.T) {
	h := newHarness(t)
	ids := h.servers("a", "b", "c")
	ctx := context.Background()
	j, err := h.eng.Submit(ctx, JobKind(model.BatchTuning), ids[0], struct{}{}, nil, h.owner)
	if err != nil {
		t.Fatal(err)
	}
	h.waitRunning(ids[0])
	b := h.create(h.owner, 3, ids...)
	h.waitRunning(ids[1])
	h.gate.let(ids[1])
	h.waitRunning(ids[2])
	h.settle()
	if got := h.batch(b.ID); got.Items[0].State != model.ItemPending || !got.Items[1].Canary {
		t.Fatalf("%+v", got.Items)
	}
	h.gate.let(ids[2])
	h.gate.let(ids[0]) // the other job ends, and so does the batch's
	got := h.waitState(b.ID, model.BatchCompleted)
	if got.Items[0].JobID == j.ID || got.Items[0].JobID == 0 {
		t.Fatalf("%+v", got.Items[0])
	}
}
