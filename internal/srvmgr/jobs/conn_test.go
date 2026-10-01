package jobs

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// link is one SSH connection of a test: it records the commands and,
// once cut, fails every operation as a broken connection does.
type link struct {
	mu     sync.Mutex
	cut    bool
	cmds   []string
	closed atomic.Bool
}

func (l *link) err() error {
	if l.cut {
		return &remote.UnreachableError{Err: io.EOF}
	}
	return nil
}

func (l *link) Run(_ context.Context, cmd remote.Cmd) (remote.Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.err(); err != nil {
		return remote.Result{}, err
	}
	l.cmds = append(l.cmds, strings.Join(cmd.Args, " "))
	return remote.Result{}, nil
}

func (l *link) Stream(context.Context, remote.Cmd, func(string)) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err()
}

func (l *link) ReadFile(context.Context, string, bool) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return nil, l.err()
}

func (l *link) WriteFile(context.Context, string, []byte, remote.FileSpec) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err()
}

func (l *link) Close() error { l.closed.Store(true); return nil }

func (l *link) commands() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.cmds)
}

// dialer opens a new link per connection; while down, the server cannot
// be reached.
type dialer struct {
	mu    sync.Mutex
	links []*link
	dials int
	down  bool
}

func (d *dialer) Connect(context.Context, int64) (remote.Executor, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials++
	if d.down {
		return nil, &remote.UnreachableError{Err: errors.New("connection refused")}
	}
	l := &link{}
	d.links = append(d.links, l)
	return l, nil
}

// drop breaks the current connection; down: no new one can be opened.
func (d *dialer) drop(down bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	l := d.links[len(d.links)-1]
	l.mu.Lock()
	l.cut = true
	l.mu.Unlock()
	d.down = down
}

func (d *dialer) count() (links, dials int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.links), d.dials
}

func (d *dialer) link(i int) *link {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.links[i]
}

// run is a step or an Undo that runs one command on the server.
func run(command string) func(context.Context, *Env) error {
	return func(ctx context.Context, env *Env) error {
		ex, err := env.Exec(ctx)
		if err != nil {
			return err
		}
		_, err = ex.Run(ctx, remote.Cmd{Args: []string{command}})
		return err
	}
}

// connHarness runs the steps on a server reached through d.
func connHarness(t *testing.T, d *dialer, steps ...Step) (*harness, model.Job) {
	t.Helper()
	h := newHarness(t, nil, simpleKind("demo", steps...))
	h.eng.Connect = d
	h.start()
	j, err := h.eng.Submit(context.Background(), "demo", h.newServer(), nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return h, j
}

// The connection breaks during a step: the rollback reconnects and
// undoes the earlier step over the new connection.
func TestRollbackReconnectsAfterLostConnection(t *testing.T) {
	d := &dialer{}
	h, j := connHarness(t, d,
		Step{Name: "install", Phase: model.JobInstalling, Run: run("install"), Undo: run("uninstall")},
		Step{Name: "start", Phase: model.JobStarting, Run: func(ctx context.Context, env *Env) error {
			d.drop(false)
			if err := run("start")(ctx, env); err != nil {
				return Fail("Нет связи с сервером.", err)
			}
			return nil
		}},
	)
	j = h.wait(j.ID, model.JobFailed)
	if got := h.steps(j.ID); got[0] != model.StepRolledBack {
		t.Fatalf("steps %v\n%s", got, h.logText(j.ID))
	}
	if links, _ := d.count(); links != 2 || !slices.Equal(d.link(0).commands(), []string{"install"}) || !slices.Equal(d.link(1).commands(), []string{"uninstall"}) {
		t.Fatalf("%d connections\n%s", links, h.logText(j.ID))
	}
	for i := 0; i < 100 && !d.link(0).closed.Load(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !d.link(0).closed.Load() || !d.link(1).closed.Load() {
		t.Fatal("a connection was left open")
	}
}

// The rollback does not trust the connection of the failed step even
// when nothing broke visibly.
func TestRollbackUsesNewConnection(t *testing.T) {
	d := &dialer{}
	h, j := connHarness(t, d,
		Step{Name: "install", Phase: model.JobInstalling, Run: run("install"), Undo: run("uninstall")},
		Step{Name: "start", Phase: model.JobStarting, Run: func(context.Context, *Env) error { return Fail("Служба не запустилась.", nil) }},
	)
	j = h.wait(j.ID, model.JobFailed)
	if links, _ := d.count(); links != 2 || !slices.Equal(d.link(1).commands(), []string{"uninstall"}) || h.steps(j.ID)[0] != model.StepRolledBack {
		t.Fatalf("%d connections, steps %v\n%s", links, h.steps(j.ID), h.logText(j.ID))
	}
}

// The server is gone: the rollback dials once, and every Undo reports
// that failure.
func TestRollbackDialsOnceWhenServerGone(t *testing.T) {
	d := &dialer{}
	h, j := connHarness(t, d,
		Step{Name: "install", Phase: model.JobInstalling, Run: run("install"), Undo: run("uninstall")},
		Step{Name: "configure", Phase: model.JobConfiguring, Run: run("configure"), Undo: run("unconfigure")},
		Step{Name: "start", Phase: model.JobStarting, Run: func(ctx context.Context, env *Env) error {
			d.drop(true)
			return run("start")(ctx, env)
		}},
	)
	j = h.wait(j.ID, model.JobFailed)
	if links, dials := d.count(); links != 1 || dials != 2 {
		t.Fatalf("%d connections, %d dials", links, dials)
	}
	if log := h.logText(j.ID); strings.Count(log, "Откат не удался") != 2 || !strings.Contains(log, "connection refused") {
		t.Fatalf("log:\n%s", log)
	}
}

// A step that gets by without the server after the connection broke: the
// next step works over a new connection.
func TestStepReconnectsAfterLostConnection(t *testing.T) {
	d := &dialer{}
	h, j := connHarness(t, d,
		Step{Name: "probe", Phase: model.JobConnecting, Run: func(ctx context.Context, env *Env) error {
			if _, err := env.Exec(ctx); err != nil {
				return err
			}
			d.drop(false)
			if err := run("probe")(ctx, env); err != nil {
				env.Warnf("Проверка пропущена: %v", err)
			}
			return nil
		}},
		Step{Name: "install", Phase: model.JobInstalling, Run: run("install")},
	)
	h.wait(j.ID, model.JobCompleted)
	if links, _ := d.count(); links != 2 || !slices.Equal(d.link(1).commands(), []string{"install"}) {
		t.Fatalf("%d connections", links)
	}
}
