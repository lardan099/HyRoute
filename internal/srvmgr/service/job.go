package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// JobKind is the name of the service control job.
const JobKind = "service"

// Params are the action of a service job.
type Params struct {
	Action remote.ServiceAction `json:"action"` // start, stop, restart
}

// Deps are the service job's collaborators.
type Deps struct {
	Store JobStore
	Keys  *secrets.Keyring
	// Wait bounds how long the service may take to reach the wanted state.
	Wait time.Duration
	Poll time.Duration
}

type control struct{ Deps }

// ErrBadAction: not start, stop or restart.
var ErrBadAction = errors.New("unknown service action")

// Kind is the service job: connect, run the action, check the result.
func Kind(d Deps) *jobs.Kind {
	if d.Wait == 0 {
		d.Wait = 30 * time.Second
	}
	if d.Poll == 0 {
		d.Poll = time.Second
	}
	x := &control{d}
	return &jobs.Kind{
		Name: JobKind,
		Steps: func(raw json.RawMessage) ([]jobs.Step, error) {
			var p Params
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, err
			}
			switch p.Action {
			case remote.ServiceStart, remote.ServiceStop, remote.ServiceRestart:
			default:
				return nil, ErrBadAction
			}
			return []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: x.connect},
				{Name: string(p.Action), Phase: model.JobStarting, Run: func(ctx context.Context, env *jobs.Env) error { return x.act(ctx, env, p.Action) }},
				{Name: "check", Phase: model.JobVerifying, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.check(ctx, env, p.Action) }},
			}, nil
		},
		// A half-done start, stop or restart is not repeated on its own
		// after a controller restart: the admin looks and decides.
		Recover:  func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveFailed, nil },
		Finished: x.finished,
	}
}

// JobStore is Store plus the server state the job sets.
type JobStore interface {
	Store
	SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error
}

// finished: a running service makes the server healthy; one that is
// stopped (on purpose or not) needs attention.
func (x *control) finished(ctx context.Context, env *jobs.Env, j model.Job) {
	var p Params
	if json.Unmarshal(j.Params, &p) != nil {
		return
	}
	state := model.StateNeedsAttention
	if j.State == model.JobCompleted && p.Action != remote.ServiceStop {
		state = model.StateHealthy
	}
	x.Store.SetServerState(ctx, env.ServerID, state, time.Now())
}

func sudo(env *jobs.Env) bool { return env.Get("root") != "true" }

func (x *control) installation(ctx context.Context, env *jobs.Env) (model.Installation, error) {
	in, err := x.Store.Installation(ctx, env.ServerID)
	if errors.Is(err, store.ErrNotFound) {
		return in, jobs.Fail("HyRoute не знает, где на сервере Hysteria: разверните её или импортируйте сервер.", nil)
	}
	return in, err
}

func (x *control) connect(ctx context.Context, env *jobs.Env) error {
	ex, err := env.Exec(ctx)
	if err != nil {
		return jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	p, err := remote.RunProbe(ctx, ex)
	if err != nil {
		return jobs.Fail("Не удалось выполнить команды на сервере.", err)
	}
	if !p.Privileged() {
		return jobs.Fail("Пользователь SSH не root и не может выполнять sudo без пароля.", nil)
	}
	env.Set("root", strconv.FormatBool(p.Root))
	return nil
}

var actionText = map[remote.ServiceAction]string{
	remote.ServiceStart:   "Запуск",
	remote.ServiceStop:    "Остановка",
	remote.ServiceRestart: "Перезапуск",
}

func (x *control) act(ctx context.Context, env *jobs.Env, a remote.ServiceAction) error {
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := env.Exec(ctx)
	if err != nil {
		return jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	if err := remote.Systemctl(ctx, ex, a, in.Unit, sudo(env)); err != nil {
		return jobs.Fail(actionText[a]+" службы "+in.Unit+" не удался.", err)
	}
	env.Logf("%s службы %s: команда выполнена.", actionText[a], in.Unit)
	return nil
}

// check waits for the state the action should lead to; a service that
// does not start gets its last journal lines (redacted) in the log.
func (x *control) check(ctx context.Context, env *jobs.Env, a remote.ServiceAction) error {
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := env.Exec(ctx)
	if err != nil {
		return jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	want := "active"
	if a == remote.ServiceStop {
		want = "inactive"
	}
	deadline := time.Now().Add(x.Wait)
	var st string
	for {
		if st, err = remote.ActiveState(ctx, ex, in.Unit); err != nil {
			return err
		}
		// A service that stops cleanly may also report failed (killed).
		if st == want || (want == "inactive" && st == "failed") {
			break
		}
		if time.Now().After(deadline) || (want == "active" && st == "failed") {
			x.journal(ctx, env, ex, in.Unit)
			return jobs.Fail(fmt.Sprintf("Служба %s в состоянии %s, а ожидалось %s.", in.Unit, st, want), nil)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(x.Poll):
		}
	}
	if want == "active" {
		// Right after a start systemd says active even if Hysteria exits a
		// moment later on a bad config: look once more.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(x.Poll):
		}
		if st, err = remote.ActiveState(ctx, ex, in.Unit); err != nil {
			return err
		}
		if st != "active" {
			x.journal(ctx, env, ex, in.Unit)
			return jobs.Fail(fmt.Sprintf("Служба %s запустилась и сразу остановилась (%s).", in.Unit, st), nil)
		}
	}
	env.Logf("Служба %s: %s.", in.Unit, st)
	return nil
}

func (x *control) journal(ctx context.Context, env *jobs.Env, ex remote.Executor, unit string) {
	lines, err := remote.JournalTail(ctx, ex, unit, 20, sudo(env))
	if err != nil || len(lines) == 0 {
		return
	}
	r, err := Redactor(ctx, x.Store, x.Keys, env.ServerID)
	if err != nil {
		return
	}
	env.Logf("Последние строки журнала %s:", unit)
	for _, l := range lines {
		env.Logf("  %s", r.String(l))
	}
}
