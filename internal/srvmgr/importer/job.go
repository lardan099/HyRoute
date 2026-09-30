package importer

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// JobKind is the name of the import job.
const JobKind = "import"

// Store is what the import keeps in the controller's database.
type Store interface {
	store.Configs
	store.Installations
	SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error
}

// Deps are the import's collaborators.
type Deps struct {
	Store Store
	Keys  *secrets.Keyring
	Now   func() time.Time
}

type importer struct{ Deps }

// Kind is the import job: connect, inspect (report in the job data) and
// save the config revision and the installation in the controller. Every
// command on the server goes through remote.ReadOnly.
func Kind(d Deps) *jobs.Kind {
	if d.Now == nil {
		d.Now = time.Now
	}
	x := &importer{d}
	return &jobs.Kind{
		Name: JobKind,
		Steps: func(json.RawMessage) ([]jobs.Step, error) {
			return []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: x.connect},
				{Name: "inspect", Phase: model.JobPreflight, Safe: true, Run: x.inspect},
				{Name: "save", Phase: model.JobVerifying, Safe: true, Done: x.saved, Run: x.save},
			}, nil
		},
		// Nothing on the server changes: after a restart it simply goes on.
		Recover:  func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
		Finished: x.finished,
	}
}

func sudo(env *jobs.Env) bool { return env.Get("root") != "true" }

// exec is the job's connection, read-only.
func exec(ctx context.Context, env *jobs.Env) (remote.Executor, error) {
	ex, err := env.Exec(ctx)
	if err != nil {
		return nil, jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	return remote.ReadOnly(ex), nil
}

func (x *importer) connect(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	p, err := remote.RunProbe(ctx, ex)
	if err != nil {
		return jobs.Fail("Не удалось выполнить команды на сервере.", err)
	}
	if !p.Privileged() {
		return jobs.Fail("Пользователь SSH не root и не может выполнять sudo без пароля: конфиг Hysteria ему не прочитать.", nil)
	}
	env.Set("root", strconv.FormatBool(p.Root))
	env.Logf("Подключено как %s к %s (%s, %s). Импорт только читает сервер.", p.User, p.Hostname, p.Kernel, p.Arch)
	return nil
}

// fail turns a discovery error into the job's error.
func fail(err error) error {
	var e *Error
	if errors.As(err, &e) {
		return jobs.Fail(e.Msg, nil)
	}
	return jobs.Fail("Не удалось прочитать установку Hysteria.", err)
}

func (x *importer) inspect(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	f, _, err := Discover(ctx, ex, sudo(env), x.Now())
	if err != nil {
		return fail(err)
	}
	b, _ := json.Marshal(f)
	env.Set("report", string(b))
	state := "не работает"
	if f.Active {
		state = "работает"
	}
	env.Logf("Найдена служба %s (%s): %s, Hysteria %s, конфиг %s.", f.Unit, state, f.Binary, orDash(f.Version), f.Config)
	for _, fd := range f.Findings {
		if fd.Level == Warn {
			env.Warnf("%s. %s", fd.Title, fd.Details)
		}
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func report(env *jobs.Env) (Found, error) {
	var f Found
	err := json.Unmarshal([]byte(env.Get("report")), &f)
	return f, err
}

func (f *Found) installation(serverID int64, managed bool, at time.Time) model.Installation {
	return model.Installation{ServerID: serverID, Binary: f.Binary, Config: f.Config, Unit: f.Unit, User: f.User, Version: f.Version, Managed: managed, At: at}
}

// saved: the controller already has this config and installation (a
// retry after the save, or a re-import of an unchanged server).
func (x *importer) saved(ctx context.Context, env *jobs.Env) (bool, error) {
	f, err := report(env)
	if err != nil {
		return false, err
	}
	cur, err := x.Store.CurrentConfig(ctx, env.ServerID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	in, err := x.Store.Installation(ctx, env.ServerID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	want := f.installation(env.ServerID, in.Managed, in.At)
	return cur.SHA256 == f.ConfigSHA256 && in == want, nil
}

func (x *importer) save(ctx context.Context, env *jobs.Env) error {
	f, err := report(env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	// The config itself never went into the job data: read it again, and
	// it must be the one inspected.
	raw, err := ex.ReadFile(ctx, f.Config, sudo(env))
	if err != nil {
		return jobs.Fail("Не удалось прочитать конфиг ещё раз.", err)
	}
	if sha(raw) != f.ConfigSHA256 {
		return jobs.Fail("Конфиг на сервере изменился во время импорта. Повторите импорт.", nil)
	}
	now := x.Now()
	cur, err := x.Store.CurrentConfig(ctx, env.ServerID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err == nil && cur.SHA256 == f.ConfigSHA256 {
		env.Logf("Конфиг совпадает с ревизией %d, сохранённой в controller.", cur.Revision)
	} else {
		c := model.ServerConfig{ServerID: env.ServerID, SHA256: f.ConfigSHA256, Meta: f.Meta, Source: model.ConfigImport, JobID: env.JobID, By: env.CreatedBy, At: now}
		err := x.Store.AddConfig(ctx, &c, func(rev int) ([]byte, error) {
			return x.Keys.Seal(raw, model.ConfigContext(env.ServerID, rev))
		})
		if err != nil {
			return err
		}
		env.Logf("Конфиг сохранён в controller как ревизия %d (в зашифрованном виде).", c.Revision)
	}
	// An installation HyRoute deployed stays its own when it is where
	// HyRoute put it.
	managed := false
	if prev, err := x.Store.Installation(ctx, env.ServerID); err == nil {
		managed = prev.Managed && prev.Binary == f.Binary && prev.Config == f.Config && prev.Unit == f.Unit
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return x.Store.SetInstallation(ctx, f.installation(env.ServerID, managed, now))
}

func (x *importer) finished(ctx context.Context, env *jobs.Env, j model.Job) {
	if j.State != model.JobCompleted {
		return // nothing changed
	}
	f, err := report(env)
	if err != nil {
		return
	}
	state := model.StateHealthy
	if f.NeedsAttention() {
		state = model.StateNeedsAttention
	}
	x.Store.SetServerState(ctx, env.ServerID, state, x.Now())
}
