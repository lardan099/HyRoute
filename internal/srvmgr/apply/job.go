package apply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/importer"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// JobKind is the name of the config apply job.
const JobKind = "apply"

// SecretConfig is the candidate in the job's sealed secrets.
const SecretConfig = "config"

// Backup is the suffix of the previous config kept while applying.
const Backup = ".hyroute-prev"

// Params are the job's parameters (the config itself is a secret).
type Params struct {
	// Base is the revision the candidate was edited from, BaseSHA256 its
	// file: the server must still have it.
	Base       int    `json:"base"`
	BaseSHA256 string `json:"baseSha256"`
	// SHA256 is of the candidate.
	SHA256 string `json:"sha256"`
}

// Store is what applying keeps in the controller's database.
type Store interface {
	store.Configs
	store.Installations
	ServerByID(ctx context.Context, id int64) (model.Server, error)
	SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error
}

// Deps are the apply job's collaborators.
type Deps struct {
	Store Store
	Keys  *secrets.Keyring
	Jobs  *jobs.Engine
	Now   func() time.Time
	// VerifyTimeout bounds the wait for the restarted service (ACME
	// waits three times as long).
	VerifyTimeout time.Duration
	Poll          time.Duration
}

type applier struct{ Deps }

// Applier starts apply jobs and is the job kind.
type Applier struct{ x *applier }

// New returns the applier.
func New(d Deps) *Applier {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.VerifyTimeout == 0 {
		d.VerifyTimeout = 30 * time.Second
	}
	if d.Poll == 0 {
		d.Poll = 2 * time.Second
	}
	return &Applier{&applier{d}}
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Submit checks the editor's candidate and queues the apply job. A
// candidate with errors or without changes is a *model.FieldError.
func (a *Applier) Submit(ctx context.Context, serverID int64, base int, text string, fields *Fields, actor int64) (model.Job, error) {
	e := &Editor{Store: a.x.Store, Keys: a.x.Keys}
	ch, cand, cur, err := e.Render(ctx, serverID, base, text, fields)
	if err != nil {
		return model.Job{}, err
	}
	for _, p := range ch.Problems {
		if !p.Warning {
			return model.Job{}, &model.FieldError{Field: p.Field, Msg: "Конфиг не прошёл проверку: " + p.Field + ": " + p.Message}
		}
	}
	// The candidate is re-encoded YAML: compare what the editor compares.
	if !Changed(ch.Diff) && len(ch.Secrets) == 0 {
		return model.Job{}, &model.FieldError{Field: "yaml", Msg: "Изменений нет: конфиг такой же, как на сервере."}
	}
	p := Params{Base: cur.Revision, BaseSHA256: cur.SHA256, SHA256: sha(cand)}
	return a.x.Jobs.Submit(ctx, JobKind, serverID, p, map[string]string{SecretConfig: string(cand)}, actor)
}

// Kind is the apply job.
func (a *Applier) Kind() *jobs.Kind {
	x := a.x
	return &jobs.Kind{
		Name: JobKind,
		Steps: func(raw json.RawMessage) ([]jobs.Step, error) {
			var p Params
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, err
			}
			return []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: x.connect},
				{Name: "validate", Phase: model.JobPreflight, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.validate(ctx, env, p) }},
				{Name: "prepare", Phase: model.JobConfiguring, Safe: true, Run: x.prepare, Undo: x.undoPrepare},
				{Name: "backup", Phase: model.JobConfiguring, Safe: true,
					Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.installed(ctx, env, p) },
					Run:  x.backup},
				{Name: "install", Phase: model.JobConfiguring, Safe: true,
					Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.installed(ctx, env, p) },
					Run:  func(ctx context.Context, env *jobs.Env) error { return x.install(ctx, env, p) },
					Undo: x.undoInstall},
				{Name: "restart", Phase: model.JobStarting, Safe: true, Run: x.restart},
				{Name: "verify", Phase: model.JobVerifying, Safe: true, Run: x.verify},
				{Name: "commit", Phase: model.JobVerifying, Safe: true,
					Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.committed(ctx, env, p) },
					Run:  func(ctx context.Context, env *jobs.Env) error { return x.commit(ctx, env, p) }},
			}, nil
		},
		// Every step looks at the server first: after a restart the job
		// goes on from the nearest safe step.
		Recover:  func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
		Finished: x.finished,
	}
}

func sudo(env *jobs.Env) bool { return env.Get("root") != "true" }

func exec(ctx context.Context, env *jobs.Env) (remote.Executor, error) {
	ex, err := env.Exec(ctx)
	if err != nil {
		return nil, jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	return ex, nil
}

func (x *applier) installation(ctx context.Context, env *jobs.Env) (model.Installation, error) {
	in, err := x.Store.Installation(ctx, env.ServerID)
	if errors.Is(err, store.ErrNotFound) {
		return in, jobs.Fail("HyRoute не знает, где на сервере Hysteria: разверните её или импортируйте сервер.", nil)
	}
	return in, err
}

func (x *applier) connect(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
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

// candidate is the config this job installs, parsed.
func candidate(env *jobs.Env) ([]byte, *hyconfig.Server, error) {
	b := []byte(env.Secret(SecretConfig))
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return nil, nil, jobs.Fail("Конфиг не разобрать.", err)
	}
	return b, c, nil
}

// validate: the candidate passes the checks, and the server still has
// the config the admin edited (or this job's, on a retry).
func (x *applier) validate(ctx context.Context, env *jobs.Env, p Params) error {
	b, c, err := candidate(env)
	if err != nil {
		return err
	}
	if sha(b) != p.SHA256 {
		return jobs.Fail("Конфиг задания повреждён.", nil)
	}
	var errs []string
	for _, pr := range c.Validate() {
		if !pr.Warning {
			errs = append(errs, pr.Field+": "+pr.Message)
		}
	}
	if len(errs) > 0 {
		return jobs.Fail("Конфиг не прошёл проверку, на сервер ничего не записано: "+strings.Join(errs, "; ")+".", nil)
	}
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	sum, err := remote.FileSHA256(ctx, ex, in.Config, sudo(env))
	if err != nil {
		return err
	}
	switch sum {
	case p.BaseSHA256:
	case p.SHA256:
		env.Logf("Новый конфиг уже на сервере: задание продолжается с того места, где остановилось.")
	case "":
		return jobs.Fail("На сервере нет конфига "+in.Config+".", nil)
	default:
		return jobs.Fail("Конфиг на сервере изменили не через HyRoute после последнего сохранения. Импортируйте сервер заново, чтобы HyRoute увидел эти правки, и повторите.", nil)
	}
	// Hysteria has no command that checks a config without running it:
	// the restart is that check, with the rollback behind it.
	env.Logf("Конфиг прошёл проверку HyRoute. Саму Hysteria проверит перезапуск; если она не заработает, вернётся прежний конфиг.")
	return nil
}

func (x *applier) prepare(ctx context.Context, env *jobs.Env) error {
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	st, err := remote.ActiveState(ctx, ex, in.Unit)
	if err != nil {
		return err
	}
	if env.Get("prepared") != "1" {
		env.Set("prevActive", strconv.FormatBool(st == "active"))
		env.Set("changed", "")
		srv, err := x.Store.ServerByID(ctx, env.ServerID)
		if err != nil {
			return err
		}
		env.Set("prevState", string(srv.State))
		env.Set("prepared", "1")
	}
	return nil
}

// undoPrepare runs last in a rollback, with the previous config back:
// the service starts again as it was.
func (x *applier) undoPrepare(ctx context.Context, env *jobs.Env) error {
	if env.Get("changed") != "1" {
		return jobs.ErrNothingToUndo
	}
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	action := remote.ServiceRestart
	if env.Get("prevActive") != "true" {
		action = remote.ServiceStop
	}
	if err := remote.Systemctl(ctx, ex, action, in.Unit, sudo(env)); err != nil {
		return err
	}
	if action == remote.ServiceRestart {
		env.Logf("Прежний конфиг возвращён, служба %s перезапущена с ним.", in.Unit)
	}
	env.Set("restored", "1")
	return nil
}

// installed: the candidate is the config on the server.
func (x *applier) installed(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	in, err := x.installation(ctx, env)
	if err != nil {
		return false, err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	sum, err := remote.FileSHA256(ctx, ex, in.Config, sudo(env))
	return sum == p.SHA256, err
}

// backup records the state of the config (its SHA-256) before anything
// changes it, then keeps a copy; a run again keeps the first record.
func (x *applier) backup(ctx context.Context, env *jobs.Env) error {
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	state, err := remote.FileState(ctx, ex, in.Config, sudo(env))
	if err != nil {
		return err
	}
	if prev := env.Get("configState"); prev != "" && prev != state {
		return nil // the config is this job's already; the copy is the original
	}
	if err := env.Set("configState", state); err != nil {
		return err
	}
	if err := remote.CopyFile(ctx, ex, in.Config, in.Config+Backup, sudo(env)); err != nil {
		return jobs.Fail("Не удалось сохранить копию конфига.", err)
	}
	env.Set("backup", "1")
	env.Logf("Копия прежнего конфига: %s%s.", in.Config, Backup)
	return nil
}

func (x *applier) install(ctx context.Context, env *jobs.Env, p Params) error {
	b, _, err := candidate(env)
	if err != nil {
		return err
	}
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	// The new file gets the rights of the old one (0640 root:hysteria
	// after a HyRoute deploy).
	fi, ok, err := remote.Stat(ctx, ex, in.Config, sudo(env))
	if err != nil {
		return err
	}
	spec := remote.FileSpec{Mode: 0o640, Group: in.User, Sudo: sudo(env)}
	if ok {
		spec.Mode, spec.Owner, spec.Group = fi.Mode, fi.Owner, fi.Group
	}
	if err := env.Set("changed", "1"); err != nil {
		return err
	}
	if err := ex.WriteFile(ctx, in.Config, b, spec); err != nil {
		return jobs.Fail("Не удалось записать конфиг.", err)
	}
	env.Logf("Новый конфиг записан: %s.", in.Config)
	return nil
}

func (x *applier) undoInstall(ctx context.Context, env *jobs.Env) error {
	state := env.Get("configState")
	if state == "" && env.Get("backup") != "1" {
		return jobs.ErrNothingToUndo
	}
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if state == "" {
		// Recorded by an older controller: the copy is the original.
		if err := remote.Rename(ctx, ex, in.Config+Backup, in.Config, sudo(env)); err != nil {
			return err
		}
		env.Set("backup", "")
		return nil
	}
	changed, err := remote.RestoreFile(ctx, ex, in.Config, in.Config+Backup, state, sudo(env))
	if errors.Is(err, remote.ErrBackupMismatch) {
		return fmt.Errorf("%w: %s оставлен как есть, проверьте его вручную", err, in.Config)
	}
	if err != nil {
		return err
	}
	if !changed {
		return jobs.ErrNothingToUndo
	}
	return nil
}

func (x *applier) restart(ctx context.Context, env *jobs.Env) error {
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceRestart, in.Unit, sudo(env)); err != nil {
		return jobs.Fail("Не удалось перезапустить "+in.Unit+".", err)
	}
	env.Logf("Служба %s перезапущена с новым конфигом.", in.Unit)
	return nil
}

// verify waits until the service runs and Hysteria listens on its port.
func (x *applier) verify(ctx context.Context, env *jobs.Env) error {
	_, c, err := candidate(env)
	if err != nil {
		return err
	}
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	l, _ := hyconfig.ParseListen(c.Listen)
	wait := x.VerifyTimeout
	if c.ACME != nil {
		wait *= 3 // the certificate is issued first
	}
	deadline := time.Now().Add(wait)
	for {
		st, err := remote.ActiveState(ctx, ex, in.Unit)
		if err != nil {
			return err
		}
		if st == "active" {
			ls, err := remote.Listeners(ctx, ex, sudo(env))
			if err != nil {
				return err
			}
			for _, s := range ls {
				if s.Proto == "udp" && s.Port == l.First && strings.HasPrefix(s.Process, "hysteria") {
					env.Logf("Hysteria работает с новым конфигом и принимает соединения на UDP %d.", l.First)
					return nil
				}
			}
		}
		if st == "failed" || time.Now().After(deadline) {
			x.journal(ctx, env, ex, in.Unit, c)
			return jobs.Fail(fmt.Sprintf("Hysteria не заработала с новым конфигом (служба: %s). Прежний конфиг возвращается.", st), nil)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(x.Poll):
		}
	}
}

// journal logs the last lines of the unit, redacted with the secrets of
// both the current and the new config.
func (x *applier) journal(ctx context.Context, env *jobs.Env, ex remote.Executor, unit string, c *hyconfig.Server) {
	lines, err := remote.JournalTail(ctx, ex, unit, 20, sudo(env))
	if err != nil || len(lines) == 0 {
		return
	}
	r, err := service.Redactor(ctx, x.Store, x.Keys, env.ServerID)
	if err != nil {
		return
	}
	r.Add(service.ConfigSecrets(c)...)
	env.Logf("Последние строки журнала %s:", unit)
	for _, l := range lines {
		env.Logf("  %s", r.String(l))
	}
}

func (x *applier) committed(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	cur, err := x.Store.CurrentConfig(ctx, env.ServerID)
	if err != nil {
		return false, err
	}
	return cur.SHA256 == p.SHA256, nil
}

func (x *applier) commit(ctx context.Context, env *jobs.Env, p Params) error {
	b, c, err := candidate(env)
	if err != nil {
		return err
	}
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	meta, err := importer.ConfigMeta(ctx, remote.ReadOnly(ex), c, in.Version, sudo(env), x.Now())
	if err != nil {
		return err
	}
	rev := model.ServerConfig{ServerID: env.ServerID, SHA256: p.SHA256, Meta: meta, Source: model.ConfigEdit, JobID: env.JobID, By: env.CreatedBy, At: x.Now()}
	err = x.Store.AddConfig(ctx, &rev, func(r int) ([]byte, error) {
		return x.Keys.Seal(b, model.ConfigContext(env.ServerID, r))
	})
	if err != nil {
		return err
	}
	if err := remote.RemoveFile(ctx, ex, in.Config+Backup, sudo(env)); err != nil {
		env.Warnf("Копия прежнего конфига %s%s осталась на сервере.", in.Config, Backup)
	}
	env.Logf("Конфиг сохранён в controller как ревизия %d.", rev.Revision)
	return nil
}

func (x *applier) finished(ctx context.Context, env *jobs.Env, j model.Job) {
	state := model.StateHealthy
	if j.State == model.JobFailed {
		switch {
		case env.Get("changed") == "1" && env.Rollback() != jobs.RollbackNothing && (env.Get("restored") != "1" || env.Rollback() == jobs.RollbackFailed):
			state = model.StateNeedsAttention // the rollback did not finish
		case env.Get("prevState") != "":
			state = model.ServerState(env.Get("prevState"))
		default:
			return // nothing was touched
		}
	}
	x.Store.SetServerState(ctx, env.ServerID, state, x.Now())
}
