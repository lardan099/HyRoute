package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// MaintainKind is the name of the maintenance job: Hysteria updated to
// another version, or reinstalled, with the config left as it is.
const MaintainKind = "maintain"

// Maintenance operations.
const (
	// OpUpgrade puts another version of the binary in place (a newer one,
	// or an older one to go back to).
	OpUpgrade = "upgrade"
	// OpReinstall puts back what a deploy installs besides the config:
	// the binary of the installed version, the system user, the systemd
	// unit and the rights of the files in /etc/hysteria.
	OpReinstall = "reinstall"
)

// MaintainParams are the choices of a maintenance job.
type MaintainParams struct {
	Op string `json:"op"`
	// Version: upgrade, the version to install ("" = DefaultVersion);
	// reinstall, the installed one (Submit fills it in).
	Version string `json:"version,omitempty"`
	Source  string `json:"source,omitempty"` // auto (default), direct, relay, node
	// Via is the server that provides the binary (source node).
	Via int64 `json:"via,omitempty"`
}

// Normalize fills the defaults and checks the params.
func (p *MaintainParams) Normalize() error {
	switch p.Op {
	case OpUpgrade, OpReinstall:
	default:
		return fmt.Errorf("неизвестная операция %q", p.Op)
	}
	p.Version = strings.TrimSpace(p.Version)
	if p.Version == "" {
		p.Version = hyrelease.DefaultVersion
	}
	if err := hyrelease.CheckVersion(p.Version); err != nil {
		return err
	}
	return normalizeSource(&p.Source, &p.Via)
}

var (
	// ErrNoInstallation: the controller does not know where Hysteria is.
	ErrNoInstallation = errors.New("deploy: no installation recorded")
	// ErrNotManaged: a reinstall of an installation HyRoute did not make
	// (its unit and paths are someone else's).
	ErrNotManaged = errors.New("deploy: the installation is not HyRoute's")
)

// Maintain queues a maintenance job of serverID. A reinstall keeps the
// recorded version (DefaultVersion when it is unknown) and needs an
// installation HyRoute made.
func (s *Submitter) Maintain(ctx context.Context, serverID int64, p MaintainParams, actor int64) (model.Job, error) {
	in, err := s.Store.Installation(ctx, serverID)
	if errors.Is(err, store.ErrNotFound) {
		return model.Job{}, ErrNoInstallation
	} else if err != nil {
		return model.Job{}, err
	}
	if p.Op == OpReinstall {
		if !in.Managed {
			return model.Job{}, ErrNotManaged
		}
		p.Version = ""
		if hyrelease.CheckVersion(in.Version) == nil {
			p.Version = in.Version
		}
	}
	if err := p.Normalize(); err != nil {
		return model.Job{}, &model.FieldError{Field: "params", Msg: sentence(err.Error())}
	}
	if err := s.checkVia(ctx, serverID, p.Source, p.Via); err != nil {
		return model.Job{}, err
	}
	return s.Jobs.Submit(ctx, MaintainKind, serverID, p, nil, actor)
}

// Maintenance is the maintenance job. Its Deps are those of the deploy
// (the same relay source keeps the downloaded binary for both).
func Maintenance(d Deps) *jobs.Kind {
	m := &deployer{withDefaults(d)}
	return &jobs.Kind{
		Name: MaintainKind,
		Steps: func(raw json.RawMessage) ([]jobs.Step, error) {
			var p MaintainParams
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, err
			}
			if err := p.Normalize(); err != nil {
				return nil, err
			}
			return m.maintainSteps(p), nil
		},
		// Every step looks at the server first: after a restart the job
		// goes on from the nearest safe step.
		Recover:  func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
		Finished: m.maintained,
	}
}

func (x *deployer) maintainSteps(p MaintainParams) []jobs.Step {
	steps := []jobs.Step{
		{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: x.connect},
		{Name: "check", Phase: model.JobPreflight, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.maintainCheck(ctx, env, p) }},
		{Name: "prepare", Phase: model.JobInstalling, Safe: true, Run: x.maintainPrepare, Undo: x.maintainUndoPrepare},
		{Name: "binary", Phase: model.JobDownloading, Safe: true,
			Done: func(ctx context.Context, env *jobs.Env) (bool, error) {
				in, err := x.installed(ctx, env)
				if err != nil {
					return false, err
				}
				return x.binaryDone(ctx, env, p.Version, in.Binary)
			},
			Run: func(ctx context.Context, env *jobs.Env) error {
				in, err := x.installed(ctx, env)
				if err != nil {
					return err
				}
				return x.binary(ctx, env, p.Version, p.Source, p.Via, in.Binary)
			},
			Undo: func(ctx context.Context, env *jobs.Env) error {
				in, err := x.installed(ctx, env)
				if err != nil {
					return err
				}
				return x.restoreFile(in.Binary, "binaryBackup")(ctx, env)
			}},
	}
	if p.Op == OpReinstall {
		// A reinstall is of HyRoute's installation only (Submit and the
		// check step see to it): the standard places of the deploy.
		steps = append(steps,
			jobs.Step{Name: "user", Phase: model.JobInstalling, Safe: true, Done: x.userDone, Run: x.user},
			jobs.Step{Name: "files", Phase: model.JobConfiguring, Safe: true, Done: x.filesDone, Run: x.files},
			jobs.Step{Name: "unit", Phase: model.JobConfiguring, Safe: true, Done: x.unitDone, Run: x.unit, Undo: x.undoUnit},
		)
	}
	return append(steps,
		jobs.Step{Name: "restart", Phase: model.JobStarting, Safe: true, Done: x.restartDone, Run: x.restart},
		jobs.Step{Name: "verify", Phase: model.JobVerifying, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.maintainVerify(ctx, env, p) }},
		jobs.Step{Name: "commit", Phase: model.JobVerifying, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.maintainCommit(ctx, env, p) }},
	)
}

// installed is the server's recorded installation.
func (x *deployer) installed(ctx context.Context, env *jobs.Env) (model.Installation, error) {
	in, err := x.Store.Installation(ctx, env.ServerID)
	if errors.Is(err, store.ErrNotFound) {
		return in, jobs.Fail("HyRoute не знает, где на сервере Hysteria: разверните её или импортируйте сервер.", nil)
	}
	return in, err
}

// maintainCheck: the installation is there and a release build fits the
// machine; what is installed now goes into the log.
func (x *deployer) maintainCheck(ctx context.Context, env *jobs.Env, p MaintainParams) error {
	in, err := x.installed(ctx, env)
	if err != nil {
		return err
	}
	if p.Op == OpReinstall && (!in.Managed || in.Binary != BinaryPath || in.Unit != Unit || in.Config != ConfigPath) {
		return jobs.Fail("Переустановить можно только Hysteria, которую установил HyRoute. Импортированную установку заменяет развёртывание с заменой.", nil)
	}
	var pr remote.Probe
	if err := json.Unmarshal([]byte(env.Get("probe")), &pr); err != nil {
		return err
	}
	arch := preflight.HysteriaArch(pr.Arch)
	if arch == "" {
		return jobs.Fail("Для архитектуры "+pr.Arch+" нет сборки Hysteria.", nil)
	}
	env.Set("arch", arch)
	if _, err := x.asset(ctx, env, p.Version); err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if p.Source == SourceAuto {
		code, err := remote.HTTPStatus(ctx, ex, preflight.ReleaseURL)
		if err != nil {
			return err
		}
		env.Set("github", strconv.FormatBool(code >= 200 && code < 400))
	}
	cur, err := remote.HysteriaVersion(ctx, ex, in.Binary)
	var ub *remote.UntrustedBinaryError
	if errors.As(err, &ub) {
		env.Warnf("%s.", ub.Error())
	} else if err != nil {
		return err
	}
	switch {
	case p.Op == OpReinstall:
		env.Logf("Переустановка Hysteria %s: бинарник, пользователь %s, служба %s и права файлов; конфиг и сертификаты остаются.", p.Version, User, Unit)
	case cur == "":
		env.Logf("Версию установленной Hysteria узнать не удалось; ставится %s.", p.Version)
	case cur == p.Version:
		env.Logf("На сервере уже Hysteria %s: бинарник сверяется с хешем релиза.", cur)
	default:
		env.Logf("Hysteria %s → %s. Прежний бинарник сохранится как %s%s.", cur, p.Version, in.Binary, Backup)
	}
	return nil
}

func (x *deployer) maintainPrepare(ctx context.Context, env *jobs.Env) error {
	in, err := x.installed(ctx, env)
	if err != nil {
		return err
	}
	if env.Get("prepared") == "1" {
		return nil
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	st, err := remote.ActiveState(ctx, ex, in.Unit)
	if err != nil {
		return err
	}
	srv, err := x.Store.ServerByID(ctx, env.ServerID)
	if err != nil {
		return err
	}
	env.Set("prevActive", strconv.FormatBool(st == "active"))
	env.Set("prevState", string(srv.State))
	return env.Set("prepared", "1")
}

// maintainUndoPrepare runs last in a rollback, with the files back: the
// service runs again as it was (or stays stopped).
func (x *deployer) maintainUndoPrepare(ctx context.Context, env *jobs.Env) error {
	if env.Get("changed") != "1" {
		return jobs.ErrNothingToUndo
	}
	in, err := x.installed(ctx, env)
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
		env.Logf("Прежняя установка возвращена, служба %s перезапущена.", in.Unit)
	}
	return env.Set("restored", "1")
}

// fileRights are the owner and mode a deploy gives a file of the
// installation.
type fileRights struct {
	path         string
	mode         fs.FileMode
	owner, group string
}

// rights are those of the deploy: the config and the key are readable by
// root and the service only.
var rights = []fileRights{
	{ConfigDir, 0o755, "root", "root"},
	{ConfigPath, 0o640, "root", User},
	{CertPath, 0o644, "root", "root"},
	{KeyPath, 0o640, "root", User},
}

// wrongRights are the files of the installation whose rights differ
// from the deploy's (missing ones are left alone: an ACME config has no
// certificate files).
func (x *deployer) wrongRights(ctx context.Context, env *jobs.Env) ([]fileRights, error) {
	ex, err := exec(ctx, env)
	if err != nil {
		return nil, err
	}
	var out []fileRights
	for _, r := range rights {
		fi, ok, err := remote.Stat(ctx, ex, r.path, sudo(env))
		if err != nil {
			return nil, err
		}
		if ok && (fi.Mode != r.mode || fi.Owner != r.owner || fi.Group != r.group) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (x *deployer) filesDone(ctx context.Context, env *jobs.Env) (bool, error) {
	w, err := x.wrongRights(ctx, env)
	return len(w) == 0 && err == nil, err
}

// files gives the files their rights back. Not undone: these are the
// rights the service runs with after every deploy.
func (x *deployer) files(ctx context.Context, env *jobs.Env) error {
	w, err := x.wrongRights(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if err := env.Set("changed", "1"); err != nil {
		return err
	}
	for _, r := range w {
		if err := remote.SetOwnerMode(ctx, ex, r.path, r.mode, r.owner, r.group, sudo(env)); err != nil {
			return jobs.Fail("Не удалось исправить права "+r.path+".", err)
		}
		env.Logf("Права %s: %04o %s:%s.", r.path, r.mode, r.owner, r.group)
	}
	return nil
}

// restartDone: nothing changed and the service runs.
func (x *deployer) restartDone(ctx context.Context, env *jobs.Env) (bool, error) {
	if env.Get("changed") == "1" {
		return false, nil
	}
	in, err := x.installed(ctx, env)
	if err != nil {
		return false, err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	st, err := remote.ActiveState(ctx, ex, in.Unit)
	if err == nil && st == "active" {
		env.Logf("Ничего не изменилось, служба работает: перезапуск не нужен.")
		return true, nil
	}
	return false, err
}

func (x *deployer) restart(ctx context.Context, env *jobs.Env) error {
	in, err := x.installed(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	// From here the rollback restarts the previous installation.
	if err := env.Set("changed", "1"); err != nil {
		return err
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceRestart, in.Unit, sudo(env)); err != nil {
		return jobs.Fail("Не удалось перезапустить "+in.Unit+".", err)
	}
	env.Logf("Служба %s перезапущена.", in.Unit)
	return nil
}

// currentConfig is the server's config as the controller has it (nil:
// none, or one that does not parse).
func (x *deployer) currentConfig(ctx context.Context, env *jobs.Env) (*hyconfig.Server, error) {
	cur, err := x.Store.CurrentConfig(ctx, env.ServerID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	b, err := x.Keys.Open(cur.Sealed, model.ConfigContext(env.ServerID, cur.Revision))
	if err != nil {
		return nil, err
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return nil, nil
	}
	return c, nil
}

// maintainVerify waits until the service runs the wanted version and
// Hysteria listens on the port of the config.
func (x *deployer) maintainVerify(ctx context.Context, env *jobs.Env, p MaintainParams) error {
	in, err := x.installed(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	var ub *remote.UntrustedBinaryError
	if v, err := remote.HysteriaVersion(ctx, ex, in.Binary); err != nil && !errors.As(err, &ub) {
		return err
	} else if v != "" && v != p.Version {
		return jobs.Fail(fmt.Sprintf("Бинарник на сервере сообщает версию %s вместо %s.", v, p.Version), nil)
	}
	c, err := x.currentConfig(ctx, env)
	if err != nil {
		return err
	}
	port, wait := 0, x.VerifyTimeout
	if c != nil {
		l, _ := hyconfig.ParseListen(c.Listen)
		port = l.First
		if c.ACME != nil {
			wait *= 3 // a lost certificate cache is issued again first
		}
	}
	deadline := x.Now().Add(wait)
	steady := false // active at the last poll too, with no port to look at
	for {
		st, err := remote.ActiveState(ctx, ex, in.Unit)
		if err != nil {
			return err
		}
		if st != "active" {
			steady = false
		} else {
			ls, err := remote.Listeners(ctx, ex, sudo(env))
			var noSS *remote.ExitError
			switch {
			case errors.As(err, &noSS) || port == 0:
				// Nothing to look at the port with: systemd is trusted once
				// the service stayed up for a poll.
				if steady {
					env.Logf("Служба %s работает (порт проверить нечем).", in.Unit)
					return nil
				}
				steady = true
			case err != nil:
				return err
			}
			for _, l := range ls {
				if l.Proto == "udp" && l.Port == port && strings.HasPrefix(l.Process, "hysteria") {
					env.Logf("Hysteria %s работает и принимает соединения на UDP %d.", p.Version, port)
					return nil
				}
			}
		}
		if st == "failed" || !x.Now().Before(deadline) {
			x.maintainJournal(ctx, env, ex, in.Unit)
			return jobs.Fail(fmt.Sprintf("Hysteria %s не заработала (служба: %s). Возвращается прежняя установка.", p.Version, st), nil)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(x.Poll):
		}
	}
}

// maintainJournal logs the unit's last lines, redacted with the
// passwords of the current config (the job itself has no secrets).
func (x *deployer) maintainJournal(ctx context.Context, env *jobs.Env, ex remote.Executor, unit string) {
	lines, err := remote.JournalTail(ctx, ex, unit, 20, sudo(env))
	if err != nil || len(lines) == 0 {
		return
	}
	r, err := service.Redactor(ctx, x.Store, x.Keys, env.ServerID)
	if err != nil {
		return
	}
	env.Logf("Последние строки журнала %s:", unit)
	for _, l := range lines {
		env.Logf("  %s", r.String(l))
	}
}

// maintainCommit records the version. The copies of the replaced files
// stay on the server (.hyroute-prev), as after a deploy.
func (x *deployer) maintainCommit(ctx context.Context, env *jobs.Env, p MaintainParams) error {
	in, err := x.installed(ctx, env)
	if err != nil {
		return err
	}
	if in.Version != p.Version {
		in.Version, in.At = p.Version, x.Now()
		if err := x.Store.SetInstallation(ctx, in); err != nil {
			return err
		}
	}
	if env.Get("binaryBackup") != "" && env.Get("binaryBackup") != remote.Absent {
		env.Logf("Прежний бинарник: %s%s.", in.Binary, Backup)
	}
	return nil
}

// maintained sets the server's state once the job has ended: healthy
// after success; after a failure the state from before, unless the
// rollback did not bring the previous installation back.
func (x *deployer) maintained(ctx context.Context, env *jobs.Env, j model.Job) {
	state := model.StateHealthy
	if j.State == model.JobFailed {
		switch {
		case env.Get("changed") == "1" && env.Rollback() != jobs.RollbackNothing && (env.Get("restored") != "1" || env.Rollback() == jobs.RollbackFailed):
			state = model.StateNeedsAttention
		case env.Get("prevState") != "":
			state = model.ServerState(env.Get("prevState"))
		default:
			return // nothing was touched
		}
	}
	x.Store.SetServerState(ctx, env.ServerID, state, x.Now())
}
