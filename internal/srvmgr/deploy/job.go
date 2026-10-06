package deploy

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hy2uri"
	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/firewall"
	"github.com/lardan099/hyroute/internal/srvmgr/hopping"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// JobKind is the name of the deploy job.
const JobKind = "deploy"

// Store is what the deploy keeps in the controller's database.
type Store interface {
	store.Configs
	store.Installations
	ServerByID(ctx context.Context, id int64) (model.Server, error)
	SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error
	PresetByID(ctx context.Context, id int64) (model.Preset, error)
	// HostKey: the server's trusted SSH key (the source node's).
	HostKey(ctx context.Context, serverID int64) (model.HostKey, error)
}

// Deps are the deploy's collaborators.
type Deps struct {
	Store    Store
	Keys     *secrets.Keyring
	Resolver *hyrelease.Resolver
	Direct   hyrelease.Source
	// Relay (nil: one of its own) keeps the binary it downloaded last:
	// the Deps of Kind and Maintenance share it only when it is set.
	Relay hyrelease.Source
	// Nodes connects to another managed server that provides the binary
	// (source node; connect.Connector.Connect).
	Nodes func(ctx context.Context, serverID int64) (remote.Executor, error)
	Now   func() time.Time
	// VerifyTimeout bounds the wait for a started service (ACME waits
	// three times as long: the certificate is issued first).
	VerifyTimeout time.Duration
	Poll          time.Duration
}

type deployer struct{ Deps }

// withDefaults fills the unset Deps.
func withDefaults(d Deps) Deps {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.VerifyTimeout == 0 {
		d.VerifyTimeout = 40 * time.Second
	}
	if d.Poll == 0 {
		d.Poll = 2 * time.Second
	}
	if d.Direct == nil {
		d.Direct = hyrelease.Direct{}
	}
	if d.Relay == nil {
		d.Relay = hyrelease.NewRelay(d.Resolver)
	}
	return d
}

// Kind is the deploy job.
func Kind(d Deps) *jobs.Kind {
	x := &deployer{withDefaults(d)}
	return &jobs.Kind{
		Name: JobKind,
		Steps: func(raw json.RawMessage) ([]jobs.Step, error) {
			var p Params
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, err
			}
			if err := p.Normalize(); err != nil {
				return nil, err
			}
			return x.steps(p), nil
		},
		// Every step checks the server before acting: after a restart the
		// job simply goes on from the nearest safe step.
		Recover:  func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
		Finished: x.finished,
	}
}

func (x *deployer) steps(p Params) []jobs.Step {
	u := x.uncommitted
	return []jobs.Step{
		{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: x.connect},
		{Name: "preflight", Phase: model.JobPreflight, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.preflight(ctx, env, p) }},
		{Name: "prepare", Phase: model.JobInstalling, Safe: true, Run: x.prepare, Undo: u(x.undoPrepare)},
		{Name: "binary", Phase: model.JobDownloading, Safe: true,
			Done: func(ctx context.Context, env *jobs.Env) (bool, error) {
				return x.binaryDone(ctx, env, p.Version, BinaryPath)
			},
			Run: func(ctx context.Context, env *jobs.Env) error {
				// Another version than the recorded one, older too: say so.
				if in, err := x.Store.Installation(ctx, env.ServerID); err == nil && in.Version != "" && in.Version != p.Version {
					env.Logf("Hysteria %s → %s.", in.Version, p.Version)
				}
				return x.binary(ctx, env, p.Version, p.Source, p.Via, BinaryPath)
			},
			Undo: u(x.restoreFile(BinaryPath, "binaryBackup"))},
		{Name: "user", Phase: model.JobInstalling, Safe: true, Done: x.userDone, Run: x.user},
		{Name: "tls", Phase: model.JobConfiguring, Safe: true,
			Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.tlsDone(ctx, env, p) },
			Run:  func(ctx context.Context, env *jobs.Env) error { return x.tls(ctx, env, p) },
			Undo: u(x.undoTLS)},
		{Name: "config", Phase: model.JobConfiguring, Safe: true,
			Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.configDone(ctx, env, p) },
			Run:  func(ctx context.Context, env *jobs.Env) error { return x.config(ctx, env, p) },
			Undo: u(x.restoreFile(ConfigPath, "configBackup"))},
		{Name: "unit", Phase: model.JobConfiguring, Safe: true, Done: x.unitDone, Run: x.unit, Undo: u(x.undoUnit)},
		{Name: "firewall", Phase: model.JobFirewall, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.firewall(ctx, env, p) }, Undo: u(x.undoFirewall)},
		{Name: "start", Phase: model.JobStarting, Safe: true, Done: x.startDone, Run: x.start, Undo: u(x.undoStart)},
		{Name: "verify", Phase: model.JobVerifying, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.verify(ctx, env, p) }},
		{Name: "commit", Phase: model.JobVerifying, Safe: true,
			Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.commitDone(ctx, env, p) },
			Run:  func(ctx context.Context, env *jobs.Env) error { return x.commit(ctx, env, p) }},
		{Name: "cleanup", Phase: model.JobVerifying, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.cleanup(ctx, env, p) }},
	}
}

// committed: the controller's current revision is this job's.
func (x *deployer) committed(ctx context.Context, env *jobs.Env) (bool, error) {
	cur, err := x.Store.CurrentConfig(ctx, env.ServerID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && cur.JobID == env.JobID, err
}

// uncommitted is a step's undo until the commit stores the job's
// revision. After that the server keeps what it runs: a rollback would
// part it from the revision client links and the monitor go by, and a
// retry of the job finishes the commit instead.
func (x *deployer) uncommitted(undo func(context.Context, *jobs.Env) error) func(context.Context, *jobs.Env) error {
	return func(ctx context.Context, env *jobs.Env) error {
		switch done, err := x.committed(ctx, env); {
		case err != nil:
			return err
		case done:
			return jobs.ErrNothingToUndo
		}
		return undo(ctx, env)
	}
}

// sudo: commands that need root go through sudo (the SSH user is not root).
func sudo(env *jobs.Env) bool { return env.Get("root") != "true" }

func exec(ctx context.Context, env *jobs.Env) (remote.Executor, error) {
	ex, err := env.Exec(ctx)
	if err != nil {
		return nil, jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	return ex, nil
}

func (x *deployer) connect(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	pr, err := remote.RunProbe(ctx, ex)
	if err != nil {
		return jobs.Fail("Не удалось выполнить команды на сервере.", err)
	}
	if !pr.Privileged() {
		return jobs.Fail("Пользователь SSH не root и не может выполнять sudo без пароля.", nil)
	}
	b, _ := json.Marshal(pr)
	env.Set("probe", string(b))
	env.Set("root", strconv.FormatBool(pr.Root))
	env.Logf("Подключено как %s к %s (%s, %s).", pr.User, pr.Hostname, pr.Kernel, pr.Arch)
	return nil
}

func (x *deployer) preflight(ctx context.Context, env *jobs.Env, p Params) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	var pr remote.Probe
	if err := json.Unmarshal([]byte(env.Get("probe")), &pr); err != nil {
		return err
	}
	l, _ := hyconfig.ParseListen(p.Listen())
	r, err := preflight.Run(ctx, ex, pr, preflight.Options{UDPPort: l.First, TCPPorts: p.TCPPorts()})
	if err != nil {
		return jobs.Fail("Проверка сервера прервалась.", err)
	}
	env.Set("report", r.JSON())
	if r.Blocked {
		var why []string
		for _, c := range r.Checks {
			if c.Level == preflight.Fail {
				why = append(why, c.Title)
			}
			if c.Level == preflight.Fail && c.ID == preflight.ForeignPortCheck {
				env.Set("foreign", "1") // the UI offers the import
			}
		}
		return jobs.Fail("Сервер не готов: "+strings.Join(why, "; ")+".", nil)
	}
	for _, c := range r.Checks {
		// The Hysteria found, and the port it holds, are dealt with below;
		// a port nothing could look at (preflight.UncheckedPortCheck) is
		// for the admin to know.
		if c.Level == preflight.Warn && c.ID != "hysteria" && c.ID != "port" {
			env.Warnf("%s. %s", c.Title, c.Details)
		}
	}
	env.Set("arch", r.HysteriaArch)
	env.Set("github", strconv.FormatBool(r.GitHub))
	env.Set("firewall", r.Firewall)

	// The deploy does not put the site on the server: the folder must be
	// there already.
	if p.Masq.Type == MasqFile {
		if ok, err := remote.PathExists(ctx, ex, p.Masq.Dir, sudo(env)); err != nil {
			return err
		} else if !ok {
			return jobs.Fail(fmt.Sprintf("Папки сайта-маскировки %s на сервере нет. Создайте её, положите туда index.html и дайте пользователю hysteria право читать её.", p.Masq.Dir), nil)
		}
	}

	// The other ports of a hopping list: free, and a redirect tool for
	// each address family (preflight looked at the first).
	if l.Hopping {
		spec, rs, err := hopping.FromListen(p.Listen())
		if err != nil {
			return err
		}
		var he *hopping.Error
		switch err := hopping.Check(ctx, ex, spec, rs, sudo(env)); {
		case errors.As(err, &he):
			return jobs.Fail(he.Msg, nil)
		case errors.Is(err, hopping.ErrNoSS):
			env.Warnf("Не проверено, свободны ли порты %s: на сервере нет ss.", p.HopPorts)
		case err != nil:
			return err
		}
	}

	// Whose installation is it? Once this job has started changing the
	// server, a retry must not take its own files for someone else's.
	if env.Get("claimed") == "1" {
		return nil
	}
	imported := false
	if in, err := x.Store.Installation(ctx, env.ServerID); err == nil && !in.Managed {
		// An imported installation elsewhere would keep running next to
		// ours.
		if in.Unit != Unit || in.Config != ConfigPath {
			return jobs.Fail(fmt.Sprintf("Импортированная Hysteria работает как служба %s с конфигом %s. Развёртывание ставит Hysteria в стандартные места и такую установку не заменяет: остановите и отключите её вручную или управляйте ею как есть.", in.Unit, in.Config), nil)
		}
		imported = true
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if !r.Hysteria.Installed {
		env.Set("claimed", "1")
		return nil
	}
	managed, err := x.managed(ctx, env, ex, p)
	if err != nil {
		return err
	}
	switch {
	case managed:
		env.Logf("Hysteria на сервере установлена HyRoute: повторное развёртывание изменит только то, что отличается.")
	case p.Replace:
		if err := env.Set("replacing", "1"); err != nil {
			return err
		}
		env.Warnf("Hysteria на сервере установлена не HyRoute; её файлы будут заменены, прежние сохранятся с суффиксом %s (HyRoute их потом не меняет и не удаляет).", Original)
	case imported:
		return jobs.Fail("Hysteria на этом сервере импортирована, и HyRoute управляет ею как есть. Чтобы поставить вместо неё свою, разверните с заменой: прежние файлы сохранятся.", nil)
	default:
		env.Set("foreign", "1") // the UI offers the import
		return jobs.Fail("На сервере уже есть Hysteria, установленная не HyRoute. Импортируйте сервер, чтобы управлять ею как есть, или разверните с заменой.", nil)
	}
	env.Set("claimed", "1")
	return nil
}

// managed: the config on the server is the one the controller installed
// last (or the one this job installs).
func (x *deployer) managed(ctx context.Context, env *jobs.Env, ex remote.Executor, p Params) (bool, error) {
	// An imported installation is not ours even though its config is in
	// the controller.
	if in, err := x.Store.Installation(ctx, env.ServerID); err == nil && !in.Managed {
		return false, nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	sum, err := remote.FileSHA256(ctx, ex, ConfigPath, sudo(env))
	if err != nil || sum == "" {
		return false, err
	}
	if cur, err := x.Store.CurrentConfig(ctx, env.ServerID); err == nil && cur.SHA256 == sum {
		return true, nil
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	want, _, err := x.configYAML(env, p)
	return err == nil && sha(want) == sum, nil
}

func (x *deployer) prepare(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	st, err := remote.ActiveState(ctx, ex, Unit)
	if err != nil {
		return err
	}
	env.Set("prevActive", strconv.FormatBool(st == "active"))
	env.Set("changed", "")
	srv, err := x.Store.ServerByID(ctx, env.ServerID)
	if err != nil {
		return err
	}
	if srv.State != model.StateDeploying {
		env.Set("prevState", string(srv.State))
	}
	return x.Store.SetServerState(ctx, env.ServerID, model.StateDeploying, x.Now())
}

// undoPrepare runs last in a rollback, when the files are back: the
// previous installation starts again.
func (x *deployer) undoPrepare(ctx context.Context, env *jobs.Env) error {
	if env.Get("changed") != "1" || env.Get("prevActive") != "true" {
		return jobs.ErrNothingToUndo
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceRestart, Unit, sudo(env)); err != nil {
		return err
	}
	env.Logf("Прежняя версия Hysteria запущена снова.")
	return nil
}

func (x *deployer) asset(ctx context.Context, env *jobs.Env, version string) (hyrelease.Asset, error) {
	a, err := x.Resolver.Resolve(ctx, version, env.Get("arch"))
	if err != nil {
		if v := cmp.Or(version, hyrelease.DefaultVersion); !hyrelease.Pinned(v) {
			// The hashes come from GitHub, through the controller only: a
			// node or the server itself is not trusted with them.
			return a, jobs.Fail(fmt.Sprintf("Controller не получил хеши релиза Hysteria %s с GitHub: такой версии нет или GitHub недоступен. Без доступа controller к GitHub ставится только версия %s — её хеши встроены в HyRoute.", v, hyrelease.DefaultVersion), err)
		}
		return a, jobs.Fail("Не удалось найти сборку Hysteria для сервера.", err)
	}
	return a, nil
}

// binaryDone: the file at path is the release binary of version.
func (x *deployer) binaryDone(ctx context.Context, env *jobs.Env, version, path string) (bool, error) {
	a, err := x.asset(ctx, env, version)
	if err != nil {
		return false, err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	sum, err := remote.FileSHA256(ctx, ex, path, sudo(env))
	if err != nil {
		return false, err
	}
	if sum == a.SHA256 {
		env.Logf("Hysteria %s уже установлена, SHA-256 совпадает с хешем релиза.", a.Version)
		return true, nil
	}
	return false, nil
}

// binary puts the release binary of version at path: downloaded from
// source, checked against the release hash, with a copy of the file it
// replaces (restoreFile(path, "binaryBackup") undoes it).
func (x *deployer) binary(ctx context.Context, env *jobs.Env, version, source string, via int64, path string) error {
	a, err := x.asset(ctx, env, version)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	src := x.Relay
	how := "через controller"
	switch {
	case source == SourceNode:
		n, err := x.node(ctx, via)
		if err != nil {
			return err
		}
		src, how = n, "через сервер «"+n.Server+"»"
	case source == SourceDirect || ((source == SourceAuto || source == "") && env.Get("github") == "true"):
		src, how = x.Direct, "сервер скачивает сам"
	}
	su := sudo(env)
	dir, err := remote.TempDir(ctx, ex, su)
	if err != nil {
		return jobs.Fail("Не удалось создать временный каталог на сервере.", err)
	}
	defer remote.RemoveTempDir(context.WithoutCancel(ctx), ex, dir, su)
	tmp := dir + "/hysteria"
	env.Logf("Загрузка Hysteria %s (%s, %s).", a.Version, a.Name, how)
	if err := src.Fetch(ctx, ex, a, tmp, su); err != nil {
		var de *hyrelease.DownloadError
		switch {
		case errors.Is(err, hyrelease.ErrChecksum):
			return jobs.Fail("Скачанный файл Hysteria не совпадает с хешем релиза; установка отменена.", err)
		case errors.As(err, &de) && env.Get("github") == "false":
			return jobs.Fail("С сервера GitHub недоступен, а controller не скачал Hysteria. Выберите загрузку через другой сервер, которому GitHub доступен.", err)
		case errors.As(err, &de):
			return jobs.Fail("Controller не скачал Hysteria с GitHub. Выберите загрузку самим сервером или через другой сервер.", err)
		}
		return jobs.Fail("Не удалось загрузить Hysteria на сервер.", err)
	}
	env.Logf("SHA-256 совпал с хешем релиза.")
	if err := x.backup(ctx, env, ex, path, "binaryBackup"); err != nil {
		return err
	}
	if err := remote.InstallFile(ctx, ex, tmp, path, 0o755, "root", "root", su); err != nil {
		return jobs.Fail("Не удалось установить Hysteria.", err)
	}
	env.Logf("Установлено: %s.", path)
	return nil
}

// backup records the state of the file at path (its SHA-256 or
// remote.Absent) under flag, then keeps a copy as path.hyroute-prev (and
// path.hyroute-orig when the job replaces a foreign installation). The
// record reaches the database before the copy and before the caller
// changes path, so the rollback of an interrupted job knows what was
// there. It also marks the job as changing the server.
//
// A step run again (after a restart or a retry) keeps the first record:
// the file may be this job's already, and its copy is the original.
func (x *deployer) backup(ctx context.Context, env *jobs.Env, ex remote.Executor, path, flag string) error {
	state, err := remote.FileState(ctx, ex, path, sudo(env))
	if err != nil {
		return err
	}
	if prev := env.Get(flag); prev != "" && prev != "1" {
		if prev != state {
			return env.Set("changed", "1") // changed by this job already
		}
	} else if err := env.Set(flag, state); err != nil {
		return err
	}
	if err := env.Set("changed", "1"); err != nil {
		return err
	}
	if state == remote.Absent {
		return nil
	}
	if err := remote.CopyFile(ctx, ex, path, path+Backup, sudo(env)); err != nil {
		return jobs.Fail("Не удалось сохранить копию "+path+".", err)
	}
	// The files of a replaced installation stay for good: the next change
	// of the file reuses .hyroute-prev.
	if env.Get("replacing") == "1" {
		if ok, err := remote.PathExists(ctx, ex, path+Original, sudo(env)); err != nil {
			return err
		} else if !ok {
			if err := remote.CopyFile(ctx, ex, path, path+Original, sudo(env)); err != nil {
				return jobs.Fail("Не удалось сохранить копию "+path+".", err)
			}
		}
	}
	return nil
}

// restoreFile undoes a replaced file: the backup goes back, or the new
// file goes away when there was none. A file whose state was never
// recorded was not touched by this job and stays as it is.
func (x *deployer) restoreFile(path, flag string) func(context.Context, *jobs.Env) error {
	return func(ctx context.Context, env *jobs.Env) error {
		state := env.Get(flag)
		switch state {
		case "":
			return jobs.ErrNothingToUndo
		case "1":
			// Recorded by an older controller: a backup was made.
			state = ""
		}
		ex, err := exec(ctx, env)
		if err != nil {
			return err
		}
		if state == "" {
			if ok, err := remote.PathExists(ctx, ex, path+Backup, sudo(env)); err != nil || !ok {
				return err
			}
			return remote.Rename(ctx, ex, path+Backup, path, sudo(env))
		}
		changed, err := remote.RestoreFile(ctx, ex, path, path+Backup, state, sudo(env))
		if errors.Is(err, remote.ErrBackupMismatch) {
			return fmt.Errorf("%w: %s оставлен как есть, проверьте его вручную", err, path)
		}
		if err == nil && !changed {
			return jobs.ErrNothingToUndo
		}
		return err
	}
}

func (x *deployer) userDone(ctx context.Context, env *jobs.Env) (bool, error) {
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	return remote.UserExists(ctx, ex, User)
}

func (x *deployer) user(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if err := remote.CreateSystemUser(ctx, ex, User, Home, sudo(env)); err != nil {
		return jobs.Fail("Не удалось создать системного пользователя hysteria.", err)
	}
	env.Logf("Создан системный пользователь %s (домашний каталог %s).", User, Home)
	return nil
}

func (x *deployer) tlsDone(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	if p.TLS == TLSACME {
		return remote.PathExists(ctx, ex, ConfigDir, false)
	}
	cert, err := ex.ReadFile(ctx, CertPath, sudo(env))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	pin, err := Pin(cert)
	if err != nil {
		return false, nil // not ours: replace it
	}
	if ok, err := remote.PathExists(ctx, ex, KeyPath, sudo(env)); err != nil || !ok {
		return false, err
	}
	// Our certificate: the one of this job, or the one of the current
	// revision (a redeploy keeps it, so the client pin stays).
	mine, _ := Pin([]byte(env.Secret(SecretCert)))
	cur, err := x.Store.CurrentConfig(ctx, env.ServerID)
	if pin == mine || (err == nil && cur.Meta.PinSHA256 == pin) {
		env.Set("pin", pin)
		return true, nil
	}
	return false, nil
}

func (x *deployer) tls(ctx context.Context, env *jobs.Env, p Params) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	su := sudo(env)
	if err := remote.MakeDir(ctx, ex, ConfigDir, 0o755, "root", "root", su); err != nil {
		return jobs.Fail("Не удалось создать "+ConfigDir+".", err)
	}
	if p.TLS == TLSACME {
		env.Logf("Сертификат для %s выпустит Let's Encrypt при запуске Hysteria.", p.Domain)
		return nil
	}
	cert, key := env.Secret(SecretCert), env.Secret(SecretKey)
	pin, err := Pin([]byte(cert))
	if err != nil || key == "" {
		return jobs.Fail("Нет сертификата для развёртывания.", err)
	}
	if err := x.backup(ctx, env, ex, CertPath, "certBackup"); err != nil {
		return err
	}
	if err := x.backup(ctx, env, ex, KeyPath, "keyBackup"); err != nil {
		return err
	}
	if err := env.Set("tlsWritten", "1"); err != nil {
		return err
	}
	if err := ex.WriteFile(ctx, CertPath, []byte(cert), remote.FileSpec{Mode: 0o644, Sudo: su}); err != nil {
		return jobs.Fail("Не удалось записать сертификат.", err)
	}
	if err := ex.WriteFile(ctx, KeyPath, []byte(key), remote.FileSpec{Mode: 0o640, Group: User, Sudo: su}); err != nil {
		return jobs.Fail("Не удалось записать ключ сертификата.", err)
	}
	env.Set("pin", pin)
	env.Logf("Самоподписанный сертификат установлен; клиенты проверяют его по pinSHA256 %s.", pin)
	return nil
}

func (x *deployer) undoTLS(ctx context.Context, env *jobs.Env) error {
	if env.Get("tlsWritten") != "1" {
		return jobs.ErrNothingToUndo // ACME: nothing was written
	}
	cerr := x.restoreFile(CertPath, "certBackup")(ctx, env)
	kerr := x.restoreFile(KeyPath, "keyBackup")(ctx, env)
	for _, err := range []error{cerr, kerr} {
		if err != nil && !errors.Is(err, jobs.ErrNothingToUndo) {
			return err
		}
	}
	if cerr != nil && kerr != nil {
		return jobs.ErrNothingToUndo
	}
	return nil
}

// configYAML is the config this job installs and its meta.
func (x *deployer) configYAML(env *jobs.Env, p Params) ([]byte, model.ConfigMeta, error) {
	c, err := BuildConfig(p, secretsOf(env.Secret))
	if err != nil {
		return nil, model.ConfigMeta{}, err
	}
	b, err := c.Marshal()
	m := Meta(p, env.Get("pin"))
	m.Auth = strings.ToLower(c.Auth.Type)
	return b, m, err
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (x *deployer) configDone(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	want, _, err := x.configYAML(env, p)
	if err != nil {
		return false, jobs.Fail("Не удалось составить конфиг Hysteria.", err)
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	sum, err := remote.FileSHA256(ctx, ex, ConfigPath, sudo(env))
	return sum == sha(want), err
}

func (x *deployer) config(ctx context.Context, env *jobs.Env, p Params) error {
	want, _, err := x.configYAML(env, p)
	if err != nil {
		return jobs.Fail("Не удалось составить конфиг Hysteria.", err)
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if err := x.backup(ctx, env, ex, ConfigPath, "configBackup"); err != nil {
		return err
	}
	// Passwords inside: readable by root and the service only.
	if err := ex.WriteFile(ctx, ConfigPath, want, remote.FileSpec{Mode: 0o640, Group: User, Sudo: sudo(env)}); err != nil {
		return jobs.Fail("Не удалось записать конфиг.", err)
	}
	env.Logf("Конфиг записан: %s (listen %s).", ConfigPath, p.Listen())
	if n := p.presetNote(); n != "" {
		env.Logf("%s", n)
	}
	return nil
}

func (x *deployer) unitDone(ctx context.Context, env *jobs.Env) (bool, error) {
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	b, err := ex.ReadFile(ctx, UnitPath, sudo(env))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if string(b) != UnitText {
		return false, nil
	}
	res, err := ex.Run(ctx, remote.Cmd{Args: []string{"systemctl", "is-enabled", "--", Unit}})
	return err == nil && res.OK(), err
}

func (x *deployer) unit(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	su := sudo(env)
	if err := x.backup(ctx, env, ex, UnitPath, "unitBackup"); err != nil {
		return err
	}
	if err := ex.WriteFile(ctx, UnitPath, []byte(UnitText), remote.FileSpec{Mode: 0o644, Sudo: su}); err != nil {
		return jobs.Fail("Не удалось записать службу systemd.", err)
	}
	if err := remote.DaemonReload(ctx, ex, su); err != nil {
		return jobs.Fail("systemd не перечитал службы.", err)
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceEnable, Unit, su); err != nil {
		return jobs.Fail("Не удалось включить автозапуск службы.", err)
	}
	env.Logf("Служба %s установлена и включена в автозапуск.", Unit)
	return nil
}

func (x *deployer) undoUnit(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if env.Get("unitBackup") == "" {
		return jobs.ErrNothingToUndo
	}
	if env.Get("unitBackup") == remote.Absent {
		// A fresh install: nothing to start at boot.
		remote.Systemctl(ctx, ex, remote.ServiceDisable, Unit, sudo(env))
	}
	if err := x.restoreFile(UnitPath, "unitBackup")(ctx, env); err != nil && !errors.Is(err, jobs.ErrNothingToUndo) {
		return err
	}
	return remote.DaemonReload(ctx, ex, sudo(env))
}

// ports are what clients and the ACME challenge need reachable.
func ports(p Params) []remote.PortSpec {
	var specs []remote.PortSpec
	rs, _ := hy2uri.ParsePorts(p.Ports())
	for _, r := range rs {
		specs = append(specs, remote.PortSpec{From: int(r.From), To: int(r.To), Proto: "udp"})
	}
	for _, tp := range p.TCPPorts() {
		specs = append(specs, remote.PortSpec{From: tp, To: tp, Proto: "tcp"})
	}
	return specs
}

// firewall opens the ports before the service starts; the rules it adds
// are recorded in the job first, and the rollback closes them.
func (x *deployer) firewall(ctx context.Context, env *jobs.Env, p Params) error {
	tool := env.Get("firewall")
	specs := ports(p)
	list := firewall.List(specs)
	if p.KeepFirewall {
		env.Logf("Брандмауэр не трогаем (так выбрано). Нужные порты: %s.", list)
		return nil
	}
	switch {
	case firewall.Managed(tool):
		ex, err := exec(ctx, env)
		if err != nil {
			return err
		}
		return firewall.Open(ctx, env, ex, tool, specs, sudo(env))
	case tool == "nftables" || tool == "iptables":
		env.Warnf("Входящие соединения закрыты политикой %s. HyRoute не меняет такие правила сам: откройте %s вручную.", tool, list)
	default:
		env.Logf("Брандмауэр не ограничивает входящие соединения; порты: %s.", list)
	}
	return nil
}

func (x *deployer) undoFirewall(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	return firewall.Undo(ctx, env, ex, sudo(env))
}

// fwRecord is what the controller records about the firewall after this
// deploy.
func fwRecord(env *jobs.Env, p Params, prev model.Firewall) model.Firewall {
	fw := firewall.Record(env, prev)
	fw.Keep = p.KeepFirewall
	return fw
}

// cleanup closes the rules HyRoute opened for ports the new config no
// longer uses. It runs after the commit and never fails the job: the
// deploy is done by then, and a rollback would undo it.
func (x *deployer) cleanup(ctx context.Context, env *jobs.Env, p Params) error {
	if err := x.cleanupFirewall(ctx, env, ports(p)); ctx.Err() != nil {
		return ctx.Err() // the controller is stopping: the step runs again
	} else if err != nil {
		env.Warnf("Старые правила брандмауэра не проверены: %v.", err)
	}
	return nil
}

func (x *deployer) cleanupFirewall(ctx context.Context, env *jobs.Env, want []remote.PortSpec) error {
	in, err := x.Store.Installation(ctx, env.ServerID)
	if err != nil {
		return err
	}
	if in.Firewall.Keep || !firewall.Managed(in.Firewall.Tool) {
		return nil
	}
	ex, err := env.Exec(ctx)
	if err != nil {
		return err
	}
	fw := firewall.Cleanup(ctx, env, ex, in.Firewall, env.Get("firewall"), want, sudo(env))
	if fw == in.Firewall {
		return nil
	}
	return x.Store.SetFirewall(ctx, env.ServerID, fw)
}

func (x *deployer) startDone(ctx context.Context, env *jobs.Env) (bool, error) {
	if env.Get("changed") == "1" {
		return false, nil
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	st, err := remote.ActiveState(ctx, ex, Unit)
	if err == nil && st == "active" {
		env.Logf("Ничего не изменилось, служба работает: перезапуск не нужен.")
		return true, nil
	}
	return false, err
}

func (x *deployer) start(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if err := env.Set("started", "1"); err != nil {
		return err
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceRestart, Unit, sudo(env)); err != nil {
		x.journal(ctx, env, ex)
		return jobs.Fail("Служба Hysteria не запустилась.", err)
	}
	env.Logf("Служба %s запущена.", Unit)
	return nil
}

func (x *deployer) undoStart(ctx context.Context, env *jobs.Env) error {
	if env.Get("started") != "1" {
		return jobs.ErrNothingToUndo // the running service was left alone
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	return remote.Systemctl(ctx, ex, remote.ServiceStop, Unit, sudo(env))
}

// journal copies the service's last lines into the job log (redacted by
// the job log).
func (x *deployer) journal(ctx context.Context, env *jobs.Env, ex remote.Executor) {
	lines, err := remote.JournalTail(ctx, ex, Unit, 20, sudo(env))
	if err != nil || len(lines) == 0 {
		return
	}
	env.Warnf("Журнал службы:\n%s", strings.Join(lines, "\n"))
}

func (x *deployer) verify(ctx context.Context, env *jobs.Env, p Params) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	l, _ := hyconfig.ParseListen(p.Listen())
	timeout := x.VerifyTimeout
	if p.TLS == TLSACME {
		timeout *= 3
		env.Logf("Ожидание сертификата Let's Encrypt для %s…", p.Domain)
	}
	deadline := x.Now().Add(timeout)
	for {
		u, err := remote.Unit(ctx, ex, Unit)
		if err != nil {
			return err
		}
		st := u.ActiveState
		if st == "failed" {
			x.journal(ctx, env, ex)
			return jobs.Fail("Hysteria остановилась с ошибкой сразу после запуска.", nil)
		}
		if st == "active" {
			ls, err := remote.Listeners(ctx, ex, sudo(env))
			var noSS *remote.ExitError
			switch {
			case errors.As(err, &noSS):
				// No ss to look at the port with. systemd calls a service
				// "active" also while it still gets its certificate or
				// between the restarts of a crash loop: its own process
				// must have said it serves.
				up, err := serving(ctx, ex, u.MainPID, sudo(env))
				if err != nil {
					return err
				}
				if up {
					env.Logf("Hysteria работает: служба сообщила «server up and running» (порт проверить нечем: нет ss).")
					return nil
				}
			case err != nil:
				return err
			}
			for _, li := range ls {
				// The service's own process: another Hysteria on the port
				// (its own unit, a container) is not this deploy working.
				if li.Proto == "udp" && li.Port == l.First && li.Process == "hysteria" && li.PID == u.MainPID {
					env.Logf("Hysteria работает и принимает соединения на UDP %d.", l.First)
					return nil
				}
			}
		}
		if !x.Now().Before(deadline) {
			x.journal(ctx, env, ex)
			return jobs.Fail(fmt.Sprintf("Hysteria не начала принимать соединения на UDP %d за %s.", l.First, timeout), errors.New("service state "+st))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(x.Poll):
		}
	}
}

// serving: the unit's running process pid logged "server up and running",
// which Hysteria does once it has its certificate and takes clients.
func serving(ctx context.Context, ex remote.Executor, pid int, su bool) (bool, error) {
	if pid == 0 {
		return false, nil
	}
	es, err := remote.JournalEntries(ctx, ex, Unit, 200, su)
	if err != nil {
		return false, err
	}
	for _, e := range es {
		if e.PID == pid && strings.Contains(e.Message, "server up and running") {
			return true, nil
		}
	}
	return false, nil
}

func (x *deployer) commitDone(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	want, meta, err := x.configYAML(env, p)
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
	fw := in.Firewall
	in.Firewall = model.Firewall{}
	return cur.SHA256 == sha(want) && cur.Meta == meta && in == x.installation(env, p, in.At) && fw == fwRecord(env, p, fw), nil
}

// installation is what a deploy puts on the server.
func (x *deployer) installation(env *jobs.Env, p Params, at time.Time) model.Installation {
	return model.Installation{ServerID: env.ServerID, Binary: BinaryPath, Config: ConfigPath, Unit: Unit, User: User, Version: p.Version, Managed: true, At: at}
}

func (x *deployer) commit(ctx context.Context, env *jobs.Env, p Params) error {
	want, meta, err := x.configYAML(env, p)
	if err != nil {
		return err
	}
	now := x.Now()
	cur, err := x.Store.CurrentConfig(ctx, env.ServerID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err == nil && cur.SHA256 == sha(want) && cur.Meta == meta {
		env.Logf("Конфиг совпадает с ревизией %d в controller.", cur.Revision)
	} else {
		c := model.ServerConfig{ServerID: env.ServerID, SHA256: sha(want), Meta: meta, Source: model.ConfigDeploy, JobID: env.JobID, By: env.CreatedBy, At: now}
		err = x.Store.AddConfig(ctx, &c, func(rev int) ([]byte, error) {
			return x.Keys.Seal(want, model.ConfigContext(env.ServerID, rev))
		})
		if err != nil {
			return err
		}
		env.Logf("Конфиг сохранён в controller как ревизия %d.", c.Revision)
		cur = c
	}
	err = x.record(ctx, env, p, now)
	if err != nil && cur.JobID == env.JobID {
		// The rollback leaves the server as it is (uncommitted), and a
		// retry starts at this step.
		return jobs.Fail("Hysteria работает с новым конфигом, и он сохранён в controller, но установку записать не удалось. Повторите задание: сервер оно больше не изменит.", err)
	}
	return err
}

// record stores the installation and the firewall rules the deploy left.
func (x *deployer) record(ctx context.Context, env *jobs.Env, p Params, now time.Time) error {
	prev, err := x.Store.Installation(ctx, env.ServerID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err := x.Store.SetInstallation(ctx, x.installation(env, p, now)); err != nil {
		return err
	}
	return x.Store.SetFirewall(ctx, env.ServerID, fwRecord(env, p, prev.Firewall))
}

func (x *deployer) finished(ctx context.Context, env *jobs.Env, j model.Job) {
	state := model.StateHealthy
	if j.State == model.JobFailed {
		// Something on the server changed and was rolled back (or could
		// not be, or stays for a retry of the commit): look at it.
		state = model.StateNeedsAttention
		if committed, _ := x.committed(ctx, env); !committed && (env.Get("changed") != "1" || env.Rollback() == jobs.RollbackNothing) {
			state = model.ServerState(env.Get("prevState"))
			if state == "" {
				return
			}
		}
	}
	x.Store.SetServerState(ctx, env.ServerID, state, x.Now())
}

// node is the source that takes the binary from managed server via: its
// installed Hysteria when that is the release's file, else a download of
// its own.
func (x *deployer) node(ctx context.Context, via int64) (*hyrelease.Node, error) {
	if x.Nodes == nil {
		return nil, jobs.Fail("Загрузка через другой сервер здесь недоступна.", nil)
	}
	srv, err := x.Store.ServerByID(ctx, via)
	if errors.Is(err, store.ErrNotFound) {
		return nil, jobs.Fail("Сервера, через который загружать Hysteria, больше нет.", nil)
	} else if err != nil {
		return nil, err
	}
	n := &hyrelease.Node{Server: srv.Name, Open: func(ctx context.Context) (remote.Executor, bool, error) {
		ex, err := x.Nodes(ctx, via)
		if err != nil {
			return nil, false, err
		}
		p, err := remote.RunProbe(ctx, ex)
		if err != nil {
			ex.Close()
			return nil, false, err
		}
		// sudo where the node has it: a user without it still reads the
		// installed binary and downloads into a temporary directory of
		// its own.
		return ex, !p.Root && p.Sudo, nil
	}}
	if in, err := x.Store.Installation(ctx, via); err == nil {
		n.Installed = in.Binary
	}
	return n, nil
}
