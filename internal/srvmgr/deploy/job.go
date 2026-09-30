package deploy

import (
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
}

// Deps are the deploy's collaborators.
type Deps struct {
	Store    Store
	Keys     *secrets.Keyring
	Resolver *hyrelease.Resolver
	Direct   hyrelease.Source
	Relay    hyrelease.Source
	Now      func() time.Time
	// VerifyTimeout bounds the wait for a started service (ACME waits
	// three times as long: the certificate is issued first).
	VerifyTimeout time.Duration
	Poll          time.Duration
}

type deployer struct{ Deps }

// Kind is the deploy job.
func Kind(d Deps) *jobs.Kind {
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
	x := &deployer{d}
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
	return []jobs.Step{
		{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: x.connect},
		{Name: "preflight", Phase: model.JobPreflight, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.preflight(ctx, env, p) }},
		{Name: "prepare", Phase: model.JobInstalling, Safe: true, Run: x.prepare, Undo: x.undoPrepare},
		{Name: "binary", Phase: model.JobDownloading, Safe: true,
			Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.binaryDone(ctx, env, p) },
			Run:  func(ctx context.Context, env *jobs.Env) error { return x.binary(ctx, env, p) },
			Undo: x.restoreFile(BinaryPath, "binaryBackup")},
		{Name: "user", Phase: model.JobInstalling, Safe: true, Done: x.userDone, Run: x.user},
		{Name: "tls", Phase: model.JobConfiguring, Safe: true,
			Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.tlsDone(ctx, env, p) },
			Run:  func(ctx context.Context, env *jobs.Env) error { return x.tls(ctx, env, p) },
			Undo: x.undoTLS},
		{Name: "config", Phase: model.JobConfiguring, Safe: true,
			Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.configDone(ctx, env, p) },
			Run:  func(ctx context.Context, env *jobs.Env) error { return x.config(ctx, env, p) },
			Undo: x.restoreFile(ConfigPath, "configBackup")},
		{Name: "unit", Phase: model.JobConfiguring, Safe: true, Done: x.unitDone, Run: x.unit, Undo: x.undoUnit},
		{Name: "firewall", Phase: model.JobFirewall, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.firewall(ctx, env, p) }, Undo: x.undoFirewall},
		{Name: "start", Phase: model.JobStarting, Safe: true, Done: x.startDone, Run: x.start, Undo: x.undoStart},
		{Name: "verify", Phase: model.JobVerifying, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.verify(ctx, env, p) }},
		{Name: "commit", Phase: model.JobVerifying, Safe: true,
			Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.commitDone(ctx, env, p) },
			Run:  func(ctx context.Context, env *jobs.Env) error { return x.commit(ctx, env, p) }},
		{Name: "cleanup", Phase: model.JobVerifying, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.cleanup(ctx, env, p) }},
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
		}
		return jobs.Fail("Сервер не готов: "+strings.Join(why, "; ")+".", nil)
	}
	for _, c := range r.Checks {
		if c.Level == preflight.Warn && c.ID != "hysteria" && c.ID != "port" {
			env.Warnf("%s. %s", c.Title, c.Details)
		}
	}
	env.Set("arch", r.HysteriaArch)
	env.Set("github", strconv.FormatBool(r.GitHub))
	env.Set("firewall", r.Firewall)

	if l.Hopping {
		ok := false
		for _, path := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/sbin/iptables", "/sbin/iptables"} {
			if e, err := remote.PathExists(ctx, ex, path, false); err != nil {
				return err
			} else if e {
				ok = true
				break
			}
		}
		if !ok {
			return jobs.Fail("Для диапазона портов Hysteria нужен nftables или iptables, а на сервере нет ни того, ни другого.", nil)
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
		env.Warnf("Hysteria на сервере установлена не HyRoute; её файлы будут заменены, прежние сохранятся с суффиксом %s.", Backup)
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

func (x *deployer) asset(ctx context.Context, env *jobs.Env, p Params) (hyrelease.Asset, error) {
	a, err := x.Resolver.Resolve(ctx, p.Version, env.Get("arch"))
	if err != nil {
		return a, jobs.Fail("Не удалось найти сборку Hysteria для сервера.", err)
	}
	return a, nil
}

func (x *deployer) binaryDone(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	a, err := x.asset(ctx, env, p)
	if err != nil {
		return false, err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	sum, err := remote.FileSHA256(ctx, ex, BinaryPath, sudo(env))
	if err != nil {
		return false, err
	}
	if sum == a.SHA256 {
		env.Logf("Hysteria %s уже установлена.", a.Version)
		return true, nil
	}
	return false, nil
}

func (x *deployer) binary(ctx context.Context, env *jobs.Env, p Params) error {
	a, err := x.asset(ctx, env, p)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	src := x.Relay
	if p.Source == SourceDirect || (p.Source == SourceAuto && env.Get("github") == "true") {
		src = x.Direct
	}
	su := sudo(env)
	dir, err := remote.TempDir(ctx, ex, su)
	if err != nil {
		return jobs.Fail("Не удалось создать временный каталог на сервере.", err)
	}
	defer remote.RemoveTempDir(context.WithoutCancel(ctx), ex, dir, su)
	tmp := dir + "/hysteria"
	how := map[string]string{"direct": "сервер скачивает сам", "relay": "через controller"}[src.Name()]
	env.Logf("Загрузка Hysteria %s (%s, %s).", a.Version, a.Name, how)
	if err := src.Fetch(ctx, ex, a, tmp, su); err != nil {
		if errors.Is(err, hyrelease.ErrChecksum) {
			return jobs.Fail("Скачанный файл Hysteria не совпадает с хешем релиза; установка отменена.", err)
		}
		return jobs.Fail("Не удалось загрузить Hysteria на сервер.", err)
	}
	env.Logf("SHA-256 совпал с хешем релиза.")
	if err := x.backup(ctx, env, ex, BinaryPath, "binaryBackup"); err != nil {
		return err
	}
	if err := remote.InstallFile(ctx, ex, tmp, BinaryPath, 0o755, "root", "root", su); err != nil {
		return jobs.Fail("Не удалось установить Hysteria.", err)
	}
	env.Logf("Установлено: %s.", BinaryPath)
	return nil
}

// backup records the state of the file at path (its SHA-256 or
// remote.Absent) under flag, then keeps a copy as path.hyroute-prev. The
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
	s := map[string]string{SecretAuth: env.Secret(SecretAuth), SecretObfs: env.Secret(SecretObfs)}
	if s[SecretAuth] == "" {
		return nil, model.ConfigMeta{}, errors.New("no auth secret")
	}
	c, err := BuildConfig(p, s)
	if err != nil {
		return nil, model.ConfigMeta{}, err
	}
	b, err := c.Marshal()
	return b, Meta(p, env.Get("pin")), err
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
		st, err := remote.ActiveState(ctx, ex, Unit)
		if err != nil {
			return err
		}
		if st == "failed" {
			x.journal(ctx, env, ex)
			return jobs.Fail("Hysteria остановилась с ошибкой сразу после запуска.", nil)
		}
		if st == "active" {
			ls, err := remote.Listeners(ctx, ex, sudo(env))
			if err != nil {
				// No ss: trust systemd.
				env.Logf("Служба работает (порт проверить нечем: нет ss).")
				return nil
			}
			for _, li := range ls {
				if li.Proto == "udp" && li.Port == l.First && li.Process == "hysteria" {
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
	}
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
		// not be): look at it.
		state = model.StateNeedsAttention
		if env.Get("changed") != "1" || env.Rollback() == jobs.RollbackNothing {
			state = model.ServerState(env.Get("prevState"))
			if state == "" {
				return
			}
		}
	}
	x.Store.SetServerState(ctx, env.ServerID, state, x.Now())
}
