package apply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/firewall"
	"github.com/lardan099/hyroute/internal/srvmgr/hopping"
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
	// From is the revision a rollback installs again (0: an edit).
	From int `json:"from,omitempty"`
	// Rotated says what a rotation replaces ("auth", "user:<name>",
	// "obfs", "cert"); empty for an edit or a rollback.
	Rotated []string `json:"rotated,omitempty"`
	// Pin is of the new certificate a rotation installs (in the job's
	// secrets with its key).
	Pin string `json:"pin,omitempty"`
	// Preset and Sections: the preset whose sections the job lays over
	// the config (for the log and the job page).
	Preset   string   `json:"preset,omitempty"`
	Sections []string `json:"sections,omitempty"`
	// Change names an edit made by a part of the panel (ChangeRouting).
	Change string `json:"change,omitempty"`
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
			// A retry of prepare, cert or install starts at validate: the
			// config on the server is checked again (a rollback brought
			// the previous one back, and it may have been edited since).
			steps := []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: x.connect},
				{Name: "validate", Phase: model.JobPreflight, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.validate(ctx, env, p) }},
				{Name: "prepare", Phase: model.JobConfiguring, Run: x.prepare, Undo: x.undoPrepare},
			}
			if p.Pin != "" {
				// A rotation of the certificate.
				steps = append(steps, jobs.Step{Name: "cert", Phase: model.JobConfiguring,
					Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.certDone(ctx, env, p) },
					Run:  func(ctx context.Context, env *jobs.Env) error { return x.cert(ctx, env, p) },
					Undo: x.undoCert})
			}
			return append(steps, []jobs.Step{
				{Name: "install", Phase: model.JobConfiguring,
					Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.installed(ctx, env, p) },
					Run:  func(ctx context.Context, env *jobs.Env) error { return x.install(ctx, env, p) },
					Undo: x.undoInstall},
				{Name: "firewall", Phase: model.JobFirewall, Safe: true, Run: x.firewall, Undo: x.undoFirewall},
				{Name: "restart", Phase: model.JobStarting, Safe: true, Run: x.restart},
				{Name: "verify", Phase: model.JobVerifying, Safe: true, Run: x.verify},
				{Name: "commit", Phase: model.JobVerifying, Safe: true,
					Done: func(ctx context.Context, env *jobs.Env) (bool, error) { return x.committed(ctx, env, p) },
					Run:  func(ctx context.Context, env *jobs.Env) error { return x.commit(ctx, env, p) }},
				{Name: "cleanup", Phase: model.JobVerifying, Safe: true, Run: x.cleanup},
			}...), nil
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
	if err := x.checkPorts(ctx, env, ex, c); err != nil {
		return err
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
// changes it, then keeps a copy. A run again keeps the first record, and
// copies again while the config is in that state: a rollback in between
// took the earlier copy back. A config in another state is this job's
// already, and the copy is the original.
func (x *applier) backup(ctx context.Context, env *jobs.Env, ex remote.Executor, in model.Installation) error {
	state, err := remote.FileState(ctx, ex, in.Config, sudo(env))
	if err != nil {
		return err
	}
	if prev := env.Get("configState"); prev != "" && prev != state {
		return nil
	}
	if err := env.Set("configState", state); err != nil {
		return err
	}
	if err := remote.CopyFile(ctx, ex, in.Config, in.Config+Backup, sudo(env)); err != nil {
		return jobs.Fail("Не удалось сохранить копию конфига.", err)
	}
	env.Logf("Копия прежнего конфига: %s%s.", in.Config, Backup)
	return nil
}

// backupFile records the state of the file at path under flag (its
// SHA-256 or remote.Absent) before anything changes it, then keeps a copy
// as path.hyroute-prev. A run again keeps the first record and copies
// again while the file is in that state; in another state the file is
// this job's already, and the copy is the original.
func (x *applier) backupFile(ctx context.Context, env *jobs.Env, ex remote.Executor, path, flag string) error {
	state, err := remote.FileState(ctx, ex, path, sudo(env))
	if err != nil {
		return err
	}
	if prev := env.Get(flag); prev != "" && prev != state {
		return nil
	}
	if err := env.Set(flag, state); err != nil {
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

// restoreFile puts back the file backupFile recorded under flag.
func (x *applier) restoreFile(ctx context.Context, env *jobs.Env, path, flag string) error {
	state := env.Get(flag)
	if state == "" {
		return jobs.ErrNothingToUndo
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
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

// certFiles are where the candidate keeps its certificate and key.
func certFiles(env *jobs.Env) (cert, key string, err error) {
	_, c, err := candidate(env)
	if err != nil {
		return "", "", err
	}
	if c.TLS == nil || c.TLS.Cert == "" || c.TLS.Key == "" {
		return "", "", jobs.Fail("В конфиге нет файлов сертификата.", nil)
	}
	return c.TLS.Cert, c.TLS.Key, nil
}

// certDone: the new certificate is in place.
func (x *applier) certDone(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	cert, _, err := certFiles(env)
	if err != nil {
		return false, err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	b, err := ex.ReadFile(ctx, cert, sudo(env))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	pin, _ := deploy.Pin(b)
	return pin == p.Pin, nil
}

// cert writes the new certificate and key of a rotation over the files
// the config names, keeping copies and the rights of the old files.
func (x *applier) cert(ctx context.Context, env *jobs.Env, p Params) error {
	cert, key, err := certFiles(env)
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
	certPEM, keyPEM := env.Secret(SecretCert), env.Secret(SecretKey)
	if pin, err := deploy.Pin([]byte(certPEM)); err != nil || pin != p.Pin || keyPEM == "" {
		return jobs.Fail("Нового сертификата в задании нет.", err)
	}
	for _, f := range []struct {
		path, flag string
		data       string
		spec       remote.FileSpec
	}{
		{cert, "certState", certPEM, remote.FileSpec{Mode: 0o644}},
		{key, "keyState", keyPEM, remote.FileSpec{Mode: 0o640, Group: in.User}},
	} {
		if err := x.backupFile(ctx, env, ex, f.path, f.flag); err != nil {
			return err
		}
		fi, ok, err := remote.Stat(ctx, ex, f.path, sudo(env))
		if err != nil {
			return err
		}
		spec := f.spec
		if ok {
			spec.Mode, spec.Owner, spec.Group = fi.Mode, fi.Owner, fi.Group
		}
		spec.Sudo = sudo(env)
		if err := env.Set("changed", "1"); err != nil {
			return err
		}
		if err := ex.WriteFile(ctx, f.path, []byte(f.data), spec); err != nil {
			return jobs.Fail("Не удалось записать "+f.path+".", err)
		}
	}
	env.Logf("Новый самоподписанный сертификат записан: %s; pinSHA256 %s.", cert, p.Pin)
	return nil
}

func (x *applier) undoCert(ctx context.Context, env *jobs.Env) error {
	if env.Get("certState") == "" && env.Get("keyState") == "" {
		return jobs.ErrNothingToUndo
	}
	cert, key, err := certFiles(env)
	if err != nil {
		return err
	}
	cerr := x.restoreFile(ctx, env, cert, "certState")
	kerr := x.restoreFile(ctx, env, key, "keyState")
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

// install writes the candidate, with a copy of the config it replaces
// made right before (also when a retry runs it again after a rollback).
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
	if err := x.backup(ctx, env, ex, in); err != nil {
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

// checkPorts: when the candidate listens on other ports, the server can
// take them (no other program on those UDP ports; for hopping, the
// redirect tool for each address family).
func (x *applier) checkPorts(ctx context.Context, env *jobs.Env, ex remote.Executor, c *hyconfig.Server) error {
	if strings.Contains(c.Listen, "://") {
		return nil // Realms: no ports of its own
	}
	if cur, err := x.current(ctx, env); err != nil {
		return err
	} else if cur != nil && cur.Listen == c.Listen {
		return nil
	}
	spec, rs, err := hopping.FromListen(c.Listen)
	if err != nil {
		return jobs.Fail("Порты конфига: "+err.Error()+".", nil)
	}
	var he *hopping.Error
	switch err := hopping.Check(ctx, ex, spec, rs, sudo(env)); {
	case errors.As(err, &he):
		return jobs.Fail(he.Msg, nil)
	case errors.Is(err, hopping.ErrNoSS):
		env.Warnf("Не проверено, свободны ли новые порты: на сервере нет ss.")
	case err != nil:
		return err
	}
	if hopping.Hopping(rs) {
		env.Logf("Порты: Hysteria будет слушать UDP %d и перенаправлять на него остальные (%s, всего %d).", rs[0].From, hopping.Join(rs), hopping.Count(rs))
	}
	return nil
}

// current is the config the controller has for the server (nil: none).
func (x *applier) current(ctx context.Context, env *jobs.Env) (*hyconfig.Server, error) {
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

// firewall opens the ports the new config adds before the restart (in
// ufw or firewalld; the rollback closes them again). Ports the current
// config already uses are left as they are, and other firewalls are left
// to the admin, with a warning.
func (x *applier) firewall(ctx context.Context, env *jobs.Env) error {
	_, c, err := candidate(env)
	if err != nil {
		return err
	}
	want, err := firewall.Ports(c)
	if err != nil {
		return jobs.Fail("Не удалось разобрать порты нового конфига.", err)
	}
	in, err := x.installation(ctx, env)
	if err != nil {
		return err
	}
	old, err := x.current(ctx, env)
	if err != nil {
		return err
	}
	var had []remote.PortSpec
	if old != nil {
		had, _ = firewall.Ports(old)
	}
	var added []remote.PortSpec
	for _, p := range want {
		if !slices.Contains(had, p) {
			added = append(added, p)
		}
	}
	if in.Firewall.Keep {
		if len(added) > 0 {
			env.Warnf("Брандмауэр не трогаем (так выбрано при развёртывании): откройте %s сами, если нужно.", firewall.List(added))
		}
		return nil
	}
	if len(added) == 0 {
		return nil
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	fw, err := remote.ReadFirewall(ctx, ex, sudo(env))
	if err != nil {
		return jobs.Fail("Не удалось проверить брандмауэр сервера.", err)
	}
	if err := env.Set("firewall", fw.Tool); err != nil {
		return err
	}
	switch {
	case firewall.Managed(fw.Tool):
		return firewall.Open(ctx, env, ex, fw.Tool, added, sudo(env))
	case fw.DropPolicy:
		env.Warnf("Входящие соединения закрыты политикой %s. HyRoute не меняет такие правила сам: откройте %s вручную.", fw.Tool, firewall.List(added))
	}
	return nil
}

func (x *applier) undoFirewall(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	return firewall.Undo(ctx, env, ex, sudo(env))
}

// cleanup closes the rules HyRoute opened for ports the new config no
// longer uses. It runs after the commit and never fails the job.
func (x *applier) cleanup(ctx context.Context, env *jobs.Env) error {
	err := x.cleanupFirewall(ctx, env)
	if ctx.Err() != nil {
		return ctx.Err() // the controller is stopping: the step runs again
	}
	if err != nil {
		env.Warnf("Старые правила брандмауэра не проверены: %v.", err)
	}
	return nil
}

func (x *applier) cleanupFirewall(ctx context.Context, env *jobs.Env) error {
	_, c, err := candidate(env)
	if err != nil {
		return err
	}
	want, err := firewall.Ports(c)
	if err != nil {
		return err
	}
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
	tool := env.Get("firewall")
	if tool == "" {
		// The ports only went away: the firewall step did not look.
		f, err := remote.ReadFirewall(ctx, ex, sudo(env))
		if err != nil {
			return err
		}
		tool = f.Tool
	}
	fw := firewall.Cleanup(ctx, env, ex, in.Firewall, tool, want, sudo(env))
	if fw == in.Firewall {
		return nil
	}
	return x.Store.SetFirewall(ctx, env.ServerID, fw)
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
	l, lerr := hyconfig.ParseListen(c.Listen) // Realms: no port to look at
	wait := x.VerifyTimeout
	if c.ACME != nil {
		wait *= 3 // the certificate is issued first
	}
	deadline := time.Now().Add(wait)
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
			case errors.As(err, &noSS) || lerr != nil:
				// ss is missing (or cannot list), or Realms has no port:
				// systemd is trusted, as in the deploy, once the service
				// stayed up for a poll; a config Hysteria rejects stops it
				// right away.
				if steady {
					why := "порт проверить нечем: на сервере нет ss"
					if lerr != nil {
						why = "в режиме Realms своего порта у Hysteria нет"
					}
					env.Logf("Служба %s работает с новым конфигом (%s).", in.Unit, why)
					return nil
				}
				steady = true
			case err != nil:
				return err
			}
			for _, s := range ls {
				if lerr == nil && s.Proto == "udp" && s.Port == l.First && strings.HasPrefix(s.Process, "hysteria") {
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
	return cur.SHA256 == p.SHA256 && (p.Pin == "" || cur.Meta.PinSHA256 == p.Pin), nil
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
	// The rules the job opened are HyRoute's from now on (recorded before
	// the revision: a resumed job skips the commit once it is there).
	if fw := firewall.Record(env, in.Firewall); fw != in.Firewall {
		if err := x.Store.SetFirewall(ctx, env.ServerID, fw); err != nil {
			return err
		}
	}
	rev := model.ServerConfig{ServerID: env.ServerID, SHA256: p.SHA256, Meta: meta, Source: model.ConfigEdit, JobID: env.JobID, By: env.CreatedBy, At: x.Now()}
	switch {
	case p.From != 0:
		rev.Source, rev.FromRevision = model.ConfigRollback, p.From
	case len(p.Rotated) > 0:
		rev.Source = model.ConfigRotate
	}
	if p.Pin != "" && meta.PinSHA256 != p.Pin {
		return jobs.Fail("На сервере не тот сертификат, который записало задание.", nil)
	}
	err = x.Store.AddConfig(ctx, &rev, func(r int) ([]byte, error) {
		return x.Keys.Seal(b, model.ConfigContext(env.ServerID, r))
	})
	if err != nil {
		return err
	}
	if err := remote.RemoveFile(ctx, ex, in.Config+Backup, sudo(env)); err != nil {
		env.Warnf("Копия прежнего конфига %s%s осталась на сервере.", in.Config, Backup)
	}
	// The old key is not kept: a rotation is meant to retire it.
	if p.Pin != "" {
		for _, f := range []string{c.TLS.Cert, c.TLS.Key} {
			if err := remote.RemoveFile(ctx, ex, f+Backup, sudo(env)); err != nil {
				env.Warnf("Копия прежнего файла %s%s осталась на сервере: удалите её.", f, Backup)
			}
		}
	}
	switch {
	case len(p.Rotated) > 0:
		env.Logf("Новые значения сохранены в controller как ревизия %d. Старые ссылки клиентов больше не работают: выдайте новые.", rev.Revision)
		return nil
	case p.From != 0:
		env.Logf("Возвращена версия %d; в controller она сохранена как ревизия %d.", p.From, rev.Revision)
	case p.Preset != "":
		env.Logf("Разделы пресета «%s» (%s) применены; конфиг сохранён в controller как ревизия %d.", p.Preset, strings.Join(p.Sections, ", "), rev.Revision)
	case p.Change == ChangeRouting:
		env.Logf("Маршрутизация изменена; конфиг сохранён в controller как ревизия %d.", rev.Revision)
	default:
		env.Logf("Конфиг сохранён в controller как ревизия %d.", rev.Revision)
	}
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
