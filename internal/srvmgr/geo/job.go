package geo

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

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/importer"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// JobKind is the job that puts the controller's databases on a server.
const JobKind = "geo"

// ServerDir is where they go: root's directory, files Hysteria's user
// reads.
const ServerDir = "/etc/hysteria/geo"

// Backup is the suffix of a file kept while the job runs.
const Backup = ".hyroute-prev"

// Download sources.
const (
	SourceAuto   = "auto" // the server downloads, else the controller uploads
	SourceDirect = "direct"
	SourceRelay  = "relay"
	SourceNode   = "node" // another managed server (Via)
)

// Params are the job's: the release and files it installs (the
// controller's when it was queued) and where they come from.
type Params struct {
	Release string `json:"release"`
	Files   []File `json:"files"`
	Source  string `json:"source"`
	Via     int64  `json:"via,omitempty"`
}

// DB is what the job keeps in the controller's database.
type DB interface {
	store.Configs
	store.Installations
	store.ServerGeos
	ServerByID(ctx context.Context, id int64) (model.Server, error)
	SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error
}

// Deps are the job's collaborators.
type Deps struct {
	DB    DB
	Keys  *secrets.Keyring
	Files *Store
	Jobs  *jobs.Engine
	// Nodes connects to another managed server (source node).
	Nodes func(ctx context.Context, serverID int64) (remote.Executor, error)
	Now   func() time.Time
	// VerifyTimeout bounds the wait for the restarted service.
	VerifyTimeout time.Duration
	Poll          time.Duration
}

type installer struct{ Deps }

// Installer queues and runs geo jobs.
type Installer struct{ x *installer }

// New returns the installer.
func New(d Deps) *Installer {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.VerifyTimeout == 0 {
		d.VerifyTimeout = 30 * time.Second
	}
	if d.Poll == 0 {
		d.Poll = 2 * time.Second
	}
	return &Installer{&installer{d}}
}

// ErrNoInstallation: HyRoute knows of no Hysteria on the server.
var ErrNoInstallation = errors.New("geo: no installation")

// Submit queues the job that installs the controller's databases on a
// server, from source (via: the node).
func (i *Installer) Submit(ctx context.Context, serverID int64, source string, via int64, actor int64) (model.Job, error) {
	x := i.x
	if source == "" {
		source = SourceAuto
	}
	switch source {
	case SourceAuto, SourceDirect, SourceRelay:
		via = 0
	case SourceNode:
		if via <= 0 || via == serverID {
			return model.Job{}, &model.FieldError{Field: "via", Msg: "Выберите другой сервер, через который загружать базы."}
		}
		if _, err := x.DB.ServerByID(ctx, via); errors.Is(err, store.ErrNotFound) {
			return model.Job{}, &model.FieldError{Field: "via", Msg: "Сервер, через который загружать базы, не найден."}
		} else if err != nil {
			return model.Job{}, err
		}
	default:
		return model.Job{}, &model.FieldError{Field: "source", Msg: fmt.Sprintf("Неизвестный источник загрузки %q.", source)}
	}
	if _, err := x.DB.Installation(ctx, serverID); errors.Is(err, store.ErrNotFound) {
		return model.Job{}, ErrNoInstallation
	} else if err != nil {
		return model.Job{}, err
	}
	info, err := x.Files.Info()
	if err != nil {
		return model.Job{}, err
	}
	if info.Release == "" {
		return model.Job{}, ErrNone
	}
	return x.Jobs.Submit(ctx, JobKind, serverID, Params{Release: info.Release, Files: info.Files, Source: source, Via: via}, nil, actor)
}

// Kind is the geo job.
func (i *Installer) Kind() *jobs.Kind {
	x := i.x
	return &jobs.Kind{
		Name: JobKind,
		Steps: func(raw json.RawMessage) ([]jobs.Step, error) {
			var p Params
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, err
			}
			w := func(f func(context.Context, *jobs.Env, Params) error) func(context.Context, *jobs.Env) error {
				return func(ctx context.Context, env *jobs.Env) error { return f(ctx, env, p) }
			}
			d := func(f func(context.Context, *jobs.Env, Params) (bool, error)) func(context.Context, *jobs.Env) (bool, error) {
				return func(ctx context.Context, env *jobs.Env) (bool, error) { return f(ctx, env, p) }
			}
			// A retry or a recovery before the commit starts at check,
			// which compares the controller's files and the server's
			// config again (a rollback may have run, the controller may
			// have newer databases, the config may have been edited);
			// steps done already are skipped, a service restarted
			// already is not restarted again.
			return []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: x.connect},
				{Name: "check", Phase: model.JobPreflight, Safe: true, Run: w(x.check)},
				{Name: "prepare", Phase: model.JobConfiguring, Run: x.prepare, Undo: x.undoPrepare},
				{Name: "dir", Phase: model.JobInstalling, Run: x.dir},
				{Name: "files", Phase: model.JobInstalling, Done: d(x.filesDone), Run: w(x.files), Undo: w(x.undoFiles)},
				{Name: "config", Phase: model.JobConfiguring, Done: x.configDone, Run: x.config, Undo: x.undoConfig},
				{Name: "restart", Phase: model.JobStarting, Done: restarted, Run: w(x.restart)},
				{Name: "verify", Phase: model.JobVerifying, Run: x.verify},
				{Name: "commit", Phase: model.JobVerifying, Safe: true, Done: d(x.committed), Run: w(x.commit)},
				{Name: "cleanup", Phase: model.JobVerifying, Safe: true, Run: w(x.cleanup)},
			}, nil
		},
		Recover:  func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
		Finished: x.finished,
	}
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sudo(env *jobs.Env) bool { return env.Get("root") != "true" }

func exec(ctx context.Context, env *jobs.Env) (remote.Executor, error) {
	ex, err := env.Exec(ctx)
	if err != nil {
		return nil, jobs.Fail("Не удалось подключиться к серверу по SSH.", err)
	}
	return ex, nil
}

func (x *installer) connect(ctx context.Context, env *jobs.Env) error {
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
	return env.Set("root", strconv.FormatBool(p.Root))
}

// base is the config revision the job started from, its config and the
// installation.
func (x *installer) base(ctx context.Context, env *jobs.Env) (model.ServerConfig, []byte, model.Installation, error) {
	in, err := x.DB.Installation(ctx, env.ServerID)
	if err != nil {
		return model.ServerConfig{}, nil, in, jobs.Fail("HyRoute не знает установки Hysteria на этом сервере.", err)
	}
	rev, err := strconv.Atoi(env.Get("base"))
	if err != nil {
		return model.ServerConfig{}, nil, in, fmt.Errorf("geo: no base revision")
	}
	c, err := x.DB.ConfigRevision(ctx, env.ServerID, rev)
	if errors.Is(err, store.ErrNotFound) {
		return c, nil, in, jobs.Fail(fmt.Sprintf("Ревизии конфига %d больше нет.", rev), nil)
	} else if err != nil {
		return c, nil, in, err
	}
	b, err := x.Keys.Open(c.Sealed, model.ConfigContext(env.ServerID, c.Revision))
	return c, b, in, err
}

// want is the base config with the paths of the databases.
func want(b []byte) ([]byte, *hyconfig.Server, error) {
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return nil, nil, jobs.Fail("Конфиг сервера не разобрать.", err)
	}
	ip, site := ServerDir+"/"+GeoIP, ServerDir+"/"+GeoSite
	if c.ACL.GeoIP == ip && c.ACL.GeoSite == site {
		return b, c, nil
	}
	c.ACL.GeoIP, c.ACL.GeoSite = ip, site
	out, err := c.Marshal()
	return out, c, err
}

// check: the controller still has the job's files, the server has the
// config of the base revision (or the one this job writes).
func (x *installer) check(ctx context.Context, env *jobs.Env, p Params) error {
	for _, f := range p.Files {
		if _, have, err := x.Files.Open(f.Name); err != nil || have.SHA256 != f.SHA256 {
			return jobs.Fail("Базы geo у controller уже другие (или их нет): запустите задание заново.", err)
		}
	}
	if env.Get("base") == "" {
		cur, err := x.DB.CurrentConfig(ctx, env.ServerID)
		if errors.Is(err, store.ErrNotFound) {
			return jobs.Fail("HyRoute не знает конфиг этого сервера: разверните Hysteria или импортируйте сервер.", nil)
		} else if err != nil {
			return err
		}
		if err := env.Set("base", strconv.Itoa(cur.Revision)); err != nil {
			return err
		}
	}
	cur, b, in, err := x.base(ctx, env)
	if err != nil {
		return err
	}
	w, _, err := want(b)
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
	if sum != cur.SHA256 && sum != sha(w) {
		return jobs.Fail("Конфиг на сервере изменён не через HyRoute: импортируйте сервер заново или примените конфиг, потом повторите.", nil)
	}
	env.Logf("Базы geo релиза %s (%s).", p.Release, sourceText(p))
	return nil
}

func sourceText(p Params) string {
	switch p.Source {
	case SourceDirect:
		return "сервер скачивает сам"
	case SourceRelay:
		return "через controller"
	case SourceNode:
		return "через другой сервер"
	}
	return "сервер скачивает сам, если не выйдет — через controller"
}

// prepare holds the undo that restarts the service with what the rest of
// the rollback put back (the steps after it undo first).
func (x *installer) prepare(context.Context, *jobs.Env) error { return nil }

// committed: the controller recorded the new config; the server keeps
// what it runs, a rollback would part them.
func committedRevision(env *jobs.Env) bool { return env.Get("committed") == "1" }

func (x *installer) undoPrepare(ctx context.Context, env *jobs.Env) error {
	if env.Get("restarted") != "1" || committedRevision(env) {
		return jobs.ErrNothingToUndo
	}
	// The service gets the previous files back: a retry restarts it.
	if err := env.Set("restarted:done", ""); err != nil {
		return err
	}
	_, _, in, err := x.base(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceRestart, in.Unit, sudo(env)); err != nil {
		return err
	}
	env.Logf("Служба %s перезапущена с прежними базами и конфигом.", in.Unit)
	// A retry starts from what is on the server now.
	for _, k := range []string{"restarted", "changed"} {
		if err := env.Set(k, ""); err != nil {
			return err
		}
	}
	return nil
}

func (x *installer) dir(ctx context.Context, env *jobs.Env) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	if err := remote.MakeDir(ctx, ex, ServerDir, 0o755, "root", "root", sudo(env)); err != nil {
		return jobs.Fail("Не удалось создать каталог "+ServerDir+".", err)
	}
	return nil
}

func (x *installer) filesDone(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	for _, f := range p.Files {
		sum, err := remote.FileSHA256(ctx, ex, ServerDir+"/"+f.Name, sudo(env))
		if err != nil || sum != f.SHA256 {
			return false, err
		}
	}
	env.Logf("На сервере уже базы этого релиза.")
	return true, nil
}

// files puts each database that differs on the server: fetched into a
// temporary directory, checked, the old file kept.
func (x *installer) files(ctx context.Context, env *jobs.Env, p Params) error {
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	su := sudo(env)
	tmpDir, err := remote.TempDir(ctx, ex, su)
	if err != nil {
		return jobs.Fail("Не удалось создать временный каталог на сервере.", err)
	}
	defer remote.RemoveTempDir(context.WithoutCancel(ctx), ex, tmpDir, su)
	for _, f := range p.Files {
		path := ServerDir + "/" + f.Name
		if sum, err := remote.FileSHA256(ctx, ex, path, su); err != nil {
			return err
		} else if sum == f.SHA256 {
			continue
		}
		tmp := tmpDir + "/" + f.Name
		if err := x.fetch(ctx, env, ex, p, f, tmp); err != nil {
			return err
		}
		if err := backup(ctx, env, ex, path, "file:"+f.Name, su); err != nil {
			return err
		}
		if err := env.Set("changed", "1"); err != nil {
			return err
		}
		if err := remote.InstallFile(ctx, ex, tmp, path, 0o644, "root", "root", su); err != nil {
			return jobs.Fail("Не удалось установить "+path+".", err)
		}
		env.Logf("Установлено: %s (%s).", path, size(f.Size))
	}
	return nil
}

func size(n int64) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%.1f МБ", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d КБ", (n+1023)>>10)
}

// fetch leaves database f at tmp on the server, checked.
func (x *installer) fetch(ctx context.Context, env *jobs.Env, ex remote.Executor, p Params, f File, tmp string) error {
	su := sudo(env)
	a := hyrelease.Asset{Version: p.Release, Name: f.Name, URL: f.URL, SHA256: f.SHA256}
	var src hyrelease.Source = uploaded{x.Files}
	switch p.Source {
	case SourceAuto, SourceDirect:
		src = hyrelease.Direct{}
	case SourceNode:
		n, err := x.node(ctx, p.Via)
		if err != nil {
			return err
		}
		n.Installed = ServerDir + "/" + f.Name // the node's own copy, if HyRoute put it
		src = n
	}
	err := src.Fetch(ctx, ex, a, tmp, su)
	if err != nil && p.Source == SourceAuto && !errors.Is(err, hyrelease.ErrChecksum) {
		env.Logf("Сервер не скачал %s сам (%v): загрузка через controller.", f.Name, err)
		err = uploaded{x.Files}.Fetch(ctx, ex, a, tmp, su)
	}
	switch {
	case errors.Is(err, hyrelease.ErrChecksum):
		return jobs.Fail(f.Name+" не совпадает с хешем релиза; файлы на сервере не тронуты.", err)
	case err != nil:
		return jobs.Fail("Не удалось загрузить "+f.Name+" на сервер.", err)
	}
	return nil
}

// node is the source through managed server via.
func (x *installer) node(ctx context.Context, via int64) (*hyrelease.Node, error) {
	if x.Nodes == nil {
		return nil, jobs.Fail("Загрузка через другой сервер здесь недоступна.", nil)
	}
	srv, err := x.DB.ServerByID(ctx, via)
	if errors.Is(err, store.ErrNotFound) {
		return nil, jobs.Fail("Сервера, через который загружать базы, больше нет.", nil)
	} else if err != nil {
		return nil, err
	}
	return &hyrelease.Node{Server: srv.Name, Open: func(ctx context.Context) (remote.Executor, bool, error) {
		ex, err := x.Nodes(ctx, via)
		if err != nil {
			return nil, false, err
		}
		p, err := remote.RunProbe(ctx, ex)
		if err != nil {
			ex.Close()
			return nil, false, err
		}
		return ex, !p.Root, nil
	}}, nil
}

// uploaded: the controller writes its own file over SFTP and the server
// checks it.
type uploaded struct{ s *Store }

func (uploaded) Name() string { return "relay" }

func (u uploaded) Fetch(ctx context.Context, ex remote.Executor, a hyrelease.Asset, path string, sudo bool) error {
	b, f, err := u.s.Open(a.Name)
	if err != nil {
		return err
	}
	if f.SHA256 != a.SHA256 {
		return fmt.Errorf("%w (%s)", hyrelease.ErrChecksum, a.Name)
	}
	if err := ex.WriteFile(ctx, path, b, remote.FileSpec{Mode: fs.FileMode(0o600), Sudo: sudo}); err != nil {
		return fmt.Errorf("не удалось загрузить %s на сервер: %w", a.Name, err)
	}
	sum, err := remote.FileSHA256(ctx, ex, path, sudo)
	if err != nil {
		return err
	}
	if sum != a.SHA256 {
		return fmt.Errorf("%w (%s)", hyrelease.ErrChecksum, a.Name)
	}
	return nil
}

func (x *installer) undoFiles(ctx context.Context, env *jobs.Env, p Params) error {
	if committedRevision(env) {
		return jobs.ErrNothingToUndo
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	undone := false
	for _, f := range p.Files {
		if env.Get("file:"+f.Name) == "" {
			continue
		}
		changed, err := restore(ctx, env, ex, ServerDir+"/"+f.Name, "file:"+f.Name, sudo(env))
		if err != nil {
			return err
		}
		undone = undone || changed
	}
	if !undone {
		return jobs.ErrNothingToUndo
	}
	env.Logf("Прежние базы geo возвращены.")
	return nil
}

func (x *installer) configDone(ctx context.Context, env *jobs.Env) (bool, error) {
	cur, b, in, err := x.base(ctx, env)
	if err != nil {
		return false, err
	}
	w, _, err := want(b)
	if err != nil {
		return false, err
	}
	if sha(w) == cur.SHA256 {
		return true, nil
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return false, err
	}
	sum, err := remote.FileSHA256(ctx, ex, in.Config, sudo(env))
	return sum == sha(w), err
}

// config writes acl.geoip and acl.geosite: Hysteria reads the files and
// downloads nothing.
func (x *installer) config(ctx context.Context, env *jobs.Env) error {
	_, b, in, err := x.base(ctx, env)
	if err != nil {
		return err
	}
	w, _, err := want(b)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	su := sudo(env)
	if err := backup(ctx, env, ex, in.Config, "configState", su); err != nil {
		return err
	}
	for _, k := range []string{"changed", "configChanged"} {
		if err := env.Set(k, "1"); err != nil {
			return err
		}
	}
	fi, ok, err := remote.Stat(ctx, ex, in.Config, su)
	if err != nil {
		return err
	}
	spec := remote.FileSpec{Mode: 0o640, Group: in.User, Sudo: su}
	if ok {
		spec.Mode, spec.Owner, spec.Group = fi.Mode, fi.Owner, fi.Group
	}
	if err := ex.WriteFile(ctx, in.Config, w, spec); err != nil {
		return jobs.Fail("Не удалось записать конфиг.", err)
	}
	env.Logf("В конфиг записаны пути баз: acl.geoip и acl.geosite в %s.", ServerDir)
	return nil
}

func (x *installer) undoConfig(ctx context.Context, env *jobs.Env) error {
	if env.Get("configState") == "" || committedRevision(env) {
		return jobs.ErrNothingToUndo
	}
	_, _, in, err := x.base(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	changed, err := restore(ctx, env, ex, in.Config, "configState", sudo(env))
	if err != nil {
		return err
	}
	if !changed {
		return jobs.ErrNothingToUndo
	}
	env.Logf("Прежний конфиг возвращён.")
	return nil
}

// restart restarts the service when the job changed something, or when
// the files were there already but HyRoute has no record of them:
// Hysteria reads them only at start and may run others.
func (x *installer) restart(ctx context.Context, env *jobs.Env, p Params) error {
	unknown := false
	if env.Get("changed") != "1" {
		known, err := x.recorded(ctx, env, p)
		if err != nil || known {
			return err
		}
		unknown = true
	}
	_, _, in, err := x.base(ctx, env)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	// The service as it is now: one the admin stopped stays stopped. One
	// this job restarted in an attempt whose rollback did not finish may
	// be down because of it: it is restarted again.
	st, err := remote.ActiveState(ctx, ex, in.Unit)
	if err != nil {
		return err
	}
	if st != "active" && env.Get("restarted") != "1" {
		env.Logf("Служба %s не запущена (%s): новые базы она прочтёт при запуске.", in.Unit, st)
		return nil
	}
	if unknown {
		env.Logf("Базы этого релиза уже были на сервере, но ставил их не HyRoute: служба перезапускается, чтобы читать именно их.")
	}
	if err := env.Set("restarted", "1"); err != nil {
		return err
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceRestart, in.Unit, sudo(env)); err != nil {
		return jobs.Fail("Не удалось перезапустить службу.", err)
	}
	env.Logf("Служба %s перезапущена.", in.Unit)
	return env.Set("restarted:done", "1")
}

// recorded: HyRoute's record says the server has the job's files (a job
// of HyRoute put them there and restarted the service with them, or left
// a stopped one to read them at start).
func (x *installer) recorded(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	g, err := x.DB.ServerGeo(ctx, env.ServerID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	for _, f := range p.Files {
		have := g.GeoSite
		if f.Name == GeoIP {
			have = g.GeoIP
		}
		if have != f.SHA256 {
			return false, nil
		}
	}
	return true, nil
}

// restarted: the service runs what this job put there (the restart is
// recorded once it ran; the undo of prepare clears the record).
func restarted(_ context.Context, env *jobs.Env) (bool, error) {
	return env.Get("restarted:done") == "1", nil
}

// verify waits until the service runs and Hysteria listens on its port
// (systemd is trusted where ss is missing, once the service stayed up for
// a poll).
func (x *installer) verify(ctx context.Context, env *jobs.Env) error {
	if env.Get("restarted") != "1" {
		return nil
	}
	_, b, in, err := x.base(ctx, env)
	if err != nil {
		return err
	}
	_, c, err := want(b)
	if err != nil {
		return err
	}
	ex, err := exec(ctx, env)
	if err != nil {
		return err
	}
	su := sudo(env)
	l, lerr := hyconfig.ParseListen(c.Listen)
	wait := x.VerifyTimeout
	if c.ACME != nil {
		wait *= 3 // Hysteria may get a certificate before it listens
	}
	deadline := time.Now().Add(wait)
	steady := false
	for {
		st, err := remote.ActiveState(ctx, ex, in.Unit)
		if err != nil {
			return err
		}
		if st != "active" {
			steady = false
		} else {
			ls, err := remote.Listeners(ctx, ex, su)
			var noSS *remote.ExitError
			switch {
			case errors.As(err, &noSS) || lerr != nil:
				if steady {
					env.Logf("Служба работает.")
					return nil
				}
				steady = true
			case err != nil:
				return err
			}
			for _, s := range ls {
				if lerr == nil && s.Proto == "udp" && s.Port == l.First && strings.HasPrefix(s.Process, "hysteria") {
					env.Logf("Hysteria работает и принимает соединения на UDP %d.", l.First)
					return nil
				}
			}
		}
		if st == "failed" || time.Now().After(deadline) {
			if lines, err := remote.JournalTail(ctx, ex, in.Unit, 20, su); err == nil && len(lines) > 0 {
				env.Logf("Последние строки журнала %s:", in.Unit)
				r := redact.New()
				for _, line := range lines {
					env.Logf("  %s", r.String(line))
				}
			}
			return jobs.Fail(fmt.Sprintf("Hysteria не заработала с новыми базами (служба: %s). Изменения откатываются.", st), nil)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(x.Poll):
		}
	}
}

func (x *installer) committed(ctx context.Context, env *jobs.Env, p Params) (bool, error) {
	g, err := x.DB.ServerGeo(ctx, env.ServerID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && g.JobID == env.JobID, err
}

// commit stores the revision with the paths (source geo) and what the
// server has now.
func (x *installer) commit(ctx context.Context, env *jobs.Env, p Params) error {
	_, b, in, err := x.base(ctx, env)
	if err != nil {
		return err
	}
	if env.Get("configChanged") == "1" {
		w, c, err := want(b)
		if err != nil {
			return err
		}
		cur, err := x.DB.CurrentConfig(ctx, env.ServerID)
		if err != nil {
			return err
		}
		if cur.SHA256 != sha(w) {
			ex, err := exec(ctx, env)
			if err != nil {
				return err
			}
			meta, err := importer.ConfigMeta(ctx, remote.ReadOnly(ex), c, in.Version, sudo(env), x.Now())
			if err != nil {
				return err
			}
			rev := model.ServerConfig{ServerID: env.ServerID, SHA256: sha(w), Meta: meta, Source: model.ConfigGeo, JobID: env.JobID, By: env.CreatedBy, At: x.Now()}
			if err := x.DB.AddConfig(ctx, &rev, func(r int) ([]byte, error) { return x.Keys.Seal(w, model.ConfigContext(env.ServerID, r)) }); err != nil {
				return err
			}
			if err := env.Set("committed", "1"); err != nil {
				return err
			}
			env.Logf("Конфиг сохранён в controller как ревизия %d.", rev.Revision)
		}
	}
	g := model.ServerGeo{ServerID: env.ServerID, Release: p.Release, JobID: env.JobID, At: x.Now()}
	for _, f := range p.Files {
		if f.Name == GeoIP {
			g.GeoIP = f.SHA256
		} else {
			g.GeoSite = f.SHA256
		}
	}
	if err := x.DB.SetServerGeo(ctx, g); err != nil {
		return err
	}
	env.Logf("На сервере базы geo релиза %s.", p.Release)
	return nil
}

// cleanup removes the copies the job kept; it never fails the job (the
// change is committed: a rollback now would part server and controller).
func (x *installer) cleanup(ctx context.Context, env *jobs.Env, p Params) error {
	_, _, in, err := x.base(ctx, env)
	if err == nil {
		var ex remote.Executor
		if ex, err = exec(ctx, env); err == nil {
			x.removeCopies(ctx, env, ex, in, p)
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		env.Warnf("Копии прежних файлов (%s) остались на сервере: %v", Backup, err)
	}
	return nil
}

func (x *installer) removeCopies(ctx context.Context, env *jobs.Env, ex remote.Executor, in model.Installation, p Params) {
	paths := map[string]string{"configState": in.Config}
	for _, f := range p.Files {
		paths["file:"+f.Name] = ServerDir + "/" + f.Name
	}
	for flag, path := range paths {
		if st := env.Get(flag); st == "" || st == remote.Absent {
			continue
		}
		if err := remote.RemoveFile(ctx, ex, path+Backup, sudo(env)); err != nil {
			env.Warnf("Копия %s%s осталась на сервере.", path, Backup)
		}
	}
}

// finished: a server whose rollback did not finish needs attention; it
// is healthy again once a job completed that restarted Hysteria and saw
// it listen with the config and databases HyRoute has recorded.
func (x *installer) finished(ctx context.Context, env *jobs.Env, j model.Job) {
	switch {
	case j.State == model.JobFailed && env.Rollback() == jobs.RollbackFailed:
		x.DB.SetServerState(ctx, env.ServerID, model.StateNeedsAttention, x.Now())
	case j.State == model.JobCompleted && env.Get("restarted") == "1":
		if srv, err := x.DB.ServerByID(ctx, env.ServerID); err == nil && srv.State == model.StateNeedsAttention {
			x.DB.SetServerState(ctx, env.ServerID, model.StateHealthy, x.Now())
		}
	}
}

// backup records the state of the file at path under flag (its SHA-256
// or remote.Absent) and keeps a copy; a step run again keeps the first
// record.
func backup(ctx context.Context, env *jobs.Env, ex remote.Executor, path, flag string, su bool) error {
	state, err := remote.FileState(ctx, ex, path, su)
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
	if err := remote.CopyFile(ctx, ex, path, path+Backup, su); err != nil {
		return jobs.Fail("Не удалось сохранить копию "+path+".", err)
	}
	return nil
}

// restore puts back what backup recorded under flag.
func restore(ctx context.Context, env *jobs.Env, ex remote.Executor, path, flag string, su bool) (bool, error) {
	changed, err := remote.RestoreFile(ctx, ex, path, path+Backup, env.Get(flag), su)
	if errors.Is(err, remote.ErrBackupMismatch) {
		return false, fmt.Errorf("%w: %s оставлен как есть, проверьте его вручную", err, path)
	}
	return changed, err
}

// UsesGeo reports whether a config's inline ACL has geoip or geosite
// rules (an acl.file is not known without reading it).
func UsesGeo(c *hyconfig.Server) bool {
	for _, l := range c.ACL.Inline {
		code, _, _ := strings.Cut(l, "#")
		if strings.Contains(strings.ToLower(code), "geoip:") || strings.Contains(strings.ToLower(code), "geosite:") {
			return true
		}
	}
	return false
}
