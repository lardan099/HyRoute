package cascade

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/importer"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// JobUnlink takes a link off its servers (P3-02c).
const JobUnlink = "unlink"

// ErrNotDeployed: nothing of the link is on its servers (new or failed);
// the chain is deleted without a job.
var ErrNotDeployed = errors.New("cascade: the link is not deployed")

type unlinkParams struct {
	jobParams
	// Delete: the chain goes too once the link is off the servers.
	Delete bool `json:"delete,omitempty"`
}

// Unlink queues the job that takes link idx of a chain off its servers:
// the entry's outbound first (its traffic goes direct again, not into a
// link going away), then the link service and its config, then the
// link's user on the exit. deleteChain removes the chain after.
func (l *Linker) Unlink(ctx context.Context, chainID int64, idx int, deleteChain bool, actor int64) (model.Job, error) {
	x := l.x
	c, err := x.Store.ChainByID(ctx, chainID)
	if err != nil {
		return model.Job{}, err
	}
	if idx < 0 || idx >= len(c.Links) {
		return model.Job{}, store.ErrNotFound
	}
	link := c.Links[idx]
	if link.State == model.LinkNew || link.State == model.LinkFailed {
		return model.Job{}, ErrNotDeployed
	}
	p := unlinkParams{jobParams: jobParams{Chain: chainID, Idx: idx, Entry: link.From, Exit: link.To, Prev: link.State}, Delete: deleteChain}
	for _, s := range []struct {
		id   int64
		rev  *int
		hash *string
	}{{link.From, &p.EntryBase, &p.EntryBaseSHA}, {link.To, &p.ExitBase, &p.ExitBaseSHA}} {
		cur, err := x.Store.CurrentConfig(ctx, s.id)
		if errors.Is(err, store.ErrNotFound) {
			return model.Job{}, ErrNoConfig
		} else if err != nil {
			return model.Job{}, err
		}
		if _, err := x.Store.Installation(ctx, s.id); errors.Is(err, store.ErrNotFound) {
			return model.Job{}, ErrNoInstallation
		} else if err != nil {
			return model.Job{}, err
		}
		*s.rev, *s.hash = cur.Revision, cur.SHA256
	}
	return x.Jobs.SubmitOn(ctx, JobUnlink, []int64{link.From, link.To}, p, nil, actor)
}

// UnlinkKind is the unlink job.
func (l *Linker) UnlinkKind() *jobs.Kind {
	x := l.x
	return &jobs.Kind{
		Name: JobUnlink,
		Steps: func(raw json.RawMessage) ([]jobs.Step, error) {
			var p unlinkParams
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, err
			}
			w := func(f func(context.Context, *jobs.Env, unlinkParams) error) func(context.Context, *jobs.Env) error {
				return func(ctx context.Context, env *jobs.Env) error { return f(ctx, env, p) }
			}
			d := func(f func(context.Context, *jobs.Env, unlinkParams) (bool, error)) func(context.Context, *jobs.Env) (bool, error) {
				return func(ctx context.Context, env *jobs.Env) (bool, error) { return f(ctx, env, p) }
			}
			return []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error { return x.connect(ctx, env, p.jobParams) }},
				{Name: "check", Phase: model.JobPreflight, Safe: true, Run: w(x.uncheck)},
				{Name: "entry-config", Phase: model.JobConfiguring, Safe: true, Done: d(x.unEntryDone), Run: w(x.unEntry),
					Undo: func(ctx context.Context, env *jobs.Env) error {
						return x.undoConfig(ctx, env, p.Entry, "entryConfig", "entryChanged", "входа")
					}},
				{Name: "entry-restart", Phase: model.JobStarting, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error {
					return x.restart(ctx, env, p.Entry, "entryChanged", "входа")
				}},
				{Name: "entry-verify", Phase: model.JobVerifying, Safe: true, Run: w(x.unEntryVerify)},
				{Name: "link-service", Phase: model.JobConfiguring, Safe: true, Done: d(x.unServiceDone), Run: w(x.unService), Undo: w(x.undoUnService)},
				{Name: "link-config", Phase: model.JobConfiguring, Safe: true, Done: d(x.unConfigDone), Run: w(x.unConfig), Undo: w(x.undoUnConfig)},
				{Name: "exit-config", Phase: model.JobConfiguring, Safe: true, Done: d(x.unExitDone), Run: w(x.unExit),
					Undo: func(ctx context.Context, env *jobs.Env) error {
						return x.undoConfig(ctx, env, p.Exit, "exitConfig", "exitChanged", "выхода")
					}},
				{Name: "exit-restart", Phase: model.JobStarting, Safe: true, Run: func(ctx context.Context, env *jobs.Env) error {
					return x.restart(ctx, env, p.Exit, "exitChanged", "выхода")
				}},
				{Name: "exit-verify", Phase: model.JobVerifying, Safe: true, Run: w(x.unExitVerify)},
				{Name: "commit", Phase: model.JobVerifying, Safe: true, Done: d(x.unCommitted), Run: w(x.unCommit)},
				{Name: "cleanup", Phase: model.JobVerifying, Safe: true, Run: w(x.unCleanup)},
			}, nil
		},
		Recover:  func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
		Finished: x.unFinished,
	}
}

// unplan is what the unlink job writes: both configs without the link,
// built from the base revisions (no chain needed: the chain may be gone
// once the job commits).
type unplan struct {
	inExit, inEntry         model.Installation
	exitBase, exitCfg       []byte
	entryBase, entryCfg     []byte
	exitParsed, entryParsed *hyconfig.Server
	linkPath, unitPath      string
	red                     *redact.Redactor
}

func (x *linker) unplan(ctx context.Context, p unlinkParams) (*unplan, error) {
	u := &unplan{red: redact.New()}
	var err error
	if u.inExit, err = x.Store.Installation(ctx, p.Exit); err != nil {
		return nil, err
	}
	if u.inEntry, err = x.Store.Installation(ctx, p.Entry); err != nil {
		return nil, err
	}
	if u.exitBase, _, err = x.revision(ctx, p.Exit, p.ExitBase); err != nil {
		return nil, err
	}
	if u.exitParsed, err = hyconfig.ParseServer(u.exitBase); err != nil {
		return nil, jobs.Fail("Конфиг сервера выхода не разобрать.", err)
	}
	u.red.Add(service.ConfigSecrets(u.exitParsed)...)
	u.exitCfg = u.exitBase
	if ExitWithout(u.exitParsed, User(p.Chain, p.Idx)) {
		if u.exitCfg, err = u.exitParsed.Marshal(); err != nil {
			return nil, err
		}
	}
	if u.entryBase, _, err = x.revision(ctx, p.Entry, p.EntryBase); err != nil {
		return nil, err
	}
	if u.entryParsed, err = hyconfig.ParseServer(u.entryBase); err != nil {
		return nil, jobs.Fail("Конфиг сервера входа не разобрать.", err)
	}
	u.red.Add(service.ConfigSecrets(u.entryParsed)...)
	u.entryCfg = u.entryBase
	if EntryWithout(u.entryParsed) {
		if u.entryCfg, err = u.entryParsed.Marshal(); err != nil {
			return nil, err
		}
	}
	u.linkPath, u.unitPath = ConfigPath(u.inEntry, p.Chain, p.Idx), UnitPath(p.Chain, p.Idx)
	return u, nil
}

// uncheck: the servers still have the configs the job builds on (or this
// job's). The link becomes unlinking.
func (x *linker) uncheck(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	for _, s := range []struct {
		id         int64
		path, base string
		want       []byte
		role       string
	}{{p.Exit, u.inExit.Config, p.ExitBaseSHA, u.exitCfg, "выхода"}, {p.Entry, u.inEntry.Config, p.EntryBaseSHA, u.entryCfg, "входа"}} {
		ex, err := execOn(ctx, env, s.id)
		if err != nil {
			return err
		}
		sum, err := remote.FileSHA256(ctx, ex, s.path, sudo(env, s.id))
		if err != nil {
			return err
		}
		switch sum {
		case s.base, sha(s.want):
		case "":
			return jobs.Fail("На сервере "+s.role+" нет конфига "+s.path+".", nil)
		default:
			return jobs.Fail("Конфиг на сервере "+s.role+" изменили не через HyRoute после последнего сохранения. Импортируйте этот сервер заново и повторите.", nil)
		}
	}
	c, err := x.Store.ChainByID(ctx, p.Chain)
	if err != nil {
		return err
	}
	if p.Idx < len(c.Links) {
		link := c.Links[p.Idx]
		link.State, link.UpdatedAt = model.LinkUnlinking, x.Now()
		return x.Store.UpdateLink(ctx, link)
	}
	return nil
}

func (x *linker) unEntryDone(ctx context.Context, env *jobs.Env, p unlinkParams) (bool, error) {
	u, err := x.unplan(ctx, p)
	if err != nil {
		return false, err
	}
	return x.fileIs(ctx, env, p.Entry, u.inEntry.Config, u.entryCfg)
}

func (x *linker) unEntry(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	if err := backupFile(ctx, env, ex, u.inEntry.Config, "entryConfig", su); err != nil {
		return err
	}
	if err := env.Set("entryChanged", "1"); err != nil {
		return err
	}
	if err := writeConfig(ctx, ex, u.inEntry, u.entryCfg, su); err != nil {
		return jobs.Fail("Не удалось записать конфиг сервера входа.", err)
	}
	env.Logf("С сервера входа убран outbound «%s»: его трафик снова идёт напрямую.", OutboundName)
	return nil
}

func (x *linker) unEntryVerify(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	if env.Get("entryChanged") != "1" {
		return nil
	}
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	return x.waitServer(ctx, env, p.Entry, u.inEntry, u.entryParsed, u.red, "входа")
}

func (x *linker) absent(ctx context.Context, env *jobs.Env, server int64, path string) (bool, error) {
	ex, err := execOn(ctx, env, server)
	if err != nil {
		return false, err
	}
	_, err = ex.ReadFile(ctx, path, sudo(env, server))
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	return false, err
}

// unServiceDone: the unit is gone and nothing was recorded to stop.
func (x *linker) unServiceDone(ctx context.Context, env *jobs.Env, p unlinkParams) (bool, error) {
	if env.Get("linkUnit") != "" {
		return false, nil // this job removes it: the run makes sure it is stopped
	}
	return x.absent(ctx, env, p.Entry, UnitPath(p.Chain, p.Idx))
}

func (x *linker) unService(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	unit, path := UnitName(p.Chain, p.Idx), UnitPath(p.Chain, p.Idx)
	if err := backupFile(ctx, env, ex, path, "linkUnit", su); err != nil {
		return err
	}
	if st := env.Get("linkUnit"); st == remote.Absent {
		return nil
	}
	// Stopped before the file goes: systemd knows the unit until the
	// reload.
	remote.Systemctl(ctx, ex, remote.ServiceStop, unit, su)
	remote.Systemctl(ctx, ex, remote.ServiceDisable, unit, su)
	if err := remote.RemoveFile(ctx, ex, path, su); err != nil {
		return jobs.Fail("Не удалось удалить службу связи.", err)
	}
	if err := remote.DaemonReload(ctx, ex, su); err != nil {
		return jobs.Fail("systemd не перечитал службы.", err)
	}
	env.Logf("Служба связи %s остановлена и удалена.", unit)
	return nil
}

// undoUnService puts the unit back and starts it (its config is back
// already: the link-config undo runs first).
func (x *linker) undoUnService(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	state := env.Get("linkUnit")
	if state == "" || state == remote.Absent {
		return jobs.ErrNothingToUndo
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	if _, err := restoreFile(ctx, env, ex, UnitPath(p.Chain, p.Idx), "linkUnit", su); err != nil && !errors.Is(err, jobs.ErrNothingToUndo) {
		return err
	}
	if err := remote.DaemonReload(ctx, ex, su); err != nil {
		return err
	}
	unit := UnitName(p.Chain, p.Idx)
	if err := remote.Systemctl(ctx, ex, remote.ServiceEnable, unit, su); err != nil {
		return err
	}
	return remote.Systemctl(ctx, ex, remote.ServiceRestart, unit, su)
}

func (x *linker) unConfigDone(ctx context.Context, env *jobs.Env, p unlinkParams) (bool, error) {
	u, err := x.unplan(ctx, p)
	if err != nil {
		return false, err
	}
	return x.absent(ctx, env, p.Entry, u.linkPath)
}

func (x *linker) unConfig(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	if err := backupFile(ctx, env, ex, u.linkPath, "linkConfig", su); err != nil {
		return err
	}
	if err := remote.RemoveFile(ctx, ex, u.linkPath, su); err != nil {
		return jobs.Fail("Не удалось удалить конфиг клиента связи.", err)
	}
	env.Logf("Конфиг клиента связи удалён: %s.", u.linkPath)
	return nil
}

func (x *linker) undoUnConfig(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	if env.Get("linkConfig") == "" {
		return jobs.ErrNothingToUndo
	}
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	_, err = restoreFile(ctx, env, ex, u.linkPath, "linkConfig", sudo(env, p.Entry))
	return err
}

func (x *linker) unExitDone(ctx context.Context, env *jobs.Env, p unlinkParams) (bool, error) {
	u, err := x.unplan(ctx, p)
	if err != nil {
		return false, err
	}
	return x.fileIs(ctx, env, p.Exit, u.inExit.Config, u.exitCfg)
}

func (x *linker) unExit(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Exit)
	if err != nil {
		return err
	}
	su := sudo(env, p.Exit)
	if err := backupFile(ctx, env, ex, u.inExit.Config, "exitConfig", su); err != nil {
		return err
	}
	if err := env.Set("exitChanged", "1"); err != nil {
		return err
	}
	if err := writeConfig(ctx, ex, u.inExit, u.exitCfg, su); err != nil {
		return jobs.Fail("Не удалось записать конфиг сервера выхода.", err)
	}
	env.Logf("С сервера выхода убран пользователь связи %s.", User(p.Chain, p.Idx))
	return nil
}

func (x *linker) unExitVerify(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	if env.Get("exitChanged") != "1" {
		return nil
	}
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	return x.waitServer(ctx, env, p.Exit, u.inExit, u.exitParsed, u.red, "выхода")
}

// unCommitted: the chain is gone (Delete) or its link is new again.
func (x *linker) unCommitted(ctx context.Context, env *jobs.Env, p unlinkParams) (bool, error) {
	c, err := x.Store.ChainByID(ctx, p.Chain)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	return !p.Delete && p.Idx < len(c.Links) && c.Links[p.Idx].State == model.LinkNew, nil
}

// unCommit stores the revisions without the link (source cascade), then
// deletes the chain or makes its link new again, without secrets: a new
// deployment makes new ones.
func (x *linker) unCommit(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	for _, s := range []struct {
		id        int64
		in        model.Installation
		cfg, base []byte
		c         *hyconfig.Server
	}{{p.Entry, u.inEntry, u.entryCfg, u.entryBase, u.entryParsed}, {p.Exit, u.inExit, u.exitCfg, u.exitBase, u.exitParsed}} {
		if sha(s.cfg) == sha(s.base) {
			continue
		}
		cur, err := x.Store.CurrentConfig(ctx, s.id)
		if err != nil {
			return err
		}
		if cur.SHA256 == sha(s.cfg) {
			continue
		}
		ex, err := execOn(ctx, env, s.id)
		if err != nil {
			return err
		}
		meta, err := importer.ConfigMeta(ctx, remote.ReadOnly(ex), s.c, s.in.Version, sudo(env, s.id), x.Now())
		if err != nil {
			return err
		}
		rev := model.ServerConfig{ServerID: s.id, SHA256: sha(s.cfg), Meta: meta, Source: model.ConfigCascade, JobID: env.JobID, By: env.CreatedBy, At: x.Now()}
		cfg, id := s.cfg, s.id
		if err := x.Store.AddConfig(ctx, &rev, func(r int) ([]byte, error) { return x.Keys.Seal(cfg, model.ConfigContext(id, r)) }); err != nil {
			return err
		}
	}
	if p.Delete {
		if err := x.Store.DeleteChain(ctx, p.Chain, x.Now()); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		env.Logf("Связь снята с серверов, каскад удалён.")
		return nil
	}
	c, err := x.Store.ChainByID(ctx, p.Chain)
	if err != nil {
		return err
	}
	if p.Idx < len(c.Links) {
		link := c.Links[p.Idx]
		link.State, link.FromRevision, link.ToRevision, link.ConfigSHA256, link.UpdatedAt = model.LinkNew, 0, 0, "", x.Now()
		if err := x.Store.UpdateLink(ctx, link); err != nil {
			return err
		}
		if err := x.Store.SetLinkSecrets(ctx, p.Chain, p.Idx, nil, x.Now()); err != nil {
			return err
		}
	}
	env.Logf("Связь снята с серверов; каскад остался, его можно развернуть снова.")
	return nil
}

func (x *linker) unCleanup(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		server int64
		path   string
		flag   string
	}{{p.Exit, u.inExit.Config, "exitConfig"}, {p.Entry, u.inEntry.Config, "entryConfig"}, {p.Entry, u.linkPath, "linkConfig"}, {p.Entry, u.unitPath, "linkUnit"}} {
		if st := env.Get(f.flag); st == "" || st == remote.Absent {
			continue
		}
		ex, err := execOn(ctx, env, f.server)
		if err != nil {
			return err
		}
		if err := remote.RemoveFile(ctx, ex, f.path+Backup, sudo(env, f.server)); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			env.Warnf("Копия %s%s осталась на сервере.", f.path, Backup)
		}
	}
	return nil
}

// unFinished: a failed unlink leaves the link as it was; servers whose
// rollback did not finish need attention.
func (x *linker) unFinished(ctx context.Context, env *jobs.Env, j model.Job) {
	var p unlinkParams
	if err := env.DecodeParams(&p); err != nil || j.State != model.JobFailed {
		return
	}
	if c, err := x.Store.ChainByID(ctx, p.Chain); err == nil && p.Idx < len(c.Links) {
		link := c.Links[p.Idx]
		link.State, link.UpdatedAt = p.Prev, x.Now()
		if !link.State.Valid() || link.State == model.LinkUnlinking || link.State == model.LinkLinking {
			link.State = model.LinkStale
		}
		x.Store.UpdateLink(ctx, link)
	}
	if env.Rollback() == jobs.RollbackFailed {
		for _, s := range []int64{p.Entry, p.Exit} {
			x.Store.SetServerState(ctx, s, model.StateNeedsAttention, x.Now())
		}
	}
}

// Sync compares the deployed links of a chain with the servers' current
// configs: a link that a redeployment would change (passwords rotated,
// ports, address or certificate changed, the outbound gone after a
// deploy) becomes stale; a stale one that would not change is active
// again. It returns the chain as stored after.
func (l *Linker) Sync(ctx context.Context, c model.Chain) (model.Chain, error) {
	x := l.x
	for i, link := range c.Links {
		if link.State != model.LinkActive && link.State != model.LinkStale {
			continue
		}
		fresh, entryRev, exitRev, err := x.fresh(ctx, c.ID, link)
		if err != nil {
			return c, err
		}
		want := model.LinkStale
		if fresh {
			want = model.LinkActive
		}
		if want == link.State && (!fresh || (link.FromRevision == entryRev && link.ToRevision == exitRev)) {
			continue
		}
		link.State, link.UpdatedAt = want, x.Now()
		if fresh {
			link.FromRevision, link.ToRevision = entryRev, exitRev
		}
		if err := x.Store.UpdateLink(ctx, link); err != nil {
			return c, err
		}
		c.Links[i] = link
	}
	return c, nil
}

// fresh reports whether deploying the link again on the servers' current
// configs would change nothing, with those revisions.
func (x *linker) fresh(ctx context.Context, chainID int64, link model.ChainLink) (bool, int, int, error) {
	ce, err := x.Store.CurrentConfig(ctx, link.From)
	if err != nil {
		return false, 0, 0, err
	}
	cx, err := x.Store.CurrentConfig(ctx, link.To)
	if err != nil {
		return false, 0, 0, err
	}
	if ce.Revision == link.FromRevision && cx.Revision == link.ToRevision {
		return true, ce.Revision, cx.Revision, nil
	}
	pl, err := x.plan(ctx, jobParams{Chain: chainID, Idx: link.Idx, Entry: link.From, Exit: link.To, EntryBase: ce.Revision, ExitBase: cx.Revision})
	var se *jobs.StepError
	if errors.As(err, &se) {
		return false, ce.Revision, cx.Revision, nil // e.g. the exit's auth is http now
	} else if err != nil {
		return false, 0, 0, err
	}
	fresh := sha(pl.exitCfg) == sha(pl.exitBase) && sha(pl.entryCfg) == sha(pl.entryBase) && pl.client != nil && sha(pl.client) == link.ConfigSHA256
	return fresh, ce.Revision, cx.Revision, nil
}
