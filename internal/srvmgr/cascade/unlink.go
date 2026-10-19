package cascade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// JobUnlink takes a link off its servers (P3-02c); one job takes several
// links of a chain off (P4-08).
const JobUnlink = "unlink"

var (
	// ErrNotDeployed: nothing of the link is on its servers (new or
	// failed); the chain is deleted without a job.
	ErrNotDeployed = errors.New("cascade: the link is not deployed")
	// ErrReached: the latest job of the link is not a failed unlink that
	// could not reach one of its servers; the chain is deleted the normal
	// way (Unlink), not without a server (ForceDelete).
	ErrReached = errors.New("cascade: the latest unlink reached the link's servers")
)

type unlinkParams struct {
	jobParams
	// Delete: the chain goes too once the links are off the servers.
	Delete bool `json:"delete,omitempty"`
	// Force (with Delete): a server the job cannot reach is skipped, left
	// as it is and marked needs attention, instead of failing the job
	// (ForceDelete).
	Force bool `json:"force,omitempty"`
}

// hops are the links of the unlink job, each with the job's Delete and
// Force.
func (p unlinkParams) hops() []unlinkParams {
	var out []unlinkParams
	for _, h := range p.jobParams.hops() {
		out = append(out, unlinkParams{jobParams: h, Delete: p.Delete, Force: p.Force})
	}
	return out
}

// nodes are the servers of the job, each once, the entry of a link before
// its exit: the chain's order for an unlink.
func (p jobParams) nodes() []int64 {
	var out []int64
	for _, h := range p.hops() {
		for _, s := range []int64{h.Entry, h.Exit} {
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// onServers: something of the link may be on its servers (not new, not
// failed), so a job takes it off.
func onServers(l model.ChainLink) bool {
	return l.State != model.LinkNew && l.State != model.LinkFailed
}

// deployedLinks are the links of c on its servers, entry first.
func deployedLinks(c model.Chain) []int {
	var out []int
	for i, l := range c.Links {
		if onServers(l) {
			out = append(out, i)
		}
	}
	return out
}

// unreached records that the connect step of an unlink could not reach a
// server: unreached:<id> is "1".
func unreached(server int64) string { return "unreached:" + strconv.FormatInt(server, 10) }

// skipped: a forced unlink goes on without this server.
func skipped(env *jobs.Env, p unlinkParams, server int64) bool {
	return p.Force && env.Get(unreached(server)) == "1"
}

// Unlink queues the job that takes link idx of a chain off its servers:
// the entry's outbound first (its traffic goes direct again, not into a
// link going away), then the link service and its config, then the
// link's user on the exit. deleteChain removes the chain after: the job
// then takes every deployed link of the chain off (UnlinkChain).
func (l *Linker) Unlink(ctx context.Context, chainID int64, idx int, deleteChain bool, actor int64) (model.Job, error) {
	c, err := l.x.Store.ChainByID(ctx, chainID)
	if err != nil {
		return model.Job{}, err
	}
	if idx < 0 || idx >= len(c.Links) {
		return model.Job{}, store.ErrNotFound
	}
	if !onServers(c.Links[idx]) {
		return model.Job{}, ErrNotDeployed
	}
	idxs := []int{idx}
	if deleteChain {
		idxs = deployedLinks(c)
	}
	return l.x.unlink(ctx, c, idxs, unlinkParams{Delete: deleteChain}, actor)
}

// UnlinkChain queues the job that takes every deployed link of a chain
// off its servers (P4-08), from the entry towards the exit: no server
// sends into a link that is going away. deleteChain removes the chain
// after. ErrNotDeployed: no link is on the servers.
func (l *Linker) UnlinkChain(ctx context.Context, chainID int64, deleteChain bool, actor int64) (model.Job, error) {
	c, err := l.x.Store.ChainByID(ctx, chainID)
	if err != nil {
		return model.Job{}, err
	}
	idxs := deployedLinks(c)
	if len(idxs) == 0 {
		return model.Job{}, ErrNotDeployed
	}
	return l.x.unlink(ctx, c, idxs, unlinkParams{Delete: deleteChain}, actor)
}

// ForceDelete queues the unlink job that deletes the chain without the
// servers it cannot reach. It is for the chain whose latest unlink with
// delete failed for want of a server (Unreached of a deployed link idx;
// ErrReached otherwise): from each server it reaches the job takes the
// links off as UnlinkChain does, one it cannot reach it skips and marks
// needs attention with a note of what the links left there; then the
// chain and its link secrets go. It returns the job and the servers the
// failed unlink did not reach.
func (l *Linker) ForceDelete(ctx context.Context, chainID int64, idx int, actor int64) (model.Job, []Unreached, error) {
	c, err := l.x.Store.ChainByID(ctx, chainID)
	if err != nil {
		return model.Job{}, nil, err
	}
	if idx < 0 || idx >= len(c.Links) {
		return model.Job{}, nil, store.ErrNotFound
	}
	if !onServers(c.Links[idx]) {
		return model.Job{}, nil, ErrNotDeployed
	}
	un, err := l.Unreached(ctx, c, idx)
	if err != nil {
		return model.Job{}, nil, err
	}
	if len(un) == 0 {
		return model.Job{}, nil, ErrReached
	}
	j, err := l.x.unlink(ctx, c, deployedLinks(c), unlinkParams{Delete: true, Force: true}, actor)
	return j, un, err
}

// Forced reports whether job j is an unlink that goes on without the
// servers it cannot reach (ForceDelete): retrying it is for owners and
// admins, as starting it.
func Forced(j model.Job) bool {
	if j.Kind != JobUnlink {
		return false
	}
	var p unlinkParams
	return json.Unmarshal(j.Params, &p) == nil && p.Force
}

// Unreached is a server the latest unlink of a link could not reach, with
// what the links leave there when the chain is deleted without it.
type Unreached struct {
	Server int64
	// Entry: a link of the job starts at the server (an entry or a
	// relay).
	Entry bool
	// Left is what the links put on the server and the deletion leaves
	// there (Left), by the server's current config.
	Left []string
}

// scanJobs bounds how many jobs of the entry Unreached looks through for
// the latest job of a link: an older one does not count, and the admin
// deletes the chain the normal way first.
const scanJobs = 1000

// Unreached are the servers that the latest job of deployed link idx of
// chain c (link or unlink) could not reach, when that job is an unlink
// with delete and failed: the chain may then be deleted without them
// (ForceDelete). They are of every link of that job, in the chain's
// order. Nil: the normal unlink may still work (no such attempt, a newer
// job of the link ran, every server answered, or a job of the link is
// running).
func (l *Linker) Unreached(ctx context.Context, c model.Chain, idx int) ([]Unreached, error) {
	x := l.x
	if idx < 0 || idx >= len(c.Links) {
		return nil, nil
	}
	link := c.Links[idx]
	if !onServers(link) {
		return nil, nil
	}
	j, p, err := x.lastLinkJob(ctx, c.ID, link)
	if err != nil || j.Kind != JobUnlink || j.State != model.JobFailed || !p.Delete {
		return nil, err
	}
	var out []Unreached
	for _, s := range p.nodes() {
		if j.Data[unreached(s)] != "1" {
			continue
		}
		in, err := x.Store.Installation(ctx, s)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		var cfg *hyconfig.Server
		if cur, err := x.Store.CurrentConfig(ctx, s); err == nil {
			if b, _, err := x.revision(ctx, s, cur.Revision); err == nil {
				cfg, _ = hyconfig.ParseServer(b)
			}
		}
		u := Unreached{Server: s}
		for _, h := range p.jobParams.hops() {
			if h.Entry == s {
				u.Entry = true
				u.Left = append(u.Left, Left(c.ID, h.Idx, true, in, cfg)...)
			}
			if h.Exit == s {
				u.Left = append(u.Left, Left(c.ID, h.Idx, false, in, cfg)...)
			}
		}
		out = append(out, u)
	}
	return out, nil
}

// lastLinkJob is the newest link or unlink job that works on the link,
// with its params (a zero job: none among the entry's latest scanJobs
// jobs).
func (x *linker) lastLinkJob(ctx context.Context, chainID int64, link model.ChainLink) (model.Job, unlinkParams, error) {
	var before int64
	for seen := 0; seen < scanJobs; {
		js, err := x.Jobs.Store.ListJobs(ctx, model.JobFilter{ServerID: link.From, Limit: 100, BeforeID: before})
		if err != nil || len(js) == 0 {
			return model.Job{}, unlinkParams{}, err
		}
		for _, j := range js {
			if j.Kind != JobLink && j.Kind != JobUnlink {
				continue
			}
			var p unlinkParams
			if json.Unmarshal(j.Params, &p) == nil && p.Chain == chainID && p.covers(link.Idx) {
				return j, p, nil
			}
		}
		seen += len(js)
		before = js[len(js)-1].ID
	}
	return model.Job{}, unlinkParams{}, nil
}

// unlink queues the unlink job of links idxs of chain c (entry first)
// with the params of p that are not about the links.
func (x *linker) unlink(ctx context.Context, c model.Chain, idxs []int, p unlinkParams, actor int64) (model.Job, error) {
	var hops []jobParams
	for _, idx := range idxs {
		if idx < 0 || idx >= len(c.Links) {
			return model.Job{}, store.ErrNotFound
		}
		link := c.Links[idx]
		if !onServers(link) {
			return model.Job{}, ErrNotDeployed
		}
		h, err := x.hop(ctx, c.ID, link)
		if err != nil {
			return model.Job{}, err
		}
		hops = append(hops, h)
	}
	if len(hops) == 0 {
		return model.Job{}, ErrNotDeployed
	}
	p.jobParams = hops[0]
	if len(hops) > 1 {
		p.jobParams = jobParams{Chain: c.ID, Hops: hops}
	}
	return x.Jobs.SubmitOn(ctx, JobUnlink, jobServers(c, idxs), p, nil, actor)
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
			w := func(h unlinkParams, f func(context.Context, *jobs.Env, unlinkParams) error) func(context.Context, *jobs.Env) error {
				return func(ctx context.Context, env *jobs.Env) error { return f(ctx, env, h) }
			}
			d := func(h unlinkParams, f func(context.Context, *jobs.Env, unlinkParams) (bool, error)) func(context.Context, *jobs.Env) (bool, error) {
				return func(ctx context.Context, env *jobs.Env) (bool, error) { return f(ctx, env, h) }
			}
			// on: in a forced unlink a step of one server does nothing once
			// the connect step could not reach that server (its Undo finds
			// nothing recorded). The steps of a normal unlink are as they
			// are.
			on := func(server int64, s jobs.Step) jobs.Step {
				if !p.Force {
					return s
				}
				done, run := s.Done, s.Run
				s.Done = func(ctx context.Context, env *jobs.Env) (bool, error) {
					if done == nil || skipped(env, p, server) {
						return false, nil
					}
					return done(ctx, env)
				}
				s.Run = func(ctx context.Context, env *jobs.Env) error {
					if skipped(env, p, server) {
						return nil
					}
					return run(ctx, env)
				}
				return s
			}
			// As in the link job, a retry or a recovery before the commit
			// starts at check.
			steps := []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: w(p, x.unconnect)},
				{Name: "check", Phase: model.JobPreflight, Safe: true, Run: w(p, x.uncheck)},
			}
			// Hop by hop from the entry. A relay's config is written whole
			// by the hop that ends there (without the credentials of that
			// hop and without the outbound of the next), so the step of
			// the next hop finds it done.
			for _, h := range p.hops() {
				steps = append(steps,
					on(h.Entry, jobs.Step{Name: h.key("entry-config"), Phase: model.JobConfiguring, Done: d(h, x.unEntryDone), Run: w(h, x.unEntry),
						Undo: func(ctx context.Context, env *jobs.Env) error {
							return x.undoConfig(ctx, env, h.Entry, h.key("entryConfig"), h.key("entryChanged"), x.role(ctx, h.jobParams, h.Entry, "входа"))
						}}),
					on(h.Entry, jobs.Step{Name: h.key("entry-restart"), Phase: model.JobStarting, Done: restarted(h.key("entryChanged")), Run: func(ctx context.Context, env *jobs.Env) error {
						return x.restart(ctx, env, h.Entry, h.key("entryChanged"), x.role(ctx, h.jobParams, h.Entry, "входа"))
					}}),
					on(h.Entry, jobs.Step{Name: h.key("entry-verify"), Phase: model.JobVerifying, Run: w(h, x.unEntryVerify)}),
					on(h.Entry, jobs.Step{Name: h.key("link-service"), Phase: model.JobConfiguring, Done: d(h, x.unServiceDone), Run: w(h, x.unService), Undo: w(h, x.undoUnService)}),
					on(h.Entry, jobs.Step{Name: h.key("link-config"), Phase: model.JobConfiguring, Done: d(h, x.unConfigDone), Run: w(h, x.unConfig), Undo: w(h, x.undoUnConfig)}),
					on(h.Exit, jobs.Step{Name: h.key("exit-config"), Phase: model.JobConfiguring, Done: d(h, x.unExitDone), Run: w(h, x.unExit),
						Undo: func(ctx context.Context, env *jobs.Env) error {
							return x.undoConfig(ctx, env, h.Exit, h.key("exitConfig"), h.key("exitChanged"), x.role(ctx, h.jobParams, h.Exit, "выхода"))
						}}),
					on(h.Exit, jobs.Step{Name: h.key("exit-restart"), Phase: model.JobStarting, Done: restarted(h.key("exitChanged")), Run: func(ctx context.Context, env *jobs.Env) error {
						return x.restart(ctx, env, h.Exit, h.key("exitChanged"), x.role(ctx, h.jobParams, h.Exit, "выхода"))
					}}),
					on(h.Exit, jobs.Step{Name: h.key("exit-verify"), Phase: model.JobVerifying, Run: w(h, x.unExitVerify)}),
				)
			}
			return append(steps,
				jobs.Step{Name: "commit", Phase: model.JobVerifying, Safe: true, Done: d(p, x.unCommitted), Run: w(p, x.unCommit)},
				jobs.Step{Name: "cleanup", Phase: model.JobVerifying, Safe: true, Run: w(p, x.unCleanup)},
			), nil
		},
		Recover:  func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
		Finished: x.unFinished,
	}
}

// unplan is what the unlink job writes for a hop: both configs without
// the links of the job, built from the base revisions (no chain needed:
// the chain may be gone once the job commits).
type unplan struct {
	inExit, inEntry         model.Installation
	exitBase, exitCfg       []byte
	entryBase, entryCfg     []byte
	exitParsed, entryParsed *hyconfig.Server
	linkPath, unitPath      string
	exitRole, entryRole     string
	red                     *redact.Redactor
}

// without takes out of config cfg of server, in place, what the links of
// hop p's job put there: the credentials of each link that ends at the
// server and the outbound of the one that starts there. It reports
// whether cfg changed.
func without(p jobParams, server int64, cfg *hyconfig.Server) bool {
	changed := false
	for _, h := range p.all() {
		if h.Exit == server {
			changed = ExitWithout(cfg, User(h.Chain, h.Idx)) || changed
		}
		if h.Entry == server {
			changed = EntryWithout(cfg) || changed
		}
	}
	return changed
}

func (x *linker) unplan(ctx context.Context, p unlinkParams) (*unplan, error) {
	u := &unplan{red: redact.New()}
	var err error
	u.exitRole, u.entryRole = x.role(ctx, p.jobParams, p.Exit, "выхода"), x.role(ctx, p.jobParams, p.Entry, "входа")
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
		return nil, jobs.Fail("Конфиг сервера "+u.exitRole+" не разобрать.", err)
	}
	u.red.Add(service.ConfigSecrets(u.exitParsed)...)
	u.exitCfg = u.exitBase
	if without(p.jobParams, p.Exit, u.exitParsed) {
		if u.exitCfg, err = u.exitParsed.Marshal(); err != nil {
			return nil, err
		}
	}
	if u.entryBase, _, err = x.revision(ctx, p.Entry, p.EntryBase); err != nil {
		return nil, err
	}
	if u.entryParsed, err = hyconfig.ParseServer(u.entryBase); err != nil {
		return nil, jobs.Fail("Конфиг сервера "+u.entryRole+" не разобрать.", err)
	}
	u.red.Add(service.ConfigSecrets(u.entryParsed)...)
	u.entryCfg = u.entryBase
	if without(p.jobParams, p.Entry, u.entryParsed) {
		if u.entryCfg, err = u.entryParsed.Marshal(); err != nil {
			return nil, err
		}
	}
	u.linkPath, u.unitPath = ConfigPath(u.inEntry, p.Chain, p.Idx), UnitPath(p.Chain, p.Idx)
	return u, nil
}

// unconnect connects to the job's servers as the link job does. A server
// it cannot reach is recorded (unreached): the unlink fails there, and the
// chain may then be deleted without that server (ForceDelete). A forced
// unlink goes on without it; the steps of that server do nothing, and the
// commit marks it.
func (x *linker) unconnect(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	skip := 0
	for _, s := range p.servers() {
		role := x.serverRole(ctx, p.jobParams, s)
		down, err := x.reach(ctx, env, s, role)
		if ctx.Err() != nil {
			return ctx.Err() // stopping: no record of a server that did answer
		}
		if down || env.Get(unreached(s)) != "" {
			mark := ""
			if down {
				mark = "1"
			}
			if err := env.Set(unreached(s), mark); err != nil {
				return err
			}
		}
		if err == nil {
			continue
		}
		if !down || !p.Force {
			return err
		}
		var se *jobs.StepError
		if errors.As(err, &se) && se.Err != nil {
			err = se.Err
		}
		env.Warnf("Сервер %s не отвечает (%v): каскад удаляется без него, на сервере ничего не меняется.", role, err)
		skip++
	}
	switch {
	case p.Force && skip == 0 && !p.multi():
		env.Logf("Оба сервера отвечают: связь снимается с обоих, как при обычном удалении.")
	case p.Force && skip == 0:
		env.Logf("Все серверы отвечают: связи снимаются со всех, как при обычном удалении.")
	}
	return nil
}

// uncheck: the servers still have the configs the job builds on (or this
// job's); a forced unlink does not look at a server it skips. The links
// become unlinking.
func (x *linker) uncheck(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	type server struct {
		id         int64
		path, base string
		want       []byte
		role       string
	}
	var servers []server
	for _, h := range p.hops() {
		u, err := x.unplan(ctx, h)
		if err != nil {
			return err
		}
		for _, s := range []server{{h.Exit, u.inExit.Config, h.ExitBaseSHA, u.exitCfg, u.exitRole}, {h.Entry, u.inEntry.Config, h.EntryBaseSHA, u.entryCfg, u.entryRole}} {
			if !slices.ContainsFunc(servers, func(o server) bool { return o.id == s.id }) {
				servers = append(servers, s)
			}
		}
	}
	for _, s := range servers {
		if skipped(env, p, s.id) {
			continue
		}
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
	for _, h := range p.hops() {
		if h.Idx < len(c.Links) {
			link := c.Links[h.Idx]
			link.State, link.UpdatedAt = model.LinkUnlinking, x.Now()
			if err := x.Store.UpdateLink(ctx, link); err != nil {
				return err
			}
		}
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
	if err := backupFile(ctx, env, ex, u.inEntry.Config, p.key("entryConfig"), su); err != nil {
		return err
	}
	if err := env.Set(p.key("entryChanged"), "1"); err != nil {
		return err
	}
	if err := writeConfig(ctx, ex, u.inEntry, u.entryCfg, su); err != nil {
		return jobs.Fail("Не удалось записать конфиг сервера "+u.entryRole+".", err)
	}
	env.Logf("С сервера %s убран outbound «%s»: его трафик снова идёт напрямую.", u.entryRole, OutboundName)
	return nil
}

func (x *linker) unEntryVerify(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	if env.Get(p.key("entryChanged")) != "1" {
		return nil
	}
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	return x.waitServer(ctx, env, p.Entry, u.inEntry, u.entryParsed, u.red, u.entryRole)
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
	if env.Get(p.key("linkUnit")) != "" {
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
	if err := backupFile(ctx, env, ex, path, p.key("linkUnit"), su); err != nil {
		return err
	}
	if st := env.Get(p.key("linkUnit")); st == remote.Absent {
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
	state := env.Get(p.key("linkUnit"))
	if state == "" || state == remote.Absent || committedRevision(env) {
		return jobs.ErrNothingToUndo
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	if _, err := restoreFile(ctx, env, ex, UnitPath(p.Chain, p.Idx), p.key("linkUnit"), su); err != nil && !errors.Is(err, jobs.ErrNothingToUndo) {
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
	if err := backupFile(ctx, env, ex, u.linkPath, p.key("linkConfig"), su); err != nil {
		return err
	}
	if err := remote.RemoveFile(ctx, ex, u.linkPath, su); err != nil {
		return jobs.Fail("Не удалось удалить конфиг клиента связи.", err)
	}
	env.Logf("Конфиг клиента связи удалён: %s.", u.linkPath)
	return nil
}

func (x *linker) undoUnConfig(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	if env.Get(p.key("linkConfig")) == "" || committedRevision(env) {
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
	_, err = restoreFile(ctx, env, ex, u.linkPath, p.key("linkConfig"), sudo(env, p.Entry))
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
	if err := backupFile(ctx, env, ex, u.inExit.Config, p.key("exitConfig"), su); err != nil {
		return err
	}
	if err := env.Set(p.key("exitChanged"), "1"); err != nil {
		return err
	}
	if err := writeConfig(ctx, ex, u.inExit, u.exitCfg, su); err != nil {
		return jobs.Fail("Не удалось записать конфиг сервера "+u.exitRole+".", err)
	}
	if base, err := hyconfig.ParseServer(u.exitBase); err == nil && HasUser(base, User(p.Chain, p.Idx)) {
		env.Logf("С сервера %s убран пользователь связи %s.", u.exitRole, User(p.Chain, p.Idx))
	}
	if slices.ContainsFunc(p.all(), func(h jobParams) bool { return h.Entry == p.Exit }) {
		env.Logf("С сервера %s убран outbound «%s» следующего участка: его трафик снова идёт напрямую.", u.exitRole, OutboundName)
	}
	return nil
}

func (x *linker) unExitVerify(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	if env.Get(p.key("exitChanged")) != "1" {
		return nil
	}
	u, err := x.unplan(ctx, p)
	if err != nil {
		return err
	}
	return x.waitServer(ctx, env, p.Exit, u.inExit, u.exitParsed, u.red, u.exitRole)
}

// unCommitted: the chain is gone (Delete) or the job's links are new
// again.
func (x *linker) unCommitted(ctx context.Context, env *jobs.Env, p unlinkParams) (bool, error) {
	c, err := x.Store.ChainByID(ctx, p.Chain)
	if errors.Is(err, store.ErrNotFound) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	if p.Delete {
		return false, nil
	}
	for _, h := range p.hops() {
		if h.Idx >= len(c.Links) || c.Links[h.Idx].State != model.LinkNew {
			return false, nil
		}
	}
	return true, nil
}

// unCommit stores the revisions without the links (source cascade), then
// deletes the chain or makes its links new again, without secrets: a new
// deployment makes new ones. A server a forced unlink skipped keeps its
// revision (it still runs that config) and is marked first.
func (x *linker) unCommit(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	var all, cs []newConfig
	for _, h := range p.hops() {
		u, err := x.unplan(ctx, h)
		if err != nil {
			return err
		}
		for _, c := range []newConfig{{h.Entry, u.inEntry, u.entryCfg, u.entryBase, u.entryParsed}, {h.Exit, u.inExit, u.exitCfg, u.exitBase, u.exitParsed}} {
			all = addConfig(all, c)
			if !skipped(env, p, c.id) {
				cs = addConfig(cs, c)
			}
		}
	}
	if _, err := x.addRevisions(ctx, env, cs); err != nil {
		return err
	}
	if p.Delete {
		var off, left []string
		for _, s := range p.nodes() {
			role := x.serverRole(ctx, p.jobParams, s)
			if !skipped(env, p, s) {
				off = append(off, role)
				continue
			}
			i := slices.IndexFunc(all, func(c newConfig) bool { return c.id == s })
			if err := x.strand(ctx, env, p, all[i].in, all[i].base, s); err != nil {
				return err
			}
			left = append(left, role)
		}
		if err := x.Store.DeleteChain(ctx, p.Chain, x.Now()); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		switch {
		case len(left) == 0:
			env.Logf("Связь снята с серверов, каскад удалён.")
		case len(off) == 0:
			env.Logf("Каскад удалён без серверов: ни один не ответил, на них ничего не изменилось.")
		case !p.multi():
			env.Logf("Связь снята с сервера %s, сервер %s пропущен; каскад удалён.", off[0], left[0])
		default:
			env.Logf("Связи сняты с серверов %s, пропущены %s; каскад удалён.", strings.Join(off, ", "), strings.Join(left, ", "))
		}
		return nil
	}
	c, err := x.Store.ChainByID(ctx, p.Chain)
	if err != nil {
		return err
	}
	for _, h := range p.hops() {
		if h.Idx >= len(c.Links) {
			continue
		}
		link := c.Links[h.Idx]
		link.State, link.FromRevision, link.ToRevision, link.ConfigSHA256, link.UnitSHA256, link.UpdatedAt = model.LinkNew, 0, 0, "", "", x.Now()
		if err := x.Store.UpdateLink(ctx, link); err != nil {
			return err
		}
		if err := x.Store.SetLinkSecrets(ctx, p.Chain, h.Idx, nil, x.Now()); err != nil {
			return err
		}
	}
	env.Logf("Связь снята с серверов; каскад остался, его можно развернуть снова.")
	return nil
}

// strand marks a server a forced unlink skipped, once per job: needs
// attention, with a note of what the job's links may have left there
// (Left, by base, the revision the job built on; in is its
// installation). A server the links never changed (an exit with password
// auth) is not marked.
func (x *linker) strand(ctx context.Context, env *jobs.Env, p unlinkParams, in model.Installation, base []byte, server int64) error {
	key := "stranded:" + strconv.FormatInt(server, 10)
	if env.Get(key) == "1" {
		return nil
	}
	role := x.serverRole(ctx, p.jobParams, server)
	c, err := hyconfig.ParseServer(base) // the parsed plan has the links taken out
	if err != nil {
		return err
	}
	var left []string
	for _, h := range p.jobParams.hops() {
		if h.Entry == server {
			left = append(left, Left(p.Chain, h.Idx, true, in, c)...)
		}
		if h.Exit == server {
			left = append(left, Left(p.Chain, h.Idx, false, in, c)...)
		}
	}
	if len(left) == 0 {
		env.Logf("На сервере %s от каскада ничего нет (вход клиентов по общему паролю или пользователя связи в конфиге нет): сервер не помечается.", role)
		return env.Set(key, "1")
	}
	name := "#" + strconv.FormatInt(p.Chain, 10)
	if ch, err := x.Store.ChainByID(ctx, p.Chain); err == nil {
		name = "«" + ch.Name + "»"
	}
	what := strings.Join(left, "; ")
	note := fmt.Sprintf("Каскад %s удалён %s без этого сервера: он не отвечал. На сервере могли остаться: %s. Уберите их, когда сервер снова будет доступен.", name, x.Now().Format("02.01.2006"), what)
	if err := x.Store.AddServerNote(ctx, server, note, x.Now()); err != nil {
		return err
	}
	if err := x.Store.SetServerState(ctx, server, model.StateNeedsAttention, x.Now()); err != nil {
		return err
	}
	env.Warnf("Сервер %s помечен «Требует внимания», в его заметки записано, что на нём могло остаться: %s.", role, what)
	return env.Set(key, "1")
}

func (x *linker) unCleanup(ctx context.Context, env *jobs.Env, p unlinkParams) error {
	for _, h := range p.hops() {
		u, err := x.unplan(ctx, h)
		if err != nil {
			return err
		}
		for _, f := range []struct {
			server int64
			path   string
			flag   string
		}{{h.Exit, u.inExit.Config, h.key("exitConfig")}, {h.Entry, u.inEntry.Config, h.key("entryConfig")}, {h.Entry, u.linkPath, h.key("linkConfig")}, {h.Entry, u.unitPath, h.key("linkUnit")}} {
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
	}
	return nil
}

// unFinished: a failed unlink leaves the links as they were; servers
// whose rollback did not finish need attention.
func (x *linker) unFinished(ctx context.Context, env *jobs.Env, j model.Job) {
	var p unlinkParams
	if err := env.DecodeParams(&p); err != nil || j.State != model.JobFailed {
		return
	}
	if c, err := x.Store.ChainByID(ctx, p.Chain); err == nil {
		for _, h := range p.hops() {
			if h.Idx >= len(c.Links) {
				continue
			}
			link := c.Links[h.Idx]
			link.State, link.UpdatedAt = h.Prev, x.Now()
			if !link.State.Valid() || link.State == model.LinkUnlinking || link.State == model.LinkLinking {
				link.State = model.LinkStale
			}
			x.Store.UpdateLink(ctx, link)
		}
	}
	if env.Rollback() == jobs.RollbackFailed {
		for _, s := range p.servers() {
			x.Store.SetServerState(ctx, s, model.StateNeedsAttention, x.Now())
		}
	}
}

// Sync compares the deployed links of a chain with the servers' current
// configs: a link that a redeployment would change (passwords rotated,
// ports, address or certificate changed, the outbound gone after a
// deploy) becomes stale; a stale one that would not change is active
// again. It returns the chain as stored after. Each link of a longer
// chain is looked at alone: a relay's config has both the credentials of
// the link before and the outbound of the link after.
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
// configs would change nothing, with those revisions. The same revisions
// are not enough: the link client takes the exit's address and hop
// interval from its server record, which changes without a revision.
func (x *linker) fresh(ctx context.Context, chainID int64, link model.ChainLink) (bool, int, int, error) {
	ce, err := x.Store.CurrentConfig(ctx, link.From)
	if err != nil {
		return false, 0, 0, err
	}
	cx, err := x.Store.CurrentConfig(ctx, link.To)
	if err != nil {
		return false, 0, 0, err
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
