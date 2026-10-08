package cascade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/importer"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// JobLink deploys a link, or deploys it again (P3-02b); one job deploys
// several links of a chain (P4-08).
const JobLink = "link"

// Backup is the suffix of the files the job replaces, kept while it works.
const Backup = ".hyroute-prev"

// Store is what the link job keeps in the controller's database.
type Store interface {
	store.Chains
	store.Configs
	store.Installations
	ServerByID(ctx context.Context, id int64) (model.Server, error)
	SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error
	AddServerNote(ctx context.Context, id int64, note string, at time.Time) error
}

// Deps are the link job's collaborators.
type Deps struct {
	Store Store
	Keys  *secrets.Keyring
	Jobs  *jobs.Engine
	Now   func() time.Time
	// VerifyTimeout bounds the wait for a restarted service and for the
	// link to come up; Poll is how often they are looked at.
	VerifyTimeout time.Duration
	Poll          time.Duration
}

type linker struct{ Deps }

// Linker starts link jobs and is their kind.
type Linker struct{ x *linker }

// New returns the linker.
func New(d Deps) *Linker {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.VerifyTimeout == 0 {
		d.VerifyTimeout = 30 * time.Second
	}
	if d.Poll == 0 {
		d.Poll = 2 * time.Second
	}
	return &Linker{&linker{d}}
}

var (
	// ErrNoConfig: HyRoute does not know the config of a server of the
	// link.
	ErrNoConfig = errors.New("cascade: a server has no config")
	// ErrNoInstallation: HyRoute does not know where Hysteria is on a
	// server of the link.
	ErrNoInstallation = errors.New("cascade: a server has no known installation")
)

// jobParams are the params of a link job (no secrets): one link, or
// several links of a chain (Hops).
type jobParams struct {
	Chain int64 `json:"chain"`
	Idx   int   `json:"idx"`
	Entry int64 `json:"entry"`
	Exit  int64 `json:"exit"`
	// EntryBase and ExitBase are the config revisions the job builds on,
	// with the SHA-256 of their files: a server still has that file, or
	// the one this job writes.
	EntryBase    int    `json:"entryBase"`
	EntryBaseSHA string `json:"entryBaseSha"`
	ExitBase     int    `json:"exitBase"`
	ExitBaseSHA  string `json:"exitBaseSha"`
	// Prev is the link's state before the job: a failed redeployment goes
	// back to it.
	Prev model.LinkState `json:"prev"`
	// Hops are the links of a job on several links of a chain (P4-08),
	// each as the params of a job on it alone, in the order the job works
	// on them: a deployment from the exit towards the entry, an unlink
	// from the entry towards the exit. The fields above but Chain are then
	// not used. A relay is in two hops with the same base revision: what
	// the job writes to a server has the parts of every hop of the job
	// that touches it (with, without).
	Hops []jobParams `json:"hops,omitempty"`

	// job is the job a hop belongs to; nil: a job on one link.
	job *jobParams
}

// hops are the links of the job, in its order, each knowing its job. A
// job on one link is its only hop.
func (p jobParams) hops() []jobParams {
	if len(p.Hops) == 0 {
		return []jobParams{p}
	}
	job := p
	out := make([]jobParams, len(p.Hops))
	for i, h := range p.Hops {
		h.Chain, h.Hops, h.job = p.Chain, nil, &job
		out[i] = h
	}
	return out
}

// multi: a job on several links (or a hop of one).
func (p jobParams) multi() bool { return p.job != nil || len(p.Hops) > 0 }

// all are the hops of the job hop p belongs to.
func (p jobParams) all() []jobParams {
	if p.job == nil {
		return []jobParams{p}
	}
	return p.job.hops()
}

// key is the name under which hop p records k in the job's data, and the
// name of its step k: a job on one link keeps the names it always had.
func (p jobParams) key(k string) string {
	if !p.multi() {
		return k
	}
	return k + ":" + strconv.Itoa(p.Idx)
}

// covers reports whether the job works on link idx.
func (p jobParams) covers(idx int) bool {
	return slices.ContainsFunc(p.hops(), func(h jobParams) bool { return h.Idx == idx })
}

// servers are the servers of the job, each once, in the order of its
// hops, the exit of a hop before its entry.
func (p jobParams) servers() []int64 {
	var out []int64
	for _, h := range p.hops() {
		for _, s := range []int64{h.Exit, h.Entry} {
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Submit queues the job that deploys link idx of a chain, or deploys it
// again (a stale link, new settings). The job changes both servers.
func (l *Linker) Submit(ctx context.Context, chainID int64, idx int, actor int64) (model.Job, error) {
	c, err := l.x.Store.ChainByID(ctx, chainID)
	if err != nil {
		return model.Job{}, err
	}
	if idx < 0 || idx >= len(c.Links) {
		return model.Job{}, store.ErrNotFound
	}
	return l.x.submit(ctx, c, []int{idx}, actor)
}

// Deploy queues the job that deploys the links of a chain that need it
// (P4-08): those not active (new, failed, stale; «Обновить» touches only
// these), or every link when all are active (deployed again over what
// runs, as for a chain of two). One job deploys them from the exit
// towards the entry, so a server gets the outbound into a link only once
// the hops after it work; a failure on any hop rolls back what the job
// changed on every server.
func (l *Linker) Deploy(ctx context.Context, chainID int64, actor int64) (model.Job, error) {
	c, err := l.x.Store.ChainByID(ctx, chainID)
	if err != nil {
		return model.Job{}, err
	}
	var idxs, all []int
	for i := len(c.Links) - 1; i >= 0; i-- {
		all = append(all, i)
		if c.Links[i].State != model.LinkActive {
			idxs = append(idxs, i)
		}
	}
	if len(idxs) == 0 {
		idxs = all
	}
	if len(idxs) == 0 {
		return model.Job{}, store.ErrNotFound
	}
	return l.x.submit(ctx, c, idxs, actor)
}

// submit queues the job that deploys links idxs of chain c, in that order.
func (x *linker) submit(ctx context.Context, c model.Chain, idxs []int, actor int64) (model.Job, error) {
	var hops []jobParams
	for _, idx := range idxs {
		link := c.Links[idx]
		if _, err := ParseParams(link.Params); err != nil {
			return model.Job{}, err
		}
		h, err := x.hop(ctx, c.ID, link)
		if err != nil {
			return model.Job{}, err
		}
		// The link's secrets are made once, before the job: every step
		// builds the same files from them.
		sealed, err := x.Store.LinkSecrets(ctx, c.ID, idx)
		if err != nil {
			return model.Job{}, err
		}
		if len(sealed) == 0 {
			s, err := NewSecrets()
			if err != nil {
				return model.Job{}, err
			}
			if sealed, err = SealSecrets(x.Keys, c.ID, idx, s); err != nil {
				return model.Job{}, err
			}
			if err := x.Store.SetLinkSecrets(ctx, c.ID, idx, sealed, x.Now()); err != nil {
				return model.Job{}, err
			}
		}
		hops = append(hops, h)
	}
	p := hops[0]
	if len(hops) > 1 {
		p = jobParams{Chain: c.ID, Hops: hops}
	}
	return x.Jobs.SubmitOn(ctx, JobLink, jobServers(c, idxs), p, nil, actor)
}

// hop is the params of a job on link alone: its servers' current
// revisions and its state.
func (x *linker) hop(ctx context.Context, chainID int64, link model.ChainLink) (jobParams, error) {
	p := jobParams{Chain: chainID, Idx: link.Idx, Entry: link.From, Exit: link.To, Prev: link.State}
	for _, s := range []struct {
		id   int64
		rev  *int
		hash *string
	}{{link.From, &p.EntryBase, &p.EntryBaseSHA}, {link.To, &p.ExitBase, &p.ExitBaseSHA}} {
		cur, err := x.Store.CurrentConfig(ctx, s.id)
		if errors.Is(err, store.ErrNotFound) {
			return p, ErrNoConfig
		} else if err != nil {
			return p, err
		}
		if _, err := x.Store.Installation(ctx, s.id); errors.Is(err, store.ErrNotFound) {
			return p, ErrNoInstallation
		} else if err != nil {
			return p, err
		}
		*s.rev, *s.hash = cur.Revision, cur.SHA256
	}
	return p, nil
}

// jobServers are the servers a job on links idxs of chain c changes, in
// the chain's order: the first is the job's server (the entry of a job on
// one link).
func jobServers(c model.Chain, idxs []int) []int64 {
	lo, hi := slices.Min(idxs), slices.Max(idxs)
	return slices.Clone(c.Nodes[lo : hi+2])
}

// Kind is the link job.
func (l *Linker) Kind() *jobs.Kind {
	x := l.x
	return &jobs.Kind{
		Name: JobLink,
		Steps: func(raw json.RawMessage) ([]jobs.Step, error) {
			var p jobParams
			if err := json.Unmarshal(raw, &p); err != nil {
				return nil, err
			}
			w := func(h jobParams, f func(context.Context, *jobs.Env, jobParams) error) func(context.Context, *jobs.Env) error {
				return func(ctx context.Context, env *jobs.Env) error { return f(ctx, env, h) }
			}
			d := func(h jobParams, f func(context.Context, *jobs.Env, jobParams) (bool, error)) func(context.Context, *jobs.Env) (bool, error) {
				return func(ctx context.Context, env *jobs.Env) (bool, error) { return f(ctx, env, h) }
			}
			// Each step looks at the servers first. A retry or a recovery
			// before the commit starts at check, which compares the
			// servers' configs with the base revisions again and marks
			// the links linking (a rollback may have run, and the configs
			// may have been edited since); steps done already are skipped,
			// a service restarted already is not restarted again.
			steps := []jobs.Step{
				{Name: "connect", Phase: model.JobConnecting, Safe: true, Run: w(p, x.connect)},
				{Name: "check", Phase: model.JobPreflight, Safe: true, Run: w(p, x.check)},
			}
			// Hop by hop from the exit: the entry of a hop gets the outbound
			// into the link once the link works. A relay's config is
			// written whole by the hop it starts (outbound and the
			// credentials of the hop before it), so the step of the hop
			// before finds it done.
			for _, h := range p.hops() {
				steps = append(steps,
					jobs.Step{Name: h.key("exit-config"), Phase: model.JobConfiguring, Done: d(h, x.exitConfigDone), Run: w(h, x.exitConfig), Undo: w(h, x.undoExitConfig)},
					jobs.Step{Name: h.key("exit-restart"), Phase: model.JobStarting, Done: restarted(h.key("exitChanged")), Run: w(h, x.exitRestart)},
					jobs.Step{Name: h.key("exit-verify"), Phase: model.JobVerifying, Run: w(h, x.exitVerify)},
					jobs.Step{Name: h.key("link-config"), Phase: model.JobConfiguring, Done: d(h, x.linkConfigDone), Run: w(h, x.linkConfig), Undo: w(h, x.undoLinkConfig)},
					jobs.Step{Name: h.key("link-service"), Phase: model.JobStarting, Run: w(h, x.linkService), Undo: w(h, x.undoLinkService)},
					jobs.Step{Name: h.key("link-check"), Phase: model.JobVerifying, Run: w(h, x.linkCheck)},
					jobs.Step{Name: h.key("entry-config"), Phase: model.JobConfiguring, Done: d(h, x.entryConfigDone), Run: w(h, x.entryConfig), Undo: w(h, x.undoEntryConfig)},
					jobs.Step{Name: h.key("entry-restart"), Phase: model.JobStarting, Done: restarted(h.key("entryChanged")), Run: w(h, x.entryRestart)},
					jobs.Step{Name: h.key("entry-verify"), Phase: model.JobVerifying, Run: w(h, x.entryVerify)},
				)
			}
			return append(steps,
				jobs.Step{Name: "commit", Phase: model.JobVerifying, Safe: true, Done: d(p, x.committed), Run: w(p, x.commit)},
				jobs.Step{Name: "cleanup", Phase: model.JobVerifying, Safe: true, Run: w(p, x.cleanup)},
			), nil
		},
		Recover:  func(context.Context, *jobs.Env) (jobs.Resolution, error) { return jobs.ResolveRetry, nil },
		Finished: x.finished,
	}
}

// sudo: commands on the server go through sudo unless the SSH user is
// root (the connect step records it per server).
func sudo(env *jobs.Env, server int64) bool {
	return env.Get("root:"+strconv.FormatInt(server, 10)) != "true"
}

func execOn(ctx context.Context, env *jobs.Env, server int64) (remote.Executor, error) {
	ex, err := env.ExecOn(ctx, server)
	if err != nil {
		return nil, jobs.Fail(fmt.Sprintf("Не удалось подключиться по SSH к серверу %d.", server), err)
	}
	return ex, nil
}

// role names a server of job (or hop) p in the messages, after the word
// «сервер» in the genitive: входа or выхода (legacy) in a job on one
// link, the server's name in a job on several, where a relay is both.
func (x *linker) role(ctx context.Context, p jobParams, server int64, legacy string) string {
	if !p.multi() {
		return legacy
	}
	if s, err := x.Store.ServerByID(ctx, server); err == nil {
		return "«" + s.Name + "»"
	}
	return "#" + strconv.FormatInt(server, 10)
}

// plan is what the job writes, built again by every step from the
// stored revisions, the link's params and its secrets: a resumed job
// writes the same files.
type plan struct {
	link            model.ChainLink
	params          Params
	secrets         Secrets
	exit, entry     model.Server
	inExit, inEntry model.Installation
	exitMeta        model.ConfigMeta
	// exitCfg and entryCfg are the servers' configs with the links of the
	// job, exitBase and entryBase without; changed when they differ.
	exitBase, exitCfg   []byte
	entryBase, entryCfg []byte
	exitParsed          *hyconfig.Server
	entryParsed         *hyconfig.Server
	client              []byte
	unit                string
	linkPath, unitPath  string
	// exitRole and entryRole name the servers in messages (role).
	exitRole, entryRole string
	// others are the secrets of the other hops of the job.
	others []Secrets
	// nodes is how many servers the chain has.
	nodes int
}

func (x *linker) revision(ctx context.Context, server int64, rev int) ([]byte, model.ConfigMeta, error) {
	c, err := x.Store.ConfigRevision(ctx, server, rev)
	if err != nil {
		return nil, model.ConfigMeta{}, err
	}
	b, err := x.Keys.Open(c.Sealed, model.ConfigContext(server, rev))
	return b, c.Meta, err
}

// linkData are the params and secrets of link idx of chain c.
func (x *linker) linkData(ctx context.Context, c model.Chain, idx int) (Params, Secrets, error) {
	if idx >= len(c.Links) {
		return Params{}, Secrets{}, jobs.Fail("Связи этого каскада больше нет.", nil)
	}
	params, err := ParseParams(c.Links[idx].Params)
	if err != nil {
		return params, Secrets{}, err
	}
	sealed, err := x.Store.LinkSecrets(ctx, c.ID, idx)
	if err != nil {
		return params, Secrets{}, err
	}
	s, err := OpenSecrets(x.Keys, c.ID, idx, sealed)
	if err != nil {
		return params, s, jobs.Fail("Секреты связи не открываются.", err)
	}
	return params, s, nil
}

// with puts into config cfg of server, in place, what the links of hop
// p's job need there: the credentials of each link that ends at the
// server and the outbound of the one that starts there. It reports
// whether cfg changed and whether it is whole: a link that starts there
// without a local port yet (the check step picks it) leaves it not.
func (x *linker) with(ctx context.Context, p jobParams, c model.Chain, server int64, cfg *hyconfig.Server) (changed, whole bool, err error) {
	whole = true
	for _, h := range p.all() {
		if h.Exit != server && h.Entry != server {
			continue
		}
		params, s, err := x.linkData(ctx, c, h.Idx)
		if err != nil {
			return false, false, err
		}
		if h.Exit == server {
			ch, err := ExitWith(cfg, User(h.Chain, h.Idx), s.ExitPassword)
			if errors.Is(err, ErrAuth) {
				return false, false, jobs.Fail("На сервере "+x.role(ctx, p, server, "выхода")+" клиентов проверяет внешний сервис (auth http или command): для связи HyRoute не может завести свой пароль.", nil)
			} else if err != nil {
				return false, false, err
			}
			changed = changed || ch
		}
		if h.Entry == server {
			if params.LocalPort == 0 {
				whole = false
				continue
			}
			changed = EntryWith(cfg, params.LocalPort, s) || changed
		}
	}
	return changed, whole, nil
}

// plan builds what hop p writes; the link client's config needs the
// local port (the check step picks it).
func (x *linker) plan(ctx context.Context, p jobParams) (*plan, error) {
	c, err := x.Store.ChainByID(ctx, p.Chain)
	if err != nil {
		return nil, err
	}
	if p.Idx >= len(c.Links) {
		return nil, jobs.Fail("Связи этого каскада больше нет.", nil)
	}
	pl := &plan{link: c.Links[p.Idx], nodes: len(c.Nodes)}
	if pl.params, pl.secrets, err = x.linkData(ctx, c, p.Idx); err != nil {
		return nil, err
	}
	for _, h := range p.all() {
		if h.Idx != p.Idx {
			_, s, err := x.linkData(ctx, c, h.Idx)
			if err != nil {
				return nil, err
			}
			pl.others = append(pl.others, s)
		}
	}
	if pl.exit, err = x.Store.ServerByID(ctx, p.Exit); err != nil {
		return nil, err
	}
	if pl.entry, err = x.Store.ServerByID(ctx, p.Entry); err != nil {
		return nil, err
	}
	pl.exitRole, pl.entryRole = x.role(ctx, p, p.Exit, "выхода"), x.role(ctx, p, p.Entry, "входа")
	if pl.inExit, err = x.Store.Installation(ctx, p.Exit); err != nil {
		return nil, err
	}
	if pl.inEntry, err = x.Store.Installation(ctx, p.Entry); err != nil {
		return nil, err
	}

	if pl.exitBase, pl.exitMeta, err = x.revision(ctx, p.Exit, p.ExitBase); err != nil {
		return nil, err
	}
	if pl.exitParsed, err = hyconfig.ParseServer(pl.exitBase); err != nil {
		return nil, jobs.Fail("Конфиг сервера "+pl.exitRole+" не разобрать.", err)
	}
	changed, whole, err := x.with(ctx, p, c, p.Exit, pl.exitParsed)
	if err != nil {
		return nil, err
	}
	pl.exitCfg = pl.exitBase
	switch {
	case !whole:
		pl.exitCfg = nil // a relay whose next link has no port yet
	case changed:
		if pl.exitCfg, err = pl.exitParsed.Marshal(); err != nil {
			return nil, err
		}
	}

	if pl.entryBase, _, err = x.revision(ctx, p.Entry, p.EntryBase); err != nil {
		return nil, err
	}
	if pl.entryParsed, err = hyconfig.ParseServer(pl.entryBase); err != nil {
		return nil, jobs.Fail("Конфиг сервера "+pl.entryRole+" не разобрать.", err)
	}
	pl.linkPath, pl.unitPath = ConfigPath(pl.inEntry, p.Chain, p.Idx), UnitPath(p.Chain, p.Idx)
	if pl.unit, err = UnitText(pl.inEntry, p.Chain, p.Idx); err != nil {
		return nil, jobs.Fail("Службу связи не описать для этого сервера "+pl.entryRole+".", err)
	}
	if pl.params.LocalPort == 0 {
		return pl, nil // the check step picks the port
	}
	pl.entryCfg = pl.entryBase
	if changed, _, err = x.with(ctx, p, c, p.Entry, pl.entryParsed); err != nil {
		return nil, err
	} else if changed {
		if pl.entryCfg, err = pl.entryParsed.Marshal(); err != nil {
			return nil, err
		}
	}
	cc, err := ClientConfig(pl.exit, pl.exitParsed, pl.exitMeta, p.Chain, p.Idx, pl.params, pl.secrets)
	if err != nil {
		return nil, jobs.Fail("Конфиг клиента связи не собрать: "+err.Error()+".", nil)
	}
	if pl.client, err = cc.Marshal(); err != nil {
		return nil, err
	}
	return pl, nil
}

// redactor hides the secrets of the job's links and the passwords of
// both configs.
func (pl *plan) redactor() *redact.Redactor {
	r := redact.New()
	r.Add(pl.secrets.ExitPassword, pl.secrets.SOCKSPassword)
	for _, s := range pl.others {
		r.Add(s.ExitPassword, s.SOCKSPassword)
	}
	if pl.exitParsed != nil {
		r.Add(service.ConfigSecrets(pl.exitParsed)...)
	}
	if pl.entryParsed != nil {
		r.Add(service.ConfigSecrets(pl.entryParsed)...)
	}
	return r
}

// hopName names the link of hop p in messages of a job on several links
// (« «A» → «B»», with a space before); "" for a job on one link.
func (x *linker) hopName(ctx context.Context, p jobParams) string {
	if !p.multi() {
		return ""
	}
	return " " + x.role(ctx, p, p.Entry, "") + " → " + x.role(ctx, p, p.Exit, "")
}

// connect connects to every server of the job, the exit of a link before
// its entry.
func (x *linker) connect(ctx context.Context, env *jobs.Env, p jobParams) error {
	for _, s := range p.servers() {
		if _, err := x.reach(ctx, env, s, x.serverRole(ctx, p, s)); err != nil {
			return err
		}
	}
	return nil
}

// serverRole is role for a server of job p: the exit or the entry of a job
// on one link.
func (x *linker) serverRole(ctx context.Context, p jobParams, server int64) string {
	legacy := "входа"
	if server == p.Exit {
		legacy = "выхода"
	}
	return x.role(ctx, p, server, legacy)
}

// reach connects to a server of the job and records whether its SSH user
// is root. unreachable: the job has no SSH connection to the server (no
// answer, the login or the host key refused), or the connection broke
// before its commands ran; not a server that answers without root.
func (x *linker) reach(ctx context.Context, env *jobs.Env, server int64, role string) (unreachable bool, err error) {
	ex, err := execOn(ctx, env, server)
	if err != nil {
		return true, err
	}
	pr, err := remote.RunProbe(ctx, ex)
	if err != nil {
		var ue *remote.UnreachableError
		return errors.As(err, &ue), jobs.Fail("Не удалось выполнить команды на сервере "+role+".", err)
	}
	if !pr.Privileged() {
		return false, jobs.Fail("На сервере "+role+" пользователь SSH не root и не может выполнять sudo без пароля.", nil)
	}
	return false, env.Set("root:"+strconv.FormatInt(server, 10), strconv.FormatBool(pr.Root))
}

// check: the servers still have the configs the job builds on (or this
// job's), nothing of someone else is in the way, and every link client
// has a port on its entry's loopback.
func (x *linker) check(ctx context.Context, env *jobs.Env, p jobParams) error {
	for _, h := range p.hops() {
		pl, err := x.plan(ctx, h)
		if err != nil {
			return err
		}
		first := h.Prev == model.LinkNew || h.Prev == model.LinkFailed || h.Prev == ""
		if first {
			base, _ := hyconfig.ParseServer(pl.exitBase)
			if HasUser(base, User(h.Chain, h.Idx)) {
				return jobs.Fail("На сервере "+pl.exitRole+" уже есть пользователь "+User(h.Chain, h.Idx)+", заведённый не этим каскадом: переименуйте его или удалите.", nil)
			}
			entry, _ := hyconfig.ParseServer(pl.entryBase)
			if HasOutbound(entry) {
				return jobs.Fail("В конфиге сервера "+pl.entryRole+" уже есть outbound «cascade», сделанный не HyRoute: переименуйте его.", nil)
			}
		}
		exEntry, err := execOn(ctx, env, h.Entry)
		if err != nil {
			return err
		}
		if pl.params.LocalPort == 0 || first {
			if _, err := x.localPort(ctx, env, exEntry, h, pl); err != nil {
				return err
			}
		}
	}
	// The configs with every link of the job: each server once.
	type server struct {
		id         int64
		path, base string
		want       []byte
		role       string
	}
	var servers []server
	var links []model.ChainLink
	for _, h := range p.hops() {
		pl, err := x.plan(ctx, h)
		if err != nil {
			return err
		}
		for _, c := range []*hyconfig.Server{pl.exitParsed, pl.entryParsed} {
			for _, pr := range c.Validate() {
				if !pr.Warning {
					return jobs.Fail("Конфиг с каскадом не прошёл проверку, на серверы ничего не записано: "+pr.Field+": "+pr.Message+".", nil)
				}
			}
		}
		for _, s := range []server{{h.Exit, pl.inExit.Config, h.ExitBaseSHA, pl.exitCfg, pl.exitRole}, {h.Entry, pl.inEntry.Config, h.EntryBaseSHA, pl.entryCfg, pl.entryRole}} {
			if !slices.ContainsFunc(servers, func(o server) bool { return o.id == s.id }) {
				servers = append(servers, s)
			}
		}
		links = append(links, pl.link)
	}
	for _, s := range servers {
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
	for _, link := range links {
		link.State, link.UpdatedAt = model.LinkLinking, x.Now()
		if err := x.Store.UpdateLink(ctx, link); err != nil {
			return err
		}
	}
	return nil
}

// localPort gives the link client its port on the entry's loopback, by
// ss: a link without one picks a free one; a link deployed first keeps
// its stored port only while no other program listens there (one may
// have taken it after an unlink or a failed deployment). The link's own
// client, still up when a recovery checks again, is not another program;
// nor is anything there once the entry has the config this job writes,
// with the outbound to that port (a recovery after entry-config): a new
// port would part the link from it. It reports whether the port was
// picked (and stored).
func (x *linker) localPort(ctx context.Context, env *jobs.Env, ex remote.Executor, p jobParams, pl *plan) (bool, error) {
	ls, err := remote.Listeners(ctx, ex, sudo(env, p.Entry))
	var noSS *remote.ExitError
	switch {
	case errors.As(err, &noSS):
		env.Warnf("На сервере %s нет ss: свободен ли порт клиента связи, не проверено.", pl.entryRole)
	case err != nil:
		return false, err
	}
	used := map[int]bool{}
	for _, l := range ls {
		used[l.Port] = true
	}
	old := pl.params.LocalPort
	if old != 0 {
		if !used[old] {
			return false, nil
		}
		u, err := remote.Unit(ctx, ex, UnitName(p.Chain, p.Idx))
		var failed *remote.ExitError
		if err != nil && !errors.As(err, &failed) {
			return false, err
		}
		for _, l := range ls {
			if l.Port == old && u.MainPID != 0 && l.PID == u.MainPID {
				return false, nil
			}
		}
		if pl.entryCfg != nil {
			if mine, err := x.fileIs(ctx, env, p.Entry, pl.inEntry.Config, pl.entryCfg); err != nil || mine {
				return false, err
			}
		}
	}
	pl.params.LocalPort = pickPort(p.Chain, p.Idx, used)
	pl.link.Params = pl.params.Raw()
	if err := x.Store.UpdateLink(ctx, pl.link); err != nil {
		return false, err
	}
	if old != 0 {
		env.Logf("Порт %d на loopback сервера %s занят другой программой: клиент связи получает другой.", old, pl.entryRole)
	}
	env.Logf("Клиент связи будет слушать SOCKS5 на 127.0.0.1:%d сервера %s.", pl.params.LocalPort, pl.entryRole)
	return true, nil
}

// pickPort is a free port for the link client, 40000–49999, starting at a
// place that differs per link.
func pickPort(chain int64, idx int, used map[int]bool) int {
	start := int((chain*7+int64(idx)*131)%10000+10000) % 10000
	for i := 0; i < 10000; i++ {
		p := 40000 + (start+i)%10000
		if !used[p] {
			return p
		}
	}
	return 40000 + start
}

// backupFile records the state of path under flag (its SHA-256 or
// remote.Absent) before anything changes it, then keeps a copy as
// path.hyroute-prev. A run again keeps the first record and copies again
// while the file is in that state; in another state the file is this
// job's already, and the copy is the original.
func backupFile(ctx context.Context, env *jobs.Env, ex remote.Executor, path, flag string, su bool) error {
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

// restoreFile puts back what backupFile recorded under flag; false: the
// file was as recorded already.
func restoreFile(ctx context.Context, env *jobs.Env, ex remote.Executor, path, flag string, su bool) (bool, error) {
	state := env.Get(flag)
	if state == "" {
		return false, jobs.ErrNothingToUndo
	}
	changed, err := remote.RestoreFile(ctx, ex, path, path+Backup, state, su)
	if errors.Is(err, remote.ErrBackupMismatch) {
		return false, fmt.Errorf("%w: %s оставлен как есть, проверьте его вручную", err, path)
	}
	return changed, err
}

// writeConfig writes a server's config with the rights of the old file.
func writeConfig(ctx context.Context, ex remote.Executor, in model.Installation, b []byte, su bool) error {
	fi, ok, err := remote.Stat(ctx, ex, in.Config, su)
	if err != nil {
		return err
	}
	spec := remote.FileSpec{Mode: 0o640, Group: in.User, Sudo: su}
	if ok {
		spec.Mode, spec.Owner, spec.Group = fi.Mode, fi.Owner, fi.Group
	}
	return ex.WriteFile(ctx, in.Config, b, spec)
}

func (x *linker) fileIs(ctx context.Context, env *jobs.Env, server int64, path string, want []byte) (bool, error) {
	ex, err := execOn(ctx, env, server)
	if err != nil {
		return false, err
	}
	sum, err := remote.FileSHA256(ctx, ex, path, sudo(env, server))
	return sum == sha(want), err
}

// exitConfigDone: the exit has its config with the link (a password exit
// is never changed; a relay got it with the outbound of the hop after).
func (x *linker) exitConfigDone(ctx context.Context, env *jobs.Env, p jobParams) (bool, error) {
	pl, err := x.plan(ctx, p)
	if err != nil {
		return false, err
	}
	return x.fileIs(ctx, env, p.Exit, pl.inExit.Config, pl.exitCfg)
}

func (x *linker) exitConfig(ctx context.Context, env *jobs.Env, p jobParams) error {
	pl, err := x.plan(ctx, p)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Exit)
	if err != nil {
		return err
	}
	su := sudo(env, p.Exit)
	if err := backupFile(ctx, env, ex, pl.inExit.Config, p.key("exitConfig"), su); err != nil {
		return err
	}
	if err := env.Set(p.key("exitChanged"), "1"); err != nil {
		return err
	}
	if err := writeConfig(ctx, ex, pl.inExit, pl.exitCfg, su); err != nil {
		return jobs.Fail("Не удалось записать конфиг сервера "+pl.exitRole+".", err)
	}
	if strings.EqualFold(pl.exitParsed.Auth.Type, "userpass") {
		env.Logf("На сервер %s добавлен пользователь связи %s.", pl.exitRole, User(p.Chain, p.Idx))
	} else {
		env.Logf("Конфиг сервера %s записан.", pl.exitRole)
	}
	return nil
}

func (x *linker) undoExitConfig(ctx context.Context, env *jobs.Env, p jobParams) error {
	return x.undoConfig(ctx, env, p.Exit, p.key("exitConfig"), p.key("exitChanged"), x.role(ctx, p, p.Exit, "выхода"))
}

// undoConfig puts a server's config back and restarts its service with it
// when this job changed it.
func (x *linker) undoConfig(ctx context.Context, env *jobs.Env, server int64, flag, changedFlag, role string) error {
	if env.Get(flag) == "" || committedRevision(env) {
		return jobs.ErrNothingToUndo
	}
	// The service gets the previous config back: a retry restarts it.
	if err := env.Set(changedFlag+":restarted", ""); err != nil {
		return err
	}
	in, err := x.Store.Installation(ctx, server)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, server)
	if err != nil {
		return err
	}
	su := sudo(env, server)
	if _, err := restoreFile(ctx, env, ex, in.Config, flag, su); err != nil && !errors.Is(err, jobs.ErrNothingToUndo) {
		return err
	}
	if env.Get(changedFlag) != "1" {
		return nil
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceRestart, in.Unit, su); err != nil {
		return err
	}
	env.Logf("Прежний конфиг сервера %s возвращён, служба %s перезапущена с ним.", role, in.Unit)
	return nil
}

func (x *linker) restart(ctx context.Context, env *jobs.Env, server int64, changedFlag, role string) error {
	if env.Get(changedFlag) != "1" {
		return nil
	}
	in, err := x.Store.Installation(ctx, server)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, server)
	if err != nil {
		return err
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceRestart, in.Unit, sudo(env, server)); err != nil {
		return jobs.Fail("Не удалось перезапустить службу сервера "+role+".", err)
	}
	env.Logf("Служба %s сервера %s перезапущена.", in.Unit, role)
	return env.Set(changedFlag+":restarted", "1")
}

// restarted: the service runs the config this job wrote (the restart
// after it is recorded; the undo of the config clears the record).
func restarted(changedFlag string) func(context.Context, *jobs.Env) (bool, error) {
	return func(_ context.Context, env *jobs.Env) (bool, error) {
		return env.Get(changedFlag+":restarted") == "1", nil
	}
}

func (x *linker) exitRestart(ctx context.Context, env *jobs.Env, p jobParams) error {
	return x.restart(ctx, env, p.Exit, p.key("exitChanged"), x.role(ctx, p, p.Exit, "выхода"))
}

func (x *linker) exitVerify(ctx context.Context, env *jobs.Env, p jobParams) error {
	if env.Get(p.key("exitChanged")) != "1" {
		return nil
	}
	pl, err := x.plan(ctx, p)
	if err != nil {
		return err
	}
	return x.waitServer(ctx, env, p.Exit, pl.inExit, pl.exitParsed, pl.redactor(), pl.exitRole)
}

// waitServer waits until a server's service runs and Hysteria listens on
// its port (systemd is trusted where ss is missing, once the service
// stayed up for a poll).
func (x *linker) waitServer(ctx context.Context, env *jobs.Env, server int64, in model.Installation, c *hyconfig.Server, red *redact.Redactor, role string) error {
	ex, err := execOn(ctx, env, server)
	if err != nil {
		return err
	}
	su := sudo(env, server)
	l, lerr := hyconfig.ParseListen(c.Listen) // Realms: no port to look at
	wait := x.VerifyTimeout
	if c.ACME != nil {
		wait *= 3
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
					why := "порт проверить нечем: на сервере нет ss"
					if lerr != nil {
						why = "в режиме Realms своего порта у Hysteria нет"
					}
					env.Logf("Служба сервера %s работает (%s).", role, why)
					return nil
				}
				steady = true
			case err != nil:
				return err
			}
			for _, s := range ls {
				if lerr == nil && s.Proto == "udp" && s.Port == l.First && strings.HasPrefix(s.Process, "hysteria") {
					env.Logf("Hysteria на сервере %s работает и принимает соединения на UDP %d.", role, l.First)
					return nil
				}
			}
		}
		if st == "failed" || time.Now().After(deadline) {
			x.journal(ctx, env, ex, in.Unit, su, red)
			return jobs.Fail(fmt.Sprintf("Hysteria на сервере %s не заработала (служба: %s). Изменения откатываются.", role, st), nil)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(x.Poll):
		}
	}
}

// journal logs the last lines of a unit with every secret of the link
// hidden.
func (x *linker) journal(ctx context.Context, env *jobs.Env, ex remote.Executor, unit string, su bool, r *redact.Redactor) {
	lines, err := remote.JournalTail(ctx, ex, unit, 20, su)
	if err != nil || len(lines) == 0 {
		return
	}
	env.Logf("Последние строки журнала %s:", unit)
	for _, l := range lines {
		env.Logf("  %s", r.String(l))
	}
}

func (x *linker) linkConfigDone(ctx context.Context, env *jobs.Env, p jobParams) (bool, error) {
	pl, err := x.plan(ctx, p)
	if err != nil {
		return false, err
	}
	return x.fileIs(ctx, env, p.Entry, pl.linkPath, pl.client)
}

func (x *linker) linkConfig(ctx context.Context, env *jobs.Env, p jobParams) error {
	pl, err := x.plan(ctx, p)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	if err := backupFile(ctx, env, ex, pl.linkPath, p.key("linkConfig"), su); err != nil {
		return err
	}
	// Passwords inside: root and the service's group only.
	if err := ex.WriteFile(ctx, pl.linkPath, pl.client, remote.FileSpec{Mode: 0o640, Group: pl.inEntry.User, Sudo: su}); err != nil {
		return jobs.Fail("Не удалось записать конфиг клиента связи.", err)
	}
	env.Logf("Конфиг клиента связи записан: %s.", pl.linkPath)
	return nil
}

// undoLinkConfig puts the link client's config back (or removes it) and,
// when the link service was there before the job, restarts it with that.
func (x *linker) undoLinkConfig(ctx context.Context, env *jobs.Env, p jobParams) error {
	if env.Get(p.key("linkConfig")) == "" || committedRevision(env) {
		return jobs.ErrNothingToUndo
	}
	in, err := x.Store.Installation(ctx, p.Entry)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	changed, err := restoreFile(ctx, env, ex, ConfigPath(in, p.Chain, p.Idx), p.key("linkConfig"), su)
	if err != nil && !errors.Is(err, jobs.ErrNothingToUndo) {
		return err
	}
	if unit := env.Get(p.key("linkUnit")); unit != "" && unit != remote.Absent && changed {
		return remote.Systemctl(ctx, ex, remote.ServiceRestart, UnitName(p.Chain, p.Idx), su)
	}
	return nil
}

// linkService installs the link's unit and (re)starts it: the client
// reads its config only at start.
func (x *linker) linkService(ctx context.Context, env *jobs.Env, p jobParams) error {
	pl, err := x.plan(ctx, p)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	if err := backupFile(ctx, env, ex, pl.unitPath, p.key("linkUnit"), su); err != nil {
		return err
	}
	if err := ex.WriteFile(ctx, pl.unitPath, []byte(pl.unit), remote.FileSpec{Mode: 0o644, Sudo: su}); err != nil {
		return jobs.Fail("Не удалось записать службу связи.", err)
	}
	if err := remote.DaemonReload(ctx, ex, su); err != nil {
		return jobs.Fail("systemd не перечитал службы.", err)
	}
	unit := UnitName(p.Chain, p.Idx)
	if err := remote.Systemctl(ctx, ex, remote.ServiceEnable, unit, su); err != nil {
		return jobs.Fail("Не удалось включить автозапуск службы связи.", err)
	}
	if err := remote.Systemctl(ctx, ex, remote.ServiceRestart, unit, su); err != nil {
		return jobs.Fail("Не удалось запустить службу связи.", err)
	}
	env.Logf("Служба связи %s запущена.", unit)
	return nil
}

func (x *linker) undoLinkService(ctx context.Context, env *jobs.Env, p jobParams) error {
	state := env.Get(p.key("linkUnit"))
	if state == "" || committedRevision(env) {
		return jobs.ErrNothingToUndo
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	unit := UnitName(p.Chain, p.Idx)
	if state == remote.Absent {
		// A new link: nothing of it stays.
		remote.Systemctl(ctx, ex, remote.ServiceStop, unit, su)
		remote.Systemctl(ctx, ex, remote.ServiceDisable, unit, su)
	}
	if _, err := restoreFile(ctx, env, ex, UnitPath(p.Chain, p.Idx), p.key("linkUnit"), su); err != nil && !errors.Is(err, jobs.ErrNothingToUndo) {
		return err
	}
	return remote.DaemonReload(ctx, ex, su)
}

// linkCheck waits until the link works as the monitor checks it
// (CheckLink): the service runs, its SOCKS5 takes the outbound's password
// through a tunnel to the entry's loopback, the client reaches the exit.
// The exit answering but not opening the check target is a warning.
func (x *linker) linkCheck(ctx context.Context, env *jobs.Env, p jobParams) error {
	pl, err := x.plan(ctx, p)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	if _, err := checkTarget(pl.params, pl.exit); err != nil {
		return jobs.Fail("Адрес проверки связи не подходит.", err)
	}
	pr := Probe{Chain: p.Chain, Link: pl.link, Params: pl.params, Secrets: pl.secrets, Entry: pl.inEntry, Exit: pl.exit, Sudo: su, Hop: pl.nodes > 2, EntryName: pl.entry.Name}
	deadline := time.Now().Add(x.VerifyTimeout)
	for {
		c := CheckLink(ctx, ex, pr, x.Now())
		if c.Status != model.StateOffline {
			env.Logf("Связь%s работает: сервер %s ответил клиенту связи (рукопожатие %d мс).", x.hopName(ctx, p), pl.exitRole, c.HandshakeMillis)
			if c.TCPMillis > 0 {
				target, _ := checkTarget(pl.params, pl.exit)
				env.Logf("Через сервер %s открыт %s за %d мс.", pl.exitRole, target, c.TCPMillis)
			}
			if c.Status == model.StateDegraded {
				env.Warnf("%s.", capitalize(c.Reason))
			}
			return nil
		}
		if c.Service == "failed" || time.Now().After(deadline) {
			x.journal(ctx, env, ex, UnitName(p.Chain, p.Idx), su, pl.redactor())
			return jobs.Fail("Связь"+x.hopName(ctx, p)+" не заработала: "+c.Reason+". Изменения откатываются.", nil)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(x.Poll):
		}
	}
}

// capitalize makes the first letter upper case.
func capitalize(s string) string {
	for i, r := range s {
		return strings.ToUpper(string(r)) + s[i+len(string(r)):]
	}
	return s
}

// PingLink runs `hysteria ping` with the link client's config on the entry,
// as root (the config is root's and the service group's): only a binary
// that only root can change (remote.CheckBinary).
func PingLink(ctx context.Context, ex remote.Executor, binary, config, target string, su bool) (Ping, error) {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	if err := remote.CheckBinary(ctx, ex, binary, su); err != nil {
		return Ping{}, err
	}
	res, err := ex.Run(ctx, remote.Cmd{Args: []string{binary, "--config", config, "--log-format", "json", "ping", target}, Sudo: su})
	if err != nil {
		var ue *remote.UnreachableError
		if errors.As(err, &ue) || ctx.Err() == nil {
			return Ping{}, err
		}
		return Ping{Error: "no answer in 25 s"}, nil
	}
	return ParsePing(append(res.Stdout, res.Stderr...)), nil
}

func (x *linker) entryConfigDone(ctx context.Context, env *jobs.Env, p jobParams) (bool, error) {
	pl, err := x.plan(ctx, p)
	if err != nil {
		return false, err
	}
	return x.fileIs(ctx, env, p.Entry, pl.inEntry.Config, pl.entryCfg)
}

func (x *linker) entryConfig(ctx context.Context, env *jobs.Env, p jobParams) error {
	pl, err := x.plan(ctx, p)
	if err != nil {
		return err
	}
	ex, err := execOn(ctx, env, p.Entry)
	if err != nil {
		return err
	}
	su := sudo(env, p.Entry)
	if err := backupFile(ctx, env, ex, pl.inEntry.Config, p.key("entryConfig"), su); err != nil {
		return err
	}
	if err := env.Set(p.key("entryChanged"), "1"); err != nil {
		return err
	}
	if err := writeConfig(ctx, ex, pl.inEntry, pl.entryCfg, su); err != nil {
		return jobs.Fail("Не удалось записать конфиг сервера "+pl.entryRole+".", err)
	}
	env.Logf("На сервер %s добавлен outbound «%s»: весь трафик идёт через сервер %s, кроме того, что правила ACL отправляют иначе.", pl.entryRole, OutboundName, pl.exitRole)
	for _, h := range p.all() {
		if h.Exit == p.Entry && strings.EqualFold(pl.entryParsed.Auth.Type, "userpass") {
			env.Logf("Заодно на него добавлен пользователь связи %s: через сервер %s пойдёт трафик сервера %s.", User(h.Chain, h.Idx), pl.entryRole, x.role(ctx, h, h.Entry, "входа"))
		}
	}
	return nil
}

func (x *linker) undoEntryConfig(ctx context.Context, env *jobs.Env, p jobParams) error {
	return x.undoConfig(ctx, env, p.Entry, p.key("entryConfig"), p.key("entryChanged"), x.role(ctx, p, p.Entry, "входа"))
}

func (x *linker) entryRestart(ctx context.Context, env *jobs.Env, p jobParams) error {
	return x.restart(ctx, env, p.Entry, p.key("entryChanged"), x.role(ctx, p, p.Entry, "входа"))
}

func (x *linker) entryVerify(ctx context.Context, env *jobs.Env, p jobParams) error {
	if env.Get(p.key("entryChanged")) != "1" {
		return nil
	}
	pl, err := x.plan(ctx, p)
	if err != nil {
		return err
	}
	return x.waitServer(ctx, env, p.Entry, pl.inEntry, pl.entryParsed, pl.redactor(), pl.entryRole)
}

// committed: the revisions are stored and every link of the job is active
// with this client config.
func (x *linker) committed(ctx context.Context, env *jobs.Env, p jobParams) (bool, error) {
	for _, h := range p.hops() {
		pl, err := x.plan(ctx, h)
		if err != nil {
			return false, err
		}
		if pl.link.State != model.LinkActive || pl.link.ConfigSHA256 != sha(pl.client) {
			return false, nil
		}
	}
	return true, nil
}

// newConfig is a server's config a commit stores as a revision.
type newConfig struct {
	id        int64
	in        model.Installation
	cfg, base []byte
	c         *hyconfig.Server
}

// committedRevision: a commit stored a revision. The servers keep what
// they run from then on (a rollback would part them from the controller),
// and a retry finishes the commit.
func committedRevision(env *jobs.Env) bool { return env.Get("committed") == "1" }

// addRevisions stores the configs that changed and are not the current
// revisions yet (source cascade) and returns the revisions they are. The
// summaries come first, as they read the servers (the certificate of a
// TLS file): a broken connection there leaves the database as it was.
func (x *linker) addRevisions(ctx context.Context, env *jobs.Env, cs []newConfig) (map[int64]int, error) {
	revs := map[int64]int{}
	var add []model.ServerConfig
	var cfgs [][]byte
	for _, s := range cs {
		if sha(s.cfg) == sha(s.base) {
			continue
		}
		cur, err := x.Store.CurrentConfig(ctx, s.id)
		if err != nil {
			return nil, err
		}
		if cur.SHA256 == sha(s.cfg) {
			revs[s.id] = cur.Revision
			continue
		}
		ex, err := execOn(ctx, env, s.id)
		if err != nil {
			return nil, err
		}
		meta, err := importer.ConfigMeta(ctx, remote.ReadOnly(ex), s.c, s.in.Version, sudo(env, s.id), x.Now())
		if err != nil {
			return nil, err
		}
		add = append(add, model.ServerConfig{ServerID: s.id, SHA256: sha(s.cfg), Meta: meta, Source: model.ConfigCascade, JobID: env.JobID, By: env.CreatedBy, At: x.Now()})
		cfgs = append(cfgs, s.cfg)
	}
	for i := range add {
		rev, cfg := &add[i], cfgs[i]
		if err := x.Store.AddConfig(ctx, rev, func(r int) ([]byte, error) { return x.Keys.Seal(cfg, model.ConfigContext(rev.ServerID, r)) }); err != nil {
			return nil, err
		}
		if err := env.Set("committed", "1"); err != nil {
			return nil, err
		}
		revs[rev.ServerID] = rev.Revision
	}
	return revs, nil
}

// addConfig appends c to cs unless its server is there already: a relay
// is in two hops with the same config.
func addConfig(cs []newConfig, c newConfig) []newConfig {
	if slices.ContainsFunc(cs, func(o newConfig) bool { return o.id == c.id }) {
		return cs
	}
	return append(cs, c)
}

// commit stores the new revisions of the job's servers (source cascade)
// and marks its links active. A revision stored already is not stored
// again.
func (x *linker) commit(ctx context.Context, env *jobs.Env, p jobParams) error {
	hs := p.hops()
	plans := make([]*plan, len(hs))
	revs := map[int64]int{}
	var cs []newConfig
	for i, h := range hs {
		pl, err := x.plan(ctx, h)
		if err != nil {
			return err
		}
		plans[i] = pl
		revs[h.Exit], revs[h.Entry] = h.ExitBase, h.EntryBase
		cs = addConfig(cs, newConfig{h.Exit, pl.inExit, pl.exitCfg, pl.exitBase, pl.exitParsed})
		cs = addConfig(cs, newConfig{h.Entry, pl.inEntry, pl.entryCfg, pl.entryBase, pl.entryParsed})
	}
	added, err := x.addRevisions(ctx, env, cs)
	if err != nil {
		return err
	}
	maps.Copy(revs, added)
	for i, h := range hs {
		link := plans[i].link
		link.State, link.FromRevision, link.ToRevision, link.ConfigSHA256, link.UpdatedAt = model.LinkActive, revs[h.Entry], revs[h.Exit], sha(plans[i].client), x.Now()
		// The unit as the job wrote it: the reconciliation compares the
		// one on the entry with it (P4-06).
		link.UnitSHA256 = sha([]byte(plans[i].unit))
		if err := x.Store.UpdateLink(ctx, link); err != nil {
			return err
		}
		if !p.multi() {
			env.Logf("Каскад работает: конфиги сохранены в controller (вход — ревизия %d, выход — ревизия %d).", link.FromRevision, link.ToRevision)
		}
	}
	if len(hs) > 1 {
		env.Logf("Каскад работает: все %d участка развёрнуты, конфиги серверов сохранены в controller.", len(hs))
	}
	return nil
}

// cleanup removes the copies the job kept; it never fails the job.
func (x *linker) cleanup(ctx context.Context, env *jobs.Env, p jobParams) error {
	// The links are committed: a failure here must not roll them back.
	warn := func(err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		env.Warnf("Копии прежних файлов (%s) остались на серверах: %v", Backup, err)
		return nil
	}
	for _, h := range p.hops() {
		pl, err := x.plan(ctx, h)
		if err != nil {
			return warn(err)
		}
		for _, f := range []struct {
			server int64
			path   string
			flag   string
		}{{h.Exit, pl.inExit.Config, h.key("exitConfig")}, {h.Entry, pl.inEntry.Config, h.key("entryConfig")}, {h.Entry, pl.linkPath, h.key("linkConfig")}, {h.Entry, pl.unitPath, h.key("linkUnit")}} {
			if st := env.Get(f.flag); st == "" || st == remote.Absent {
				continue
			}
			ex, err := execOn(ctx, env, f.server)
			if err != nil {
				return warn(err)
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

// finished: a failed first deployment leaves a link failed, a failed
// redeployment as it was; servers whose rollback did not finish need
// attention, and the links count as deployed then (stale): parts of them
// may be on the servers, and only unlink takes them off. So it is when
// the job failed without a rollback (a controller that builds other steps
// for it went on with it) after it recorded a change of a server.
func (x *linker) finished(ctx context.Context, env *jobs.Env, j model.Job) {
	var p jobParams
	if err := env.DecodeParams(&p); err != nil {
		return
	}
	if j.State != model.JobFailed {
		return
	}
	left := env.Rollback() == jobs.RollbackFailed
	if env.Rollback() == jobs.RollbackNotRun {
		for _, h := range p.hops() {
			for _, k := range []string{"exitConfig", "linkConfig", "linkUnit", "entryConfig"} {
				left = left || env.Get(h.key(k)) != ""
			}
		}
	}
	c, err := x.Store.ChainByID(ctx, p.Chain)
	for _, h := range p.hops() {
		if err != nil || h.Idx >= len(c.Links) {
			break
		}
		link := c.Links[h.Idx]
		switch {
		case committedRevision(env):
			link.State = model.LinkStale // on the servers: a retry finishes the commit
		case h.Prev == model.LinkActive || h.Prev == model.LinkStale:
			link.State = h.Prev
		case left:
			link.State = model.LinkStale
		default:
			link.State = model.LinkFailed
		}
		link.UpdatedAt = x.Now()
		x.Store.UpdateLink(ctx, link)
	}
	if left {
		for _, s := range p.servers() {
			x.Store.SetServerState(ctx, s, model.StateNeedsAttention, x.Now())
		}
	}
}
