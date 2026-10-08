package events

import (
	"context"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
)

// AttentionStore is what the summary reads.
type AttentionStore interface {
	ListServers(ctx context.Context) ([]model.Server, error)
	HealthHistory(ctx context.Context, serverID int64, since time.Time, limit int) ([]model.Health, error)
	ListJobs(ctx context.Context, f model.JobFilter) ([]model.Job, error)
	ListChains(ctx context.Context) ([]model.Chain, error)
	LinkChecks(ctx context.Context, chainID int64, idx int, since time.Time, limit int) ([]model.LinkCheck, error)
	Installation(ctx context.Context, serverID int64) (model.Installation, error)
	CurrentConfig(ctx context.Context, serverID int64) (model.ServerConfig, error)
	ServerGeos(ctx context.Context) ([]model.ServerGeo, error)
	ListEvents(ctx context.Context, f model.EventFilter) ([]model.Event, error)
}

// Attention builds the summary «Требует внимания» of the overview: what
// wants a look now, without secrets and addresses.
type Attention struct {
	Store AttentionStore
	// Keys open the configs (the lint of their rules); nil: no lint.
	Keys *secrets.Keyring
	// Redact holds the secrets the controller knows (texts pass through
	// it, as events do).
	Redact *redact.Redactor
	// Geo are the controller's geo databases (nil: none); GeoInterval is
	// how often they are updated (0: by hand).
	Geo         *geo.Store
	GeoInterval time.Duration
	// Monitoring: the monitor runs; Paused are the servers it does not
	// log in to for now, with the next attempt (monitor.Collector).
	Monitoring bool
	Paused     func() map[int64]time.Time
	Now        func() time.Time

	mu   sync.Mutex
	lint map[int64]lintResult
}

// lintResult is the lint of a server's rules at a config revision.
type lintResult struct {
	revision     int
	entry        bool
	warns, fails int
}

// Item is one thing that wants a look.
type Item struct {
	// Kind: server, job, link, lint, hysteria, geo, monitor, or the kind
	// of an open event (host_key, ssh_auth, disk, drift).
	Kind     string         `json:"kind"`
	Severity model.Severity `json:"severity"`
	// Subject and SubjectID: where the admin goes to look (server,
	// chain, job; controller: nowhere in particular).
	Subject   string `json:"subject"`
	SubjectID int64  `json:"subjectId,omitempty"`
	// Name is the server's or cascade's ("" for the controller).
	Name  string    `json:"name"`
	Text  string    `json:"text"`
	Since time.Time `json:"since,omitzero"`
}

// Summary is what wants a look now.
type Summary struct {
	Items []Item
	// Network is the open event «the controller has no network» (nil: it
	// has).
	Network *model.Event
	// Monitoring: the monitor runs.
	Monitoring bool
}

var severityRank = map[model.Severity]int{model.SeverityCritical: 0, model.SeverityWarning: 1, model.SeverityInfo: 2}

func (a *Attention) now() time.Time {
	if a.Now == nil {
		return time.Now()
	}
	return a.Now()
}

// Summary gathers the items: servers not healthy with the reason, the
// failed newest job of each server, stale, failed and broken cascade
// links, warnings of routing rules, old Hysteria, old geo databases,
// paused or disabled monitoring, and the open events nothing above tells.
func (a *Attention) Summary(ctx context.Context) (Summary, error) {
	out := Summary{Items: []Item{}, Monitoring: a.Monitoring}
	servers, err := a.Store.ListServers(ctx)
	if err != nil {
		return out, err
	}
	byID := map[int64]model.Server{}
	for _, s := range servers {
		byID[s.ID] = s
	}
	open, err := a.Store.ListEvents(ctx, model.EventFilter{OpenOnly: true})
	if err != nil {
		return out, err
	}
	openByKey := map[string]model.Event{}
	for _, e := range open {
		openByKey[e.Key] = e
	}
	add := func(it Item) { out.Items = append(out.Items, it) }

	for _, s := range servers {
		if it, ok := a.serverItem(ctx, s, openByKey); ok {
			add(it)
		}
	}
	if err := a.jobItems(ctx, byID, add); err != nil {
		return out, err
	}
	if err := a.linkItems(ctx, byID, add); err != nil {
		return out, err
	}
	for _, s := range servers {
		a.serverExtras(ctx, s, add)
	}
	a.geoItems(ctx, byID, add)

	paused := map[int64]time.Time{}
	if a.Paused != nil {
		paused = a.Paused()
	}
	if !a.Monitoring {
		add(Item{Kind: "monitor", Severity: model.SeverityInfo, Subject: model.SubjectController,
			Text: "Мониторинг выключен (-monitor-interval 0): состояния серверов, их диски и связи каскадов не проверяются."})
	}
	for id, until := range paused {
		s, ok := byID[id]
		if !ok {
			continue
		}
		add(Item{Kind: "monitor", Severity: model.SeverityWarning, Subject: model.SubjectServer, SubjectID: id, Name: s.Name,
			Text: "Мониторинг на паузе: сервер отклонил вход по SSH. Следующая попытка — в " + until.Local().Format("15:04") + " или сразу после смены данных входа."})
	}
	for _, e := range open {
		switch e.Kind {
		case model.EventNetwork:
			ev := e
			out.Network = &ev
			continue
		case model.EventSSHAuth:
			if _, ok := paused[e.SubjectID]; ok {
				continue // the pause tells it
			}
		case model.EventHostKey, model.EventDisk, model.EventDrift, model.EventGeo:
		default:
			continue // the items above tell it
		}
		add(Item{Kind: string(e.Kind), Severity: e.Severity, Subject: e.Subject, SubjectID: e.SubjectID, Name: byID[e.SubjectID].Name, Text: e.Text, Since: e.OpenedAt})
	}

	for i := range out.Items {
		out.Items[i].Text = Clean(out.Items[i].Text, a.Redact, servers)
	}
	sort.SliceStable(out.Items, func(i, j int) bool {
		x, y := out.Items[i], out.Items[j]
		if severityRank[x.Severity] != severityRank[y.Severity] {
			return severityRank[x.Severity] < severityRank[y.Severity]
		}
		if x.Name != y.Name {
			return x.Name < y.Name
		}
		return x.Kind < y.Kind
	})
	return out, nil
}

// serverItem is a server that is not healthy, with why.
func (a *Attention) serverItem(ctx context.Context, s model.Server, open map[string]model.Event) (Item, bool) {
	it := Item{Kind: "server", Subject: model.SubjectServer, SubjectID: s.ID, Name: s.Name, Since: s.UpdatedAt}
	switch s.State {
	case model.StateHealthy:
		return it, false
	case model.StateNew:
		it.Severity, it.Text = model.SeverityInfo, "Ещё не развёрнут: разверните Hysteria или импортируйте установленную."
	case model.StateDeploying:
		it.Severity, it.Text = model.SeverityInfo, "Идёт развёртывание."
	case model.StateNeedsAttention:
		it.Severity, it.Text = model.SeverityCritical, "Задание не довело откат: проверьте сервер и его заметки, затем повторите задание."
		if e, ok := open[AttentionKey(s.ID)]; ok {
			it.Text, it.Since = e.Text, e.OpenedAt
		}
	default:
		it.Severity, it.Text = model.SeverityWarning, "Работает с проблемами."
		if s.State == model.StateOffline {
			it.Severity, it.Text = model.SeverityCritical, "SSH не отвечает."
		}
		if hs, err := a.Store.HealthHistory(ctx, s.ID, time.Time{}, 1); err == nil && len(hs) > 0 && hs[0].Status == s.State && hs[0].Reason != "" {
			it.Text = hs[0].Reason
		}
		if e, ok := open["server:"+strconv.FormatInt(s.ID, 10)]; ok {
			it.Since = e.OpenedAt
		}
	}
	return it, true
}

// jobItems are the failed jobs that are the newest of their server.
func (a *Attention) jobItems(ctx context.Context, byID map[int64]model.Server, add func(Item)) error {
	js, err := a.Store.ListJobs(ctx, model.JobFilter{Limit: 500})
	if err != nil {
		return err
	}
	seen := map[int64]bool{}
	for _, j := range js {
		if j.ServerID == 0 || seen[j.ServerID] {
			continue
		}
		seen[j.ServerID] = true
		if j.State != model.JobFailed {
			continue
		}
		text := "«" + KindName(j.Kind) + "» не выполнено."
		if j.ErrorMessage != "" && j.ErrorMessage != "Задание не выполнено." {
			text += " " + j.ErrorMessage
		}
		add(Item{Kind: "job", Severity: model.SeverityWarning, Subject: model.SubjectJob, SubjectID: j.ID, Name: byID[j.ServerID].Name, Text: text, Since: j.FinishedAt})
	}
	return nil
}

// linkChecksFresh: an older check of a link says nothing about now.
const linkChecksFresh = time.Hour

// linkItems are cascade links that are stale or failed, or whose last
// check found them offline or degraded.
func (a *Attention) linkItems(ctx context.Context, byID map[int64]model.Server, add func(Item)) error {
	chains, err := a.Store.ListChains(ctx)
	if err != nil {
		return err
	}
	for _, c := range chains {
		for _, l := range c.Links {
			what := "Связь «" + byID[l.From].Name + "» → «" + byID[l.To].Name + "»"
			it := Item{Kind: "link", Subject: model.SubjectChain, SubjectID: c.ID, Name: c.Name, Since: l.UpdatedAt}
			switch l.State {
			case model.LinkStale:
				it.Severity, it.Text = model.SeverityWarning, what+" устарела: серверы изменились после развёртывания. Обновите связь."
				add(it)
				continue
			case model.LinkFailed:
				it.Severity, it.Text = model.SeverityWarning, what+": первое развёртывание не удалось и откатилось."
				add(it)
				continue
			case model.LinkActive:
			default:
				continue
			}
			cs, err := a.Store.LinkChecks(ctx, c.ID, l.Idx, a.now().Add(-linkChecksFresh), 1)
			if err != nil || len(cs) == 0 {
				continue
			}
			switch cs[0].Status {
			case model.StateOffline:
				it.Severity, it.Text = model.SeverityCritical, what+" не работает: "+cs[0].Reason+"."
			case model.StateDegraded:
				it.Severity, it.Text = model.SeverityWarning, what+" работает с проблемами: "+cs[0].Reason+"."
			default:
				continue
			}
			it.Since = cs[0].At
			add(it)
		}
	}
	return nil
}

// serverExtras are the routing lint and an old Hysteria of a server.
func (a *Attention) serverExtras(ctx context.Context, s model.Server, add func(Item)) {
	in, err := a.Store.Installation(ctx, s.ID)
	if err != nil {
		return // nothing installed: nothing to tell
	}
	if older(in.Version, hyrelease.DefaultVersion) {
		add(Item{Kind: "hysteria", Severity: model.SeverityInfo, Subject: model.SubjectServer, SubjectID: s.ID, Name: s.Name,
			Text: "Hysteria " + in.Version + " — есть " + hyrelease.DefaultVersion + ": обновите её («Обслуживание» на странице сервера)."})
	}
	if lr, ok := a.lintOf(ctx, s.ID); ok && lr.warns+lr.fails > 0 {
		sev, text := model.SeverityInfo, "Правила маршрутизации: "
		var parts []string
		if lr.fails > 0 {
			sev = model.SeverityWarning
			parts = append(parts, plural(lr.fails, "ошибка", "ошибки", "ошибок"))
		}
		if lr.warns > 0 {
			parts = append(parts, plural(lr.warns, "предупреждение", "предупреждения", "предупреждений"))
		}
		add(Item{Kind: "lint", Severity: sev, Subject: model.SubjectServer, SubjectID: s.ID, Name: s.Name, Text: text + strings.Join(parts, " и ") + "."})
	}
}

// lintOf checks the rules of the server's current config (acl.inline,
// without the geo databases: names are not looked up), once per
// revision.
func (a *Attention) lintOf(ctx context.Context, serverID int64) (lintResult, bool) {
	if a.Keys == nil {
		return lintResult{}, false
	}
	cur, err := a.Store.CurrentConfig(ctx, serverID)
	if err != nil {
		return lintResult{}, false
	}
	entry := a.isEntry(ctx, serverID)
	a.mu.Lock()
	lr, ok := a.lint[serverID]
	a.mu.Unlock()
	if ok && lr.revision == cur.Revision && lr.entry == entry {
		return lr, true
	}
	b, err := a.Keys.Open(cur.Sealed, model.ConfigContext(serverID, cur.Revision))
	if err != nil {
		return lintResult{}, false
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return lintResult{}, false
	}
	lr = lintResult{revision: cur.Revision, entry: entry}
	if c.ACL.File == "" && len(c.ACL.Inline) > 0 {
		env := acl.EnvOf(c)
		env.Entry = entry
		for _, p := range acl.Check(acl.ParseInline(c.ACL.Inline), env) {
			if p.Level == acl.Error {
				lr.fails++
			} else {
				lr.warns++
			}
		}
	}
	a.mu.Lock()
	if a.lint == nil {
		a.lint = map[int64]lintResult{}
	}
	a.lint[serverID] = lr
	a.mu.Unlock()
	return lr, true
}

// isEntry: the server is the entry of a deployed link.
func (a *Attention) isEntry(ctx context.Context, serverID int64) bool {
	chains, err := a.Store.ListChains(ctx)
	if err != nil {
		return false
	}
	for _, c := range chains {
		for _, l := range c.Links {
			if l.From == serverID && (l.State == model.LinkActive || l.State == model.LinkStale) {
				return true
			}
		}
	}
	return false
}

// geoItems: the controller's databases not updated for long, and servers
// with another release than the controller's.
func (a *Attention) geoItems(ctx context.Context, byID map[int64]model.Server, add func(Item)) {
	if a.Geo == nil {
		return
	}
	info, err := a.Geo.Info()
	if err != nil || info.Release == "" {
		return // none yet: the first download is the admin's
	}
	if a.GeoInterval > 0 && !info.CheckedAt.IsZero() && a.now().Sub(info.CheckedAt) > 2*a.GeoInterval {
		add(Item{Kind: "geo", Severity: model.SeverityWarning, Subject: model.SubjectController, Since: info.CheckedAt,
			Text: "Базы geo controller давно не обновлялись: последняя проверка релиза — " + info.CheckedAt.Local().Format("02.01.2006") + "."})
	}
	gs, err := a.Store.ServerGeos(ctx)
	if err != nil {
		return
	}
	for _, g := range gs {
		s, ok := byID[g.ServerID]
		if !ok || g.Release == info.Release {
			continue
		}
		add(Item{Kind: "geo", Severity: model.SeverityInfo, Subject: model.SubjectServer, SubjectID: s.ID, Name: s.Name, Since: g.At,
			Text: "Базы geo на сервере — релиз " + g.Release + ", у controller — " + info.Release + "."})
	}
}

// older compares "v2.6.0" < "v2.12.3" (anything unparsable is not older).
func older(v, than string) bool {
	a, okA := semver(v)
	b, okB := semver(than)
	return okA && okB && slices.Compare(a, b) < 0
}

func semver(v string) ([]int, bool) {
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) != 3 {
		return nil, false
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// plural is n with the Russian word form for it: 1 ошибка, 2 ошибки,
// 5 ошибок, 21 ошибка.
func plural(n int, one, few, many string) string {
	w := many
	switch m10, m100 := n%10, n%100; {
	case m10 == 1 && m100 != 11:
		w = one
	case m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14):
		w = few
	}
	return strconv.Itoa(n) + " " + w
}
