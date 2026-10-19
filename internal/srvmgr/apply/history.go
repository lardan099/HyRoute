package apply

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// ErrNoRevision: the server has no such config revision.
var ErrNoRevision = errors.New("no such revision")

// open is a revision and its config.
func (e *Editor) open(ctx context.Context, serverID int64, revision int) (model.ServerConfig, []byte, error) {
	c, err := e.Store.ConfigRevision(ctx, serverID, revision)
	if errors.Is(err, store.ErrNotFound) {
		return c, nil, ErrNoRevision
	} else if err != nil {
		return c, nil, err
	}
	b, err := e.Keys.Open(c.Sealed, model.ConfigContext(serverID, c.Revision))
	return c, b, err
}

// Revision is a revision's config with its secrets masked.
func (e *Editor) Revision(ctx context.Context, serverID int64, revision int) (View, error) {
	c, b, err := e.open(ctx, serverID, revision)
	if err != nil {
		return View{}, err
	}
	return view(c, b)
}

func view(c model.ServerConfig, b []byte) (View, error) {
	m, _, err := Mask(b)
	if err != nil {
		return View{}, err
	}
	v := View{Revision: c.Revision, SHA256: c.SHA256, YAML: string(m), Unknown: []string{}}
	if sc, err := hyconfig.ParseServer(m); err == nil {
		v.Fields = FieldsOf(sc)
		v.Unknown = append(v.Unknown, hyconfig.UnknownFields(sc)...)
	}
	return v, nil
}

// Comparison is the difference between two revisions without secrets:
// the diff of the masked configs and the paths of secrets that differ.
type Comparison struct {
	From    int      `json:"from"`
	To      int      `json:"to"`
	Diff    []Line   `json:"diff"`
	Secrets []string `json:"secrets"`
}

// Compare is what changes from revision from to revision to.
func (e *Editor) Compare(ctx context.Context, serverID int64, from, to int) (Comparison, error) {
	_, a, err := e.open(ctx, serverID, from)
	if err != nil {
		return Comparison{}, err
	}
	_, b, err := e.open(ctx, serverID, to)
	if err != nil {
		return Comparison{}, err
	}
	diff, secrets, err := CompareConfigs(a, b)
	if err != nil {
		return Comparison{}, err
	}
	return Comparison{From: from, To: to, Diff: diff, Secrets: secrets}, nil
}

// Rollback queues the apply job that installs revision revision again,
// with the checks, backup, restart and rollback of any apply. base is the
// revision the admin compared with: it must still be the current one.
func (a *Applier) Rollback(ctx context.Context, serverID int64, base, revision int, actor int64) (model.Job, error) {
	e := &Editor{Store: a.x.Store, Keys: a.x.Keys}
	cur, _, err := e.Current(ctx, serverID)
	if err != nil {
		return model.Job{}, err
	}
	if cur.Revision != base {
		return model.Job{}, &StaleError{Current: cur.Revision}
	}
	if revision == cur.Revision {
		return model.Job{}, &model.FieldError{Field: "revision", Msg: "Это текущая версия конфига."}
	}
	_, b, err := e.open(ctx, serverID, revision)
	if err != nil {
		return model.Job{}, err
	}
	if sha(b) == cur.SHA256 {
		return model.Job{}, &model.FieldError{Field: "revision", Msg: fmt.Sprintf("Версия %d совпадает с текущей: возвращать нечего.", revision)}
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return model.Job{}, &model.FieldError{Field: "revision", Msg: "Эту версию конфига не разобрать: " + err.Error()}
	}
	var errs []string
	for _, p := range c.Validate() {
		if !p.Warning {
			errs = append(errs, p.Field+": "+p.Message)
		}
	}
	if len(errs) > 0 {
		return model.Job{}, &model.FieldError{Field: "revision", Msg: "Версия не проходит проверку: " + strings.Join(errs, "; ") + "."}
	}
	p := Params{Base: cur.Revision, BaseSHA256: cur.SHA256, SHA256: sha(b), From: revision}
	return a.x.Jobs.Submit(ctx, JobKind, serverID, p, map[string]string{SecretConfig: string(b)}, actor)
}
