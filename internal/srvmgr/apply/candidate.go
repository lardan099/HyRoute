package apply

import (
	"context"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// ChangeRouting names an apply job of the routing editor (P3-06).
const ChangeRouting = "routing"

// Candidate is the current config (base must still be it) as change
// leaves it, checked as the editor checks a text. change gets the config
// with its secrets.
func (e *Editor) Candidate(ctx context.Context, serverID int64, base int, change func(c *hyconfig.Server) error) (Check, []byte, model.ServerConfig, error) {
	cur, b, err := e.Current(ctx, serverID)
	if err != nil {
		return Check{}, nil, cur, err
	}
	if cur.Revision != base {
		return Check{}, nil, cur, &StaleError{Current: cur.Revision}
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return Check{}, nil, cur, &model.FieldError{Field: "config", Msg: "Текущий конфиг не разобрать: " + err.Error()}
	}
	if err := change(c); err != nil {
		return Check{}, nil, cur, err
	}
	cand, err := c.Marshal()
	if err != nil {
		return Check{}, nil, cur, err
	}
	ch, cand, err := Build(b, string(cand), nil)
	return ch, cand, cur, err
}

// Queue queues the apply job for a candidate Candidate built from cur;
// change names it on the job page (ChangeRouting). A candidate with errors
// or without changes is a *model.FieldError.
func (a *Applier) Queue(ctx context.Context, serverID int64, cur model.ServerConfig, ch Check, cand []byte, change string, actor int64) (model.Job, error) {
	for _, p := range ch.Problems {
		if !p.Warning {
			return model.Job{}, &model.FieldError{Field: p.Field, Msg: "Конфиг не прошёл проверку: " + p.Field + ": " + p.Message}
		}
	}
	if !Changed(ch.Diff) && len(ch.Secrets) == 0 {
		return model.Job{}, &model.FieldError{Field: "config", Msg: "Изменений нет: на сервере уже так."}
	}
	p := Params{Base: cur.Revision, BaseSHA256: cur.SHA256, SHA256: sha(cand), Change: change}
	return a.x.Jobs.Submit(ctx, JobKind, serverID, p, map[string]string{SecretConfig: string(cand)}, actor)
}
