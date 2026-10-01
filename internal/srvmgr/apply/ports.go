package apply

import (
	"context"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/hopping"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// ErrSamePorts: the spec is the ports the config already has.
var ErrSamePorts = &model.FieldError{Field: "ports", Msg: "Порты не изменились."}

// SetPorts queues the apply job that makes the current config (base must
// still be it) listen on the ports of spec, through the typed model; the
// job checks the server for them and opens them in the firewall. A spec
// that does not parse is a *model.FieldError, the same ports
// ErrSamePorts.
func (a *Applier) SetPorts(ctx context.Context, serverID int64, base int, spec hopping.Spec, actor int64) (model.Job, error) {
	rs, err := spec.Parse()
	if err != nil {
		return model.Job{}, &model.FieldError{Field: "ports", Msg: sentence(err.Error())}
	}
	e := &Editor{Store: a.x.Store, Keys: a.x.Keys}
	cur, b, err := e.Current(ctx, serverID)
	if err != nil {
		return model.Job{}, err
	}
	if cur.Revision != base {
		return model.Job{}, &StaleError{Current: cur.Revision}
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return model.Job{}, &model.FieldError{Field: "config", Msg: "Текущий конфиг не разобрать: " + err.Error()}
	}
	if strings.Contains(c.Listen, "://") {
		return model.Job{}, &model.FieldError{Field: "ports", Msg: "Сервер работает в режиме Realms: у него нет своих портов."}
	}
	listen := spec.Listen(rs)
	if os, old, err := hopping.FromListen(c.Listen); err == nil && listen == os.Listen(old) {
		return model.Job{}, ErrSamePorts
	}
	c.Listen = listen
	cand, err := c.Marshal()
	if err != nil {
		return model.Job{}, err
	}
	var errs []string
	for _, p := range c.Validate() {
		if !p.Warning {
			errs = append(errs, p.Field+": "+p.Message)
		}
	}
	if len(errs) > 0 {
		return model.Job{}, &model.FieldError{Field: "config", Msg: "Конфиг не проходит проверку, сначала исправьте его: " + strings.Join(errs, "; ") + "."}
	}
	p := Params{Base: cur.Revision, BaseSHA256: cur.SHA256, SHA256: sha(cand)}
	return a.x.Jobs.Submit(ctx, JobKind, serverID, p, map[string]string{SecretConfig: string(cand)}, actor)
}

// sentence makes an error text a sentence.
func sentence(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	s = strings.ToUpper(string(r[0])) + string(r[1:])
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
