package batch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preset"
	"github.com/lardan099/hyroute/internal/srvmgr/routing"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/tuning"
)

// The params of each action, as a batch keeps them (no secrets). Each
// server gets the job its single-server route would queue with them.
type (
	// MaintainParams: the version to update Hysteria to and where the
	// binary comes from (deploy.MaintainParams, operation upgrade).
	MaintainParams struct {
		Version string `json:"version"`
		Source  string `json:"source,omitempty"`
		Via     int64  `json:"via,omitempty"`
	}
	// GeoParams: where the geo databases come from.
	GeoParams struct {
		Source string `json:"source,omitempty"`
		Via    int64  `json:"via,omitempty"`
	}
	// PresetParams: the preset and its sections laid over each config.
	PresetParams struct {
		Preset   int64    `json:"preset"`
		Sections []string `json:"sections"`
		// SHA256 is the preset's config when the batch was made: a preset
		// replaced since (deleted and another made, edited) is not laid.
		SHA256 string `json:"sha256"`
	}
	// RoutingParams: the rule template, where its rules go (routing.Place*)
	// and whether its outbounds and resolver come with it.
	RoutingParams struct {
		Template  string `json:"template"`
		Place     string `json:"place"`
		Outbounds bool   `json:"outbounds,omitempty"`
		Resolver  bool   `json:"resolver,omitempty"`
		// SHA256 is the template's content when the batch was made.
		SHA256 string `json:"sha256"`
	}
	// TuningParams: the kernel settings.
	TuningParams struct {
		Keys []string `json:"keys"`
	}
	// RotateParams: what gets new values on each server where it can
	// (Salamander only where the config has it, the certificate only where
	// it is self-signed); the passwords of cascade links stay, and on the
	// exit of a cascade the shared password, Salamander and the
	// certificate the link uses stay too.
	RotateParams struct {
		Auth bool `json:"auth,omitempty"`
		Obfs bool `json:"obfs,omitempty"`
		Cert bool `json:"cert,omitempty"`
	}
)

// JobKind is the kind of the jobs of an action.
func JobKind(a model.BatchAction) string {
	switch a {
	case model.BatchMaintain:
		return deploy.MaintainKind
	case model.BatchGeo:
		return geo.JobKind
	case model.BatchTuning:
		return tuning.JobKind
	}
	return apply.JobKind
}

// Unchanged: the server already is as the action would make it, or it
// has nothing the action changes; no job is queued.
type Unchanged struct{ Msg string }

func (e *Unchanged) Error() string { return e.Msg }

// ActionStore is what the actions read.
type ActionStore interface {
	PresetByID(ctx context.Context, id int64) (model.Preset, error)
	ListPresets(ctx context.Context) ([]model.Preset, error)
	ListChains(ctx context.Context) ([]model.Chain, error)
}

// Actions queue the job of each action on one server through the same
// services as the single-server routes: every job has its own checks,
// backups and rollback.
type Actions struct {
	Store   ActionStore
	Jobs    *jobs.Engine
	Deploy  *deploy.Submitter
	Geo     *geo.Installer
	Apply   *apply.Applier
	Editor  *apply.Editor
	Routing *routing.Service
}

func invalid(field, msg string) error { return &model.FieldError{Field: field, Msg: msg} }

// Check reads and checks the params of an action and returns them as the
// batch keeps them. Problems are *model.FieldError.
func (a *Actions) Check(ctx context.Context, action model.BatchAction, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	var out any
	switch action {
	case model.BatchMaintain:
		var p MaintainParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		mp := deploy.MaintainParams{Op: deploy.OpUpgrade, Version: p.Version, Source: p.Source, Via: p.Via}
		if err := mp.Normalize(); err != nil {
			field := "source"
			if hyrelease.CheckVersion(mp.Version) != nil {
				field = "version"
			}
			return nil, invalid(field, sentence(err.Error()))
		}
		out = MaintainParams{Version: mp.Version, Source: mp.Source, Via: mp.Via}
	case model.BatchGeo:
		var p GeoParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		switch p.Source {
		case "", geo.SourceAuto, geo.SourceDirect, geo.SourceRelay:
			p.Via = 0
		case geo.SourceNode:
			if p.Via <= 0 {
				return nil, invalid("via", "Выберите сервер, через который загружать базы.")
			}
		default:
			return nil, invalid("source", fmt.Sprintf("Неизвестный источник загрузки %q.", p.Source))
		}
		if p.Source == "" {
			p.Source = geo.SourceAuto
		}
		out = p
	case model.BatchPreset:
		var p PresetParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		pr, err := a.Store.PresetByID(ctx, p.Preset)
		if errors.Is(err, store.ErrNotFound) {
			return nil, invalid("preset", "Такого пресета нет.")
		} else if err != nil {
			return nil, err
		}
		p.SHA256 = presetSum(pr)
		if len(p.Sections) == 0 {
			return nil, invalid("sections", "Выберите разделы пресета.")
		}
		for _, s := range p.Sections {
			if !slices.Contains(preset.Sections, s) {
				return nil, invalid("sections", "Неизвестный раздел пресета «"+s+"».")
			}
		}
		out = p
	case model.BatchRouting:
		var p RoutingParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		t, err := a.template(ctx, p.Template, "")
		if err != nil {
			return nil, err
		}
		p.SHA256 = templateSum(t)
		switch p.Place {
		case "":
			p.Place = routing.PlaceTop
		case routing.PlaceTop, routing.PlaceBottom, routing.PlaceReplace:
		default:
			return nil, invalid("place", "Правила шаблона ставятся в начало, в конец или вместо правил сервера.")
		}
		out = p
	case model.BatchTuning:
		var p TuningParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		if len(p.Keys) == 0 {
			return nil, invalid("keys", "Выберите хотя бы одну настройку.")
		}
		for _, k := range p.Keys {
			if !slices.Contains(tuning.Keys, k) {
				return nil, invalid("keys", "HyRoute не меняет "+k+".")
			}
		}
		out = p
	case model.BatchRotate:
		var p RotateParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		if !p.Auth && !p.Obfs && !p.Cert {
			return nil, invalid("rotate", "Выберите, что сменить.")
		}
		out = p
	default:
		return nil, invalid("action", fmt.Sprintf("Неизвестное действие %q.", action))
	}
	return json.Marshal(out)
}

// Via is the server an action downloads through (0: none).
func Via(b model.Batch) int64 {
	var p struct {
		Via int64 `json:"via"`
	}
	json.Unmarshal(b.Params, &p)
	return p.Via
}

// template is a rule template by its ID; sum, when set, is the content
// the batch was made with (a template of a preset replaced since is not
// laid).
func (a *Actions) template(ctx context.Context, id, sum string) (routing.Template, error) {
	ps, err := a.Store.ListPresets(ctx)
	if err != nil {
		return routing.Template{}, err
	}
	for _, t := range routing.Templates(ps) {
		if t.ID == id {
			if sum != "" && templateSum(t) != sum {
				return routing.Template{}, invalid("template", "Шаблон правил пакета заменён с тех пор, как пакет создан: его пресет удалили или изменили.")
			}
			return t, nil
		}
	}
	return routing.Template{}, invalid("template", "Такого шаблона правил нет: его пресет удалён.")
}

// presetSum and templateSum name the content a batch lays: a preset ID
// alone could later name another preset.
func presetSum(p model.Preset) string {
	h := sha256.Sum256([]byte(p.Config))
	return hex.EncodeToString(h[:])
}

func templateSum(t routing.Template) string {
	b, _ := json.Marshal(t)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Queue queues the job of b's action on the server for actor, as the
// single-server route would: the current revision of the config is the
// base. note says what of the action the server did not get (a rotation
// without Salamander). A server that has nothing to change is
// *Unchanged; jobs.ErrBusy: it has another job now.
func (a *Actions) Queue(ctx context.Context, b model.Batch, serverID, actor int64) (j model.Job, note string, err error) {
	switch b.Action {
	case model.BatchMaintain:
		var p MaintainParams
		if err := json.Unmarshal(b.Params, &p); err != nil {
			return j, "", err
		}
		j, err = a.Deploy.Maintain(ctx, serverID, deploy.MaintainParams{Op: deploy.OpUpgrade, Version: p.Version, Source: p.Source, Via: p.Via}, actor)
	case model.BatchGeo:
		var p GeoParams
		if err := json.Unmarshal(b.Params, &p); err != nil {
			return j, "", err
		}
		j, err = a.Geo.Submit(ctx, serverID, p.Source, p.Via, actor)
	case model.BatchPreset:
		j, err = a.preset(ctx, b, serverID, actor)
	case model.BatchRouting:
		j, err = a.routing(ctx, b, serverID, actor)
	case model.BatchTuning:
		var p TuningParams
		if err := json.Unmarshal(b.Params, &p); err != nil {
			return j, "", err
		}
		j, err = a.Jobs.Submit(ctx, tuning.JobKind, serverID, tuning.Params{Keys: p.Keys}, nil, actor)
	case model.BatchRotate:
		j, note, err = a.rotate(ctx, b, serverID, actor)
	default:
		err = fmt.Errorf("unknown action %q", b.Action)
	}
	return j, note, err
}

func (a *Actions) preset(ctx context.Context, b model.Batch, serverID, actor int64) (model.Job, error) {
	var p PresetParams
	if err := json.Unmarshal(b.Params, &p); err != nil {
		return model.Job{}, err
	}
	pr, err := a.Store.PresetByID(ctx, p.Preset)
	if errors.Is(err, store.ErrNotFound) {
		return model.Job{}, invalid("preset", "Пресет пакета удалён.")
	} else if err != nil {
		return model.Job{}, err
	}
	if p.SHA256 != "" && presetSum(pr) != p.SHA256 {
		return model.Job{}, invalid("preset", "Пресет пакета заменён с тех пор, как пакет создан: его удалили или изменили.")
	}
	cur, _, err := a.Editor.Current(ctx, serverID)
	if err != nil {
		return model.Job{}, err
	}
	ch, err := a.Editor.PresetPreview(ctx, serverID, cur.Revision, pr, p.Sections)
	if err != nil {
		return model.Job{}, err
	}
	if !apply.Changed(ch.Diff) && len(ch.Secrets) == 0 {
		return model.Job{}, &Unchanged{"Изменений нет: эти разделы на сервере уже такие, как в пресете."}
	}
	return a.Apply.ApplyPreset(ctx, serverID, cur.Revision, pr, p.Sections, actor)
}

func (a *Actions) routing(ctx context.Context, b model.Batch, serverID, actor int64) (model.Job, error) {
	var p RoutingParams
	if err := json.Unmarshal(b.Params, &p); err != nil {
		return model.Job{}, err
	}
	t, err := a.template(ctx, p.Template, p.SHA256)
	if err != nil {
		return model.Job{}, err
	}
	v, err := a.Routing.Open(ctx, serverID)
	if err != nil {
		return model.Job{}, err
	}
	if v.File != "" {
		return model.Job{}, invalid("acl", "Правила сервера — в файле "+v.File+": шаблон ставится только в правила конфига. Перенесите их в конфиг в редакторе маршрутизации.")
	}
	in := routing.Merged(v, t, p.Place, p.Outbounds, p.Resolver)
	pv, err := a.Routing.Preview(ctx, serverID, in)
	if err != nil {
		return model.Job{}, err
	}
	if pv.Same {
		return model.Job{}, &Unchanged{"Изменений нет: маршрутизация на сервере уже такая."}
	}
	return a.Routing.Apply(ctx, serverID, in, actor)
}

// rotate rotates what the server's config has of what the batch asks.
func (a *Actions) rotate(ctx context.Context, b model.Batch, serverID, actor int64) (model.Job, string, error) {
	var p RotateParams
	if err := json.Unmarshal(b.Params, &p); err != nil {
		return model.Job{}, "", err
	}
	cur, text, err := a.Editor.Current(ctx, serverID)
	if err != nil {
		return model.Job{}, "", err
	}
	c, err := hyconfig.ParseServer(text)
	if err != nil {
		return model.Job{}, "", invalid("config", "Текущий конфиг не разобрать: "+err.Error())
	}
	chains, err := a.Store.ListChains(ctx)
	if err != nil {
		return model.Job{}, "", err
	}
	links := cascade.Users(chains, serverID)
	r := apply.Rotation{Links: links}
	// The link client of a cascade into this server logs in with the
	// shared password of a password server and copies its Salamander
	// password and certificate pin: changing them in a batch would cut
	// the cascade until it is redeployed.
	exit := len(links) > 0
	const linkNote = "его использует связь каскада к этому серверу — смените на странице сервера и обновите каскад"
	var left []string
	if p.Auth {
		if ok, why := rotatable(c, links); !ok {
			left = append(left, why)
		} else if exit && strings.EqualFold(c.Auth.Type, "password") {
			left = append(left, "общий пароль: "+linkNote)
		} else {
			r.Auth = true
		}
	}
	if p.Obfs {
		switch {
		case !strings.EqualFold(c.Obfs.Type, "salamander"):
			left = append(left, "обфускации Salamander в конфиге нет")
		case exit:
			left = append(left, "пароль Salamander: "+linkNote)
		default:
			r.Obfs = true
		}
	}
	if p.Cert {
		switch {
		case !(c.ACME == nil && c.TLS != nil && cur.Meta.TLS == "self-signed" && path.IsAbs(c.TLS.Cert) && path.IsAbs(c.TLS.Key)):
			left = append(left, "сертификат не самоподписанный (ACME или от удостоверяющего центра)")
		case exit:
			left = append(left, "сертификат: "+linkNote)
		default:
			r.Cert = true
		}
	}
	note := ""
	if len(left) > 0 {
		note = "Не меняется: " + strings.Join(left, "; ") + "."
	}
	if !r.Auth && !r.Obfs && !r.Cert {
		return model.Job{}, "", &Unchanged{"Менять нечего: " + strings.Join(left, "; ") + "."}
	}
	j, err := a.Apply.Rotate(ctx, serverID, cur.Revision, r, actor)
	return j, note, err
}

// rotatable: the config holds passwords of its clients a rotation can
// replace (not only those of cascade links).
func rotatable(c *hyconfig.Server, links []string) (bool, string) {
	switch strings.ToLower(c.Auth.Type) {
	case "password":
		return true, ""
	case "userpass":
		for u := range c.Auth.UserPass {
			if !slices.ContainsFunc(links, func(l string) bool { return strings.EqualFold(l, u) }) {
				return true, ""
			}
		}
		return false, "пользователей, кроме связей каскада, нет"
	}
	return false, "клиентов проверяет внешний сервис (auth " + c.Auth.Type + ")"
}

// Message is what an item shows when its job was not queued: err of
// Queue in words for people.
func Message(err error) string {
	var fe *model.FieldError
	var stale *apply.StaleError
	var un *Unchanged
	switch {
	case errors.As(err, &un):
		return un.Msg
	case errors.As(err, &fe):
		return fe.Msg
	case errors.As(err, &stale):
		return stale.Error()
	case errors.Is(err, deploy.ErrNoInstallation), errors.Is(err, geo.ErrNoInstallation):
		return "HyRoute не знает, где на сервере Hysteria: разверните её или импортируйте сервер."
	case errors.Is(err, deploy.ErrNotHysteria):
		return "Служба этого сервера запускает не программу hysteria* (например, docker или оболочку): HyRoute её не заменяет."
	case errors.Is(err, geo.ErrNone):
		return sentence(geo.ErrNone.Error()) + "."
	case errors.Is(err, apply.ErrNoConfig):
		return "HyRoute ещё не знает конфиг этого сервера: разверните Hysteria или импортируйте сервер."
	case errors.Is(err, store.ErrNotFound):
		return "Сервер или его данные не найдены."
	case errors.Is(err, hyconfig.ErrTooLarge):
		return err.Error()
	}
	return "Задание не поставлено: ошибка controller (подробности — в его журнале)."
}

// sentence starts s with a capital letter.
func sentence(s string) string {
	for i, r := range s {
		return strings.ToUpper(string(r)) + s[i+len(string(r)):]
	}
	return s
}
