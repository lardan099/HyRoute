package apply

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preset"
)

// PresetCheck is what laying a preset over a server's config changes.
type PresetCheck struct {
	Check
	// NewObfs: the obfuscation password is new (client links change).
	NewObfs bool `json:"newObfs"`
}

// presetCandidate is the current config (base must still be it) with the
// sections of preset p laid over it, and its check.
func (e *Editor) presetCandidate(ctx context.Context, serverID int64, base int, p model.Preset, sections []string) (PresetCheck, []byte, model.ServerConfig, error) {
	cur, b, err := e.Current(ctx, serverID)
	if err != nil {
		return PresetCheck{}, nil, cur, err
	}
	if cur.Revision != base {
		return PresetCheck{}, nil, cur, &StaleError{Current: cur.Revision}
	}
	if len(sections) == 0 {
		return PresetCheck{}, nil, cur, &model.FieldError{Field: "sections", Msg: "Выберите разделы пресета."}
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return PresetCheck{}, nil, cur, &model.FieldError{Field: "config", Msg: "Текущий конфиг не разобрать: " + err.Error()}
	}
	pc, err := preset.Parse(p)
	if err != nil {
		return PresetCheck{}, nil, cur, &model.FieldError{Field: "preset", Msg: "Пресет не разобрать: " + err.Error()}
	}
	if strings.Contains(c.Listen, "://") && slices.Contains(sections, preset.Ports) {
		return PresetCheck{}, nil, cur, &model.FieldError{Field: "sections", Msg: "Сервер работает в режиме Realms: портов у него нет."}
	}
	newObfs, err := preset.Overlay(c, pc, sections, generated)
	if errors.Is(err, preset.ErrNoSection) {
		return PresetCheck{}, nil, cur, &model.FieldError{Field: "sections", Msg: "В пресете нет такого раздела: " + strings.TrimPrefix(err.Error(), preset.ErrNoSection.Error()+" ") + "."}
	} else if err != nil {
		return PresetCheck{}, nil, cur, err
	}
	cand, err := c.Marshal()
	if err != nil {
		return PresetCheck{}, nil, cur, err
	}
	ch, cand, err := Build(b, string(cand), nil)
	return PresetCheck{Check: ch, NewObfs: newObfs}, cand, cur, err
}

// PresetPreview is the check and diff of laying the sections of preset p
// over the server's config; nothing is stored or sent to the server.
func (e *Editor) PresetPreview(ctx context.Context, serverID int64, base int, p model.Preset, sections []string) (PresetCheck, error) {
	ch, _, _, err := e.presetCandidate(ctx, serverID, base, p, sections)
	return ch, err
}

// ApplyPreset queues the apply job that lays the sections of preset p over
// the server's config. A candidate with errors or without changes is a
// *model.FieldError.
func (a *Applier) ApplyPreset(ctx context.Context, serverID int64, base int, p model.Preset, sections []string, actor int64) (model.Job, error) {
	e := &Editor{Store: a.x.Store, Keys: a.x.Keys}
	ch, cand, cur, err := e.presetCandidate(ctx, serverID, base, p, sections)
	if err != nil {
		return model.Job{}, err
	}
	for _, pr := range ch.Problems {
		if !pr.Warning {
			return model.Job{}, &model.FieldError{Field: pr.Field, Msg: "Конфиг с пресетом не проходит проверку: " + pr.Field + ": " + pr.Message}
		}
	}
	if !Changed(ch.Diff) && len(ch.Secrets) == 0 {
		return model.Job{}, &model.FieldError{Field: "sections", Msg: "Изменений нет: эти разделы на сервере уже такие, как в пресете."}
	}
	params := Params{Base: cur.Revision, BaseSHA256: cur.SHA256, SHA256: sha(cand), Preset: p.Name, Sections: sections}
	return a.x.Jobs.Submit(ctx, JobKind, serverID, params, map[string]string{SecretConfig: string(cand)}, actor)
}
