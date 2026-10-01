package preset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Store is what presets keep in the controller's database.
type Store interface {
	store.Presets
	store.Configs
	store.Audit
}

// Service manages presets.
type Service struct {
	Store Store
	Keys  *secrets.Keyring
	Now   func() time.Time
}

// ErrNoConfig: the server has no config to make a preset from.
var ErrNoConfig = errors.New("preset: the server has no config")

// Info is a preset with its sections.
type Info struct {
	model.Preset
	Sections []string
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Of is the preset with its sections.
func Of(p model.Preset) Info {
	i := Info{Preset: p, Sections: []string{}}
	if c, err := hyconfig.ParseServer([]byte(p.Config)); err == nil {
		i.Sections = Has(c)
	}
	return i
}

// Parse is the config of a preset.
func Parse(p model.Preset) (*hyconfig.Server, error) { return hyconfig.ParseServer([]byte(p.Config)) }

// checkName trims a preset name and checks it.
func checkName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 64 {
		return "", &model.FieldError{Field: "name", Msg: "Название пресета: от 1 до 64 символов."}
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return "", &model.FieldError{Field: "name", Msg: "В названии пресета непечатаемые символы."}
		}
	}
	return name, nil
}

// free: no other preset has the name, case-insensitively in any script
// (SQLite folds only ASCII).
func (s *Service) free(ctx context.Context, name string, self int64) error {
	ps, err := s.Store.ListPresets(ctx)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if p.ID != self && strings.EqualFold(p.Name, name) {
			return taken(store.ErrConflict)
		}
	}
	return nil
}

func taken(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return &model.FieldError{Field: "name", Msg: "Пресет с таким названием уже есть."}
	}
	return err
}

// create stores a preset made of config c.
func (s *Service) create(ctx context.Context, name string, c *hyconfig.Server, actor int64, action string) (Info, error) {
	name, err := checkName(name)
	if err != nil {
		return Info{}, err
	}
	if err := s.free(ctx, name, 0); err != nil {
		return Info{}, err
	}
	p, notes := Extract(c)
	if len(Has(p)) == 0 {
		return Info{}, &model.FieldError{Field: "config", Msg: "В конфиге нет ни одного раздела, который можно сохранить в пресет."}
	}
	b, err := p.Marshal()
	if err != nil {
		return Info{}, err
	}
	now := s.now()
	m := model.Preset{Name: name, Config: string(b), Notes: notes, CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
	if err := s.Store.CreatePreset(ctx, &m); err != nil {
		return Info{}, taken(err)
	}
	s.audit(ctx, actor, action, m)
	return Of(m), nil
}

func (s *Service) audit(ctx context.Context, actor int64, action string, p model.Preset) {
	s.Store.AddAudit(ctx, model.AuditEntry{Time: s.now(), UserID: actor, Action: action, Target: fmt.Sprintf("preset/%d", p.ID), Details: p.Name})
}

// FromServer makes a preset of the server's current config.
func (s *Service) FromServer(ctx context.Context, name string, serverID int64, actor int64) (Info, error) {
	cur, err := s.Store.CurrentConfig(ctx, serverID)
	if errors.Is(err, store.ErrNotFound) {
		return Info{}, ErrNoConfig
	} else if err != nil {
		return Info{}, err
	}
	b, err := s.Keys.Open(cur.Sealed, model.ConfigContext(serverID, cur.Revision))
	if err != nil {
		return Info{}, err
	}
	c, err := hyconfig.ParseServer(b)
	if err != nil {
		return Info{}, &model.FieldError{Field: "config", Msg: "Конфиг сервера не разобрать: " + err.Error()}
	}
	return s.create(ctx, name, c, actor, "preset.create")
}

// Clone copies a preset under another name.
func (s *Service) Clone(ctx context.Context, id int64, name string, actor int64) (Info, error) {
	p, err := s.Store.PresetByID(ctx, id)
	if err != nil {
		return Info{}, err
	}
	name, err = checkName(name)
	if err != nil {
		return Info{}, err
	}
	if err := s.free(ctx, name, 0); err != nil {
		return Info{}, err
	}
	now := s.now()
	m := model.Preset{Name: name, Config: p.Config, Notes: p.Notes, CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
	if err := s.Store.CreatePreset(ctx, &m); err != nil {
		return Info{}, taken(err)
	}
	s.audit(ctx, actor, "preset.clone", m)
	return Of(m), nil
}

// Rename renames a preset.
func (s *Service) Rename(ctx context.Context, id int64, name string, actor int64) (Info, error) {
	p, err := s.Store.PresetByID(ctx, id)
	if err != nil {
		return Info{}, err
	}
	if p.Name, err = checkName(name); err != nil {
		return Info{}, err
	}
	if err := s.free(ctx, p.Name, p.ID); err != nil {
		return Info{}, err
	}
	p.UpdatedAt = s.now()
	if err := s.Store.UpdatePreset(ctx, p); err != nil {
		return Info{}, taken(err)
	}
	s.audit(ctx, actor, "preset.rename", p)
	return Of(p), nil
}

// Delete removes a preset.
func (s *Service) Delete(ctx context.Context, id int64, actor int64) error {
	p, err := s.Store.PresetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.Store.DeletePreset(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, actor, "preset.delete", p)
	return nil
}

// The export format.
const (
	Format  = "hyroute-preset"
	Version = 1
	// MaxImport is the largest export Import reads.
	MaxImport = 256 << 10
)

// File is a preset as exported: JSON with the format and its version.
type File struct {
	Format  string   `json:"format"`
	Version int      `json:"version"`
	Name    string   `json:"name"`
	Config  string   `json:"config"`
	Notes   []string `json:"notes,omitempty"`
}

// Export is the export file of a preset.
func Export(p model.Preset) ([]byte, error) {
	return json.MarshalIndent(File{Format: Format, Version: Version, Name: p.Name, Config: p.Config, Notes: p.Notes}, "", "  ")
}

// Import stores the preset of an export file. The config is made a
// preset again, so a file edited by hand brings no secret or address in.
// A name in use gets a number.
func (s *Service) Import(ctx context.Context, data []byte, actor int64) (Info, error) {
	if len(data) > MaxImport {
		return Info{}, &model.FieldError{Field: "file", Msg: "Файл пресета больше 256 КиБ."}
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil || f.Format != Format {
		return Info{}, &model.FieldError{Field: "file", Msg: "Это не файл пресета HyRoute."}
	}
	if f.Version != Version {
		return Info{}, &model.FieldError{Field: "file", Msg: fmt.Sprintf("Файл пресета версии %d, а эта версия HyRoute читает версию %d.", f.Version, Version)}
	}
	c, err := hyconfig.ParseServer([]byte(f.Config))
	if err != nil {
		return Info{}, &model.FieldError{Field: "file", Msg: "Конфиг пресета не разобрать: " + err.Error()}
	}
	name, err := checkName(f.Name)
	if err != nil {
		name = "Импорт"
	}
	for i := 1; ; i++ {
		n := name
		if i > 1 {
			n = fmt.Sprintf("%s (%d)", name, i)
		}
		in, err := s.create(ctx, n, c, actor, "preset.import")
		var fe *model.FieldError
		if errors.As(err, &fe) && fe.Field == "name" && i < 100 {
			continue
		}
		return in, err
	}
}
