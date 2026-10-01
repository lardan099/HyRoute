package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preset"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// presetJSON is a preset: its config has no secrets and no server
// addresses, so every role sees it.
type presetJSON struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Sections  []string  `json:"sections"`
	Notes     []string  `json:"notes"`
	Config    string    `json:"config"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func toPresetJSON(i preset.Info) presetJSON {
	notes := i.Notes
	if notes == nil {
		notes = []string{}
	}
	return presetJSON{ID: i.ID, Name: i.Name, Sections: i.Sections, Notes: notes, Config: i.Config, CreatedAt: i.CreatedAt, UpdatedAt: i.UpdatedAt}
}

func presetError(err error) error {
	if errors.Is(err, preset.ErrNoConfig) {
		return &Error{Status: http.StatusNotFound, Code: "no_config", Message: "HyRoute ещё не знает конфиг этого сервера: разверните Hysteria или импортируйте сервер."}
	}
	return mapError(err)
}

func (s *server) listPresets(w http.ResponseWriter, r *http.Request) {
	ps, err := s.Store.ListPresets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]presetJSON, 0, len(ps))
	for _, p := range ps {
		out = append(out, toPresetJSON(preset.Of(p)))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) getPreset(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	p, err := s.Store.PresetByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusOK, toPresetJSON(preset.Of(p)))
}

// createPreset makes a preset of a server's config, or clones one.
func (s *server) createPreset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string `json:"name"`
		ServerID int64  `json:"serverId"`
		From     int64  `json:"from"`
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	var (
		p   preset.Info
		err error
	)
	actor := principal(r).User.ID
	switch {
	case in.From != 0:
		p, err = s.presets().Clone(r.Context(), in.From, in.Name, actor)
	case in.ServerID != 0:
		if _, err = s.Servers.Get(r.Context(), in.ServerID); err == nil {
			p, err = s.presets().FromServer(r.Context(), in.Name, in.ServerID, actor)
		}
	default:
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Выберите сервер или пресет, из которого сделать новый.", Details: "serverId"})
		return
	}
	if err != nil {
		s.fail(w, r, presetError(err))
		return
	}
	writeJSON(w, http.StatusCreated, toPresetJSON(p))
}

func (s *server) renamePreset(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	p, err := s.presets().Rename(r.Context(), id, in.Name, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, presetError(err))
		return
	}
	writeJSON(w, http.StatusOK, toPresetJSON(p))
}

func (s *server) deletePreset(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if err := s.presets().Delete(r.Context(), id, principal(r).User.ID); err != nil {
		s.fail(w, r, presetError(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// exportPreset is the preset's file for download.
func (s *server) exportPreset(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	p, err := s.Store.PresetByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	b, err := preset.Export(p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="preset-`+strconv.FormatInt(p.ID, 10)+`.json"`)
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

// importPreset stores the preset of an export file (the body).
func (s *server) importPreset(w http.ResponseWriter, r *http.Request) {
	var f preset.File
	r.Body = http.MaxBytesReader(w, r.Body, preset.MaxImport)
	if err := readJSON(r, &f); err != nil {
		writeError(w, err)
		return
	}
	b, _ := json.Marshal(f)
	p, err := s.presets().Import(r.Context(), b, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, presetError(err))
		return
	}
	writeJSON(w, http.StatusCreated, toPresetJSON(p))
}

func (s *server) presets() *preset.Service { return &preset.Service{Store: s.Store, Keys: s.Keys} }

// presetApplyInput: the revision the admin looked at, the preset and its
// sections to lay over the server's config.
type presetApplyInput struct {
	Base     int      `json:"base"`
	Preset   int64    `json:"preset"`
	Sections []string `json:"sections"`
}

func (s *server) readPresetApply(w http.ResponseWriter, r *http.Request) (int64, presetApplyInput, model.Preset, bool) {
	var in presetApplyInput
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return 0, in, model.Preset{}, false
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return 0, in, model.Preset{}, false
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return 0, in, model.Preset{}, false
	}
	p, err := s.Store.PresetByID(r.Context(), in.Preset)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, &Error{Status: http.StatusNotFound, Code: "no_preset", Message: "Такого пресета нет."})
		return 0, in, model.Preset{}, false
	} else if err != nil {
		s.fail(w, r, err)
		return 0, in, model.Preset{}, false
	}
	return id, in, p, true
}

// presetPreview is the check and diff of laying a preset's sections over
// the server's config; nothing is stored or sent to the server.
func (s *server) presetPreview(w http.ResponseWriter, r *http.Request) {
	id, in, p, ok := s.readPresetApply(w, r)
	if !ok {
		return
	}
	ch, err := s.editor().PresetPreview(r.Context(), id, in.Base, p, in.Sections)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

// presetApply queues the apply job for a preset's sections.
func (s *server) presetApply(w http.ResponseWriter, r *http.Request) {
	id, in, p, ok := s.readPresetApply(w, r)
	if !ok {
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Apply.ApplyPreset(r.Context(), id, in.Base, p, in.Sections, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(configError(err)))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
