package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/preset"
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
