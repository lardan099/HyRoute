package api

import (
	"errors"
	"net/http"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
)

func (s *server) editor() *apply.Editor { return &apply.Editor{Store: s.Store, Keys: s.Keys} }

func configError(err error) error {
	var stale *apply.StaleError
	switch {
	case errors.Is(err, apply.ErrNoConfig):
		return &Error{Status: http.StatusNotFound, Code: "no_config", Message: "HyRoute ещё не знает конфиг этого сервера: разверните Hysteria или импортируйте сервер."}
	case errors.As(err, &stale):
		return &Error{Status: http.StatusConflict, Code: "config_changed", Message: stale.Error()}
	}
	return mapError(err)
}

// editConfig is the current config for the editor, secrets masked.
func (s *server) editConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	v, err := s.editor().Open(r.Context(), id)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, v)
}

type renderInput struct {
	Revision int           `json:"revision"`
	YAML     string        `json:"yaml"`
	Fields   *apply.Fields `json:"fields,omitempty"`
}

// renderConfig checks a candidate: its text (with the structured fields
// applied when given), problems, diff and changed secrets. Nothing is
// stored or sent to the server.
func (s *server) renderConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in renderInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	ch, _, _, err := s.editor().Render(r.Context(), id, in.Revision, in.YAML, in.Fields)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

// applyConfig queues the apply job for the editor's candidate.
func (s *server) applyConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in renderInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Apply.Submit(r.Context(), id, in.Revision, in.YAML, in.Fields, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(configError(err)))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
