package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

func (s *server) startDeploy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var p deploy.Params
	if err := readJSON(r, &p); err != nil {
		writeError(w, err)
		return
	}
	in, err := s.Servers.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	// The job would fail at connect: say what to do now.
	if in.HostKey == nil {
		writeError(w, &Error{Status: http.StatusConflict, Code: "host_key_required", Message: "Сначала проверьте подключение к серверу и подтвердите его ключ SSH."})
		return
	}
	j, err := s.Deploy.Submit(r.Context(), id, p, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}

// configJSON is a config revision without the config: what the UI shows
// and what client links need besides the passwords.
type configJSON struct {
	Revision  int                `json:"revision"`
	SHA256    string             `json:"sha256"`
	Meta      model.ConfigMeta   `json:"meta"`
	Source    model.ConfigSource `json:"source"`
	JobID     int64              `json:"jobId"`
	CreatedAt time.Time          `json:"createdAt"`
}

func (s *server) currentConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	c, err := s.Store.CurrentConfig(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, &Error{Status: http.StatusNotFound, Code: "no_config", Message: "HyRoute ещё не устанавливал Hysteria на этот сервер."})
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, configJSON{Revision: c.Revision, SHA256: c.SHA256, Meta: c.Meta, Source: c.Source, JobID: c.JobID, CreatedAt: c.At})
}
