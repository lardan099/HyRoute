package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/importer"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

var errHostKeyRequired = &Error{Status: http.StatusConflict, Code: "host_key_required", Message: "Сначала проверьте подключение к серверу и подтвердите его ключ SSH."}

// errConfigChanged: the deploy would replace a config no deploy made; the
// UI asks and sends "overwrite": true.
var errConfigChanged = &Error{Status: http.StatusConflict, Code: "config_changed", Message: "Текущий конфиг сервера сделан не развёртыванием: его изменили в редакторе, вернули из истории или импортировали. Развёртывание соберёт конфиг заново из параметров формы, и всё, чего в форме нет (ACL, outbounds, bandwidth и другие настройки), пропадёт; пароли клиентов сохранятся. Подтвердите замену конфига."}

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
		writeError(w, errHostKeyRequired)
		return
	}
	j, err := s.Deploy.Submit(r.Context(), id, p, principal(r).User.ID)
	if errors.Is(err, deploy.ErrConfigChanged) {
		writeError(w, errConfigChanged)
		return
	} else if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}

// configJSON is a config revision without the config: what the UI shows
// and what client links need besides the passwords.
type configJSON struct {
	Revision int                `json:"revision"`
	SHA256   string             `json:"sha256"`
	Meta     model.ConfigMeta   `json:"meta"`
	Source   model.ConfigSource `json:"source"`
	// FromRevision is the revision a rollback brought back.
	FromRevision int       `json:"fromRevision,omitempty"`
	JobID        int64     `json:"jobId"`
	CreatedAt    time.Time `json:"createdAt"`
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
	writeJSON(w, http.StatusOK, configJSON{Revision: c.Revision, SHA256: c.SHA256, Meta: c.Meta, Source: c.Source, FromRevision: c.FromRevision, JobID: c.JobID, CreatedAt: c.At})
}

func (s *server) startImport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	in, err := s.Servers.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	if in.HostKey == nil {
		writeError(w, errHostKeyRequired)
		return
	}
	j, err := s.Jobs.Submit(r.Context(), importer.JobKind, id, struct{}{}, nil, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
