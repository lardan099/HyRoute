package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/hopping"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func (s *server) editor() *apply.Editor { return &apply.Editor{Store: s.Store, Keys: s.Keys} }

func configError(err error) error {
	var stale *apply.StaleError
	switch {
	case errors.Is(err, apply.ErrNoConfig):
		return &Error{Status: http.StatusNotFound, Code: "no_config", Message: "HyRoute ещё не знает конфиг этого сервера: разверните Hysteria или импортируйте сервер."}
	case errors.As(err, &stale):
		return &Error{Status: http.StatusConflict, Code: "config_changed", Message: stale.Error()}
	case errors.Is(err, apply.ErrNoRevision):
		return &Error{Status: http.StatusNotFound, Code: "no_revision", Message: "Такой версии конфига у сервера нет."}
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

// rotateInput: the revision the admin looked at and what to replace.
type rotateInput struct {
	Base int `json:"base"`
	apply.Rotation
}

// rotateConfig starts the apply job that replaces passwords or the
// self-signed certificate.
func (s *server) rotateConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in rotateInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Apply.Rotate(r.Context(), id, in.Base, in.Rotation, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(configError(err)))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}

// portsInput is the body of POST /servers/{id}/ports.
type portsInput struct {
	Base  int      `json:"base"`
	Ports []string `json:"ports"`
	Host  string   `json:"host"`
	// HopInterval of the client links, seconds (0: the client's default).
	HopInterval int `json:"hopInterval"`
}

// setPorts changes the ports of a server and the hop interval of its
// client links. New ports go through an apply job (202 with the job);
// the interval is the client's and is saved at once (200 without a job
// when the ports stay).
func (s *server) setPorts(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in portsInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if in.HopInterval != 0 && (in.HopInterval < hopping.MinInterval || in.HopInterval > hopping.MaxInterval) {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: fmt.Sprintf("Интервал смены портов: от %d до %d секунд.", hopping.MinInterval, hopping.MaxInterval), Details: "hopInterval"})
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	srv, err := s.Servers.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	j, err := s.Apply.SetPorts(r.Context(), id, in.Base, hopping.Spec{Ports: in.Ports, Host: in.Host}, principal(r).User.ID)
	same := errors.Is(err, apply.ErrSamePorts)
	if err != nil && !same {
		s.fail(w, r, jobError(configError(err)))
		return
	}
	if srv.HopInterval != in.HopInterval {
		if err := s.Store.SetHopInterval(r.Context(), id, in.HopInterval, time.Now()); err != nil {
			s.fail(w, r, err)
			return
		}
		s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: principal(r).User.ID, Action: "server.hop_interval", Target: "server/" + strconv.FormatInt(id, 10), Details: strconv.Itoa(in.HopInterval)})
	} else if same {
		s.fail(w, r, jobError(configError(err)))
		return
	}
	if same {
		writeJSON(w, http.StatusOK, map[string]any{"job": nil})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"job": toJobJSON(j)})
}

// revisionJSON is a config revision in the history (no config text).
type revisionJSON struct {
	Revision     int                `json:"revision"`
	Source       model.ConfigSource `json:"source"`
	FromRevision int                `json:"fromRevision,omitempty"`
	Meta         model.ConfigMeta   `json:"meta"`
	JobID        int64              `json:"jobId,omitempty"`
	By           string             `json:"by,omitempty"` // username ("" = the system or a removed user)
	CreatedAt    time.Time          `json:"createdAt"`
	Current      bool               `json:"current"`
}

// configRevisions is the server's config history, newest first. It has
// no config text, so every role sees it.
func (s *server) configRevisions(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	cs, err := s.Store.ListConfigs(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	names := map[int64]string{}
	out := make([]revisionJSON, 0, len(cs))
	for i, c := range cs {
		if _, seen := names[c.By]; !seen && c.By != 0 {
			if u, err := s.Store.UserByID(r.Context(), c.By); err == nil {
				names[c.By] = u.Username
			} else {
				names[c.By] = ""
			}
		}
		out = append(out, revisionJSON{Revision: c.Revision, Source: c.Source, FromRevision: c.FromRevision, Meta: c.Meta, JobID: c.JobID, By: names[c.By], CreatedAt: c.At, Current: i == 0})
	}
	writeJSON(w, http.StatusOK, out)
}

func pathRevision(r *http.Request) (int, bool) {
	n, err := strconv.Atoi(r.PathValue("rev"))
	return n, err == nil && n > 0
}

// configRevision is one revision's config, secrets masked (writers only,
// as the editor: masking cannot know every secret).
func (s *server) configRevision(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	rev, okRev := pathRevision(r)
	if !ok || !okRev {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	v, err := s.editor().Revision(r.Context(), id, rev)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// compareConfigs is the diff between revisions ?from= and ?to= without
// secrets (changed secrets are listed by path).
func (s *server) compareConfigs(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	from, err1 := strconv.Atoi(r.URL.Query().Get("from"))
	to, err2 := strconv.Atoi(r.URL.Query().Get("to"))
	if err1 != nil || err2 != nil || from < 1 || to < 1 {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "Укажите версии from и to."})
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	c, err := s.editor().Compare(r.Context(), id, from, to)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, c)
}

type rollbackInput struct {
	// Base is the current revision the admin compared with.
	Base     int `json:"base"`
	Revision int `json:"revision"`
}

// rollbackConfig queues the apply job that installs an earlier revision.
func (s *server) rollbackConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in rollbackInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Apply.Rollback(r.Context(), id, in.Base, in.Revision, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(configError(err)))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
