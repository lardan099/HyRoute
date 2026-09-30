package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

var errNoInstallation = &Error{Status: http.StatusConflict, Code: "no_installation", Message: "HyRoute не знает, где на этом сервере Hysteria: разверните её или импортируйте сервер."}

// statusTimeout bounds a status read (connect and a dozen commands).
var statusTimeout = 30 * time.Second

// installed is the server's recorded installation, for handlers that act
// on it; a server without a confirmed host key or an installation gets
// the error that says what to do.
func (s *server) installed(r *http.Request, id int64) (model.Installation, error) {
	srv, err := s.Servers.Get(r.Context(), id)
	if err != nil {
		return model.Installation{}, mapError(err)
	}
	in, err := s.Store.Installation(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return in, errNoInstallation
	} else if err != nil {
		return in, err
	}
	if srv.HostKey == nil {
		return in, errHostKeyRequired
	}
	return in, nil
}

func (s *server) serviceStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	in, err := s.installed(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), statusTimeout)
	defer cancel()
	ex, err := s.Connect.Connect(ctx, id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	defer ex.Close()
	ro := remote.ReadOnly(ex)
	p, err := remote.RunProbe(ctx, ro)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	st, err := service.Read(ctx, ro, in, !p.Root, time.Now())
	var nie *service.NotInstalledError
	if errors.As(err, &nie) {
		writeError(w, &Error{Status: http.StatusConflict, Code: "service_missing", Message: nie.Error()})
		return
	} else if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *server) serviceAction(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	a := remote.ServiceAction(r.PathValue("action"))
	switch a {
	case remote.ServiceStart, remote.ServiceStop, remote.ServiceRestart:
	default:
		writeError(w, errNotFound)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Jobs.Submit(r.Context(), service.JobKind, id, service.Params{Action: a}, nil, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
