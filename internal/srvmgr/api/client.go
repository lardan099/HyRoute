package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/profile"
)

// linkUsers are the users of the cascade links into server id: the
// entry's logins on a userpass exit, no client's.
func (s *server) linkUsers(r *http.Request, id int64) ([]string, error) {
	cs, err := s.Store.ListChains(r.Context())
	if err != nil {
		return nil, err
	}
	return cascade.Users(cs, id), nil
}

// clientSource loads what the client profile is built from.
func (s *server) clientSource(w http.ResponseWriter, r *http.Request) (int64, model.Server, model.ServerConfig, []byte, bool) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return 0, model.Server{}, model.ServerConfig{}, nil, false
	}
	in, err := s.Servers.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return 0, model.Server{}, model.ServerConfig{}, nil, false
	}
	cur, cfg, err := s.editor().Current(r.Context(), id)
	if err != nil {
		s.fail(w, r, configError(err))
		return 0, model.Server{}, model.ServerConfig{}, nil, false
	}
	return id, in.Server, cur, cfg, true
}

// clientProfile is the summary of the client side of a server: no
// secrets, anyone may see it.
func (s *server) clientProfile(w http.ResponseWriter, r *http.Request) {
	id, srv, cur, cfg, ok := s.clientSource(w, r)
	if !ok {
		return
	}
	links, err := s.linkUsers(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sum, err := profile.Summarize(srv, cfg, cur.Meta, links)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

type revealInput struct {
	// User picks the userpass user (may be empty when there is one).
	User string `json:"user"`
}

// revealClient answers the links, the client config and the QR codes with
// their passwords: a POST (CSRF-checked, operator and up, never cached),
// written to the audit log.
func (s *server) revealClient(w http.ResponseWriter, r *http.Request) {
	var in revealInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	id, srv, cur, cfg, ok := s.clientSource(w, r)
	if !ok {
		return
	}
	links, err := s.linkUsers(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pr, err := profile.Build(srv, cfg, cur.Meta, in.User, links)
	switch {
	case errors.Is(err, profile.ErrLinkUser):
		writeError(w, &Error{Status: http.StatusConflict, Code: "link_user", Message: "Это пользователь связи каскада: по нему к серверу подключается вход каскада, ссылку для клиента на него HyRoute не выдаёт. Выберите пользователя-клиента."})
		return
	case errors.Is(err, profile.ErrExternalAuth):
		writeError(w, &Error{Status: http.StatusConflict, Code: "external_auth", Message: "Пароли клиентов этого сервера проверяет внешний сервис: HyRoute их не знает, ссылку нельзя составить."})
		return
	case err != nil:
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Ссылку не составить: " + err.Error() + ".", Details: "user"})
		return
	}
	details := "revision=" + strconv.Itoa(cur.Revision)
	if pr.User != "" {
		details += " user=" + pr.User
	}
	p := principal(r)
	if err := s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: p.User.ID, Action: "client.reveal", Target: "server/" + strconv.FormatInt(id, 10), Details: details}); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, pr)
}
