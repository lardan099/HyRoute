package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/profile"
)

// clientProfile is the client side of a server: without ?reveal=1 the
// summary (no secrets, anyone); with it the links, config and QR codes
// (operator and up, written to the audit log). ?user= picks the userpass
// user.
func (s *server) clientProfile(w http.ResponseWriter, r *http.Request) {
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
	cur, cfg, err := s.editor().Current(r.Context(), id)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	srv := model.Server{ID: in.ID, Name: in.Name, Host: in.Host}
	if r.URL.Query().Get("reveal") != "1" {
		sum, err := profile.Summarize(srv, cfg, cur.Meta)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, sum)
		return
	}
	p := principal(r)
	if !p.User.Role.CanWrite() {
		writeError(w, errForbidden)
		return
	}
	user := r.URL.Query().Get("user")
	pr, err := profile.Build(srv, cfg, cur.Meta, user)
	switch {
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
	if err := s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: p.User.ID, Action: "client.reveal", Target: "server/" + strconv.FormatInt(id, 10), Details: details}); err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, pr)
}
