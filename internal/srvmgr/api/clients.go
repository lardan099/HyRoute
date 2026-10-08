package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// The client manager (P4-04): the users of a server's auth.userpass are
// added, removed and given new passwords, each an ordinary apply job
// whose candidate differs from the current config in those users only
// (apply.Applier.Clients). The list is the client summary
// (GET /servers/{id}/client), the links come from client/reveal.

// clientsInput: the revision the caller looked at and the user.
type clientsInput struct {
	Base int    `json:"base"`
	User string `json:"user"`
}

// clientsJSON is a queued change of the client users; Password is the
// generated one of an added user or a new password, shown once.
type clientsJSON struct {
	Job      jobJSON `json:"job"`
	User     string  `json:"user"`
	Password string  `json:"password,omitempty"`
}

func (s *server) addClient(w http.ResponseWriter, r *http.Request) {
	s.changeClient(w, r, apply.ClientAdd, "client.add")
}

func (s *server) removeClient(w http.ResponseWriter, r *http.Request) {
	s.changeClient(w, r, apply.ClientRemove, "client.remove")
}

func (s *server) clientPassword(w http.ResponseWriter, r *http.Request) {
	s.changeClient(w, r, apply.ClientPassword, "client.password")
}

// changeClient queues the apply job of op on the user of the body and
// audits it (the user's name, never the password).
func (s *server) changeClient(w http.ResponseWriter, r *http.Request, op, action string) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in clientsInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	in.User = strings.TrimSpace(in.User)
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	links, err := s.linkUsers(r, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	j, password, err := s.Apply.Clients(r.Context(), id, in.Base, apply.ClientOp{Op: op, User: in.User, Links: links}, principal(r).User.ID)
	switch {
	case errors.Is(err, apply.ErrNotUserPass):
		writeError(w, &Error{Status: http.StatusConflict, Code: "not_userpass", Message: "Клиенты этого сервера входят по общему паролю или через внешний сервис: отдельных пользователей у него нет. Перевести сервер на пользователей (auth: userpass) может тот, кто меняет конфиг."})
		return
	case errors.Is(err, apply.ErrLinkUser):
		writeError(w, &Error{Status: http.StatusConflict, Code: "link_user", Message: "Это пользователь связи каскада: им управляет каскад, а не менеджер клиентов."})
		return
	case err != nil:
		s.fail(w, r, jobError(configError(err)))
		return
	}
	details := "user=" + in.User + " job=" + strconv.FormatInt(j.ID, 10)
	if err := s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: principal(r).User.ID, Action: action, Target: "server/" + strconv.FormatInt(id, 10), Details: details}); err != nil {
		s.Log.Error("audit: "+action, "server", id, "err", err)
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusAccepted, clientsJSON{Job: toJobJSON(j), User: in.User, Password: password})
}
