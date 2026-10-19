package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
)

// User management and the audit log (P4-03). Who may do what is decided
// by auth.Service; the routes only keep the roles without the users
// permission out early (need(model.PermUsers)).

// changePassword changes the caller's own password: every session of the
// user ends, and this browser gets a new one (cookie and CSRF token).
func (s *server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Current, Password string }
	if err := readJSON(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	is, err := s.Auth.ChangePassword(r.Context(), principal(r), req.Current, req.Password, s.meta(r))
	if err != nil {
		setRetryAfter(w, err)
		s.fail(w, r, mapError(err))
		return
	}
	s.setSessionCookie(w, r, is.Token, s.Auth.MaxAge)
	writeJSON(w, http.StatusOK, toSessionJSON(is.User, is.CSRF))
}

// roleJSON is a built-in role with its permissions (P4-04).
type roleJSON struct {
	Role        model.Role         `json:"role"`
	Permissions []model.Permission `json:"permissions"`
	// Unscoped: the role reaches every server whatever the scope.
	Unscoped bool `json:"unscoped"`
}

// listRoles is the built-in roles, the most powerful first: the user
// dialog shows what each one may do.
func (s *server) listRoles(w http.ResponseWriter, r *http.Request) {
	out := make([]roleJSON, 0, len(model.Roles))
	for _, role := range model.Roles {
		out = append(out, roleJSON{Role: role, Permissions: role.Permissions(), Unscoped: role.Unscoped()})
	}
	writeJSON(w, http.StatusOK, out)
}

// updateUser changes the role or the scope of a user, or blocks and
// unblocks it.
func (s *server) updateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var req struct {
		Role     *model.Role
		Scope    *model.Scope
		Disabled *bool
	}
	if err := readJSON(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.Auth.UpdateUser(r.Context(), principal(r), id, auth.UserChange{Role: req.Role, Scope: req.Scope, Disabled: req.Disabled})
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusOK, toUserJSON(u))
}

func (s *server) deleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if err := s.Auth.DeleteUser(r.Context(), principal(r), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resetPassword sets another user's password: the one sent, or with
// generate one made here and returned once.
func (s *server) resetPassword(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var req struct {
		Password string
		Generate bool
	}
	if err := readJSON(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Generate == (req.Password != "") {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Введите новый пароль или попросите панель создать его.", Details: "password"})
		return
	}
	gen, err := s.Auth.ResetPassword(r.Context(), principal(r), id, req.Password)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	if gen == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]string{"password": gen})
}

// transferOwner hands the caller's owner role to the user; the caller
// becomes an admin.
func (s *server) transferOwner(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	u, err := s.Auth.TransferOwner(r.Context(), principal(r), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusOK, toUserJSON(u))
}

type auditJSON struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	UserID int64     `json:"userId"`
	// User is the name of UserID ("" for none or a deleted user).
	User   string `json:"user"`
	Action string `json:"action"`
	Target string `json:"target"`
	// Object names the target when it is a server, cascade, preset or
	// user that still exists.
	Object  string `json:"object"`
	Details string `json:"details"`
}

// auditPage bounds a page of the audit listing.
const auditPage = 200

// listAudit pages the audit log, newest first: filters user (ID), action
// (one or several, comma-separated), target ("server/3", or "server/"
// for every server), from and to (RFC 3339, to exclusive); before is the
// cursor (next of the previous page).
func (s *server) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := model.AuditFilter{UserID: queryInt(r, "user"), Target: strings.TrimSpace(q.Get("target")), BeforeID: queryInt(r, "before")}
	for _, a := range strings.Split(q.Get("action"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			f.Actions = append(f.Actions, a)
		}
	}
	for k, t := range map[string]*time.Time{"from": &f.From, "to": &f.To} {
		if v := q.Get(k); v != "" {
			p, err := time.Parse(time.RFC3339, v)
			if err != nil {
				writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Неверная дата периода.", Details: k})
				return
			}
			*t = p
		}
	}
	limit := int(queryInt(r, "limit"))
	if limit <= 0 || limit > auditPage {
		limit = 100
	}
	// One more than asked tells whether there is a next page.
	f.Limit = limit + 1
	es, err := s.Auth.AuditEntries(r.Context(), principal(r), f)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	var next int64
	if len(es) > limit {
		es = es[:limit]
		next = es[limit-1].ID
	}
	names, err := s.auditNames(r.Context(), es)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]auditJSON, 0, len(es))
	for _, e := range es {
		user := ""
		if e.UserID != 0 {
			user = names["user/"+strconv.FormatInt(e.UserID, 10)]
		}
		// The writers keep secrets out of the audit log; redact is the
		// second line.
		out = append(out, auditJSON{ID: e.ID, Time: e.Time, UserID: e.UserID, User: user, Action: e.Action,
			Target: redact.String(e.Target), Object: names[e.Target], Details: redact.String(e.Details)})
	}
	writeJSON(w, http.StatusOK, struct {
		Entries []auditJSON `json:"entries"`
		// Next is the before of the next page; 0: this is the last.
		Next int64 `json:"next"`
	}{out, next})
}

// auditNames names the users, servers, cascades and presets of es by
// their targets ("server/3"): those of the kinds es mention.
func (s *server) auditNames(ctx context.Context, es []model.AuditEntry) (map[string]string, error) {
	kinds := map[string]bool{}
	for _, e := range es {
		k, _, _ := strings.Cut(e.Target, "/")
		kinds[k] = true
	}
	names := map[string]string{}
	key := func(kind string, id int64) string { return kind + "/" + strconv.FormatInt(id, 10) }
	us, err := s.Store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	for _, u := range us {
		names[key("user", u.ID)] = u.Username
	}
	if kinds["server"] {
		ss, err := s.Store.ListServers(ctx)
		if err != nil {
			return nil, err
		}
		for _, x := range ss {
			names[key("server", x.ID)] = x.Name
		}
	}
	if kinds["chain"] {
		cs, err := s.Store.ListChains(ctx)
		if err != nil {
			return nil, err
		}
		for _, x := range cs {
			names[key("chain", x.ID)] = x.Name
		}
	}
	if kinds["preset"] {
		ps, err := s.Store.ListPresets(ctx)
		if err != nil {
			return nil, err
		}
		for _, x := range ps {
			names[key("preset", x.ID)] = x.Name
		}
	}
	return names, nil
}
