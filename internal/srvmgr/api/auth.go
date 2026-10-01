package api

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// cookieName holds the session token.
const cookieName = "hyroute_session"

type ctxKey int

const principalKey ctxKey = 1

func principal(r *http.Request) auth.Principal {
	p, _ := r.Context().Value(principalKey).(auth.Principal)
	return p
}

var (
	errUnauthorized = &Error{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "Войдите заново: сессия закончилась или не найдена."}
	errForbidden    = &Error{Status: http.StatusForbidden, Code: "forbidden", Message: "Для этого действия не хватает прав."}
	errCSRF         = &Error{Status: http.StatusForbidden, Code: "csrf", Message: "Запрос отклонён защитой от подделки. Обновите страницу и повторите."}
	errBadJSON      = &Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "Некорректный запрос."}
)

// busyRetry is the Retry-After of auth.ErrBusy: a password check takes a
// fraction of a second, so a slot frees up soon.
const busyRetry = 2

// mapError maps service errors (auth, field validation, not found) to API
// errors; anything else stays an internal error.
func mapError(err error) error {
	var rl *auth.RateLimitedError
	var inv *model.FieldError
	switch {
	case errors.As(err, &rl):
		secs := int(rl.Wait.Round(time.Second) / time.Second)
		return &Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "Слишком много неудачных попыток. Повторите через " + strconv.Itoa(max(secs, 1)) + " с.", Details: "retry-after=" + strconv.Itoa(max(secs, 1))}
	case errors.Is(err, auth.ErrBusy):
		return &Error{Status: http.StatusServiceUnavailable, Code: "auth_busy", Message: "Сервер сейчас проверяет слишком много паролей сразу. Повторите через несколько секунд.", Details: "retry-after=" + strconv.Itoa(busyRetry)}
	case errors.As(err, &inv):
		return &Error{Status: http.StatusBadRequest, Code: "invalid", Message: inv.Msg, Details: inv.Field}
	case errors.Is(err, auth.ErrBadCredentials):
		return &Error{Status: http.StatusUnauthorized, Code: "bad_credentials", Message: "Неверное имя пользователя или пароль."}
	case errors.Is(err, auth.ErrUnauthenticated):
		return errUnauthorized
	case errors.Is(err, auth.ErrForbidden):
		return errForbidden
	case errors.Is(err, auth.ErrSetupDone):
		return &Error{Status: http.StatusConflict, Code: "setup_done", Message: "Администратор уже создан. Войдите под своим именем."}
	case errors.Is(err, auth.ErrBadSetupToken):
		return &Error{Status: http.StatusForbidden, Code: "bad_setup_token", Message: "Неверный код первого запуска. Он лежит в файле setup-token в каталоге данных hyroute-server."}
	case errors.Is(err, store.ErrNotFound):
		return errNotFound
	case errors.Is(err, store.ErrBusy):
		return &Error{Status: http.StatusConflict, Code: "server_busy", Message: "На сервере выполняется задание: пока оно не закончится, сервер нельзя удалить, а его адрес, пользователя и данные для входа — изменить (откату задания нужно подключение)."}
	case errors.Is(err, store.ErrInChain):
		return &Error{Status: http.StatusConflict, Code: "chain_member", Message: "Сервер входит в каскад: сначала удалите каскад (страница «Каскады»)."}
	}
	return remoteError(err)
}

// readJSON decodes a JSON body; only application/json is accepted, which
// also keeps plain HTML forms of other sites from posting here.
func readJSON(r *http.Request, v any) error {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		return &Error{Status: http.StatusUnsupportedMediaType, Code: "bad_content_type", Message: "Ожидается JSON."}
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		e := *errBadJSON
		e.Details = err.Error()
		return &e
	}
	return nil
}

// crossSite reports a request sent by another site: browsers mark them
// with Sec-Fetch-Site, and Origin (when present) must be this host.
func crossSite(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return true
	}
	if o := r.Header.Get("Origin"); o != "" {
		host := o
		if _, rest, ok := strings.Cut(o, "://"); ok {
			host = rest
		}
		if !strings.EqualFold(host, r.Host) {
			return true
		}
	}
	return false
}

func mutating(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// clientIP is the address of the client; X-Forwarded-For counts only from
// a trusted reverse proxy on this machine.
func (s *server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if s.TrustProxy && isLoopback(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	return host
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// secureRequest: the browser talks HTTPS to us or to our reverse proxy.
func (s *server) secureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return s.TrustProxy && isLoopback(host) && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(maxAge / time.Second),
		HttpOnly: true,
		Secure:   s.secureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureRequest(r), SameSite: http.SameSiteStrictMode})
}

func (s *server) meta(r *http.Request) auth.Meta {
	return auth.Meta{IP: s.clientIP(r), UserAgent: r.UserAgent()}
}

// public handlers work without a session; they still refuse cross-site
// writes.
func (s *server) public(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if mutating(r.Method) && crossSite(r) {
			writeError(w, errCSRF)
			return
		}
		h(w, r)
	}
}

// access is what a handler needs from the caller.
type access int

const (
	// anyRole: any logged-in user; writes still need CanWrite.
	anyRole access = iota
	// ownSession: any logged-in user, writes included (logout, revoking
	// one's own sessions: read-only users must be able to leave).
	ownSession
	// manageUsers: owners and admins.
	manageUsers
	// writers: roles that may change servers, reads included (the config
	// editor: masking is a second line, not the only one).
	writers
)

// authed wraps a handler that needs a session: 401 without one, CSRF check
// on writes, 403 for read-only users on writes.
func (s *server) authed(need access, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeError(w, errUnauthorized)
			return
		}
		p, err := s.Auth.Authenticate(r.Context(), c.Value)
		if err != nil {
			if errors.Is(err, auth.ErrUnauthenticated) {
				s.clearSessionCookie(w, r)
			}
			s.fail(w, r, mapError(err))
			return
		}
		if mutating(r.Method) {
			if crossSite(r) || !auth.CheckCSRF(p.Token, r.Header.Get("X-CSRF-Token")) {
				writeError(w, errCSRF)
				return
			}
			if need != ownSession && !p.User.Role.CanWrite() {
				writeError(w, errForbidden)
				return
			}
		}
		if need == writers && !p.User.Role.CanWrite() {
			writeError(w, errForbidden)
			return
		}
		if need == manageUsers && !p.User.Role.CanManageUsers() {
			writeError(w, errForbidden)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	}
}

type userJSON struct {
	ID        int64      `json:"id"`
	Username  string     `json:"username"`
	Role      model.Role `json:"role"`
	Disabled  bool       `json:"disabled"`
	CreatedAt time.Time  `json:"createdAt"`
}

func toUserJSON(u model.User) userJSON {
	return userJSON{ID: u.ID, Username: u.Username, Role: u.Role, Disabled: u.Disabled, CreatedAt: u.CreatedAt}
}

type sessionJSON struct {
	User      userJSON `json:"user"`
	CSRFToken string   `json:"csrfToken"`
}

func (s *server) getSetup(w http.ResponseWriter, r *http.Request) {
	need, err := s.Auth.SetupNeeded(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"needed": need})
}

func (s *server) postSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token, Username, Password string
	}
	if err := readJSON(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	is, err := s.Auth.Setup(r.Context(), req.Token, req.Username, req.Password, s.meta(r))
	if err != nil {
		setRetryAfter(w, err)
		s.fail(w, r, mapError(err))
		return
	}
	if s.OnSetupDone != nil {
		s.OnSetupDone()
	}
	s.setSessionCookie(w, r, is.Token, s.Auth.MaxAge)
	writeJSON(w, http.StatusCreated, sessionJSON{User: toUserJSON(is.User), CSRFToken: is.CSRF})
}

func (s *server) postSession(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := readJSON(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	is, err := s.Auth.Login(r.Context(), req.Username, req.Password, s.meta(r))
	if err != nil {
		setRetryAfter(w, err)
		s.fail(w, r, mapError(err))
		return
	}
	s.setSessionCookie(w, r, is.Token, s.Auth.MaxAge)
	writeJSON(w, http.StatusOK, sessionJSON{User: toUserJSON(is.User), CSRFToken: is.CSRF})
}

// setRetryAfter tells the client when to retry a refused login or setup.
func setRetryAfter(w http.ResponseWriter, err error) {
	var rl *auth.RateLimitedError
	switch {
	case errors.As(err, &rl):
		// Rounded up: retrying a moment early would be refused again.
		w.Header().Set("Retry-After", strconv.Itoa(max(int((rl.Wait+time.Second-1)/time.Second), 1)))
	case errors.Is(err, auth.ErrBusy):
		w.Header().Set("Retry-After", strconv.Itoa(busyRetry))
	}
}

func (s *server) getSession(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	writeJSON(w, http.StatusOK, sessionJSON{User: toUserJSON(p.User), CSRFToken: auth.CSRFToken(p.Token)})
}

func (s *server) deleteSession(w http.ResponseWriter, r *http.Request) {
	if err := s.Auth.Logout(r.Context(), principal(r)); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	s.clearSessionCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

type sessionInfoJSON struct {
	ID         int64     `json:"id"`
	UserID     int64     `json:"userId"`
	Current    bool      `json:"current"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"userAgent"`
}

func (s *server) listSessions(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	ss, err := s.Auth.Sessions(r.Context(), p, r.URL.Query().Get("all") == "1")
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	out := make([]sessionInfoJSON, 0, len(ss))
	for _, x := range ss {
		out = append(out, sessionInfoJSON{ID: x.ID, UserID: x.UserID, Current: x.ID == p.Session.ID, CreatedAt: x.CreatedAt, LastSeenAt: x.LastSeenAt, ExpiresAt: x.ExpiresAt, IP: x.IP, UserAgent: x.UserAgent})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) revokeSession(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, errNotFound)
		return
	}
	if err := s.Auth.RevokeSession(r.Context(), principal(r), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := s.Auth.Users(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]userJSON, 0, len(us))
	for _, u := range us {
		out = append(out, toUserJSON(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username, Password string
		Role               model.Role
	}
	if err := readJSON(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.Auth.CreateUser(r.Context(), principal(r), req.Username, req.Password, req.Role)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusCreated, toUserJSON(u))
}
