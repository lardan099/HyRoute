// Package auth handles admin accounts of the server manager: first-run
// setup with a one-time token, argon2id passwords, sessions stored by the
// hash of their token, CSRF tokens derived from the session token, login
// rate limiting and roles.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Errors of the service; the API maps them to codes and statuses.
var (
	ErrBadCredentials  = errors.New("wrong username or password")
	ErrUnauthenticated = errors.New("no valid session")
	ErrForbidden       = errors.New("not allowed for this role")
	ErrSetupDone       = errors.New("setup already done")
	ErrBadSetupToken   = errors.New("wrong setup token")
	// ErrBusy: all hashing slots are taken (see MaxHashing); the client
	// retries in a moment. The attempt is not counted as failed.
	ErrBusy = errors.New("too many password checks at once")
)

// MaxHashing bounds the argon2id runs at a time: each takes Params.Memory
// (64 MiB by default), and a flood of logins must not take the memory of
// the machine. Logins and setup beyond it get ErrBusy at once instead of
// queueing, logged-in users creating accounts wait for a slot.
const MaxHashing = 3

// RateLimitedError: too many failed attempts; retry after Wait.
type RateLimitedError struct{ Wait time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("too many failed attempts, retry in %s", e.Wait.Round(time.Second))
}

// Store is what the service needs from storage.
type Store interface {
	store.Users
	store.Sessions
	store.Audit
}

// Meta describes the client of a request.
type Meta struct {
	IP        string
	UserAgent string
}

// Principal is the authenticated user of a request.
type Principal struct {
	User    model.User
	Session model.Session
	// Token is the session token from the cookie (for the CSRF token).
	Token string
}

// Issued is a new session: Token goes into the cookie, CSRF to the page.
type Issued struct {
	Token   string
	CSRF    string
	User    model.User
	Session model.Session
}

// Service is the authentication service.
type Service struct {
	Store  Store
	Params Params
	Now    func() time.Time
	// IdleTimeout ends a session not used for this long; MaxAge ends it
	// regardless.
	IdleTimeout time.Duration
	MaxAge      time.Duration

	limits   *guard
	slots    chan struct{} // one per argon2id run in progress
	failures atomic.Int64  // failed attempts audited (see auditFailure)

	mu        sync.Mutex
	setupHash []byte        // SHA-256 of the one-time setup token, nil if none
	dummy     string        // hash verified for unknown users (same timing)
	ended     chan struct{} // closed when sessions end (see Revocations)
}

// New returns a service with the default parameters.
func New(st Store) *Service {
	return &Service{
		Store:       st,
		Params:      DefaultParams,
		Now:         time.Now,
		IdleTimeout: 12 * time.Hour,
		MaxAge:      7 * 24 * time.Hour,
		limits:      newGuard(),
		slots:       make(chan struct{}, MaxHashing),
	}
}

// hashSlot takes one of the MaxHashing slots for argon2id. Without wait it
// fails at once with ErrBusy: an unauthenticated flood gets a quick answer,
// not a queue that holds its requests open.
func (s *Service) hashSlot(ctx context.Context, wait bool) (release func(), err error) {
	release = func() { <-s.slots }
	select {
	case s.slots <- struct{}{}:
		return release, nil
	default:
	}
	if !wait {
		return nil, ErrBusy
	}
	select {
	case s.slots <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// CSRFToken is derived from the session token: the page gets it from the
// API, a cross-site attacker cannot read the HttpOnly cookie to compute it.
func CSRFToken(sessionToken string) string {
	m := hmac.New(sha256.New, []byte(sessionToken))
	m.Write([]byte("hyroute-server csrf v1"))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// CheckCSRF compares the header value with the token of the session.
func CheckCSRF(sessionToken, header string) bool {
	return header != "" && subtle.ConstantTimeCompare([]byte(CSRFToken(sessionToken)), []byte(header)) == 1
}

// SetupNeeded reports whether no user exists yet.
func (s *Service) SetupNeeded(ctx context.Context) (bool, error) {
	n, err := s.Store.CountUsers(ctx)
	return n == 0, err
}

// PrepareSetup creates the one-time setup token when there are no users
// (the caller shows it in the log and writes it to a 0600 file); it
// returns "" when setup is done.
func (s *Service) PrepareSetup(ctx context.Context) (string, error) {
	need, err := s.SetupNeeded(ctx)
	if err != nil || !need {
		return "", err
	}
	tok, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.setupHash = tokenHash(tok)
	s.mu.Unlock()
	return tok, nil
}

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// MinPasswordLen and MaxPasswordLen bound passwords (the upper bound keeps
// hashing cheap for an attacker's huge inputs).
const (
	MinPasswordLen = 10
	MaxPasswordLen = 1024
)

func validateCredentials(username, password string) error {
	if !usernameRe.MatchString(username) {
		return &model.FieldError{Field: "username", Msg: "Имя пользователя: от 1 до 64 символов, латинские буквы, цифры, точка, дефис и подчёркивание."}
	}
	return validatePassword(password)
}

func validatePassword(password string) error {
	if n := utf8.RuneCountInString(password); n < MinPasswordLen || len(password) > MaxPasswordLen {
		return &model.FieldError{Field: "password", Msg: fmt.Sprintf("Пароль: не короче %d символов.", MinPasswordLen)}
	}
	return nil
}

// Setup creates the owner with the setup token and logs them in.
func (s *Service) Setup(ctx context.Context, token, username, password string, m Meta) (Issued, error) {
	a, err := s.limits.reserve(s.Now, "", addrKey(m.IP))
	if err != nil {
		return Issued{}, err
	}
	now := a.at
	s.mu.Lock()
	want := s.setupHash
	s.mu.Unlock()
	if want == nil {
		s.limits.cancel(a)
		if need, err := s.SetupNeeded(ctx); err != nil {
			return Issued{}, err
		} else if !need {
			return Issued{}, ErrSetupDone
		}
		return Issued{}, ErrBadSetupToken
	}
	if subtle.ConstantTimeCompare(tokenHash(strings.TrimSpace(token)), want) != 1 {
		// The reserved attempt stays as the failure.
		s.auditFailure(ctx, "setup_failed", "", "wrong setup token from "+m.IP)
		return Issued{}, ErrBadSetupToken
	}
	s.limits.succeeded(a)
	if err := validateCredentials(username, password); err != nil {
		return Issued{}, err
	}
	release, err := s.hashSlot(ctx, false)
	if err != nil {
		return Issued{}, err
	}
	hash, err := HashPassword(password, s.Params)
	release()
	if err != nil {
		return Issued{}, err
	}
	u := model.User{Username: username, PasswordHash: hash, Role: model.RoleOwner, CreatedAt: now, UpdatedAt: now, LastLoginAt: now}
	if err := s.Store.CreateFirstUser(ctx, &u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return Issued{}, ErrSetupDone
		}
		return Issued{}, err
	}
	s.mu.Lock()
	s.setupHash = nil
	s.mu.Unlock()
	s.audit(ctx, u.ID, "setup", u.Username, "owner created")
	return s.issue(ctx, u, m, now)
}

// SetupDone reports whether the setup token was used (the caller removes
// the token file).
func (s *Service) SetupDone() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setupHash == nil
}

// Login checks the password and opens a session. The attempt is reserved
// in the rate limit before the password is hashed (see guard), and the
// hashing takes a slot (see MaxHashing).
func (s *Service) Login(ctx context.Context, username, password string, m Meta) (Issued, error) {
	if len(password) > MaxPasswordLen || len(username) > 64 {
		return Issued{}, ErrBadCredentials
	}
	a, err := s.limits.reserve(s.Now, strings.ToLower(username), addrKey(m.IP))
	if err != nil {
		// Not audited: a flood of attempts must not fill the database.
		return Issued{}, err
	}
	now := a.at
	u, err := s.Store.UserByName(ctx, username)
	found := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.limits.cancel(a)
		return Issued{}, err
	}
	release, err := s.hashSlot(ctx, false)
	if err != nil {
		s.limits.cancel(a)
		return Issued{}, err
	}
	hash := u.PasswordHash
	if !found {
		hash = s.dummyHash()
	}
	ok, stale, verr := VerifyPassword(hash, password, s.Params)
	ok = ok && found && verr == nil && !u.Disabled
	fresh := ""
	if ok && stale {
		fresh, _ = HashPassword(password, s.Params)
	}
	release()
	if !ok {
		// The reserved attempt stays as the failure.
		s.auditFailure(ctx, "login_failed", username, "from "+m.IP)
		return Issued{}, ErrBadCredentials
	}
	s.limits.succeeded(a)
	if fresh != "" {
		s.Store.UpdatePasswordHash(ctx, u.ID, fresh, now)
	}
	if s.Store.SetLastLogin(ctx, u.ID, now) == nil {
		u.LastLoginAt = now
	}
	s.audit(ctx, u.ID, "login", u.Username, "from "+m.IP)
	return s.issue(ctx, u, m, now)
}

// dummyHash is a real hash with the current parameters, so a login with an
// unknown name takes as long as with a known one. The caller holds a
// hashing slot.
func (s *Service) dummyHash() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dummy == "" {
		s.dummy, _ = HashPassword("not a password of anybody", s.Params)
	}
	return s.dummy
}

func (s *Service) issue(ctx context.Context, u model.User, m Meta, now time.Time) (Issued, error) {
	tok, err := randomToken()
	if err != nil {
		return Issued{}, err
	}
	ua := m.UserAgent
	if len(ua) > 256 {
		ua = ua[:256]
	}
	sess := model.Session{TokenHash: tokenHash(tok), UserID: u.ID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(s.MaxAge), IP: m.IP, UserAgent: ua}
	if err := s.Store.CreateSession(ctx, &sess); err != nil {
		return Issued{}, err
	}
	return Issued{Token: tok, CSRF: CSRFToken(tok), User: u, Session: sess}, nil
}

// touchEvery limits last-seen writes to one per minute per session.
const touchEvery = time.Minute

// Authenticate resolves a session token to its user.
func (s *Service) Authenticate(ctx context.Context, token string) (Principal, error) {
	return s.authenticate(ctx, token, true)
}

// Recheck tells a long request (an event stream) whether its session still
// holds: ErrUnauthenticated after a logout, a revocation, the end of the
// session or a disabled user. It is not activity of the session: an open
// stream does not keep an idle session alive.
func (s *Service) Recheck(ctx context.Context, token string) error {
	_, err := s.authenticate(ctx, token, false)
	return err
}

func (s *Service) authenticate(ctx context.Context, token string, touch bool) (Principal, error) {
	if token == "" || len(token) > 128 {
		return Principal{}, ErrUnauthenticated
	}
	sess, err := s.Store.SessionByTokenHash(ctx, tokenHash(token))
	if errors.Is(err, store.ErrNotFound) {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, err
	}
	now := s.Now()
	if !sess.RevokedAt.IsZero() || !now.Before(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > s.IdleTimeout {
		return Principal{}, ErrUnauthenticated
	}
	u, err := s.Store.UserByID(ctx, sess.UserID)
	if errors.Is(err, store.ErrNotFound) || u.Disabled {
		return Principal{}, ErrUnauthenticated
	}
	if err != nil {
		return Principal{}, err
	}
	if touch && now.Sub(sess.LastSeenAt) >= touchEvery {
		if err := s.Store.TouchSession(ctx, sess.ID, now); err == nil {
			sess.LastSeenAt = now
		}
	}
	return Principal{User: u, Session: sess, Token: token}, nil
}

// Logout revokes the session of p.
func (s *Service) Logout(ctx context.Context, p Principal) error {
	s.audit(ctx, p.User.ID, "logout", p.User.Username, "")
	err := s.Store.RevokeSession(ctx, p.Session.ID, s.Now())
	s.sessionsEnded()
	return err
}

// Revocations returns a channel closed when sessions end next: a logout, a
// revoked session, a changed password, a blocked or deleted user. A live
// event stream then rechecks its session at once instead of at its next
// keepalive. Take the next channel before rechecking, so sessions that
// end meanwhile are not missed.
func (s *Service) Revocations() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended == nil {
		s.ended = make(chan struct{})
	}
	return s.ended
}

// sessionsEnded wakes the waiters of Revocations; the sessions are already
// ended in the store.
func (s *Service) sessionsEnded() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended != nil {
		close(s.ended)
		s.ended = nil
	}
}

// Sessions lists live sessions: all of them for owners and admins when all
// is set, otherwise those of p.
func (s *Service) Sessions(ctx context.Context, p Principal, all bool) ([]model.Session, error) {
	uid := p.User.ID
	if all {
		if !p.User.Role.CanManageUsers() {
			return nil, ErrForbidden
		}
		uid = 0
	}
	now := s.Now()
	ss, err := s.Store.ListSessions(ctx, uid, now)
	if err != nil {
		return nil, err
	}
	// Idle sessions are dead for Authenticate, so they are not listed.
	live := ss[:0]
	for _, x := range ss {
		if now.Sub(x.LastSeenAt) <= s.IdleTimeout {
			live = append(live, x)
		}
	}
	return live, nil
}

// RevokeSession ends a session: one's own, or that of a user p manages
// (see mayManage: an owner's only for an owner).
func (s *Service) RevokeSession(ctx context.Context, p Principal, id int64) error {
	sess, err := s.Store.SessionByID(ctx, id)
	if err != nil {
		return err
	}
	if sess.UserID != p.User.ID {
		if !p.User.Role.CanManageUsers() {
			return ErrForbidden
		}
		u, err := s.Store.UserByID(ctx, sess.UserID)
		if err != nil {
			return err
		}
		if err := mayManage(p.User, u); err != nil {
			return err
		}
	}
	s.audit(ctx, p.User.ID, "session_revoked", userTarget(sess.UserID), fmt.Sprint("session ", id))
	err = s.Store.RevokeSession(ctx, id, s.Now())
	s.sessionsEnded()
	return err
}

// CreateUser adds an admin, operator or read-only user; only owners and
// admins may. An owner is made of an existing user (UpdateUser,
// TransferOwner), not created.
func (s *Service) CreateUser(ctx context.Context, p Principal, username, password string, role model.Role) (model.User, error) {
	if !p.User.Role.CanManageUsers() {
		return model.User{}, ErrForbidden
	}
	if !role.Valid() || role == model.RoleOwner {
		return model.User{}, &model.FieldError{Field: "role", Msg: "Роль: admin, operator или readonly."}
	}
	if err := validateCredentials(username, password); err != nil {
		return model.User{}, err
	}
	release, err := s.hashSlot(ctx, true)
	if err != nil {
		return model.User{}, err
	}
	hash, err := HashPassword(password, s.Params)
	release()
	if err != nil {
		return model.User{}, err
	}
	now := s.Now()
	u := model.User{Username: username, PasswordHash: hash, Role: role, CreatedAt: now, UpdatedAt: now}
	if err := s.Store.CreateUser(ctx, &u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return model.User{}, &model.FieldError{Field: "username", Msg: "Пользователь с таким именем уже есть."}
		}
		return model.User{}, err
	}
	s.audit(ctx, p.User.ID, "user_created", userTarget(u.ID), u.Username+": "+string(role))
	return u, nil
}

// Users lists accounts (any logged-in user may see who has access).
func (s *Service) Users(ctx context.Context) ([]model.User, error) {
	return s.Store.ListUsers(ctx)
}

// Cleanup deletes sessions that ended more than a day ago and the failed
// attempts beyond the newest maxFailures.
func (s *Service) Cleanup(ctx context.Context) error {
	if err := s.Store.DeleteSessionsBefore(ctx, s.Now().Add(-24*time.Hour)); err != nil {
		return err
	}
	return s.Store.TrimAudit(ctx, failureActions, maxFailures)
}

func (s *Service) audit(ctx context.Context, uid int64, action, target, details string) {
	s.Store.AddAudit(ctx, model.AuditEntry{Time: s.Now(), UserID: uid, Action: action, Target: target, Details: details})
}

// Failed logins and setup attempts come from anyone who reaches the admin,
// from any number of addresses: the audit log keeps the newest maxFailures
// of them, trimmed every trimFailures, so a flood does not fill the disk.
// Everything else stays.
var (
	maxFailures    = 10000
	trimFailures   = int64(1000)
	failureActions = []string{"login_failed", "setup_failed"}
)

func (s *Service) auditFailure(ctx context.Context, action, target, details string) {
	s.audit(ctx, 0, action, target, details)
	if s.failures.Add(1)%trimFailures == 0 {
		s.Store.TrimAudit(ctx, failureActions, maxFailures)
	}
}
