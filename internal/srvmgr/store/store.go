// Package store holds the repository interfaces of the server manager.
// Business logic depends on these interfaces only; store/sqlite implements
// them. Repositories are added by the features that need them.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

var (
	// ErrNotFound: no row with this key.
	ErrNotFound = errors.New("not found")
	// ErrConflict: a unique key or a state precondition does not hold.
	ErrConflict = errors.New("conflict")
)

// Store is the whole persistent state of the controller.
type Store interface {
	// SchemaVersion is the newest applied migration.
	SchemaVersion(ctx context.Context) (int, error)
	Users
	Sessions
	Audit
	Close() error
}

// Users stores admin accounts. Usernames are unique case-insensitively.
type Users interface {
	CountUsers(ctx context.Context) (int, error)
	// CreateUser sets u.ID; ErrConflict if the name is taken.
	CreateUser(ctx context.Context, u *model.User) error
	// CreateFirstUser is CreateUser that succeeds only while there are no
	// users at all (ErrConflict otherwise), atomically.
	CreateFirstUser(ctx context.Context, u *model.User) error
	UserByID(ctx context.Context, id int64) (model.User, error)
	UserByName(ctx context.Context, username string) (model.User, error)
	ListUsers(ctx context.Context) ([]model.User, error)
	// UpdatePasswordHash replaces the hash (rehash with new parameters).
	UpdatePasswordHash(ctx context.Context, id int64, hash string, at time.Time) error
	SetUserDisabled(ctx context.Context, id int64, disabled bool, at time.Time) error
}

// Sessions stores logins by the hash of their token.
type Sessions interface {
	// CreateSession sets s.ID.
	CreateSession(ctx context.Context, s *model.Session) error
	SessionByTokenHash(ctx context.Context, hash []byte) (model.Session, error)
	SessionByID(ctx context.Context, id int64) (model.Session, error)
	TouchSession(ctx context.Context, id int64, at time.Time) error
	// RevokeSession marks the session revoked; revoking twice is no error.
	RevokeSession(ctx context.Context, id int64, at time.Time) error
	// ListSessions returns live (not revoked, not expired at now)
	// sessions of the user, or of everyone when userID is 0.
	ListSessions(ctx context.Context, userID int64, now time.Time) ([]model.Session, error)
	// DeleteSessionsBefore removes sessions that expired or were revoked
	// before t.
	DeleteSessionsBefore(ctx context.Context, t time.Time) error
}

// Audit appends to the audit log.
type Audit interface {
	AddAudit(ctx context.Context, e model.AuditEntry) error
	// ListAudit returns the newest entries first.
	ListAudit(ctx context.Context, limit int) ([]model.AuditEntry, error)
}
