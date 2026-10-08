// Package model holds the domain entities of the server manager. It has no
// dependencies: storage, services and the API all speak these types.
package model

import "time"

// Role is what a user may do. Phase 1 enforces only that ReadOnly cannot
// change anything and that user management needs Owner or Admin.
type Role string

const (
	RoleOwner    Role = "owner"
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleReadOnly Role = "readonly"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleOperator, RoleReadOnly:
		return true
	}
	return false
}

// CanWrite: may change servers, jobs and configs.
func (r Role) CanWrite() bool { return r.Valid() && r != RoleReadOnly }

// CanManageUsers: may create users and revoke other users' sessions.
func (r Role) CanManageUsers() bool { return r == RoleOwner || r == RoleAdmin }

// CanForce: may remove what HyRoute cannot take off a server that does not
// answer (a cascade deleted without its unreachable server).
func (r Role) CanForce() bool { return r == RoleOwner || r == RoleAdmin }

// CanBackup: may make and download copies of the database; a copy holds
// every user's password hash and every server.
func (r Role) CanBackup() bool { return r == RoleOwner }

// CanCheckKey: may try a copy of the master key against the database.
func (r Role) CanCheckKey() bool { return r == RoleOwner || r == RoleAdmin }

// User is an admin account. PasswordHash is a PHC argon2id string.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         Role
	Disabled     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Session is a login. Only the SHA-256 of its token is stored.
type Session struct {
	ID         int64
	TokenHash  []byte
	UserID     int64
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time // zero: not revoked
	IP         string
	UserAgent  string
}

// AuditEntry records who did what.
type AuditEntry struct {
	ID      int64
	Time    time.Time
	UserID  int64 // 0: nobody logged in (failed login, setup)
	Action  string
	Target  string
	Details string
}

// FieldError: an input field does not pass validation. Msg is for people
// (Russian, shown next to the field as is).
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }
