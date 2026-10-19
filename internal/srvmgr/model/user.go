// Package model holds the domain entities of the server manager. It has no
// dependencies: storage, services and the API all speak these types.
package model

import "time"

// Role is a named set of permissions (see Permissions, P4-04); there are
// no custom roles.
type Role string

const (
	RoleOwner    Role = "owner"
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	// RoleClients (менеджер клиентов): the client users and links of the
	// servers in scope, nothing else of their configs.
	RoleClients  Role = "clients"
	RoleReadOnly Role = "readonly"
)

// Roles are the built-in roles, the most powerful first.
var Roles = []Role{RoleOwner, RoleAdmin, RoleOperator, RoleClients, RoleReadOnly}

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	_, ok := rolePerms[r]
	return ok
}

// CanManageUsers: may create, change and delete users and revoke other
// users' sessions (an owner only by an owner: auth.Service holds the rules).
func (r Role) CanManageUsers() bool { return r.Can(PermUsers) }

// CanForce: may remove what HyRoute cannot take off a server that does not
// answer (a cascade deleted without its unreachable server).
func (r Role) CanForce() bool { return r == RoleOwner || r == RoleAdmin }

// CanBackup: may make and download copies of the database; a copy holds
// every user's password hash and every server.
func (r Role) CanBackup() bool { return r == RoleOwner }

// CanCheckKey: may try a copy of the master key against the database.
func (r Role) CanCheckKey() bool { return r.Can(PermSettings) }

// CanDiagnose: may download the diagnostic bundle (the state, logs and
// config summaries of every server, pseudonymized).
func (r Role) CanDiagnose() bool { return r.Can(PermSettings) }

// User is an admin account. PasswordHash is a PHC argon2id string.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         Role
	// Scope: the servers the user's server-bound permissions reach; Reach
	// is what holds for the role.
	Scope     Scope
	Disabled  bool
	CreatedAt time.Time
	UpdatedAt time.Time
	// LastLoginAt is the newest login (zero: none known).
	LastLoginAt time.Time
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

// AuditFilter selects audit entries, newest first; zero fields match all.
type AuditFilter struct {
	UserID int64
	// Actions: any of them.
	Actions []string
	// Target: this target ("server/3"); ending in "/", any target of that
	// kind ("server/").
	Target string
	// From <= Time < To.
	From, To time.Time
	// BeforeID pages: entries older than this one.
	BeforeID int64
	Limit    int
}

// FieldError: an input field does not pass validation. Msg is for people
// (Russian, shown next to the field as is).
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }
