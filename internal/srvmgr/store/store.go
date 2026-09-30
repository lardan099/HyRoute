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
	Servers
	HostKeys
	Jobs
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

// SealFunc seals the credentials of a server once its ID is known; it runs
// inside the transaction that creates or updates the server.
type SealFunc func(serverID int64) ([]model.Credential, error)

// Servers stores the server inventory. Names are unique case-insensitively.
type Servers interface {
	// CreateServer inserts s (setting s.ID) and the credentials seal
	// returns, atomically; ErrConflict if the name is taken.
	CreateServer(ctx context.Context, s *model.Server, seal SealFunc) error
	// UpdateServer replaces the fields of s, stores the credentials seal
	// returns (seal may be nil) and deletes the kinds in drop, atomically.
	UpdateServer(ctx context.Context, s *model.Server, seal SealFunc, drop []model.CredKind) error
	// SetServerState changes only the state.
	SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error
	DeleteServer(ctx context.Context, id int64) error
	ServerByID(ctx context.Context, id int64) (model.Server, error)
	ListServers(ctx context.Context) ([]model.Server, error)
	// ServerCredentials returns the sealed credentials of a server.
	ServerCredentials(ctx context.Context, id int64) ([]model.Credential, error)
}

// HostKeys stores the trusted SSH host key of each server.
type HostKeys interface {
	HostKey(ctx context.Context, serverID int64) (model.HostKey, error)
	// SetHostKey trusts k, replacing any key trusted before.
	SetHostKey(ctx context.Context, k model.HostKey) error
	DeleteHostKey(ctx context.Context, serverID int64) error
}

// Jobs stores jobs, their steps and logs.
type Jobs interface {
	// CreateJob inserts j (setting j.ID) with its steps and the sealed
	// secret seal returns (seal may be nil). A server has at most one
	// unfinished job: ErrConflict otherwise.
	CreateJob(ctx context.Context, j *model.Job, steps []model.JobStep, seal func(jobID int64) ([]byte, error)) error
	JobByID(ctx context.Context, id int64) (model.Job, error)
	JobSecret(ctx context.Context, id int64) ([]byte, error)
	ListJobs(ctx context.Context, f model.JobFilter) ([]model.Job, error)
	// UnfinishedJobs are all jobs that are not completed or failed.
	UnfinishedJobs(ctx context.Context) ([]model.Job, error)
	// ClaimJob leases a queued job for owner; false if someone else did.
	ClaimJob(ctx context.Context, id int64, owner string, until time.Time) (bool, error)
	// ExtendLease moves the lease of a job owner still holds.
	ExtendLease(ctx context.Context, id int64, owner string, until time.Time) error
	// UpdateJob writes state, step, data, attempt, errors, times and lease.
	UpdateJob(ctx context.Context, j model.Job) error
	JobSteps(ctx context.Context, jobID int64) ([]model.JobStep, error)
	UpdateJobStep(ctx context.Context, s model.JobStep) error
	// AppendJobLog sets l.Seq to the next number of the job.
	AppendJobLog(ctx context.Context, l *model.JobLog) error
	// JobLogs returns lines with Seq > after, oldest first.
	JobLogs(ctx context.Context, jobID, after int64, limit int) ([]model.JobLog, error)
}
