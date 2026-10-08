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
	// ErrBusy: the server has an unfinished job.
	ErrBusy = errors.New("server has an unfinished job")
	// ErrInChain: the server is a node of a cascade.
	ErrInChain = errors.New("server is in a cascade")
)

// SealedValue is a stored value sealed with the master key (package
// secrets), with the key version and the context it was sealed for.
type SealedValue struct {
	Version uint32
	Sealed  []byte
	Context string
}

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
	Configs
	Installations
	Metrics
	HealthChecks
	Traffic
	Presets
	Chains
	LinkChecks
	ServerGeos
	Events
	Close() error
}

// Chains stores cascades (P3-01). The role of a server follows its place
// in the chains (entry, relay, exit; standalone in none): every change of
// the chains updates servers.role in the same transaction.
type Chains interface {
	// CreateChain inserts c with its nodes and links (in state new),
	// setting c.ID and the links' From and To, after check accepted it
	// against every chain stored so far; check runs inside the
	// transaction, so two chains created at once cannot both pass it.
	// ErrConflict if the name is taken.
	CreateChain(ctx context.Context, c *model.Chain, check func(existing []model.Chain) error) error
	// UpdateChain changes the name and notes; ErrConflict if the name is
	// taken.
	UpdateChain(ctx context.Context, id int64, name, notes string, at time.Time) error
	// DeleteChain removes the chain with its nodes, links and their
	// secrets.
	DeleteChain(ctx context.Context, id int64, at time.Time) error
	ChainByID(ctx context.Context, id int64) (model.Chain, error)
	// ListChains is every chain, by name.
	ListChains(ctx context.Context) ([]model.Chain, error)
	// UpdateLink writes the params, state, applied revisions and config
	// hash of a link.
	UpdateLink(ctx context.Context, l model.ChainLink) error
	// SetLinkSecrets stores the sealed secrets of a link (nil: none).
	SetLinkSecrets(ctx context.Context, chainID int64, idx int, sealed []byte, at time.Time) error
	// LinkSecrets are the sealed secrets of a link (nil: none).
	LinkSecrets(ctx context.Context, chainID int64, idx int) ([]byte, error)
}

// Presets stores config presets. Names are unique case-insensitively.
type Presets interface {
	// CreatePreset sets p.ID; ErrConflict if the name is taken.
	CreatePreset(ctx context.Context, p *model.Preset) error
	// UpdatePreset replaces the name, config and notes; ErrConflict if
	// the name is taken.
	UpdatePreset(ctx context.Context, p model.Preset) error
	DeletePreset(ctx context.Context, id int64) error
	PresetByID(ctx context.Context, id int64) (model.Preset, error)
	// ListPresets is every preset, by name.
	ListPresets(ctx context.Context) ([]model.Preset, error)
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
	// SetLastLogin records a login of the user.
	SetLastLogin(ctx context.Context, id int64, at time.Time) error
	// ChangeUsers lets change edit users in one transaction: it gets every
	// user and returns those it changed (their role, password hash and
	// disabled flag are written, updated_at set to at) and the users whose
	// sessions end at at. A check across users (the last owner) made in
	// change holds when it commits: two changes at once cannot both pass it.
	ChangeUsers(ctx context.Context, at time.Time, change func(all []model.User) (changed []model.User, revoke []int64, err error)) error
	// DeleteUser removes the user and its sessions once check accepted it
	// against every user, atomically like ChangeUsers.
	DeleteUser(ctx context.Context, id int64, check func(all []model.User) error) error
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
	// QueryAudit returns the entries f selects, newest first (Limit: 1 to
	// 500, 100 by default).
	QueryAudit(ctx context.Context, f model.AuditFilter) ([]model.AuditEntry, error)
	// TrimAudit deletes the entries with one of actions except the newest
	// keep of them.
	TrimAudit(ctx context.Context, actions []string, keep int) error
}

// SealFunc seals the credentials of a server once its ID is known; it runs
// inside the transaction that creates or updates the server.
type SealFunc func(serverID int64) ([]model.Credential, error)

// Servers stores the server inventory. Names are unique case-insensitively.
type Servers interface {
	// CreateServer inserts s (setting s.ID) and the credentials seal
	// returns, atomically; ErrConflict if the name is taken. A new server
	// is standalone whatever s.Role says: roles come from the chains.
	CreateServer(ctx context.Context, s *model.Server, seal SealFunc) error
	// UpdateServer replaces the fields of s but its role (Chains keeps
	// it) and its state (SetServerState and SwapServerState change it: a
	// copy read before the update may be stale), stores the credentials
	// seal returns (seal may be nil) and deletes the kinds in drop,
	// atomically.
	// A change of how the controller reaches the server (host, SSH port,
	// user, auth type or new credentials) fails with ErrBusy while the
	// server has an unfinished job; a new host or port forgets the trusted
	// host key.
	UpdateServer(ctx context.Context, s *model.Server, seal SealFunc, drop []model.CredKind) error
	// SetHopInterval changes only the port hopping interval of the
	// server's client links (seconds, 0: the client's default).
	SetHopInterval(ctx context.Context, id int64, seconds int, at time.Time) error
	// SetServerState changes only the state.
	SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error
	// AddServerNote appends note to the server's notes as a paragraph of
	// its own (what a job left on the server for the admin), atomically.
	AddServerNote(ctx context.Context, id int64, note string, at time.Time) error
	// SwapServerState sets state only while the server is in one of from,
	// atomically; false: it was not (or there is no such server).
	SwapServerState(ctx context.Context, id int64, from []model.ServerState, state model.ServerState, at time.Time) (bool, error)
	// DeleteServer fails with ErrBusy while the server has an unfinished
	// job: its rollback needs the credentials and the host key; and with
	// ErrInChain while it is a node of a cascade.
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
	// UpdateJob writes state, step, attempt, errors, times and lease (not
	// the data: SetJobData).
	UpdateJob(ctx context.Context, j model.Job) error
	// SetJobData replaces the data of a job.
	SetJobData(ctx context.Context, id int64, data map[string]string) error
	JobSteps(ctx context.Context, jobID int64) ([]model.JobStep, error)
	UpdateJobStep(ctx context.Context, s model.JobStep) error
	// AppendJobLog sets l.Seq to the next number of the job.
	AppendJobLog(ctx context.Context, l *model.JobLog) error
	// JobLogs returns lines with Seq > after, oldest first.
	JobLogs(ctx context.Context, jobID, after int64, limit int) ([]model.JobLog, error)
	// SearchJobLogs returns matching lines of all jobs, newest first.
	SearchJobLogs(ctx context.Context, f model.JobLogFilter) ([]model.JobLogHit, error)
}

// Configs stores the Hysteria config revisions of servers.
type Configs interface {
	// AddConfig stores c as the server's next revision (c.Revision is
	// set); seal seals the YAML for that revision.
	AddConfig(ctx context.Context, c *model.ServerConfig, seal func(revision int) ([]byte, error)) error
	// CurrentConfig is the newest revision (ErrNotFound: none).
	CurrentConfig(ctx context.Context, serverID int64) (model.ServerConfig, error)
	// ConfigRevision is one revision (ErrNotFound: none).
	ConfigRevision(ctx context.Context, serverID int64, revision int) (model.ServerConfig, error)
	// ListConfigs is the server's revisions, newest first.
	ListConfigs(ctx context.Context, serverID int64) ([]model.ServerConfig, error)
}

// Installations stores where Hysteria is on each server.
type Installations interface {
	// SetInstallation records in, replacing what was recorded before.
	SetInstallation(ctx context.Context, in model.Installation) error
	// Installation is the recorded one (ErrNotFound: none).
	Installation(ctx context.Context, serverID int64) (model.Installation, error)
	// SetFirewall records the firewall rules HyRoute opened on the server
	// (ErrNotFound: no installation).
	SetFirewall(ctx context.Context, serverID int64, fw model.Firewall) error
}

// Metrics stores monitoring points.
type Metrics interface {
	// AddMetric stores a sample (m.Step 0); a second one at the same
	// second replaces the first.
	AddMetric(ctx context.Context, m model.Metric) error
	// Metrics are the points of step (0 or model.MetricStep) with
	// from <= At < to, oldest first.
	Metrics(ctx context.Context, serverID int64, step int, from, to time.Time) ([]model.Metric, error)
	// CompactMetrics averages the samples of every finished 15-minute
	// period into a point of model.MetricStep, then drops samples older
	// than keepSamples and averages older than keepAverages.
	CompactMetrics(ctx context.Context, now time.Time, keepSamples, keepAverages time.Duration) error
	// LatestMetrics is the newest sample of each server taken at or after
	// since.
	LatestMetrics(ctx context.Context, since time.Time) ([]model.Metric, error)
}

// Traffic keeps what each Hysteria user moved per hour.
type Traffic interface {
	// AddTraffic adds bytes per user (Tx and Rx of each entry) to the hour
	// of at.
	AddTraffic(ctx context.Context, serverID int64, at time.Time, users map[string]model.TrafficHour) error
	// Traffic is the server's traffic per user and hour for the hours
	// that start in [from rounded down to the hour, to), oldest first.
	Traffic(ctx context.Context, serverID int64, from, to time.Time) ([]model.TrafficHour, error)
	// PruneTraffic drops hours that start before before.
	PruneTraffic(ctx context.Context, before time.Time) error
}

// HealthChecks stores the results of server health checks.
type HealthChecks interface {
	// AddHealth stores a check; a second one at the same second replaces
	// the first.
	AddHealth(ctx context.Context, h model.Health) error
	// HealthHistory is the server's checks with At >= since, newest first,
	// at most limit (0: all).
	HealthHistory(ctx context.Context, serverID int64, since time.Time, limit int) ([]model.Health, error)
	// PruneHealth drops checks older than before.
	PruneHealth(ctx context.Context, before time.Time) error
}

// ServerGeos stores the geo databases servers have (P3-07).
type ServerGeos interface {
	// SetServerGeo records what a server has now.
	SetServerGeo(ctx context.Context, g model.ServerGeo) error
	// ServerGeo is what a server has; ErrNotFound: nothing HyRoute put.
	ServerGeo(ctx context.Context, serverID int64) (model.ServerGeo, error)
	// ServerGeos is every server's.
	ServerGeos(ctx context.Context) ([]model.ServerGeo, error)
}

// LinkChecks stores the checks of cascade links.
type LinkChecks interface {
	// AddLinkCheck stores a check; a second one of the link at the same
	// second replaces the first.
	AddLinkCheck(ctx context.Context, c model.LinkCheck) error
	// LinkChecks are the link's checks with At >= since, newest first, at
	// most limit (0: all).
	LinkChecks(ctx context.Context, chainID int64, idx int, since time.Time, limit int) ([]model.LinkCheck, error)
	// PruneLinkChecks drops checks older than before.
	PruneLinkChecks(ctx context.Context, before time.Time) error
}

// Events stores events (P4-05): one open event per key, closed ones kept
// for a while.
type Events interface {
	// RaiseEvent opens e at e.OpenedAt or, while an event of its key is
	// open, glues it into that one (count + 1; text, severity, subject and
	// last time from e). opened: a new event.
	RaiseEvent(ctx context.Context, e model.Event) (out model.Event, opened bool, err error)
	// CloseEvent closes the open event of key; closed: there was one.
	CloseEvent(ctx context.Context, key string, at time.Time, text string) (out model.Event, closed bool, err error)
	// ListEvents are events newest first.
	ListEvents(ctx context.Context, f model.EventFilter) ([]model.Event, error)
	// PruneEvents drops events closed before before.
	PruneEvents(ctx context.Context, before time.Time) error
}
