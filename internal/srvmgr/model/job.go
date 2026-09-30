package model

import (
	"encoding/json"
	"time"
)

// JobState is where a job is. The running states name the phase of the
// current step; completed and failed are terminal.
type JobState string

const (
	JobQueued      JobState = "queued"
	JobConnecting  JobState = "connecting"
	JobPreflight   JobState = "preflight"
	JobDownloading JobState = "downloading"
	JobInstalling  JobState = "installing"
	JobConfiguring JobState = "configuring"
	JobFirewall    JobState = "firewall"
	JobStarting    JobState = "starting"
	JobVerifying   JobState = "verifying"
	JobRollingBack JobState = "rolling_back"
	// JobRecovering: the controller restarted while the job ran; the job
	// checks the actual state of the server before anything else.
	JobRecovering JobState = "recovering"
	JobCompleted  JobState = "completed"
	JobFailed     JobState = "failed"
)

// Phases are the running states a step can belong to, in order.
var Phases = []JobState{JobConnecting, JobPreflight, JobDownloading, JobInstalling, JobConfiguring, JobFirewall, JobStarting, JobVerifying}

// Terminal reports a finished job.
func (s JobState) Terminal() bool { return s == JobCompleted || s == JobFailed }

// Job is one operation on a server (deploy, preflight, import…).
type Job struct {
	ID          int64
	Kind        string
	ServerID    int64 // 0: not about a server
	State       JobState
	CurrentStep string
	// Params are the job's inputs (no secrets: those are sealed apart).
	Params json.RawMessage
	// Data are values steps hand to later steps; kept so a retry after a
	// restart still has them. No secrets.
	Data         map[string]string
	Attempt      int
	ErrorMessage string // for people
	ErrorDetails string // technical, redacted
	CreatedBy    int64
	CreatedAt    time.Time
	StartedAt    time.Time
	FinishedAt   time.Time
	LeaseOwner   string
	LeaseUntil   time.Time
}

// StepState is where a step is.
type StepState string

const (
	StepPending    StepState = "pending"
	StepRunning    StepState = "running"
	StepDone       StepState = "done"
	StepSkipped    StepState = "skipped" // already in place (idempotent check)
	StepFailed     StepState = "failed"
	StepRolledBack StepState = "rolled_back"
)

// JobStep is one step of a job.
type JobStep struct {
	JobID      int64
	Idx        int
	Name       string
	Phase      JobState
	State      StepState
	Attempt    int
	StartedAt  time.Time
	FinishedAt time.Time
	Error      string
}

// JobLog is one line of a job's log (already redacted).
type JobLog struct {
	JobID   int64
	Seq     int64
	Time    time.Time
	Level   string // info, warn, error
	Step    string
	Message string
}

// JobFilter selects jobs to list.
type JobFilter struct {
	ServerID int64 // 0: all
	Limit    int
	BeforeID int64 // 0: newest
}

// JobLogFilter selects job log lines across jobs.
type JobLogFilter struct {
	ServerID int64  // 0: all servers
	Level    string // this level and above (info < warn < error); "": all
	Text     string // case-insensitive substring of the message
	Limit    int
}

// JobLogHit is a job log line with its job's server and kind.
type JobLogHit struct {
	JobLog
	ServerID int64
	Kind     string
}
