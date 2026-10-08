package model

import (
	"encoding/json"
	"slices"
	"time"
)

// BatchAction is what a batch does on each of its servers (P4-07): one
// ordinary job per server, the job its single-server route queues.
type BatchAction string

const (
	// BatchMaintain updates Hysteria (job maintain, upgrade).
	BatchMaintain BatchAction = "maintain"
	// BatchGeo puts the controller's geo databases on the servers (job geo).
	BatchGeo BatchAction = "geo"
	// BatchPreset lays sections of a preset over the configs (job apply).
	BatchPreset BatchAction = "preset"
	// BatchRouting puts a rule template into the routing (job apply).
	BatchRouting BatchAction = "routing"
	// BatchTuning applies kernel settings (job tuning).
	BatchTuning BatchAction = "tuning"
	// BatchRotate gives the servers new passwords (job apply): the links
	// of their clients change.
	BatchRotate BatchAction = "rotate"
)

// BatchActions are every action, in the order the UI offers them.
var BatchActions = []BatchAction{BatchMaintain, BatchGeo, BatchPreset, BatchRouting, BatchTuning, BatchRotate}

// Valid reports whether a is a known action.
func (a BatchAction) Valid() bool { return slices.Contains(BatchActions, a) }

// Permission is what the action needs on every server of the batch: what
// the route of its job on one server needs.
func (a BatchAction) Permission() Permission {
	if a == BatchMaintain {
		return PermDeploy
	}
	return PermConfig
}

// BatchState is where a batch is.
type BatchState string

const (
	// BatchRunning: jobs start as the rules allow.
	BatchRunning BatchState = "running"
	// BatchStopping: no new jobs start (Stop says why); the batch ends
	// once the running ones have.
	BatchStopping BatchState = "stopping"
	// BatchCompleted: every server's job completed (or had nothing to do).
	BatchCompleted BatchState = "completed"
	// BatchFailed: a job failed or could not be queued.
	BatchFailed BatchState = "failed"
	// BatchStopped: stopped by a user, or its author lost the right.
	BatchStopped BatchState = "stopped"
)

// Terminal reports a batch that has ended.
func (s BatchState) Terminal() bool {
	return s == BatchCompleted || s == BatchFailed || s == BatchStopped
}

// BatchStop is why a batch starts no more jobs.
type BatchStop string

const (
	StopNone BatchStop = ""
	// StopUser: a user pressed «Остановить» (Batch.StoppedBy).
	StopUser BatchStop = "user"
	// StopFailed: a job failed or was refused (the item says why).
	StopFailed BatchStop = "failed"
	// StopDenied: the batch's author no longer may do its action on a
	// server (or at all), or was blocked or deleted.
	StopDenied BatchStop = "denied"
)

// BatchItemState is where one server of a batch is.
type BatchItemState string

const (
	// ItemPending: its job has not been queued yet.
	ItemPending BatchItemState = "pending"
	// ItemStarting: its job is being queued; a controller restart in
	// between finds the job by the time (BatchItem.At).
	ItemStarting BatchItemState = "starting"
	// ItemRunning: its job is queued or running.
	ItemRunning   BatchItemState = "running"
	ItemCompleted BatchItemState = "completed"
	// ItemUnchanged: the server already is as the action would make it;
	// no job.
	ItemUnchanged BatchItemState = "unchanged"
	// ItemFailed: its job failed or was refused (Message).
	ItemFailed BatchItemState = "failed"
	// ItemSkipped: not started, the batch stopped first.
	ItemSkipped BatchItemState = "skipped"
)

// Active reports an item whose job is being queued or runs.
func (s BatchItemState) Active() bool { return s == ItemStarting || s == ItemRunning }

// Batch is one action over several servers (P4-07): a stored record and
// ordinary jobs. The canary goes first; once its job completed, the rest
// run Parallel at a time; the first failure stops what has not started.
type Batch struct {
	ID     int64
	Action BatchAction
	// Params are the action's choices (no secrets).
	Params json.RawMessage
	// Parallel is how many jobs of the batch run at once after the canary.
	Parallel int
	State    BatchState
	Stop     BatchStop
	// StoppedBy is the user who stopped it (StopUser).
	StoppedBy int64
	// RetryOf is the batch whose failed and skipped servers this one
	// retries (0: none); RetriedBy the newest batch retrying this one.
	RetryOf    int64
	RetriedBy  int64
	CreatedBy  int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
	FinishedAt time.Time
	Items      []BatchItem
}

// BatchItem is one server of a batch.
type BatchItem struct {
	Idx      int
	ServerID int64
	State    BatchItemState
	JobID    int64
	// Canary: the item whose job tried the action first.
	Canary bool
	// Message says why it failed, was skipped or changed nothing.
	Message string
	// At is when the state last changed.
	At time.Time
}

// Servers are the servers of the batch in their order.
func (b Batch) Servers() []int64 {
	out := make([]int64, len(b.Items))
	for i, it := range b.Items {
		out[i] = it.ServerID
	}
	return out
}

// BatchFilter selects batches to list, newest first.
type BatchFilter struct {
	BeforeID int64 // 0: newest
	Limit    int
	// Within, when not nil, keeps the batches whose every server is one
	// of *Within (a user's scope), the node of params "via" too. Batches
	// without servers are left out.
	Within *[]int64
}
