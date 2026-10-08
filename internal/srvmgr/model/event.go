package model

import "time"

// EventKind is what an event is about (P4-05). Channels choose the kinds
// they are told about.
type EventKind string

const (
	// EventServer: a server's status changed for N checks in a row.
	EventServer EventKind = "server"
	// EventLink: a cascade link is offline or degraded.
	EventLink EventKind = "link"
	// EventJob: a job failed.
	EventJob EventKind = "job"
	// EventAttention: a server needs attention after a job.
	EventAttention EventKind = "attention"
	// EventHostKey: a server presents another SSH host key.
	EventHostKey EventKind = "host_key"
	// EventSSHAuth: a server refused the SSH login.
	EventSSHAuth EventKind = "ssh_auth"
	// EventDisk: a server's disk is more than 90 % full.
	EventDisk EventKind = "disk"
	// EventGeo: the geo databases were not updated.
	EventGeo EventKind = "geo"
	// EventNetwork: the controller itself has no network.
	EventNetwork EventKind = "network"
	// EventDrift: a server was changed outside HyRoute (P4-06).
	EventDrift EventKind = "drift"
)

// EventKinds are every kind, in the order the admin sees them.
var EventKinds = []EventKind{EventServer, EventLink, EventJob, EventAttention, EventHostKey, EventSSHAuth, EventDisk, EventGeo, EventNetwork, EventDrift}

// Valid reports whether k is a known kind.
func (k EventKind) Valid() bool {
	for _, x := range EventKinds {
		if x == k {
			return true
		}
	}
	return false
}

// Severity is how urgent an event is.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

// What an event is about (Event.Subject).
const (
	SubjectServer     = "server"
	SubjectChain      = "chain"
	SubjectJob        = "job"
	SubjectController = "controller"
)

// Event is something the admin should know of: open while it lasts,
// closed once it is over. Repeats of an open event (the same Key) are
// glued into it: Count grows, LastAt and Text follow the newest. Texts
// name servers and cascades, never their addresses, and carry no secrets.
type Event struct {
	ID       int64
	Kind     EventKind
	Key      string
	Severity Severity
	// Subject and SubjectID: the server, cascade or job it is about
	// (SubjectController with 0: the controller itself).
	Subject   string
	SubjectID int64
	Text      string
	Count     int
	OpenedAt  time.Time
	LastAt    time.Time
	ClosedAt  time.Time // zero: open
	// CloseText says how it ended ("" while open).
	CloseText string
}

// Open reports an event that has not ended.
func (e Event) Open() bool { return e.ClosedAt.IsZero() }

// EventFilter selects events to list, newest first.
type EventFilter struct {
	OpenOnly bool
	BeforeID int64 // 0: newest
	Limit    int
}
