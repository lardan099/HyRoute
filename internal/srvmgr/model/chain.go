package model

import (
	"encoding/json"
	"strconv"
	"time"
)

// LinkState is where a cascade link is in its deployment (P3-02).
type LinkState string

const (
	// LinkNew: saved, never deployed.
	LinkNew LinkState = "new"
	// LinkLinking: a job is deploying it (or deploying it again).
	LinkLinking LinkState = "linking"
	// LinkActive: deployed and in effect.
	LinkActive LinkState = "active"
	// LinkStale: deployed, but a server changed since (passwords,
	// certificate, ports…): deploying it again brings it up to date.
	LinkStale LinkState = "stale"
	// LinkUnlinking: a job is removing it.
	LinkUnlinking LinkState = "unlinking"
	// LinkFailed: its first deployment failed and was rolled back, so
	// nothing of it is on the servers. A failed redeployment rolls back
	// to the link as it was and keeps its state (active or stale).
	LinkFailed LinkState = "failed"
)

// Valid reports whether s is a known state.
func (s LinkState) Valid() bool {
	switch s {
	case LinkNew, LinkLinking, LinkActive, LinkStale, LinkUnlinking, LinkFailed:
		return true
	}
	return false
}

// Chain is a cascade: servers in order, entry first and exit last, with a
// link between each pair of neighbours. Phase 3 deploys two nodes.
type Chain struct {
	ID    int64
	Name  string
	Notes string
	// Nodes are the server IDs, entry first.
	Nodes []int64
	// Links has len(Nodes)-1 entries: Links[i] joins Nodes[i] and
	// Nodes[i+1].
	Links []ChainLink

	CreatedBy int64
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Entry is the first server of the chain (0: no nodes).
func (c Chain) Entry() int64 {
	if len(c.Nodes) == 0 {
		return 0
	}
	return c.Nodes[0]
}

// Exit is the last server of the chain (0: no nodes).
func (c Chain) Exit() int64 {
	if len(c.Nodes) == 0 {
		return 0
	}
	return c.Nodes[len(c.Nodes)-1]
}

// NodeRole is the role of the server at node idx of a chain of n nodes.
func NodeRole(idx, n int) ServerRole {
	switch {
	case idx == 0:
		return RoleEntry
	case idx == n-1:
		return RoleExit
	default:
		return RoleRelay
	}
}

// ChainLink joins two neighbouring servers of a chain: From runs a client
// of Hysteria to To and sends its traffic there (outbound "cascade"); To
// accepts it with the link's own credentials (P3-02).
type ChainLink struct {
	ChainID int64
	Idx     int
	// From and To are Nodes[Idx] and Nodes[Idx+1].
	From int64
	To   int64
	// Params are the link's settings without secrets (cascade.Params);
	// its secrets are sealed apart (LinkSecretContext).
	Params json.RawMessage
	State  LinkState
	// FromRevision and ToRevision are the config revisions of both
	// servers the link was last deployed with; ConfigSHA256 is the hash
	// of its client config then, UnitSHA256 of its unit (P4-06; "": not
	// recorded).
	FromRevision int
	ToRevision   int
	ConfigSHA256 string
	UnitSHA256   string
	UpdatedAt    time.Time
}

// LinkSecretContext is the additional data the secrets of a link are
// sealed with: a sealed value copied to another link does not open.
func LinkSecretContext(chainID int64, idx int) string {
	return "chain/" + strconv.FormatInt(chainID, 10) + "/link/" + strconv.Itoa(idx)
}

// LinkCheck is one check of a link from its entry (P3-03).
type LinkCheck struct {
	ChainID int64
	Idx     int
	At      time.Time
	// Status is StateHealthy, StateDegraded or StateOffline.
	Status ServerState
	// Reason says why it is not healthy (for people).
	Reason string
	// Service is the active state of the link service on the entry.
	Service string
	// HandshakeMillis: the link client's handshake with the exit; TCPMillis:
	// opening the check target through the exit (0: not opened).
	HandshakeMillis int
	TCPMillis       int
}
