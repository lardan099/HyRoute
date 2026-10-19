package model

import "time"

// UDP probe outcomes of a health check.
const (
	UDPOK       = "ok"        // the port answered (QUIC version negotiation)
	UDPNoAnswer = "no_answer" // nothing came back
	UDPError    = "error"     // the probe failed (port unreachable, DNS)
	UDPSkipped  = "skipped"   // not probed (unknown obfuscation, no config)
)

// Health is one health check of a server with Hysteria installed.
type Health struct {
	ServerID int64
	At       time.Time
	// Status is StateHealthy, StateDegraded or StateOffline.
	Status ServerState
	// Reason says why the status is not healthy (for people).
	Reason string
	// SSHMillis is how long connecting took (0: SSH failed).
	SSHMillis int
	// Service is the unit's active state ("" when SSH failed).
	Service string
	// Listening: Hysteria listens on its UDP port (nil: unknown).
	Listening *bool
	UDP       string // UDPOK…
	UDPMillis int
	// Egress is the source address of the server's route out ("" unknown).
	Egress string
}
