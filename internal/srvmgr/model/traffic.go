package model

import "time"

// TrafficHour is what one user of a server moved through Hysteria in one
// hour, as the stats API counts it: Tx is the client's upload, Rx its
// download.
type TrafficHour struct {
	ServerID int64
	Hour     time.Time // start of the hour, UTC
	User     string    // the auth ID: "user" for a single password, the name for userpass
	Tx, Rx   int64
}
