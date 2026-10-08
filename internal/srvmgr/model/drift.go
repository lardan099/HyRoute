package model

import (
	"strconv"
	"strings"
	"time"
)

// DriftKind is what a reconciliation compares on a server (P4-06) with
// what HyRoute recorded.
type DriftKind string

const (
	// DriftConfig: the Hysteria config against the current revision.
	DriftConfig DriftKind = "config"
	// DriftUnit: the systemd unit of the Hysteria service (its file and
	// drop-ins) against the installation's record.
	DriftUnit DriftKind = "unit"
	// DriftBinary: the Hysteria binary against the installation's record.
	DriftBinary DriftKind = "binary"
	// DriftGeo: the geo databases HyRoute put there (server_geo).
	DriftGeo DriftKind = "geo"
	// DriftLink: the client config and unit of a cascade link on the
	// server the link starts at.
	DriftLink DriftKind = "link"
)

// DriftKey names a thing a reconciliation compares: its kind, and for a
// link "link/<chain>/<idx>".
func DriftKey(kind DriftKind, chainID int64, idx int) string {
	if kind != DriftLink {
		return string(kind)
	}
	return "link/" + strconv.FormatInt(chainID, 10) + "/" + strconv.Itoa(idx)
}

// ParseDriftKey reads what DriftKey writes; ok is false for anything else.
func ParseDriftKey(key string) (kind DriftKind, chainID int64, idx int, ok bool) {
	switch DriftKind(key) {
	case DriftConfig, DriftUnit, DriftBinary, DriftGeo:
		return DriftKind(key), 0, 0, true
	}
	rest, found := strings.CutPrefix(key, "link/")
	if !found {
		return "", 0, 0, false
	}
	c, i, found := strings.Cut(rest, "/")
	chainID, err1 := strconv.ParseInt(c, 10, 64)
	idx, err2 := strconv.Atoi(i)
	if !found || err1 != nil || err2 != nil || chainID <= 0 || idx < 0 || DriftKey(DriftLink, chainID, idx) != key {
		return "", 0, 0, false
	}
	return DriftLink, chainID, idx, true
}

// DriftFile is a file that differs: the SHA-256 HyRoute recorded and the
// one found (""; the file is missing). A unit is named by the unit and
// compared by its fingerprint (remote.UnitSHA256).
type DriftFile struct {
	Path string `json:"path"`
	Want string `json:"want"`
	Got  string `json:"got"`
}

// DriftItem is one difference a reconciliation found.
type DriftItem struct {
	Key  string    `json:"key"`
	Kind DriftKind `json:"kind"`
	// Chain and Idx are the link (DriftLink).
	Chain int64 `json:"chain,omitempty"`
	Idx   int   `json:"idx,omitempty"`
	// Files are those that differ.
	Files []DriftFile `json:"files"`
	// Revision is the config revision compared (DriftConfig).
	Revision int `json:"revision,omitempty"`
	// Units are the files systemd builds the unit from now: its file
	// and drop-ins (DriftUnit, and a link whose unit differs).
	Units []string `json:"units,omitempty"`
	// Summary says what differs, for people: names, paths and section
	// names, never values.
	Summary string `json:"summary"`
	// Since is when a round first found the difference as it is now.
	Since time.Time `json:"since"`
	// Job is the job queued to put HyRoute's version back (0: none).
	Job int64 `json:"job,omitempty"`
}

// File is the item's file at path.
func (it DriftItem) File(path string) (DriftFile, bool) {
	for _, f := range it.Files {
		if f.Path == path {
			return f, true
		}
	}
	return DriftFile{}, false
}

// Drift is the latest reconciliation of a server (P4-06).
type Drift struct {
	ServerID int64
	// At is the last round that looked at the server; Error says why it
	// could not check it (Items are then those found before).
	At    time.Time
	Error string
	// Checked are the keys compared; Skipped those HyRoute recorded
	// nothing for (not compared).
	Checked []string
	Skipped []string
	Items   []DriftItem
	// Config is the config found on the server while it differs from the
	// revision, sealed (DriftContext); nil otherwise.
	Config []byte
	// AttentionAt is when a round made the server needs_attention (zero:
	// it did not, or no longer counts); Reverts are the jobs queued from
	// the drift since then.
	AttentionAt time.Time
	Reverts     []int64
}

// Item is the difference with key.
func (d Drift) Item(key string) (DriftItem, bool) {
	for _, it := range d.Items {
		if it.Key == key {
			return it, true
		}
	}
	return DriftItem{}, false
}

// DriftContext is the additional data the config found on a server is
// sealed with.
func DriftContext(serverID int64) string {
	return "server/" + strconv.FormatInt(serverID, 10) + "/drift/config"
}
