package app

import (
	"strings"

	"github.com/lardan099/hyroute/internal/hysteria"
)

// MergeStats says what a subscription update changed.
type MergeStats struct {
	Added       int `json:"added"`
	Updated     int `json:"updated"`
	Removed     int `json:"removed"`
	MissingKept int `json:"missingKept"`
}

// connKey is a profile's connection identity: the share link without the
// name (all connection parameters, secrets included).
func connKey(p hysteria.Profile) string {
	p.Name, p.ID, p.Source, p.Missing = "", "", "", false
	return p.URI()
}

func endpointKey(p hysteria.Profile) string {
	return strings.ToLower(p.Host) + ":" + p.Ports
}

// mergeSubscription replaces the profiles of subscription source in list
// with fresh, keeping IDs stable so rules keep pointing at the same
// server, and the user's local settings with them (keepLocal). Matching
// is one to one, most certain first: same connection parameters, then
// same host:ports, then same name. Unmatched old profiles are kept
// (marked Missing) when keep reports them in use and dropped otherwise.
// The subscription's profiles stay where the first of them was in the
// list.
func mergeSubscription(list []hysteria.Profile, source string, fresh []hysteria.Profile, keep func(id string) bool, newID func() string) ([]hysteria.Profile, MergeStats) {
	var st MergeStats
	var old []hysteria.Profile
	insertAt := -1
	var rest []hysteria.Profile
	for _, p := range list {
		if p.Source == source {
			if insertAt < 0 {
				insertAt = len(rest)
			}
			old = append(old, p)
		} else {
			rest = append(rest, p)
		}
	}
	if insertAt < 0 {
		insertAt = len(rest)
	}

	// Drop exact duplicates inside the new list.
	seen := map[string]bool{}
	var uniq []hysteria.Profile
	for _, p := range fresh {
		if k := connKey(p); !seen[k] {
			seen[k] = true
			uniq = append(uniq, p)
		}
	}
	fresh = uniq

	match := make([]int, len(fresh)) // index into old, -1 = new
	for i := range match {
		match[i] = -1
	}
	used := make([]bool, len(old))
	keys := []func(hysteria.Profile) string{connKey, endpointKey, func(p hysteria.Profile) string { return p.Name }}
	for _, key := range keys {
		for i, f := range fresh {
			if match[i] >= 0 {
				continue
			}
			k := key(f)
			for j, o := range old {
				if !used[j] && key(o) == k {
					match[i], used[j] = j, true
					break
				}
			}
		}
	}

	var subs []hysteria.Profile
	for i, f := range fresh {
		f.Source, f.Missing = source, false
		if j := match[i]; j >= 0 {
			f = keepLocal(f, old[j])
			f.ID = old[j].ID
			st.Updated++
		} else {
			f.ID = newID()
			st.Added++
		}
		subs = append(subs, f)
	}
	for j, o := range old {
		if used[j] {
			continue
		}
		if keep(o.ID) {
			o.Missing = true
			subs = append(subs, o)
			st.MissingKept++
		} else {
			st.Removed++
		}
	}
	out := make([]hysteria.Profile, 0, len(rest)+len(subs))
	out = append(out, rest[:insertAt]...)
	out = append(out, subs...)
	out = append(out, rest[insertAt:]...)
	return out, st
}

// keepLocal returns fresh with the settings a share link does not carry
// taken from old, the profile it replaces: speed, port hopping intervals,
// congestion, QUIC, fast open, CA file and IP pinning are set by the user
// in the editor, and an update must neither undo them nor restart the
// server's Hysteria over them. The rest is the subscription's data.
func keepLocal(fresh, old hysteria.Profile) hysteria.Profile {
	fresh.Bandwidth, fresh.Hop, fresh.Congestion, fresh.QUIC = old.Bandwidth, old.Hop, old.Congestion, old.QUIC
	fresh.FastOpen, fresh.PinServerIP, fresh.TLS.CA = old.FastOpen, old.PinServerIP, old.TLS.CA
	if fresh.Obfs.Type == old.Obfs.Type {
		fresh.Obfs.MinPacketSize, fresh.Obfs.MaxPacketSize = old.Obfs.MinPacketSize, old.Obfs.MaxPacketSize
	}
	return fresh
}
