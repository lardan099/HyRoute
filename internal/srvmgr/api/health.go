package api

import (
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

type healthJSON struct {
	At        time.Time         `json:"at"`
	Status    model.ServerState `json:"status"`
	Reason    string            `json:"reason,omitempty"`
	SSHMillis int               `json:"sshMs"`
	Service   string            `json:"service,omitempty"`
	Listening *bool             `json:"listening"`
	UDP       string            `json:"udp"`
	UDPMillis int               `json:"udpMs,omitempty"`
	Egress    string            `json:"egress,omitempty"`
}

func toHealth(h model.Health) healthJSON {
	return healthJSON{At: h.At, Status: h.Status, Reason: h.Reason, SSHMillis: h.SSHMillis, Service: h.Service, Listening: h.Listening, UDP: h.UDP, UDPMillis: h.UDPMillis, Egress: h.Egress}
}

type serverHealthJSON struct {
	// Latest is the newest check (null: none yet).
	Latest *healthJSON `json:"latest"`
	// Changes are the checks where the status or its reason changed, in
	// the kept week, newest first.
	Changes []healthJSON `json:"changes"`
}

// maxChanges bounds the change list (a flapping server would fill a week).
const maxChanges = 50

func (s *server) serverHealth(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	hs, err := s.Store.HealthHistory(r.Context(), id, time.Now().Add(-7*24*time.Hour), 0)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := serverHealthJSON{Changes: []healthJSON{}}
	if len(hs) > 0 {
		l := toHealth(hs[0])
		out.Latest = &l
	}
	// hs is newest first: a check is a change when the one before it
	// (next in the list) differs.
	for i, h := range hs {
		if len(out.Changes) == maxChanges {
			break
		}
		if i == len(hs)-1 || hs[i+1].Status != h.Status || hs[i+1].Reason != h.Reason {
			out.Changes = append(out.Changes, toHealth(h))
		}
	}
	writeJSON(w, http.StatusOK, out)
}
