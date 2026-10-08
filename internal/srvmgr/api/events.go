package api

import (
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

type eventJSON struct {
	ID        int64           `json:"id"`
	Kind      model.EventKind `json:"kind"`
	Severity  model.Severity  `json:"severity"`
	Subject   string          `json:"subject"`
	SubjectID int64           `json:"subjectId"`
	Text      string          `json:"text"`
	Count     int             `json:"count"`
	OpenedAt  time.Time       `json:"openedAt"`
	LastAt    time.Time       `json:"lastAt"`
	ClosedAt  *time.Time      `json:"closedAt"`
	CloseText string          `json:"closeText"`
}

func toEventJSON(e model.Event) eventJSON {
	return eventJSON{ID: e.ID, Kind: e.Kind, Severity: e.Severity, Subject: e.Subject, SubjectID: e.SubjectID, Text: e.Text, Count: e.Count,
		OpenedAt: e.OpenedAt, LastAt: e.LastAt, ClosedAt: optTime(e.ClosedAt), CloseText: e.CloseText}
}

// listEvents: the events of the last 30 days, newest first; ?open=1 —
// the open ones only. Texts carry no secrets and no addresses.
func (s *server) listEvents(w http.ResponseWriter, r *http.Request) {
	limit := int(queryInt(r, "limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	evs, err := s.Store.ListEvents(r.Context(), model.EventFilter{OpenOnly: r.URL.Query().Get("open") == "1", BeforeID: queryInt(r, "before"), Limit: limit})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]eventJSON, 0, len(evs))
	for _, e := range evs {
		out = append(out, toEventJSON(e))
	}
	writeJSON(w, http.StatusOK, out)
}

type attentionJSON struct {
	Items []events.Item `json:"items"`
	// Network: the controller has no network (null: it has).
	Network *eventJSON `json:"network"`
	// Monitoring: the monitor runs.
	Monitoring bool `json:"monitoring"`
}

// attention is the summary «Требует внимания» of the overview.
func (s *server) attention(w http.ResponseWriter, r *http.Request) {
	if s.Attention == nil {
		writeJSON(w, http.StatusOK, attentionJSON{Items: []events.Item{}})
		return
	}
	sum, err := s.Attention.Summary(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := attentionJSON{Items: sum.Items, Monitoring: sum.Monitoring}
	if sum.Network != nil {
		e := toEventJSON(*sum.Network)
		out.Network = &e
	}
	writeJSON(w, http.StatusOK, out)
}
