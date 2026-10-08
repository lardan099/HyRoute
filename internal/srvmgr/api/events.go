package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
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
	set, err := s.scopeSet(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// A scoped user's page is filled from as many pages of the store as
	// it takes (a bounded number): the next page goes on before the last
	// event shown.
	f := model.EventFilter{OpenOnly: r.URL.Query().Get("open") == "1", BeforeID: queryInt(r, "before"), Limit: limit}
	out := make([]eventJSON, 0, limit)
	for range 20 {
		evs, err := s.Store.ListEvents(r.Context(), f)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, e := range evs {
			ok, err := s.subjectVisible(r.Context(), set, e.Subject, e.SubjectID)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if ok && len(out) < limit {
				out = append(out, toEventJSON(e))
			}
		}
		if set.all || len(evs) < f.Limit || len(out) >= limit {
			break
		}
		f.BeforeID = evs[len(evs)-1].ID
	}
	writeJSON(w, http.StatusOK, out)
}

// subjectVisible: a user of some servers sees what is about a server in
// the scope, a cascade or job all of whose servers are, and the
// controller itself; a cascade or job gone sees nobody.
func (s *server) subjectVisible(ctx context.Context, set scopeSet, subject string, id int64) (bool, error) {
	if set.all {
		return true, nil
	}
	switch subject {
	case model.SubjectServer:
		return set.has(id), nil
	case model.SubjectChain:
		c, err := s.Store.ChainByID(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return err == nil && set.hasAll(c.Nodes), err
	case model.SubjectJob:
		j, err := s.Store.JobByID(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return err == nil && set.hasAll(jobServers(j)), err
	}
	return true, nil
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
	set, err := s.scopeSet(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := attentionJSON{Items: []events.Item{}, Monitoring: sum.Monitoring}
	for _, it := range sum.Items {
		ok, err := s.subjectVisible(r.Context(), set, it.Subject, it.SubjectID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if ok {
			out.Items = append(out.Items, it)
		}
	}
	if sum.Network != nil {
		e := toEventJSON(*sum.Network)
		out.Network = &e
	}
	writeJSON(w, http.StatusOK, out)
}
