package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
)

// A user of some servers sees the events and the «Требует внимания»
// items of those servers, of the cascades and jobs on them only, and of
// the controller; the owner sees everything.
func TestScopeFiltersEvents(t *testing.T) {
	s := newScoped(t)
	ctx := context.Background()
	s.h = New(Deps{Store: s.db, Auth: s.auth, Attention: &events.Attention{Store: s.db, Monitoring: true, Now: time.Now}})
	onA := s.failedJob(service.JobKind, s.a, service.Params{Action: "restart"})
	onB := s.failedJob(service.JobKind, s.b, service.Params{Action: "restart"})
	raise := func(key, subject string, id int64) {
		t.Helper()
		if _, _, err := s.db.RaiseEvent(ctx, model.Event{Kind: model.EventDisk, Key: key, Severity: model.SeverityWarning, Subject: subject, SubjectID: id, Text: key, OpenedAt: time.Now(), LastAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	raise("server-a", model.SubjectServer, s.a)
	raise("server-b", model.SubjectServer, s.b)
	raise("chain-ab", model.SubjectChain, s.ab)
	raise("chain-ac", model.SubjectChain, s.ac)
	raise("job-a", model.SubjectJob, onA)
	raise("job-b", model.SubjectJob, onB)
	raise("controller", model.SubjectController, 0)

	texts := func(c *client, path string) []string {
		t.Helper()
		rec := c.do("GET", path, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		var evs []eventJSON
		json.Unmarshal(rec.Body.Bytes(), &evs)
		var out []string
		for _, e := range evs {
			out = append(out, e.Text)
		}
		slices.Sort(out)
		return out
	}
	want := []string{"chain-ac", "controller", "job-a", "server-a"}
	if got := texts(s.op, "/api/v1/events"); !slices.Equal(got, want) {
		t.Fatalf("scoped events %v, want %v", got, want)
	}
	// Paging fills the page from further back: two per page.
	if got := texts(s.op, "/api/v1/events?limit=2"); len(got) != 2 {
		t.Fatalf("a page of two: %v", got)
	}
	if got := texts(s.owner, "/api/v1/events"); len(got) != 7 {
		t.Fatalf("owner events %v", got)
	}

	subjects := func(c *client) map[string]bool {
		t.Helper()
		rec := c.do("GET", "/api/v1/attention", nil, nil)
		var a attentionJSON
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &a) != nil {
			t.Fatalf("attention %d %s", rec.Code, rec.Body)
		}
		out := map[string]bool{}
		for _, it := range a.Items {
			out[it.Subject+"/"+id(it.SubjectID)] = true
		}
		return out
	}
	got := subjects(s.op)
	for _, hidden := range []string{"server/" + id(s.b), "chain/" + id(s.ab), "job/" + id(onB)} {
		if got[hidden] {
			t.Errorf("scoped attention lists %s: %v", hidden, got)
		}
	}
	if !got["server/"+id(s.a)] || !got["job/"+id(onA)] {
		t.Errorf("scoped attention misses its own: %v", got)
	}
	if all := subjects(s.owner); !all["server/"+id(s.b)] || !all["job/"+id(onB)] {
		t.Errorf("owner attention %v", all)
	}
}
