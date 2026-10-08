package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// A difference of a cascade link is decided with `chains` on every
// server of the cascade: for a user of some of them the cascade answers
// as one that does not exist, while one of the server's own config
// passes the check.
func TestDriftDecisionNeedsWholeChain(t *testing.T) {
	s := newScoped(t)
	for _, path := range []string{"/accept", "/revert"} {
		url := "/api/v1/servers/" + id(s.a) + "/reconcile" + path
		hidden := s.op.do("POST", url, map[string]string{"key": model.DriftKey(model.DriftLink, s.ab, 0)}, nil)
		code(t, hidden, http.StatusNotFound, "not_found")
		if gone := s.op.do("POST", url, map[string]string{"key": model.DriftKey(model.DriftLink, 999999, 0)}, nil); gone.Code != hidden.Code || gone.Body.String() != hidden.Body.String() {
			t.Fatalf("%s: a hidden cascade %s, a missing one %d %s", path, hidden.Body, gone.Code, gone.Body)
		}
		for _, key := range []string{model.DriftKey(model.DriftLink, s.ac, 0), string(model.DriftConfig)} {
			if rec := s.op.do("POST", url, map[string]string{"key": key}, nil); rec.Code == http.StatusForbidden || rec.Code == http.StatusNotFound {
				t.Fatalf("%s %s refused: %s", path, key, rec.Body)
			}
		}
		code(t, s.op.do("POST", url, map[string]string{"key": "nonsense"}, nil), http.StatusBadRequest, "bad_request")
	}
}

// The reconciliation of a server names a link of a cascade the caller
// does not see whole only as out of their scope: no name, ID or hops.
func TestDriftHidesCascade(t *testing.T) {
	s := newScoped(t)
	ctx := context.Background()
	hidden, own := model.DriftKey(model.DriftLink, s.ab, 0), model.DriftKey(model.DriftLink, s.ac, 0)
	link := func(key string, chain int64, name string) model.DriftItem {
		return model.DriftItem{Key: key, Kind: model.DriftLink, Chain: chain, Since: time.Now(),
			Files: []model.DriftFile{{Path: "/etc/hysteria/link-x.yaml", Want: "1", Got: "2"}},
			Title: "связь каскада «" + name + "»", Summary: "Связь каскада «" + name + "» изменена вне HyRoute: конфиг клиента связи /etc/hysteria/link-x.yaml изменён."}
	}
	d := model.Drift{ServerID: s.a, At: time.Now(), Checked: []string{hidden, own, string(model.DriftConfig)},
		Items: []model.DriftItem{link(hidden, s.ab, "ab"), link(own, s.ac, "ca")}}
	if err := s.db.SetDrift(ctx, d); err != nil {
		t.Fatal(err)
	}
	var got driftJSON
	rec := s.op.do("GET", "/api/v1/servers/"+id(s.a)+"/reconcile", nil, nil)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"ab"`) || strings.Contains(rec.Body.String(), "«ab»") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	json.Unmarshal(rec.Body.Bytes(), &got)
	for _, th := range []driftThingJSON{got.Checked[0], got.Items[0].driftThingJSON} {
		if c := th.Chain; c == nil || !c.Hidden || c.ID != 0 || c.Name != "каскад вне вашей области" || th.Hops != 0 {
			t.Fatalf("hidden: %+v %+v", th, c)
		}
	}
	if it := got.Items[0]; it.Title != "связь каскада вне вашей области" || it.Summary != "Связь каскада вне вашей области изменена вне HyRoute: конфиг клиента связи /etc/hysteria/link-x.yaml изменён." {
		t.Fatalf("texts: %q %q", it.Title, it.Summary)
	}
	if th := got.Items[1]; th.Chain == nil || th.Chain.Hidden || th.Chain.ID != s.ac || th.Chain.Name != "ca" || th.Hops != 1 || th.Title != "связь каскада «ca»" {
		t.Fatalf("in scope: %+v %+v", th, th.Chain)
	}
	// The owner sees it whole.
	rec = s.owner.do("GET", "/api/v1/servers/"+id(s.a)+"/reconcile", nil, nil)
	got = driftJSON{}
	json.Unmarshal(rec.Body.Bytes(), &got)
	if th := got.Items[0]; th.Chain == nil || th.Chain.Hidden || th.Chain.Name != "ab" || th.Title != "связь каскада «ab»" {
		t.Fatalf("owner: %s", rec.Body)
	}
}
