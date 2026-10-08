package api

import (
	"net/http"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// A difference of a cascade link is decided with `chains` on every
// server of the cascade: a user of some of them may not accept or revert
// it, while one of the server's own config passes the check.
func TestDriftDecisionNeedsWholeChain(t *testing.T) {
	s := newScoped(t)
	for _, path := range []string{"/accept", "/revert"} {
		url := "/api/v1/servers/" + id(s.a) + "/reconcile" + path
		code(t, s.op.do("POST", url, map[string]string{"key": model.DriftKey(model.DriftLink, s.ab, 0)}, nil), http.StatusForbidden, "forbidden")
		for _, key := range []string{model.DriftKey(model.DriftLink, s.ac, 0), string(model.DriftConfig)} {
			if rec := s.op.do("POST", url, map[string]string{"key": key}, nil); rec.Code == http.StatusForbidden {
				t.Fatalf("%s %s refused: %s", path, key, rec.Body)
			}
		}
		code(t, s.op.do("POST", url, map[string]string{"key": "nonsense"}, nil), http.StatusBadRequest, "bad_request")
	}
}
