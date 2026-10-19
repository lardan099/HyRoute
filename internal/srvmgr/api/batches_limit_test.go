package api

import (
	"net/http"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/batch"
)

// A batch names at most batch.MaxServers servers, repeats counted once.
func TestBatchServersBounded(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	many := make([]int64, batch.MaxServers+1)
	for i := range many {
		many[i] = int64(i + 1)
	}
	code(t, owner.do("POST", "/api/v1/batches/tuning", map[string]any{"servers": many, "params": map[string]any{"keys": []string{"net.core.rmem_max"}}}, nil), http.StatusBadRequest, "invalid")
}

// The routing body limit is for routing documents, not for the server
// list of a routing batch.
func TestRoutingBody(t *testing.T) {
	for p, want := range map[string]bool{
		"/api/v1/servers/3/routing/apply":   true,
		"/api/v1/servers/3/routing/preview": true,
		"/api/v1/routing/import":            true,
		"/api/v1/chain-templates/import":    true,
		"/api/v1/batches/routing":           false,
		"/api/v1/servers/3/config/apply":    false,
	} {
		if routingBody(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}
