package apply

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// «Вернуть версию HyRoute» (P4-06): the apply job puts the current
// revision back over a config changed outside HyRoute, with a backup of
// that one, the restart and the check, and stores no new revision.
func TestRevert(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	drifted := strings.Replace(deployed, "listen: :443", "listen: :8443", 1) + "# edited by hand\n"
	h.v.mu.Lock()
	h.v.files[cfgPath] = []byte(drifted)
	h.v.start()
	h.v.mu.Unlock()
	h.db.SetServerState(ctx, h.server, model.StateNeedsAttention, h.app.x.Now())

	j, err := h.app.Revert(ctx, h.server, sha([]byte(drifted)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(j.Params), "fake-apply") || !strings.Contains(string(j.Params), sha([]byte(drifted))) {
		t.Fatalf("params %s", j.Params)
	}
	j, log := h.wait(j)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if h.v.file() != deployed || h.v.state != "active" || h.v.port != 443 {
		t.Fatalf("server: %s %d\n%s", h.v.state, h.v.port, h.v.file())
	}
	if h.v.has(cfgPath + Backup) {
		t.Fatal("the copy of the config changed by hand is left")
	}
	if cs, _ := h.db.ListConfigs(ctx, h.server); len(cs) != 1 {
		t.Fatalf("%d revisions: a revert adds none", len(cs))
	}
	if h.state() != model.StateHealthy || !strings.Contains(log, "изменён вне HyRoute") || !strings.Contains(log, "ревизия 1) снова на сервере") || strings.Contains(log, "fake-apply-auth-pass") {
		t.Fatalf("state %s\n%s", h.state(), log)
	}
	// Nothing differs any more: nothing to revert.
	var fe *model.FieldError
	if _, err := h.app.Revert(ctx, h.server, sha([]byte(deployed)), 0); !errors.As(err, &fe) {
		t.Fatalf("revert of the revision itself: %v", err)
	}
}

// Hysteria does not work with the revision: the config changed by hand
// comes back, and the server runs it as before.
func TestRevertRollsBack(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	drifted := strings.Replace(deployed, "    rewriteHost: true\n", "", 1)
	h.v.mu.Lock()
	h.v.files[cfgPath] = []byte(drifted)
	h.v.bad = "rewriteHost: true"
	h.v.start()
	h.v.mu.Unlock()
	h.db.SetServerState(ctx, h.server, model.StateNeedsAttention, h.app.x.Now())

	j, err := h.app.Revert(ctx, h.server, sha([]byte(drifted)), 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "verify" {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if h.v.file() != drifted || h.v.state != "active" || h.v.has(cfgPath+Backup) {
		t.Fatalf("not rolled back: %s\n%s", h.v.state, h.v.file())
	}
	if cs, _ := h.db.ListConfigs(ctx, h.server); len(cs) != 1 {
		t.Fatalf("%d revisions", len(cs))
	}
	if h.state() != model.StateNeedsAttention {
		t.Fatalf("state %s: the difference is still there", h.state())
	}
}

// The config changed again after the reconciliation: the job stops before
// writing anything.
func TestRevertChangedAgain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seen := deployed + "# first edit\n"
	now := deployed + "# second edit\n"
	h.v.mu.Lock()
	h.v.files[cfgPath] = []byte(now)
	h.v.mu.Unlock()
	j, err := h.app.Revert(ctx, h.server, sha([]byte(seen)), 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "validate" || !strings.Contains(j.ErrorMessage, "изменился ещё раз") {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if len(h.v.writes) != 0 || h.v.file() != now {
		t.Fatalf("written: %+v", h.v.writes)
	}
}

// A config deleted on the server is written again (0640, the service's
// group); the rollback would remove it.
func TestRevertDeletedConfig(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.v.mu.Lock()
	delete(h.v.files, cfgPath)
	h.v.mu.Unlock()
	j, err := h.app.Revert(ctx, h.server, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if h.v.file() != deployed || len(h.v.writes) != 1 || h.v.writes[0].Mode != 0o640 || h.v.writes[0].Group != "hysteria" {
		t.Fatalf("written %+v\n%s", h.v.writes, h.v.file())
	}
}
