package apply

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// toRev2 applies a new port and a new auth password: revision 2.
func toRev2(t *testing.T, h *harness) {
	t.Helper()
	text := h.edit(func(s string) string {
		s = strings.Replace(s, "listen: :443", "listen: :8443", 1)
		return strings.Replace(s, "password: '"+Hidden+"'", "password: fake-apply-new-pass", 1)
	})
	j, err := h.app.Submit(context.Background(), h.server, 1, text, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j, log := h.wait(j); j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
}

func TestHistoryHidesSecrets(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	toRev2(t, h)
	e := &Editor{Store: h.db, Keys: h.keys}

	v, err := e.Revision(ctx, h.server, 1)
	if err != nil || v.Revision != 1 || !strings.Contains(v.YAML, "listen: :443") || strings.Contains(v.YAML, "fake-apply") {
		t.Fatalf("%+v %v", v, err)
	}
	c, err := e.Compare(ctx, h.server, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	var minus, plus bool
	for _, l := range c.Diff {
		if strings.Contains(l.Text, "fake-apply") {
			t.Fatalf("secret in the diff: %q", l.Text)
		}
		minus = minus || (l.Op == "-" && l.Text == "listen: :443")
		plus = plus || (l.Op == "+" && l.Text == "listen: :8443")
	}
	if !minus || !plus || len(c.Secrets) != 1 || c.Secrets[0] != "auth.password" {
		t.Fatalf("%+v", c)
	}
	if _, err := e.Revision(ctx, h.server, 9); !errors.Is(err, ErrNoRevision) {
		t.Fatalf("missing revision: %v", err)
	}
}

func TestRollback(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	toRev2(t, h)

	j, err := h.app.Rollback(ctx, h.server, 2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if h.v.file() != deployed || h.v.state != "active" || h.v.port != 443 {
		t.Fatalf("server: %s %d\n%s", h.v.state, h.v.port, h.v.file())
	}
	cur, _ := h.db.CurrentConfig(ctx, h.server)
	first, _ := h.db.ConfigRevision(ctx, h.server, 1)
	if cur.Revision != 3 || cur.Source != model.ConfigRollback || cur.FromRevision != 1 || cur.SHA256 != first.SHA256 || cur.JobID != j.ID {
		t.Fatalf("%+v", cur)
	}
	if !strings.Contains(log, "Возвращена версия 1") || strings.Contains(log, "fake-apply") {
		t.Fatal(log)
	}

	var stale *StaleError
	if _, err := h.app.Rollback(ctx, h.server, 2, 1, 0); !errors.As(err, &stale) || stale.Current != 3 {
		t.Fatalf("stale base: %v", err)
	}
	var fe *model.FieldError
	if _, err := h.app.Rollback(ctx, h.server, 3, 3, 0); !errors.As(err, &fe) {
		t.Fatalf("current revision: %v", err)
	}
	if _, err := h.app.Rollback(ctx, h.server, 3, 1, 0); !errors.As(err, &fe) || !strings.Contains(fe.Msg, "совпадает") {
		t.Fatalf("same as current: %v", err)
	}
	if _, err := h.app.Rollback(ctx, h.server, 3, 42, 0); !errors.Is(err, ErrNoRevision) {
		t.Fatalf("missing revision: %v", err)
	}
}

// A revision that no longer runs: the apply rollback keeps the current
// config and no revision is added.
func TestRollbackFailsKeepsCurrent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	toRev2(t, h)
	cur := h.v.file()
	h.v.mu.Lock()
	h.v.bad = "listen: :443\n"
	h.v.mu.Unlock()

	j, err := h.app.Rollback(ctx, h.server, 2, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobFailed {
		t.Fatalf("%s\n%s", j.State, log)
	}
	if h.v.file() != cur || h.v.state != "active" || h.v.port != 8443 {
		t.Fatalf("server: %s %d", h.v.state, h.v.port)
	}
	if c, _ := h.db.CurrentConfig(ctx, h.server); c.Revision != 2 {
		t.Fatalf("revision %d", c.Revision)
	}
}
