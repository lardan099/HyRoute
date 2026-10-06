package cascade

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// linked is a world whose link is deployed.
func linked(t *testing.T, exitCfg string) *world {
	t.Helper()
	w := newWorld(t, exitCfg)
	if j, log := w.wait(w.submit()); j.State != model.JobCompleted {
		t.Fatalf("link: %s %s\n%s", j.State, j.ErrorMessage, log)
	}
	return w
}

func (w *world) unlink(del bool) (model.Job, string) {
	w.t.Helper()
	j, err := w.linker.Unlink(context.Background(), w.chain, 0, del, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return w.wait(j)
}

// rev stores cfg as the server's next revision and puts it on its host,
// as an edit through HyRoute does.
func (w *world) rev(server int64, h *host, cfg string) {
	w.t.Helper()
	h.mu.Lock()
	h.files[cfgPath] = []byte(cfg)
	h.restart(unitName)
	h.mu.Unlock()
	c := model.ServerConfig{ServerID: server, SHA256: sha([]byte(cfg)), Meta: model.ConfigMeta{TLS: "acme"}, Source: model.ConfigEdit, At: time.Now()}
	if err := w.db.AddConfig(context.Background(), &c, func(r int) ([]byte, error) { return w.keys.Seal([]byte(cfg), model.ConfigContext(server, r)) }); err != nil {
		w.t.Fatal(err)
	}
}

func TestUnlinkDeletesChain(t *testing.T) {
	w := linked(t, exitUP)
	unit := UnitName(w.chain, 0)
	j, log := w.unlink(true)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	exitNow, _ := w.exit.file(cfgPath)
	ec, _ := hyconfig.ParseServer([]byte(exitNow))
	if HasUser(ec, User(w.chain, 0)) || ec.Auth.UserPass["alice"] != "fake-alice-pass" || w.exit.unit(unitName) != "active" {
		t.Fatalf("exit users %v", ec.Auth.UserPass)
	}
	entryNow, _ := w.entry.file(cfgPath)
	if nc, _ := hyconfig.ParseServer([]byte(entryNow)); HasOutbound(nc) || len(nc.Outbounds) != 0 || w.entry.unit(unitName) != "active" {
		t.Fatalf("entry outbounds %+v", nc.Outbounds)
	}
	for _, f := range []string{linkCfg(w), "/etc/systemd/system/" + unit, cfgPath + Backup, linkCfg(w) + Backup} {
		if _, found := w.entry.file(f); found {
			t.Fatalf("%s left on the entry", f)
		}
	}
	if w.entry.unit(unit) == "active" {
		t.Fatal("link service still runs")
	}
	if _, err := w.db.ChainByID(context.Background(), w.chain); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("chain: %v", err)
	}
	for _, s := range []int64{w.in, w.out} {
		srv, _ := w.db.ServerByID(context.Background(), s)
		if srv.Role != model.RoleStandalone || len(w.revs(s)) != 3 || w.revs(s)[0].Source != model.ConfigCascade {
			t.Fatalf("server %d: role %s, %d revisions", s, srv.Role, len(w.revs(s)))
		}
	}
	if !strings.Contains(log, "каскад удалён") {
		t.Fatalf("log:\n%s", log)
	}
}

// Without delete the chain stays with a link that is new again, without
// secrets; it deploys again with new ones.
func TestUnlinkKeepsChain(t *testing.T) {
	w := linked(t, exitPW)
	old := w.secrets()
	if j, log := w.unlink(false); j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if l := w.link(); l.State != model.LinkNew || l.ConfigSHA256 != "" {
		t.Fatalf("link %+v", l)
	}
	if sealed, _ := w.db.LinkSecrets(context.Background(), w.chain, 0); sealed != nil {
		t.Fatal("secrets kept")
	}
	if now, _ := w.exit.file(cfgPath); now != exitPW || w.exit.restarts(unitName) != 0 {
		t.Fatal("a password exit was touched")
	}
	if j, log := w.wait(w.submit()); j.State != model.JobCompleted {
		t.Fatalf("again: %s\n%s", j.ErrorMessage, log)
	}
	if w.secrets().SOCKSPassword == old.SOCKSPassword || w.link().State != model.LinkActive {
		t.Fatal("deployed again with the old secrets")
	}
}

// The entry does not run without the outbound (a stand-in for any
// failure): it gets it back, and the rest of the link is left as it was.
func TestUnlinkRollsBack(t *testing.T) {
	w := linked(t, exitUP)
	w.entry.mu.Lock()
	w.entry.need = OutboundName
	w.entry.mu.Unlock()
	exitBefore, _ := w.exit.file(cfgPath)
	j, log := w.unlink(true)
	if j.State != model.JobFailed {
		t.Fatalf("%s\n%s", j.State, log)
	}
	if now, _ := w.entry.file(cfgPath); !strings.Contains(now, OutboundName) || w.entry.unit(unitName) != "active" {
		t.Fatal("entry not restored")
	}
	unit := UnitName(w.chain, 0)
	if _, found := w.entry.file("/etc/systemd/system/" + unit); !found || w.entry.unit(unit) != "active" {
		t.Fatal("the link service was touched")
	}
	if now, _ := w.exit.file(cfgPath); now != exitBefore {
		t.Fatal("exit touched")
	}
	if w.link().State != model.LinkActive {
		t.Fatalf("link %s", w.link().State)
	}
}

func TestUnlinkNotDeployed(t *testing.T) {
	w := newWorld(t, exitUP)
	if _, err := w.linker.Unlink(context.Background(), w.chain, 0, true, 0); !errors.Is(err, ErrNotDeployed) {
		t.Fatalf("%v", err)
	}
}

// The exit moves to another address (no new revision): its link client
// would get the new one, so the link is stale.
func TestSyncExitMoved(t *testing.T) {
	w := linked(t, exitUP)
	ctx := context.Background()
	s, _ := w.db.ServerByID(ctx, w.out)
	s.Host = "203.0.113.99"
	if err := w.db.UpdateServer(ctx, &s, nil, nil); err != nil {
		t.Fatal(err)
	}
	c, _ := w.db.ChainByID(ctx, w.chain)
	if c, _ = w.linker.Sync(ctx, c); c.Links[0].State != model.LinkStale {
		t.Fatalf("after the exit moved: %s", c.Links[0].State)
	}
}

// A change on a server that breaks the link marks it stale; deploying
// again fixes it; a change that does not touch the link keeps it active.
func TestSync(t *testing.T) {
	w := linked(t, exitUP)
	ctx := context.Background()
	c, _ := w.db.ChainByID(ctx, w.chain)
	if c, _ = w.linker.Sync(ctx, c); c.Links[0].State != model.LinkActive {
		t.Fatalf("fresh link: %s", c.Links[0].State)
	}

	// Every user's password rotated on the exit.
	exitNow, _ := w.exit.file(cfgPath)
	ec, _ := hyconfig.ParseServer([]byte(exitNow))
	ec.Auth.UserPass[User(w.chain, 0)] = "fake-rotated-pass"
	rotated, _ := ec.Marshal()
	w.rev(w.out, w.exit, string(rotated))
	if c, _ = w.linker.Sync(ctx, c); c.Links[0].State != model.LinkStale || w.link().State != model.LinkStale {
		t.Fatalf("after rotation: %s", w.link().State)
	}
	if j, log := w.wait(w.submit()); j.State != model.JobCompleted {
		t.Fatalf("refresh: %s\n%s", j.ErrorMessage, log)
	}
	c, _ = w.db.ChainByID(ctx, w.chain)
	if c, _ = w.linker.Sync(ctx, c); c.Links[0].State != model.LinkActive {
		t.Fatalf("after refresh: %s", c.Links[0].State)
	}

	// An edit of the entry that keeps the outbound.
	entryNow, _ := w.entry.file(cfgPath)
	w.rev(w.in, w.entry, entryNow+"bandwidth:\n  up: 100 mbps\n  down: 200 mbps\n")
	c, _ = w.linker.Sync(ctx, c)
	cur, _ := w.db.CurrentConfig(ctx, w.in)
	if l := w.link(); l.State != model.LinkActive || l.FromRevision != cur.Revision {
		t.Fatalf("after an unrelated edit: %s, revision %d of %d", l.State, l.FromRevision, cur.Revision)
	}

	// A deploy over the entry that drops the outbound.
	w.rev(w.in, w.entry, entryYAML)
	if c, _ = w.linker.Sync(ctx, c); c.Links[0].State != model.LinkStale {
		t.Fatalf("after a deploy: %s", c.Links[0].State)
	}
}
