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

func (h *host) setGone(gone bool) {
	h.mu.Lock()
	h.gone = gone
	h.mu.Unlock()
}

func (h *host) ncmds() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.cmds)
}

// failUnlink: «Удалить каскад» while h does not answer fails at connect
// and changes nothing.
func (w *world) failUnlink(h *host) {
	w.t.Helper()
	h.setGone(true)
	entryBefore, _ := w.entry.file(cfgPath)
	exitBefore, _ := w.exit.file(cfgPath)
	j, log := w.unlink(true)
	if j.State != model.JobFailed || j.CurrentStep != "connect" {
		w.t.Fatalf("unlink: %s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	entryNow, _ := w.entry.file(cfgPath)
	exitNow, _ := w.exit.file(cfgPath)
	if entryNow != entryBefore || exitNow != exitBefore || w.link().State != model.LinkActive {
		w.t.Fatalf("a failed unlink changed something: link %s", w.link().State)
	}
}

func (w *world) unreached() []Unreached {
	w.t.Helper()
	c, err := w.db.ChainByID(context.Background(), w.chain)
	if err != nil {
		w.t.Fatal(err)
	}
	un, err := w.linker.Unreached(context.Background(), c, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return un
}

func (w *world) forceDelete() (model.Job, string) {
	w.t.Helper()
	j, _, err := w.linker.ForceDelete(context.Background(), w.chain, 0, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return w.wait(j)
}

// The exit's VPS is gone: «Удалить каскад» cannot connect to it, and the
// chain is then deleted without it. The entry loses all the link put
// there, as with a normal unlink; the exit is not contacted, keeps its
// revision and needs attention, with a note of the link's user left on it.
func TestForceDeleteWithoutExit(t *testing.T) {
	w := linked(t, exitUP)
	ctx := context.Background()
	if _, _, err := w.linker.ForceDelete(ctx, w.chain, 0, 0); !errors.Is(err, ErrReached) {
		t.Fatalf("before a failed unlink: %v", err)
	}
	w.failUnlink(w.exit)
	un := w.unreached()
	if len(un) != 1 || un[0].Server != w.out || un[0].Entry || len(un[0].Left) != 1 || !strings.Contains(un[0].Left[0], User(w.chain, 0)+" в "+cfgPath) {
		t.Fatalf("unreached %+v", un)
	}
	exitCmds := w.exit.ncmds()
	j, log := w.forceDelete()
	if j.State != model.JobCompleted {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	entryNow, _ := w.entry.file(cfgPath)
	if nc, _ := hyconfig.ParseServer([]byte(entryNow)); HasOutbound(nc) || w.entry.unit(unitName) != "active" {
		t.Fatalf("entry outbounds %+v", nc.Outbounds)
	}
	unit := UnitName(w.chain, 0)
	for _, f := range []string{linkCfg(w), "/etc/systemd/system/" + unit, cfgPath + Backup, linkCfg(w) + Backup} {
		if _, found := w.entry.file(f); found {
			t.Fatalf("%s left on the entry", f)
		}
	}
	if w.entry.unit(unit) == "active" {
		t.Fatal("link service still runs")
	}
	if w.exit.ncmds() != exitCmds {
		t.Fatal("the exit was contacted")
	}
	if _, err := w.db.ChainByID(ctx, w.chain); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("chain: %v", err)
	}
	if _, err := w.db.LinkSecrets(ctx, w.chain, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("link secrets: %v", err)
	}
	if er, xr := w.revs(w.in), w.revs(w.out); len(er) != 3 || er[0].Source != model.ConfigCascade || len(xr) != 2 {
		t.Fatalf("revisions: entry %d, exit %d", len(er), len(xr))
	}
	exit, _ := w.db.ServerByID(ctx, w.out)
	if exit.State != model.StateNeedsAttention || exit.Role != model.RoleStandalone || !strings.Contains(exit.Notes, "Каскад «DE» удалён") || !strings.Contains(exit.Notes, User(w.chain, 0)) {
		t.Fatalf("exit %s %s: %q", exit.State, exit.Role, exit.Notes)
	}
	if entry, _ := w.db.ServerByID(ctx, w.in); entry.State == model.StateNeedsAttention || entry.Notes != "" || entry.Role != model.RoleStandalone {
		t.Fatalf("entry %s %s: %q", entry.State, entry.Role, entry.Notes)
	}
	if !strings.Contains(log, "Сервер выхода не отвечает") || !strings.Contains(log, "сервер выхода пропущен") {
		t.Fatalf("log:\n%s", log)
	}
}

// The entry's VPS is gone: the exit loses the link's user; the entry is
// left with the link service, its client's config and the outbound, and
// its note says so.
func TestForceDeleteWithoutEntry(t *testing.T) {
	w := linked(t, exitUP)
	ctx := context.Background()
	w.failUnlink(w.entry)
	if un := w.unreached(); len(un) != 1 || un[0].Server != w.in || !un[0].Entry || len(un[0].Left) != 3 {
		t.Fatalf("unreached %+v", un)
	}
	entryBefore, _ := w.entry.file(cfgPath)
	entryCmds := w.entry.ncmds()
	j, log := w.forceDelete()
	if j.State != model.JobCompleted {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	exitNow, _ := w.exit.file(cfgPath)
	if ec, _ := hyconfig.ParseServer([]byte(exitNow)); HasUser(ec, User(w.chain, 0)) || ec.Auth.UserPass["alice"] != "fake-alice-pass" || w.exit.unit(unitName) != "active" {
		t.Fatalf("exit users %v", ec.Auth.UserPass)
	}
	if now, _ := w.entry.file(cfgPath); now != entryBefore || w.entry.ncmds() != entryCmds {
		t.Fatal("the entry was contacted")
	}
	if xr := w.revs(w.out); len(xr) != 3 || len(w.revs(w.in)) != 2 {
		t.Fatalf("revisions: entry %d, exit %d", len(w.revs(w.in)), len(xr))
	}
	entry, _ := w.db.ServerByID(ctx, w.in)
	for _, s := range []string{UnitName(w.chain, 0), linkCfg(w), "outbound «cascade» в " + cfgPath} {
		if !strings.Contains(entry.Notes, s) {
			t.Fatalf("entry note without %q: %q", s, entry.Notes)
		}
	}
	if entry.State != model.StateNeedsAttention {
		t.Fatalf("entry %s", entry.State)
	}
	if exit, _ := w.db.ServerByID(ctx, w.out); exit.State == model.StateNeedsAttention || exit.Notes != "" {
		t.Fatalf("exit %s: %q", exit.State, exit.Notes)
	}
}

// A password exit keeps nothing of the link: deleted without it, it is
// not marked.
func TestForceDeletePasswordExit(t *testing.T) {
	w := linked(t, exitPW)
	w.failUnlink(w.exit)
	if un := w.unreached(); len(un) != 1 || len(un[0].Left) != 0 {
		t.Fatalf("unreached %+v", un)
	}
	j, log := w.forceDelete()
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if exit, _ := w.db.ServerByID(context.Background(), w.out); exit.State == model.StateNeedsAttention || exit.Notes != "" {
		t.Fatalf("exit %s: %q", exit.State, exit.Notes)
	}
	if _, found := w.entry.file(linkCfg(w)); found || !strings.Contains(log, "ничего не менял") {
		t.Fatalf("log:\n%s", log)
	}
}

// The chain is deleted without a server only while the normal way cannot
// work: its latest job is «Удалить каскад» that could not reach a server.
func TestForceDeleteRefused(t *testing.T) {
	ctx := context.Background()
	fresh := newWorld(t, exitUP)
	if _, _, err := fresh.linker.ForceDelete(ctx, fresh.chain, 0, 0); !errors.Is(err, ErrNotDeployed) {
		t.Fatalf("not deployed: %v", err)
	}

	// It failed with both servers reached.
	w := linked(t, exitUP)
	w.entry.mu.Lock()
	w.entry.need = OutboundName
	w.entry.mu.Unlock()
	if j, log := w.unlink(true); j.State != model.JobFailed || j.CurrentStep == "connect" {
		t.Fatalf("%s at %s\n%s", j.State, j.CurrentStep, log)
	}
	if _, _, err := w.linker.ForceDelete(ctx, w.chain, 0, 0); !errors.Is(err, ErrReached) || len(w.unreached()) != 0 {
		t.Fatalf("after a failure on a reached server: %v", err)
	}
	w.entry.mu.Lock()
	w.entry.need = ""
	w.entry.mu.Unlock()

	// «Снять связь» is not «Удалить каскад».
	w.exit.setGone(true)
	if j, _ := w.unlink(false); j.State != model.JobFailed {
		t.Fatalf("unlink: %s", j.State)
	}
	if _, _, err := w.linker.ForceDelete(ctx, w.chain, 0, 0); !errors.Is(err, ErrReached) {
		t.Fatalf("after «Снять связь»: %v", err)
	}

	// The exit came back and the link was deployed again since.
	w.failUnlink(w.exit)
	if len(w.unreached()) != 1 {
		t.Fatal("not offered after the failed delete")
	}
	w.exit.setGone(false)
	if j, log := w.wait(w.submit()); j.State != model.JobCompleted {
		t.Fatalf("link: %s\n%s", j.ErrorMessage, log)
	}
	if _, _, err := w.linker.ForceDelete(ctx, w.chain, 0, 0); !errors.Is(err, ErrReached) {
		t.Fatalf("after a newer link job: %v", err)
	}
}

// Both servers answer again when the forced job runs: it is the normal
// unlink.
func TestForceDeleteBothBack(t *testing.T) {
	w := linked(t, exitUP)
	w.failUnlink(w.exit)
	w.exit.setGone(false)
	j, log := w.forceDelete()
	if j.State != model.JobCompleted || !strings.Contains(log, "Оба сервера отвечают") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	exitNow, _ := w.exit.file(cfgPath)
	if ec, _ := hyconfig.ParseServer([]byte(exitNow)); HasUser(ec, User(w.chain, 0)) {
		t.Fatal("the link's user stays on the exit")
	}
	for _, s := range []int64{w.in, w.out} {
		if srv, _ := w.db.ServerByID(context.Background(), s); srv.State == model.StateNeedsAttention || srv.Notes != "" {
			t.Fatalf("server %d %s: %q", s, srv.State, srv.Notes)
		}
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
