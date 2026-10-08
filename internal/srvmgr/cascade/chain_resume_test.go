package cascade

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// interrupted deploys the three-node chain and stops the controller while
// the relay checks the link to the exit: the exit has the link's user, the
// relay runs the link's client. before is every host as it was.
func interrupted(t *testing.T) (w *chainWorld, j model.Job, before []string) {
	t.Helper()
	w = three(t)
	before = w.snapshot()
	relay := w.hosts[1]
	reached := make(chan struct{})
	var once sync.Once
	block := make(chan struct{})
	relay.mu.Lock()
	relay.pingHook = func() {
		once.Do(func() { close(reached) })
		<-block
	}
	relay.mu.Unlock()
	j, err := w.linker.Deploy(context.Background(), w.chain, 0)
	if err != nil {
		t.Fatal(err)
	}
	<-reached
	stopped := make(chan struct{})
	go func() { w.stop(); close(stopped) }()
	time.Sleep(30 * time.Millisecond) // the controller is cancelled
	relay.mu.Lock()
	relay.pingHook = nil
	relay.mu.Unlock()
	close(block)
	<-stopped
	if _, found := relay.file(w.linkCfgOf(1)); !found || relay.unit(UnitName(w.chain, 1)) != "active" {
		t.Fatal("the relay does not run the link's client when the controller stops")
	}
	return w, j, before
}

// The controller dies while the relay checks the link to the exit, in
// the middle of a three-node deployment: the next controller goes on from
// the check, skips what is done and stores each server's revision once.
func TestChainResumesAfterRestart(t *testing.T) {
	w, j, _ := interrupted(t)
	w.linker, w.stop = w.controller()
	j, log := w.wait(j)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s %s\n%s", j.State, j.ErrorMessage, j.ErrorDetails, log)
	}
	if !strings.Contains(log, "с шага «check»") {
		t.Fatalf("not resumed from the check\n%s", log)
	}
	for i, id := range w.ids {
		if n := len(w.revs(id)); n != 2 {
			t.Errorf("server %d: %d revisions, want the base and one", i, n)
		}
	}
	for i, l := range w.links() {
		if l.State != model.LinkActive {
			t.Errorf("link %d: %s", i, l.State)
		}
	}
	// The exit was restarted before the controller died and not again.
	if n := w.hosts[2].restarts(unitName); n != 1 {
		t.Fatalf("exit restarted %d times\n%s", n, log)
	}
}

// The check the recovery goes on from fails (the entry's config was
// edited meanwhile): the rollback undoes what the interrupted attempt did,
// though this attempt never got to it again. The relay and the exit are
// as before, and the links failed.
func TestChainRecoveryCheckFailsRollsBack(t *testing.T) {
	w, j, before := interrupted(t)
	edited := entryYAML + "# edited over SSH\n"
	w.entry.mu.Lock()
	w.entry.files[cfgPath] = []byte(edited)
	w.entry.mu.Unlock()
	w.linker, w.stop = w.controller()
	j, log := w.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "check" || !strings.Contains(j.ErrorMessage, "изменили не через HyRoute") {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if got := w.snapshot(); fmt.Sprint(got[1:]) != fmt.Sprint(before[1:]) {
		t.Fatalf("relay and exit not as before:\n%v\n%v\n%s", before[1:], got[1:], log)
	}
	if now, _ := w.entry.file(cfgPath); now != edited {
		t.Fatalf("the entry's edit is gone:\n%s", now)
	}
	for i, l := range w.links() {
		if l.State != model.LinkFailed {
			t.Fatalf("link %d %s", i, l.State)
		}
	}
	for i, id := range w.ids {
		if s, _ := w.db.ServerByID(context.Background(), id); s.State != model.StateHealthy {
			t.Fatalf("server %d %s", i, s.State)
		}
	}
}

// The recovery's check cannot reach the exit: the rollback takes the
// link's client off the relay but cannot take the link's user off the
// exit. The links count as deployed (stale) and every server needs
// attention; once the exit answers, a retry finishes the chain.
func TestChainRecoveryWithoutExit(t *testing.T) {
	w, j, _ := interrupted(t)
	ctx := context.Background()
	relay := w.hosts[1]
	w.exit.setGone(true)
	w.linker, w.stop = w.controller()
	j, log := w.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "check" || !strings.Contains(log, "Откат не удался") {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	_, cfgLeft := relay.file(w.linkCfgOf(1))
	_, unitLeft := relay.file("/etc/systemd/system/" + UnitName(w.chain, 1))
	if cfgLeft || unitLeft || relay.unit(UnitName(w.chain, 1)) == "active" {
		t.Fatalf("the link's client left on the relay: config %v, unit %v, %s\n%s", cfgLeft, unitLeft, relay.unit(UnitName(w.chain, 1)), log)
	}
	for i, l := range w.links() {
		if l.State != model.LinkStale {
			t.Fatalf("link %d %s", i, l.State)
		}
	}
	for i, id := range w.ids {
		if s, _ := w.db.ServerByID(ctx, id); s.State != model.StateNeedsAttention {
			t.Fatalf("server %d %s", i, s.State)
		}
	}

	w.exit.setGone(false)
	r, err := w.linker.x.Jobs.Retry(ctx, j.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if j, log = w.wait(r); j.State != model.JobCompleted {
		t.Fatalf("retry: %s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	for i, l := range w.links() {
		if l.State != model.LinkActive {
			t.Fatalf("after the retry link %d %s", i, l.State)
		}
	}
}
