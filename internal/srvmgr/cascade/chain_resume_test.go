package cascade

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// The controller dies while the relay checks the link to the exit, in
// the middle of a three-node deployment: the next controller goes on from
// the check, skips what is done and stores each server's revision once.
func TestChainResumesAfterRestart(t *testing.T) {
	w := three(t)
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
