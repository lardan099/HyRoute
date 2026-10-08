package alerts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/monitor"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// unreachable is every server not answering SSH.
type unreachable struct{}

func (unreachable) Connect(context.Context, int64) (remote.Executor, error) {
	return nil, &remote.UnreachableError{Err: errors.New("i/o timeout")}
}

// A channel that does not answer does not hold up monitoring: the rounds
// that raise events end at once while its send hangs.
func TestHungChannelMonitoring(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	h, s := newHook(t)
	h.block = make(chan struct{})
	e.webhook(s.URL)
	e.n.Glue, e.n.Timeout = time.Millisecond, time.Minute
	e.start()
	if err := e.db.SetHostKey(ctx, model.HostKey{ServerID: e.srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	e.db.SetServerState(ctx, e.srv.ID, model.StateHealthy, time.Now())
	c := &monitor.Collector{Store: e.db, Conn: unreachable{}, Events: &events.Watcher{Bus: e.bus, Threshold: 1}}
	start := time.Now()
	c.Round(ctx)
	h.wait(t, 1) // the notification is out and hangs
	for range 3 {
		c.Round(ctx)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("four rounds took %v with a hung channel", took)
	}
	if srv, _ := e.db.ServerByID(ctx, e.srv.ID); srv.State != model.StateOffline {
		t.Fatalf("state %s", srv.State)
	}
}
