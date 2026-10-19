package monitor

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// sample is /proc as head prints it: busy/total jiffies, bytes in/out,
// uptime.
func sample(busy, idle, rx, tx uint64, uptime float64) string {
	return fmt.Sprintf(`==> /proc/stat <==
cpu  %d 0 0 %d 0 0 0 0 0 0

==> /proc/meminfo <==
MemTotal:        2097152 kB
MemAvailable:    1048576 kB

==> /proc/loadavg <==
0.50 0.40 0.30 1/100 42

==> /proc/net/dev <==
Inter-|   Receive |  Transmit
 face |bytes    packets|bytes
  eth0: %d 1 0 0 0 0 0 0 %d 1 0 0 0 0 0 0

==> /proc/uptime <==
%g 0
`, busy, idle, rx, tx, uptime)
}

type conn struct {
	mu   sync.Mutex
	out  map[int64]string // what head prints on each server
	down map[int64]bool
}

func (c *conn) Connect(_ context.Context, id int64) (remote.Executor, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.down[id] {
		return nil, &remote.UnreachableError{Err: errors.New("i/o timeout")}
	}
	ex := fake.New()
	ex.On("head").Reply(c.out[id], 0)
	ex.On("df").Reply("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 2097152 524288 1572864 25% /\n", 0)
	return ex, nil
}

// silent is a connection to a server that stopped answering mid-session:
// commands ignore their context and return only when it is closed.
type silent struct {
	*fake.Executor
	once   sync.Once
	closed chan struct{}
}

func (s *silent) Run(context.Context, remote.Cmd) (remote.Result, error) {
	<-s.closed
	return remote.Result{}, errors.New("connection closed")
}

func (s *silent) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

// hung is conn with one server whose connection hangs.
type hung struct {
	*conn
	id int64
}

func (h hung) Connect(ctx context.Context, id int64) (remote.Executor, error) {
	if id == h.id {
		return &silent{Executor: fake.New(), closed: make(chan struct{})}, nil
	}
	return h.conn.Connect(ctx, id)
}

// A server that hangs mid-session is cut off at the timeout: the round
// ends and the other servers are sampled.
func TestCollectorHungServer(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var ids []int64
	for _, name := range []string{"stuck", "fine"} {
		s := model.Server{Name: name, Host: name + ".example.com", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
		if err := db.CreateServer(ctx, &s, nil); err != nil {
			t.Fatal(err)
		}
		db.SetHostKey(ctx, model.HostKey{ServerID: s.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
		ids = append(ids, s.ID)
	}
	cn := &conn{out: map[int64]string{}, down: map[int64]bool{}}
	cn.set(ids[1], sample(1000, 9000, 1, 1, 100), false)
	now := time.Now()
	c := &Collector{Store: db, Conn: hung{cn, ids[0]}, Now: func() time.Time { return now }, Timeout: 300 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		c.Round(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a hung server stalled the round")
	}
	if pts, _ := db.Metrics(ctx, ids[1], 0, now.Add(-time.Hour), now.Add(time.Hour)); len(pts) != 1 {
		t.Fatalf("the other server: %d points", len(pts))
	}
}

func (c *conn) set(id int64, out string, down bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.out[id], c.down[id] = out, down
}

func TestCollector(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mk := func(name string, st model.ServerState, trusted bool) int64 {
		s := model.Server{Name: name, Host: name + ".example.com", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: st}
		if err := db.CreateServer(ctx, &s, nil); err != nil {
			t.Fatal(err)
		}
		if trusted {
			db.SetHostKey(ctx, model.HostKey{ServerID: s.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
		}
		return s.ID
	}
	a := mk("a", model.StateHealthy, true)
	b := mk("b", model.StateHealthy, true)
	deploying := mk("c", model.StateDeploying, true)
	untrusted := mk("d", model.StateNew, false)

	cn := &conn{out: map[int64]string{}, down: map[int64]bool{}}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	c := &Collector{Store: db, Conn: cn, Now: func() time.Time { return now }}
	cn.set(a, sample(1000, 9000, 1_000_000, 2_000_000, 100), false)
	cn.set(b, "", true)
	cn.set(deploying, "", true)
	cn.set(untrusted, sample(1, 1, 1, 1, 1), false)
	c.Round(ctx)

	state := func(id int64) model.ServerState {
		s, _ := db.ServerByID(ctx, id)
		return s.State
	}
	if state(b) != model.StateOffline || state(deploying) != model.StateDeploying {
		t.Fatalf("states b=%s deploying=%s", state(b), state(deploying))
	}
	pts, _ := db.Metrics(ctx, a, 0, now.Add(-time.Hour), now.Add(time.Hour))
	if len(pts) != 1 || pts[0].CPU != nil || pts[0].MemUsedMiB != 1024 || pts[0].DiskUsedMiB != 512 || pts[0].Load1 != 0.5 {
		t.Fatalf("first point %+v", pts)
	}
	if p, _ := db.Metrics(ctx, untrusted, 0, now.Add(-time.Hour), now.Add(time.Hour)); len(p) != 0 {
		t.Fatal("an untrusted server was sampled")
	}

	// A minute later: 30% busy, 60 KB/s in and 120 KB/s out; b is back.
	now = now.Add(time.Minute)
	cn.set(a, sample(1300, 9700, 4_600_000, 9_200_000, 160), false)
	cn.set(b, sample(5, 5, 5, 5, 5), false)
	c.Round(ctx)
	pts, _ = db.Metrics(ctx, a, 0, now.Add(-time.Hour), now.Add(time.Hour))
	if len(pts) != 2 || pts[1].CPU == nil || *pts[1].CPU != 30 || *pts[1].RxBps != 60000 || *pts[1].TxBps != 120000 {
		t.Fatalf("second point %+v", pts[len(pts)-1])
	}
	if state(b) != model.StateHealthy {
		t.Fatalf("b %s", state(b))
	}

	// A reboot: counters start over, no rates for this point.
	now = now.Add(time.Minute)
	cn.set(a, sample(10, 90, 100, 100, 20), false)
	c.Round(ctx)
	pts, _ = db.Metrics(ctx, a, 0, now.Add(-time.Hour), now.Add(time.Hour))
	if last := pts[len(pts)-1]; last.CPU != nil || last.RxBps != nil {
		t.Fatalf("rates across a reboot: %+v", last)
	}
}
