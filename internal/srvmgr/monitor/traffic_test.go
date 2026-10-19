package monitor

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// statsBox is a server with the stats API: its counters, its Hysteria
// process and the requests it got.
type statsBox struct {
	mu      sync.Mutex
	pid     int
	traffic string // the /traffic answer
	reqs    []remote.Cmd
}

func (b *statsBox) Connect(context.Context, int64) (remote.Executor, error) {
	ex := fake.New()
	ex.On("head").Reply(sample(100, 900, 1, 1, 50), 0)
	ex.On("df").Reply("x\n/dev/vda1 1000 100 900 10% /\n", 0)
	ex.On("systemctl", "is-active").Reply("active\n", 0)
	ex.On("systemctl", "show").Do(func(remote.Cmd) (remote.Result, error) {
		b.mu.Lock()
		defer b.mu.Unlock()
		return remote.Result{Stdout: []byte(fmt.Sprintf("LoadState=loaded\nActiveState=active\nMainPID=%d\nActiveEnterTimestampMonotonic=%d\n", b.pid, b.pid*1000))}, nil
	})
	ex.On("curl").Do(func(c remote.Cmd) (remote.Result, error) {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.reqs = append(b.reqs, c)
		if !strings.Contains(string(c.Stdin), "Authorization: fake-stats-secret") {
			return remote.Result{Stdout: []byte("\n401")}, nil
		}
		return remote.Result{Stdout: []byte(b.traffic + "\n200")}, nil
	})
	return ex, nil
}

func (b *statsBox) set(pid int, traffic string) {
	b.mu.Lock()
	b.pid, b.traffic = pid, traffic
	b.mu.Unlock()
}

func TestTraffic(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)})
	s := model.Server{Name: "s", Host: "stats.example.com", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	if err := db.CreateServer(ctx, &s, nil); err != nil {
		t.Fatal(err)
	}
	db.SetHostKey(ctx, model.HostKey{ServerID: s.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	db.SetInstallation(ctx, model.Installation{ServerID: s.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	addConfig := func(cfg string) {
		c := model.ServerConfig{ServerID: s.ID, SHA256: "x", Source: model.ConfigEdit, At: time.Now()}
		if err := db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(cfg), model.ConfigContext(s.ID, rev)) }); err != nil {
			t.Fatal(err)
		}
	}
	const base = "listen: :443\nauth:\n  type: password\n  password: fake-traffic-auth\n"
	addConfig(base + "trafficStats:\n  listen: 127.0.0.1:25413\n  secret: fake-stats-secret\n")

	bx := &statsBox{}
	now := time.Date(2026, 10, 1, 12, 10, 0, 0, time.UTC)
	c := &Collector{Store: db, Conn: bx, Keys: keys, Probe: func(context.Context, string, string) (time.Duration, error) { return time.Millisecond, nil }, Now: func() time.Time { return now }}
	round := func(pid int, traffic string) {
		t.Helper()
		bx.set(pid, traffic)
		c.Round(ctx)
		now = now.Add(time.Minute)
	}
	total := func() map[string][2]int64 {
		hs, err := db.Traffic(ctx, s.ID, now.Add(-24*time.Hour), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		m := map[string][2]int64{}
		for _, h := range hs {
			m[h.User] = [2]int64{m[h.User][0] + h.Tx, m[h.User][1] + h.Rx}
		}
		return m
	}

	// The first read only sets the counters: what Hysteria counted before
	// the controller started is not this controller's to attribute.
	round(100, `{"alice":{"tx":1000,"rx":5000}}`)
	if m := total(); len(m) != 0 {
		t.Fatalf("first read stored: %v", m)
	}
	// Growth per user; a new user counts from zero.
	round(100, `{"alice":{"tx":1500,"rx":9000},"bob":{"tx":10,"rx":20}}`)
	if m := total(); m["alice"] != [2]int64{500, 4000} || m["bob"] != [2]int64{10, 20} {
		t.Fatalf("growth: %v", m)
	}
	// Hysteria restarted (another process): its counters are all growth,
	// even where they are above the old ones.
	round(200, `{"alice":{"tx":2000,"rx":100}}`)
	if m := total(); m["alice"] != [2]int64{2500, 4100} || m["bob"] != [2]int64{10, 20} {
		t.Fatalf("restart: %v", m)
	}
	// Into the next hour: a second row.
	now = now.Add(time.Hour)
	round(200, `{"alice":{"tx":2100,"rx":200}}`)
	hs, _ := db.Traffic(ctx, s.ID, now.Add(-24*time.Hour), now.Add(time.Hour))
	if len(hs) != 3 || !hs[2].Hour.Equal(time.Date(2026, 10, 1, 13, 0, 0, 0, time.UTC)) || hs[2].Tx != 100 {
		t.Fatalf("hours: %+v", hs)
	}

	// The secret went only on stdin, never in argv.
	for _, r := range bx.reqs {
		if strings.Contains(strings.Join(r.Args, " "), "fake-stats-secret") || r.Sudo {
			t.Fatalf("request %+v", r)
		}
	}

	// Stats turned off: no request, and the counters start over once
	// they are back on.
	n := len(bx.reqs)
	addConfig(base)
	round(200, `{"alice":{"tx":9999,"rx":9999}}`)
	if len(bx.reqs) != n {
		t.Fatal("stats read while off")
	}
	addConfig(base + "trafficStats:\n  listen: 127.0.0.1:25413\n  secret: fake-stats-secret\n")
	before := total()
	round(200, `{"alice":{"tx":99999,"rx":99999}}`)
	if m := total(); m["alice"] != before["alice"] {
		t.Fatalf("read after re-enabling counted: %v", m)
	}

	// Kept 90 days.
	if err := db.PruneTraffic(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if m := total(); len(m) != 0 {
		t.Fatalf("pruned: %v", m)
	}
}
