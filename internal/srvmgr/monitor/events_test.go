package monitor

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/events"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/quicprobe"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// heard records what the collector tells Events.
type heard struct {
	mu      sync.Mutex
	servers map[int64][]model.ServerState
	disks   map[int64]uint64
	network []bool
}

func (h *heard) Server(_ context.Context, srv model.Server, st model.ServerState, _ string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.servers == nil {
		h.servers = map[int64][]model.ServerState{}
	}
	h.servers[srv.ID] = append(h.servers[srv.ID], st)
}

func (h *heard) Disk(_ context.Context, srv model.Server, used, _ uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.disks == nil {
		h.disks = map[int64]uint64{}
	}
	h.disks[srv.ID] = used
}

func (h *heard) Network(_ context.Context, online bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.network = append(h.network, online)
}

// netServers makes servers with Hysteria installed (n of them) in a
// fresh database; bx answers for them.
func netServers(t *testing.T, n int) (*sqlite.DB, *boxes, *secrets.Keyring, []int64) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)})
	bx := &boxes{m: map[int64]*box{}, probed: map[string]string{}}
	const cfg = "listen: :443\nauth:\n  type: password\n  password: fake-net-auth\n"
	var ids []int64
	for i := range n {
		s := model.Server{Name: "s" + string(rune('0'+i)), Host: "pending", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateHealthy}
		if err := db.CreateServer(ctx, &s, nil); err != nil {
			t.Fatal(err)
		}
		s.Host = hostOf(s.ID)
		db.UpdateServer(ctx, &s, nil, nil)
		db.SetHostKey(ctx, model.HostKey{ServerID: s.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
		db.SetInstallation(ctx, model.Installation{ServerID: s.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
		c := model.ServerConfig{ServerID: s.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now()}
		db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(cfg), model.ConfigContext(s.ID, rev)) })
		bx.m[s.ID] = &box{service: "active", port: 443}
		ids = append(ids, s.ID)
	}
	return db, bx, keys, ids
}

// When no server answers a round, the collector asks whether the
// controller itself has network: without it no state changes and no
// check is stored; with it the servers go offline as before.
func TestNoNetwork(t *testing.T) {
	ctx := context.Background()
	db, bx, keys, ids := netServers(t, 3)
	for _, id := range ids {
		bx.m[id].down, bx.m[id].udp = true, quicprobe.ErrNoAnswer
	}
	var asked atomic.Int32
	online := false
	h := &heard{}
	c := &Collector{Store: db, Conn: bx, Keys: keys, Probe: bx.probe, Events: h,
		Online: func(context.Context) bool { asked.Add(1); return online }}
	state := func(id int64) model.ServerState {
		s, _ := db.ServerByID(ctx, id)
		return s.State
	}
	checks := func(id int64) int {
		hs, _ := db.HealthHistory(ctx, id, time.Time{}, 0)
		return len(hs)
	}
	c.Round(ctx)
	c.Round(ctx)
	for _, id := range ids {
		if state(id) != model.StateHealthy || checks(id) != 0 {
			t.Fatalf("server %d without the controller's network: %s, %d checks", id, state(id), checks(id))
		}
	}
	if asked.Load() != 2 || len(h.servers) != 0 || len(h.network) != 2 || h.network[0] || h.network[1] || !c.Offline() {
		t.Fatalf("asked %d, heard %+v", asked.Load(), h)
	}

	// The network is back, the servers are still down: offline now.
	online = true
	c.Round(ctx)
	for _, id := range ids {
		if state(id) != model.StateOffline || checks(id) != 1 {
			t.Fatalf("server %d: %s, %d checks", id, state(id), checks(id))
		}
	}
	if len(h.network) != 3 || !h.network[2] || c.Offline() || len(h.servers) != 3 {
		t.Fatalf("heard %+v", h)
	}

	// One server answers: the network is not asked about.
	bx.m[ids[0]].down, bx.m[ids[0]].udp = false, nil
	c.Round(ctx)
	if asked.Load() != 3 || state(ids[0]) != model.StateHealthy {
		t.Fatalf("asked %d, state %s", asked.Load(), state(ids[0]))
	}
	if h.disks[ids[0]] == 0 {
		t.Fatalf("disk not heard: %+v", h.disks)
	}
}

// One server that does not answer is no sign of the controller's
// network.
func TestNoNetworkOneServer(t *testing.T) {
	ctx := context.Background()
	db, bx, keys, ids := netServers(t, 1)
	bx.m[ids[0]].down, bx.m[ids[0]].udp = true, quicprobe.ErrNoAnswer
	var asked atomic.Int32
	c := &Collector{Store: db, Conn: bx, Keys: keys, Probe: bx.probe, Online: func(context.Context) bool { asked.Add(1); return false }}
	c.Round(ctx)
	if s, _ := db.ServerByID(ctx, ids[0]); asked.Load() != 0 || s.State != model.StateOffline {
		t.Fatalf("asked %d, state %s", asked.Load(), s.State)
	}
}

// Rounds of the collector raise a server's event after the threshold
// and close it on recovery; the controller without network gives one
// event and leaves the servers' alone. Fake executor, fake time.
func TestMonitorEvents(t *testing.T) {
	ctx := context.Background()
	db, bx, keys, ids := netServers(t, 2)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	bus := &events.Bus{Store: db, Now: clock}
	var mu sync.Mutex
	var told []events.Notice
	bus.Subscribe(func(n events.Notice) { mu.Lock(); told = append(told, n); mu.Unlock() })
	take := func() []events.Notice {
		mu.Lock()
		defer mu.Unlock()
		out := told
		told = nil
		return out
	}
	online := true
	c := &Collector{Store: db, Conn: bx, Keys: keys, Probe: bx.probe, Now: clock,
		Events: &events.Watcher{Bus: bus, Threshold: 3}, Online: func(context.Context) bool { return online }}
	round := func() {
		now = now.Add(time.Minute)
		c.Round(ctx)
	}
	round()
	bx.m[ids[0]].service = "failed"
	round()
	round()
	if n := take(); len(n) != 0 {
		t.Fatalf("before the threshold: %+v", n)
	}
	round()
	n := take()
	if len(n) != 1 || n[0].Closed || !strings.HasPrefix(n[0].Event.Text, "Сервер «s0» работает с проблемами. Служба hysteria-server.service: failed") {
		t.Fatalf("after the threshold: %+v", n)
	}
	if strings.Contains(n[0].Event.Text, hostOf(ids[0])) {
		t.Fatalf("an address in %q", n[0].Event.Text)
	}

	// The controller loses its network: one event, no other.
	for _, id := range ids {
		bx.m[id].down, bx.m[id].udp = true, quicprobe.ErrNoAnswer
	}
	online = false
	for range 5 {
		round()
	}
	n = take()
	if len(n) != 1 || n[0].Event.Kind != model.EventNetwork {
		t.Fatalf("without network: %+v", n)
	}
	if s, _ := db.ServerByID(ctx, ids[1]); s.State != model.StateHealthy {
		t.Fatalf("state without network: %s", s.State)
	}

	// Back, both healthy: the network event closes at once, the server's
	// after three rounds.
	online = true
	for _, id := range ids {
		bx.m[id].down, bx.m[id].udp, bx.m[id].service = false, nil, "active"
	}
	round()
	if n := take(); len(n) != 1 || !n[0].Closed || n[0].Event.Kind != model.EventNetwork {
		t.Fatalf("network back: %+v", n)
	}
	round()
	round()
	if n := take(); len(n) != 1 || !n[0].Closed || n[0].Event.Kind != model.EventServer || n[0].Event.CloseText != "Сервер «s0» снова работает." {
		t.Fatalf("recovery: %+v", n)
	}
}
