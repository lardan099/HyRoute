package monitor

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/quicprobe"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// box is a server as the health check sees it.
type box struct {
	down    bool   // SSH unreachable
	service string // systemctl is-active
	port    int    // what ss shows Hysteria listening on
	udp     error  // the probe's answer
}

type boxes struct {
	mu     sync.Mutex
	m      map[int64]*box
	probed map[string]string // addr → obfs password the probe got
}

func (b *boxes) Connect(_ context.Context, id int64) (remote.Executor, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	x := b.m[id]
	if x.down {
		return nil, &remote.UnreachableError{Err: errors.New("connection timed out")}
	}
	ex := fake.New()
	ex.On("head").Reply(sample(100, 900, 1, 1, 50), 0)
	ex.On("df").Reply("x\n/dev/vda1 1000 100 900 10% /\n", 0)
	code := 0
	if x.service != "active" {
		code = 3
	}
	ex.On("systemctl", "is-active").Reply(x.service+"\n", code)
	ex.On("ss").Reply("udp UNCONN 0 0 *:"+strconv.Itoa(x.port)+" *:*\n", 0)
	ex.On("ip").Reply("1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.44 uid 0 \\    cache\n", 0)
	return ex, nil
}

func (b *boxes) probe(_ context.Context, addr, obfs string) (time.Duration, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probed[addr] = obfs
	for id, x := range b.m {
		if strings.HasPrefix(addr, hostOf(id)+":") {
			if x.udp != nil {
				return 0, x.udp
			}
			return 12 * time.Millisecond, nil
		}
	}
	return 0, quicprobe.ErrNoAnswer
}

func hostOf(id int64) string { return "h" + string(rune('a'+id)) + ".example.com" }

func TestHealth(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)})
	bx := &boxes{m: map[int64]*box{}, probed: map[string]string{}}

	// Each server: Hysteria on UDP 443 (the last one with Salamander).
	mk := func(n int, st model.ServerState, b *box, cfg string) int64 {
		s := model.Server{Name: "s" + string(rune('0'+n)), SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: st}
		s.Host = "pending"
		if err := db.CreateServer(ctx, &s, nil); err != nil {
			t.Fatal(err)
		}
		s.Host = hostOf(s.ID)
		db.UpdateServer(ctx, &s, nil, nil)
		db.SetHostKey(ctx, model.HostKey{ServerID: s.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
		db.SetInstallation(ctx, model.Installation{ServerID: s.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
		c := model.ServerConfig{ServerID: s.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now()}
		db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(cfg), model.ConfigContext(s.ID, rev)) })
		bx.m[s.ID] = b
		return s.ID
	}
	const plain = "listen: :443\nauth:\n  type: password\n  password: fake-health-auth\n"
	const obfs = plain + "obfs:\n  type: salamander\n  salamander:\n    password: fake-health-obfs\n"
	good := mk(1, model.StateOffline, &box{service: "active", port: 443}, plain)
	closed := mk(2, model.StateHealthy, &box{service: "active", port: 443, udp: quicprobe.ErrNoAnswer}, plain)
	stopped := mk(3, model.StateHealthy, &box{service: "failed", port: 0, udp: quicprobe.ErrNoAnswer}, plain)
	gone := mk(4, model.StateHealthy, &box{down: true, udp: quicprobe.ErrNoAnswer}, plain)
	noSSH := mk(5, model.StateHealthy, &box{down: true}, plain)
	attention := mk(6, model.StateNeedsAttention, &box{service: "failed", udp: quicprobe.ErrNoAnswer}, plain)
	busy := mk(7, model.StateHealthy, &box{service: "inactive", udp: quicprobe.ErrNoAnswer}, plain)
	obfsSrv := mk(8, model.StateHealthy, &box{service: "active", port: 443}, obfs)
	j := model.Job{Kind: "apply", ServerID: busy, State: model.JobQueued, Params: []byte("{}"), CreatedAt: time.Now()}
	if err := db.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "connect"}}, nil); err != nil {
		t.Fatal(err)
	}

	c := &Collector{Store: db, Conn: bx, Keys: keys, Probe: bx.probe}
	c.Round(ctx)

	last := func(id int64) model.Health {
		hs, _ := db.HealthHistory(ctx, id, time.Time{}, 1)
		if len(hs) == 0 {
			return model.Health{}
		}
		return hs[0]
	}
	state := func(id int64) model.ServerState {
		s, _ := db.ServerByID(ctx, id)
		return s.State
	}
	for _, tc := range []struct {
		id     int64
		status model.ServerState
		state  model.ServerState
		reason string
	}{
		{good, model.StateHealthy, model.StateHealthy, ""},
		{closed, model.StateDegraded, model.StateDegraded, "UDP 443 не отвечает снаружи"},
		{stopped, model.StateDegraded, model.StateDegraded, "Служба hysteria-server.service: failed"},
		{gone, model.StateOffline, model.StateOffline, "SSH не отвечает; UDP 443 тоже не отвечает"},
		{noSSH, model.StateDegraded, model.StateDegraded, "но Hysteria отвечает на UDP 443"},
		{attention, model.StateDegraded, model.StateNeedsAttention, "failed"}, // recorded, state is the admin's
		{obfsSrv, model.StateHealthy, model.StateHealthy, ""},
	} {
		h := last(tc.id)
		if h.Status != tc.status || state(tc.id) != tc.state || !strings.Contains(h.Reason, tc.reason) {
			t.Errorf("server %d: check %s (%q), state %s", tc.id, h.Status, h.Reason, state(tc.id))
		}
		if !utf8.ValidString(h.Reason) {
			t.Errorf("server %d: reason is not UTF-8: %q", tc.id, h.Reason)
		}
		if strings.Contains(h.Reason, "fake-health") {
			t.Errorf("secret in the reason: %q", h.Reason)
		}
	}
	if h := last(good); h.Egress != "192.0.2.44" || h.SSHMillis < 1 || h.UDP != model.UDPOK || h.UDPMillis != 12 || h.Listening == nil || !*h.Listening || h.Service != "active" {
		t.Errorf("good: %+v", h)
	}
	if h := last(busy); h.Status != "" || state(busy) != model.StateHealthy {
		t.Errorf("a server with a job was checked: %+v", h)
	}
	if bx.probed[hostOf(obfsSrv)+":443"] != "fake-health-obfs" || bx.probed[hostOf(good)+":443"] != "" {
		t.Errorf("probes %v", bx.probed)
	}
	// A week later the history is pruned.
	c.Now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	c.lastCompact = time.Time{}
	c.Round(ctx)
	if hs, _ := db.HealthHistory(ctx, good, time.Time{}, 0); len(hs) != 1 {
		t.Errorf("history after a week: %d checks", len(hs))
	}
}
