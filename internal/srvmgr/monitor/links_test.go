package monitor

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// links stands for cascade.Checker: the entry's link is down.
type links struct {
	mu      sync.Mutex
	entry   int64
	checked []int64
}

func (l *links) HasLinks(_ context.Context, id int64) bool { return id == l.entry }

func (l *links) CheckLinks(_ context.Context, srv model.Server, _ remote.Executor) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.checked = append(l.checked, srv.ID)
	return "каскад до «Exit» не работает: сервер выхода не отвечает клиенту связи", nil
}

func (l *links) Prune(context.Context, time.Time) error { return nil }

// An entry whose link is down is degraded, with the link as the reason;
// the servers of a job on two servers are both left to the job.
func TestHealthCascadeLinks(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)})
	bx := &boxes{m: map[int64]*box{}, probed: map[string]string{}}
	const cfg = "listen: :443\nauth:\n  type: password\n  password: fake-health-auth\n"
	mk := func(name string) int64 {
		s := model.Server{Name: name, Host: "pending", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateHealthy}
		db.CreateServer(ctx, &s, nil)
		s.Host = hostOf(s.ID)
		db.UpdateServer(ctx, &s, nil, nil)
		db.SetHostKey(ctx, model.HostKey{ServerID: s.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
		db.SetInstallation(ctx, model.Installation{ServerID: s.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
		c := model.ServerConfig{ServerID: s.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now()}
		db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(cfg), model.ConfigContext(s.ID, rev)) })
		bx.m[s.ID] = &box{service: "active", port: 443}
		return s.ID
	}
	entry, exit, a, b := mk("Entry"), mk("Exit"), mk("A"), mk("B")
	j := model.Job{Kind: "link", ServerID: a, Servers: []int64{b}, State: model.JobQueued, Params: []byte("{}"), CreatedAt: time.Now()}
	if err := db.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "connect"}}, nil); err != nil {
		t.Fatal(err)
	}
	lk := &links{entry: entry}
	c := &Collector{Store: db, Conn: bx, Keys: keys, Probe: bx.probe, Links: lk}
	c.Round(ctx)
	last := func(id int64) model.Health {
		hs, _ := db.HealthHistory(ctx, id, time.Time{}, 1)
		if len(hs) == 0 {
			return model.Health{}
		}
		return hs[0]
	}
	if h := last(entry); h.Status != model.StateDegraded || h.Reason != "Каскад до «Exit» не работает: сервер выхода не отвечает клиенту связи" {
		t.Fatalf("entry %+v", h)
	}
	if h := last(exit); h.Status != model.StateHealthy {
		t.Fatalf("exit %+v", h)
	}
	if len(lk.checked) != 1 || lk.checked[0] != entry {
		t.Fatalf("checked %v", lk.checked)
	}
	for _, id := range []int64{a, b} {
		if h := last(id); h.Status != "" {
			t.Fatalf("server %d of a job checked: %+v", id, h)
		}
	}
}
