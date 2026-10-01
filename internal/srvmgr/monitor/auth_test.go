package monitor

import (
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
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// refuser is a server that refuses the SSH login unless ok; it counts
// the login attempts.
type refuser struct {
	mu       sync.Mutex
	ok       bool
	attempts int
}

func (r *refuser) Connect(context.Context, int64) (remote.Executor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts++
	if !r.ok {
		return nil, fmt.Errorf("%w: ssh: handshake failed", remote.ErrAuthFailed)
	}
	ex := fake.New()
	ex.On("head").Reply(sample(1, 1, 1, 1, 1), 0)
	ex.On("df").Reply("x\n/dev/vda1 1000 100 900 10% /\n", 0)
	return ex, nil
}

func (r *refuser) set(ok bool) {
	r.mu.Lock()
	r.ok = ok
	r.mu.Unlock()
}

func (r *refuser) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempts
}

func password(pw string) store.SealFunc {
	return func(int64) ([]model.Credential, error) {
		return []model.Credential{{Kind: model.CredSSHPassword, Sealed: []byte(pw)}}, nil
	}
}

// A refused login is not repeated every minute (fail2ban would ban the
// controller): the next attempt waits for new login data or a pause that
// doubles up to authPauseMax.
func TestAuthRefusedPause(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := model.Server{Name: "s", Host: "s.example.com", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	if err := db.CreateServer(ctx, &s, password("fake-old")); err != nil {
		t.Fatal(err)
	}
	db.SetHostKey(ctx, model.HostKey{ServerID: s.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	db.SetInstallation(ctx, model.Installation{ServerID: s.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})

	r := &refuser{}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	c := &Collector{Store: db, Conn: r, Now: func() time.Time { return now }}
	step := func(after time.Duration, attempts int) {
		t.Helper()
		now = now.Add(after)
		c.Round(ctx)
		if got := r.count(); got != attempts {
			t.Fatalf("after %v: %d login attempts, want %d", after, got, attempts)
		}
	}
	step(0, 1)                // refused: a 15 min pause
	step(time.Minute, 1)      // not every minute
	step(13*time.Minute, 1)   // 14 min
	step(2*time.Minute, 2)    // 16 min: refused again, 30 min
	step(29*time.Minute, 2)   // 45 min
	step(2*time.Minute, 3)    // 47 min: 1 h
	step(59*time.Minute, 3)   // 1 h 46 min
	step(2*time.Minute, 4)    // 1 h 48 min: 2 h, then 4 h, then the cap
	for n := 5; n < 12; n++ { // past the cap: one attempt per authPauseMax
		step(authPauseMax+time.Minute, n)
		c.mu.Lock()
		pause := c.refused[s.ID].until.Sub(now)
		c.mu.Unlock()
		if want := min(authPause<<(n-1), authPauseMax); pause != want {
			t.Fatalf("refusal %d: pause %v, want %v", n, pause, want)
		}
	}
	hs, _ := db.HealthHistory(ctx, s.ID, time.Time{}, 1)
	if len(hs) != 1 || hs[0].Status != model.StateDegraded || !strings.HasPrefix(hs[0].Reason, "Сервер отклонил вход по SSH") || !strings.Contains(hs[0].Reason, "Проверьте пользователя, пароль или ключ") {
		t.Fatalf("health %+v", hs)
	}

	// New login data is tried at once.
	if err := db.UpdateServer(ctx, &s, password("fake-new"), nil); err != nil {
		t.Fatal(err)
	}
	step(time.Minute, 12)
	step(time.Minute, 12) // and refused again: paused

	// A login that works forgets the refusals: the next refusal pauses for
	// authPause again.
	r.set(true)
	step(authPause, 13)
	r.set(false)
	step(time.Minute, 14)
	step(authPause-time.Minute, 14)
	step(2*time.Minute, 15)
}
