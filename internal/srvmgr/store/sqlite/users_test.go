package sqlite

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

func TestUsers(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	owner := model.User{Username: "Admin", PasswordHash: "h1", Role: model.RoleOwner, CreatedAt: now, UpdatedAt: now}
	if err := d.CreateFirstUser(ctx, &owner); err != nil || owner.ID == 0 {
		t.Fatalf("first user: %v id %d", err, owner.ID)
	}
	second := model.User{Username: "other", PasswordHash: "h2", Role: model.RoleOwner, CreatedAt: now, UpdatedAt: now}
	if err := d.CreateFirstUser(ctx, &second); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second first user: %v", err)
	}
	dup := model.User{Username: "admin", PasswordHash: "h3", Role: model.RoleReadOnly, CreatedAt: now, UpdatedAt: now}
	if err := d.CreateUser(ctx, &dup); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate name (other case): %v", err)
	}
	ro := model.User{Username: "viewer", PasswordHash: "h4", Role: model.RoleReadOnly, CreatedAt: now, UpdatedAt: now}
	if err := d.CreateUser(ctx, &ro); err != nil {
		t.Fatal(err)
	}
	got, err := d.UserByName(ctx, "ADMIN")
	if err != nil || got.ID != owner.ID || got.Role != model.RoleOwner || !got.CreatedAt.Equal(now) {
		t.Fatalf("by name: %+v %v", got, err)
	}
	if _, err := d.UserByName(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	if n, _ := d.CountUsers(ctx); n != 2 {
		t.Fatalf("count %d", n)
	}
	if err := d.UpdatePasswordHash(ctx, ro.ID, "h5", now); err != nil {
		t.Fatal(err)
	}
	if u, _ := d.UserByID(ctx, ro.ID); u.PasswordHash != "h5" {
		t.Fatalf("hash %q", u.PasswordHash)
	}
	us, _ := d.ListUsers(ctx)
	if len(us) != 2 || us[0].ID != owner.ID {
		t.Fatalf("%+v", us)
	}
}

// Two concurrent first-run setups: exactly one wins.
func TestCreateFirstUserRace(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := model.User{Username: "u" + string(rune('a'+i)), PasswordHash: "h", Role: model.RoleOwner}
			errs[i] = d.CreateFirstUser(ctx, &u)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, store.ErrConflict):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if n, _ := d.CountUsers(ctx); ok != 1 || n != 1 {
		t.Fatalf("%d setups succeeded, %d users", ok, n)
	}
}

func TestSessions(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	u := model.User{Username: "a", PasswordHash: "h", Role: model.RoleOwner}
	d.CreateUser(ctx, &u)
	s := model.Session{TokenHash: []byte{1, 2, 3}, UserID: u.ID, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour), IP: "127.0.0.1"}
	if err := d.CreateSession(ctx, &s); err != nil || s.ID == 0 {
		t.Fatal(err)
	}
	got, err := d.SessionByTokenHash(ctx, []byte{1, 2, 3})
	if err != nil || got.ID != s.ID || !got.RevokedAt.IsZero() || got.IP != "127.0.0.1" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := d.SessionByTokenHash(ctx, []byte{9}); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if ss, _ := d.ListSessions(ctx, u.ID, now); len(ss) != 1 {
		t.Fatalf("live sessions %d", len(ss))
	}
	if ss, _ := d.ListSessions(ctx, 0, now.Add(2*time.Hour)); len(ss) != 0 {
		t.Fatal("expired session listed")
	}
	if err := d.RevokeSession(ctx, s.ID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Revoking again keeps the first time.
	d.RevokeSession(ctx, s.ID, now.Add(time.Hour))
	got, _ = d.SessionByID(ctx, s.ID)
	if !got.RevokedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("revoked at %v", got.RevokedAt)
	}
	if ss, _ := d.ListSessions(ctx, 0, now); len(ss) != 0 {
		t.Fatal("revoked session listed")
	}
	if err := d.DeleteSessionsBefore(ctx, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SessionByID(ctx, s.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("old revoked session not deleted")
	}
}

func TestAudit(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	d.AddAudit(ctx, model.AuditEntry{Time: time.Unix(1, 0), Action: "login_failed", Target: "admin"})
	d.AddAudit(ctx, model.AuditEntry{Time: time.Unix(2, 0), Action: "login", UserID: 0})
	es, err := d.ListAudit(ctx, 10)
	if err != nil || len(es) != 2 || es[0].Action != "login" || es[1].Target != "admin" {
		t.Fatalf("%+v %v", es, err)
	}
}
