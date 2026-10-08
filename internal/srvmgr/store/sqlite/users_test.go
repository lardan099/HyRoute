package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/fstest"
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

// QueryAudit filters by user, actions, target (one or a kind) and period,
// and pages by id.
func TestQueryAudit(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	add := func(ts, uid int64, action, target string) {
		t.Helper()
		if err := d.AddAudit(ctx, model.AuditEntry{Time: time.Unix(ts, 0), UserID: uid, Action: action, Target: target, Details: target}); err != nil {
			t.Fatal(err)
		}
	}
	add(100, 1, "login", "owner") // ids 1 to 6
	add(200, 1, "server_created", "server/3")
	add(300, 2, "server_updated", "server/30")
	add(400, 2, "chain_created", "chain/3")
	add(500, 0, "login_failed", "preset/1")
	add(600, 1, "job_submitted", "server/3")
	ids := func(f model.AuditFilter) []int64 {
		t.Helper()
		es, err := d.QueryAudit(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, e := range es {
			out = append(out, e.ID)
		}
		return out
	}
	for name, c := range map[string]struct {
		f    model.AuditFilter
		want []int64
	}{
		"all":        {model.AuditFilter{}, []int64{6, 5, 4, 3, 2, 1}},
		"user":       {model.AuditFilter{UserID: 2}, []int64{4, 3}},
		"actions":    {model.AuditFilter{Actions: []string{"login", "login_failed"}}, []int64{5, 1}},
		"target":     {model.AuditFilter{Target: "server/3"}, []int64{6, 2}},
		"kind":       {model.AuditFilter{Target: "server/"}, []int64{6, 3, 2}},
		"other kind": {model.AuditFilter{Target: "chain/"}, []int64{4}},
		"period":     {model.AuditFilter{From: time.Unix(200, 0), To: time.Unix(400, 0)}, []int64{3, 2}},
		"page":       {model.AuditFilter{BeforeID: 5, Limit: 2}, []int64{4, 3}},
		"together":   {model.AuditFilter{UserID: 1, Target: "server/3", From: time.Unix(300, 0)}, []int64{6}},
		"wildcards":  {model.AuditFilter{Target: "%/"}, nil},
	} {
		if got := ids(c.f); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// ChangeUsers and DeleteUser run their checks inside the transaction:
// two changes at once cannot both take the last of something.
func TestChangeUsers(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	a := model.User{Username: "a", PasswordHash: "h", Role: model.RoleOwner, CreatedAt: now, UpdatedAt: now}
	b := model.User{Username: "b", PasswordHash: "h", Role: model.RoleOwner, CreatedAt: now, UpdatedAt: now}
	d.CreateUser(ctx, &a)
	d.CreateUser(ctx, &b)
	for i, id := range []int64{a.ID, a.ID, b.ID} {
		s := model.Session{TokenHash: []byte{byte(i)}, UserID: id, CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := d.CreateSession(ctx, &s); err != nil {
			t.Fatal(err)
		}
	}
	// Each demotes one owner while another stays: only one may pass.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, id := range []int64{a.ID, b.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = d.ChangeUsers(ctx, now.Add(time.Minute), func(all []model.User) ([]model.User, []int64, error) {
				owners := 0
				var u model.User
				for _, x := range all {
					if x.Role == model.RoleOwner {
						owners++
					}
					if x.ID == id {
						u = x
					}
				}
				if owners < 2 {
					return nil, nil, store.ErrConflict
				}
				u.Role, u.PasswordHash, u.Disabled = model.RoleAdmin, "new", true
				return []model.User{u}, []int64{u.ID}, nil
			})
		}()
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("both or neither passed: %v", errs)
	}
	us, _ := d.ListUsers(ctx)
	owners := 0
	for _, u := range us {
		if u.Role == model.RoleOwner {
			owners++
			continue
		}
		if u.PasswordHash != "new" || !u.Disabled || !u.UpdatedAt.Equal(now.Add(time.Minute)) {
			t.Fatalf("not written: %+v", u)
		}
		live, _ := d.ListSessions(ctx, u.ID, now)
		if len(live) != 0 {
			t.Fatalf("%d sessions of %s left", len(live), u.Username)
		}
	}
	if owners != 1 {
		t.Fatalf("%d owners", owners)
	}
	// A refused change writes nothing.
	d.ChangeUsers(ctx, now, func(all []model.User) ([]model.User, []int64, error) {
		return all, []int64{a.ID, b.ID}, store.ErrConflict
	})
	if live, _ := d.ListSessions(ctx, 0, now); len(live) == 0 {
		t.Fatal("a refused change revoked sessions")
	}
	if err := d.ChangeUsers(ctx, now, func([]model.User) ([]model.User, []int64, error) {
		return []model.User{{ID: 999, Role: model.RoleAdmin}}, nil, nil
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}

	if err := d.SetLastLogin(ctx, a.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if u, _ := d.UserByID(ctx, a.ID); !u.LastLoginAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("last login %v", u.LastLoginAt)
	}

	// Delete: refused by check, then done with the sessions.
	if err := d.DeleteUser(ctx, a.ID, func([]model.User) error { return store.ErrConflict }); !errors.Is(err, store.ErrConflict) {
		t.Fatal(err)
	}
	var seen int
	if err := d.DeleteUser(ctx, a.ID, func(all []model.User) error { seen = len(all); return nil }); err != nil || seen != 2 {
		t.Fatalf("delete: %v, check saw %d", err, seen)
	}
	if _, err := d.UserByID(ctx, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("deleted user found")
	}
	var n int
	d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE user_id = ?`, a.ID).Scan(&n)
	if n != 0 {
		t.Fatalf("%d sessions of a deleted user", n)
	}
	if err := d.DeleteUser(ctx, a.ID, func([]model.User) error { return nil }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

// The migration takes the last login of existing users from the audit log.
func TestLastLoginMigration(t *testing.T) {
	ctx := context.Background()
	sqldb, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	d := &DB{db: sqldb}
	t.Cleanup(func() { d.Close() })
	ms, err := migrations(migrationFS)
	if err != nil {
		t.Fatal(err)
	}
	old, all := fstest.MapFS{}, fstest.MapFS{}
	before := true
	for _, m := range ms {
		f := &fstest.MapFile{Data: []byte(m.sql)}
		all[filepathName(m)] = f
		before = before && m.name != "users_audit"
		if before {
			old[filepathName(m)] = f
		}
	}
	if len(old) == len(all) {
		t.Fatal("no users_audit migration")
	}
	if err := d.migrateFS(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.ExecContext(ctx, `INSERT INTO users (id, username, password_hash, role, created_at, updated_at) VALUES
			(1, 'owner', 'h', 'owner', 1, 1), (2, 'viewer', 'h', 'readonly', 1, 1);
		INSERT INTO audit_log (ts, user_id, action, target) VALUES
			(10, 1, 'setup', 'owner'), (20, 1, 'login', 'owner'), (30, 1, 'logout', 'owner'), (40, NULL, 'login', 'viewer')`); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateFS(ctx, all); err != nil {
		t.Fatal(err)
	}
	o, _ := d.UserByID(ctx, 1)
	v, _ := d.UserByID(ctx, 2)
	if o.LastLoginAt.Unix() != 20 || !v.LastLoginAt.IsZero() {
		t.Fatalf("last logins %v %v", o.LastLoginAt, v.LastLoginAt)
	}
}
