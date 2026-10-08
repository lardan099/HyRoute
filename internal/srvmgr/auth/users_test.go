package auth

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// team is an owner with one user of every other role, all logged in.
type team struct {
	s                      *Service
	db                     *sqlite.DB
	owner, admin, op, ro   Principal
	ownerIs, adminIs, roIs Issued
}

func newTeam(t *testing.T) *team {
	t.Helper()
	s, db, _ := newService(t)
	ctx := context.Background()
	tm := &team{s: s, db: db}
	tm.ownerIs = setupOwner(t, s)
	tm.owner = principalOf(t, s, tm.ownerIs)
	for _, u := range []struct {
		name string
		role model.Role
		p    *Principal
		is   *Issued
	}{{"admin", model.RoleAdmin, &tm.admin, &tm.adminIs}, {"op", model.RoleOperator, &tm.op, nil}, {"ro", model.RoleReadOnly, &tm.ro, &tm.roIs}} {
		if _, err := s.CreateUser(ctx, tm.owner, u.name, goodPass, u.role, model.ScopeAll); err != nil {
			t.Fatal(err)
		}
		is, err := s.Login(ctx, u.name, goodPass, meta("127.0.0.1"))
		mustNoErr(t, err)
		*u.p = principalOf(t, s, is)
		if u.is != nil {
			*u.is = is
		}
	}
	return tm
}

func principalOf(t *testing.T, s *Service, is Issued) Principal {
	t.Helper()
	p, err := s.Authenticate(context.Background(), is.Token)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// refresh re-reads p's user, as the next request of its session would.
func (tm *team) refresh(t *testing.T, p *Principal) {
	t.Helper()
	*p = principalOf(t, tm.s, Issued{Token: p.Token})
}

func role(r model.Role) *model.Role { return &r }
func flag(b bool) *bool             { return &b }

func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

// Every way to lose the last owner who can log in is refused.
func TestLastOwner(t *testing.T) {
	tm := newTeam(t)
	s, ctx := tm.s, context.Background()
	id := tm.owner.User.ID
	_, err := s.UpdateUser(ctx, tm.owner, id, UserChange{Role: role(model.RoleAdmin)})
	wantErr(t, "demote the only owner", err, ErrLastOwner)
	_, err = s.UpdateUser(ctx, tm.owner, id, UserChange{Disabled: flag(true)})
	wantErr(t, "block oneself", err, ErrSelf)
	wantErr(t, "delete oneself", s.DeleteUser(ctx, tm.owner, id), ErrSelf)
	_, err = s.ResetPassword(ctx, tm.owner, id, "")
	wantErr(t, "reset one's own password", err, ErrSelf)
	_, err = s.TransferOwner(ctx, tm.owner, id)
	wantErr(t, "hand over to oneself", err, ErrSelf)
	// Admins do not touch the owner at all.
	_, err = s.UpdateUser(ctx, tm.admin, id, UserChange{Role: role(model.RoleAdmin)})
	wantErr(t, "admin demotes the owner", err, ErrForbidden)
	_, err = s.UpdateUser(ctx, tm.admin, id, UserChange{Disabled: flag(true)})
	wantErr(t, "admin blocks the owner", err, ErrForbidden)
	wantErr(t, "admin deletes the owner", s.DeleteUser(ctx, tm.admin, id), ErrForbidden)

	// A second owner who is blocked does not count.
	_, err = s.UpdateUser(ctx, tm.owner, tm.admin.User.ID, UserChange{Role: role(model.RoleOwner)})
	mustNoErr(t, err)
	_, err = s.UpdateUser(ctx, tm.owner, tm.admin.User.ID, UserChange{Disabled: flag(true)})
	mustNoErr(t, err)
	_, err = s.UpdateUser(ctx, tm.owner, id, UserChange{Role: role(model.RoleOperator)})
	wantErr(t, "demote the only active owner", err, ErrLastOwner)
	_, err = s.TransferOwner(ctx, tm.owner, tm.admin.User.ID)
	wantErr(t, "hand over to a blocked user", err, ErrBlocked)
	// Unblocked, the second owner lets the first step down.
	_, err = s.UpdateUser(ctx, tm.owner, tm.admin.User.ID, UserChange{Disabled: flag(false)})
	mustNoErr(t, err)
	_, err = s.UpdateUser(ctx, tm.owner, id, UserChange{Role: role(model.RoleAdmin)})
	mustNoErr(t, err)

	// The check holds for blocking and deleting too (reached only when the
	// caller lost the owner role meanwhile, so tested on the rule).
	o := model.User{ID: 1, Role: model.RoleOwner}
	a := model.User{ID: 2, Role: model.RoleAdmin}
	blocked := o
	blocked.Disabled = true
	for name, ok := range map[string]bool{
		"block the last":  keepsOwner([]model.User{o, a}, []model.User{blocked}, 0),
		"delete the last": keepsOwner([]model.User{o, a}, nil, 1),
		"demote the last": keepsOwner([]model.User{o, a}, []model.User{{ID: 1, Role: model.RoleAdmin}}, 0),
	} {
		if ok {
			t.Errorf("%s: allowed", name)
		}
	}
	if !keepsOwner([]model.User{o, a}, nil, 2) || !keepsOwner([]model.User{blocked, a}, []model.User{{ID: 2, Role: model.RoleOperator}}, 0) {
		t.Error("a change that keeps the owner (or never had one) refused")
	}
}

// Two owners stepping down at once: one of them stays.
func TestLastOwnerConcurrent(t *testing.T) {
	tm := newTeam(t)
	s, ctx := tm.s, context.Background()
	_, err := s.UpdateUser(ctx, tm.owner, tm.admin.User.ID, UserChange{Role: role(model.RoleOwner)})
	mustNoErr(t, err)
	tm.refresh(t, &tm.admin)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, p := range []Principal{tm.owner, tm.admin} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.UpdateUser(ctx, p, p.User.ID, UserChange{Role: role(model.RoleAdmin)})
		}()
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) || !errors.Is(errors.Join(errs...), ErrLastOwner) {
		t.Fatalf("%v", errs)
	}
	us, _ := tm.db.ListUsers(ctx)
	if activeOwners(us) != 1 {
		t.Fatalf("%d owners", activeOwners(us))
	}
}

func TestTransferOwner(t *testing.T) {
	tm := newTeam(t)
	s, ctx := tm.s, context.Background()
	_, err := s.TransferOwner(ctx, tm.admin, tm.ro.User.ID)
	wantErr(t, "admin hands over", err, ErrForbidden)
	u, err := s.TransferOwner(ctx, tm.owner, tm.ro.User.ID)
	if err != nil || u.Role != model.RoleOwner {
		t.Fatalf("%+v %v", u, err)
	}
	old, _ := tm.db.UserByID(ctx, tm.owner.User.ID)
	if old.Role != model.RoleAdmin {
		t.Fatalf("old owner is %s", old.Role)
	}
	// The old owner, now an admin, no longer touches the owner; a stale
	// copy of its user does not help it.
	_, err = s.UpdateUser(ctx, tm.owner, tm.ro.User.ID, UserChange{Disabled: flag(true)})
	wantErr(t, "former owner blocks the owner", err, ErrForbidden)
	_, err = s.TransferOwner(ctx, tm.owner, tm.admin.User.ID)
	wantErr(t, "former owner hands over again", err, ErrForbidden)
}

// Operators and read-only users manage nobody; admins manage everybody
// below owner and grant no owner role.
func TestWhoManagesWhom(t *testing.T) {
	tm := newTeam(t)
	s, ctx := tm.s, context.Background()
	for _, p := range []Principal{tm.op, tm.ro} {
		who := string(p.User.Role)
		for _, target := range []int64{tm.admin.User.ID, tm.op.User.ID, tm.ro.User.ID} {
			_, err := s.UpdateUser(ctx, p, target, UserChange{Role: role(model.RoleReadOnly)})
			wantErr(t, who+" changes a role", err, ErrForbidden)
			_, err = s.UpdateUser(ctx, p, target, UserChange{Disabled: flag(true)})
			wantErr(t, who+" blocks", err, ErrForbidden)
			_, err = s.ResetPassword(ctx, p, target, "")
			wantErr(t, who+" resets a password", err, ErrForbidden)
			wantErr(t, who+" deletes", s.DeleteUser(ctx, p, target), ErrForbidden)
		}
		_, err := s.TransferOwner(ctx, p, tm.admin.User.ID)
		wantErr(t, who+" hands over", err, ErrForbidden)
		_, err = s.AuditEntries(ctx, p, model.AuditFilter{})
		wantErr(t, who+" reads the audit", err, ErrForbidden)
	}
	_, err := s.UpdateUser(ctx, tm.admin, tm.ro.User.ID, UserChange{Role: role(model.RoleOwner)})
	wantErr(t, "admin grants owner", err, ErrForbidden)
	wantErr(t, "admin ends the owner's session", s.RevokeSession(ctx, tm.admin, tm.owner.Session.ID), ErrForbidden)
	mustNoErr(t, s.RevokeSession(ctx, tm.admin, tm.ro.Session.ID))
	_, err = s.ResetPassword(ctx, tm.admin, tm.owner.User.ID, "")
	wantErr(t, "admin resets the owner's password", err, ErrForbidden)
	u, err := s.UpdateUser(ctx, tm.admin, tm.op.User.ID, UserChange{Role: role(model.RoleAdmin)})
	if err != nil || u.Role != model.RoleAdmin {
		t.Fatalf("admin promotes an operator: %+v %v", u, err)
	}
	_, err = s.UpdateUser(ctx, tm.admin, tm.op.User.ID, UserChange{Role: role("root")})
	var fe *model.FieldError
	if !errors.As(err, &fe) || fe.Field != "role" {
		t.Fatalf("unknown role: %v", err)
	}
	if _, err := s.ResetPassword(ctx, tm.admin, tm.op.User.ID, ""); err != nil {
		t.Fatalf("admin resets an admin's password: %v", err)
	}
	if _, err := s.ResetPassword(ctx, tm.admin, 999, ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
	mustNoErr(t, s.DeleteUser(ctx, tm.admin, tm.op.User.ID))
	wantErr(t, "delete twice", s.DeleteUser(ctx, tm.admin, tm.op.User.ID), store.ErrNotFound)
	// An admin may step down itself; then it manages nobody.
	_, err = s.UpdateUser(ctx, tm.admin, tm.admin.User.ID, UserChange{Role: role(model.RoleReadOnly)})
	mustNoErr(t, err)
	tm.refresh(t, &tm.admin)
	_, err = s.UpdateUser(ctx, tm.admin, tm.ro.User.ID, UserChange{Disabled: flag(true)})
	wantErr(t, "demoted admin blocks", err, ErrForbidden)
}

// A reset or a change of the password and a block end every session of
// the user at once.
func TestSessionsEnd(t *testing.T) {
	tm := newTeam(t)
	s, ctx := tm.s, context.Background()
	second, err := s.Login(ctx, "ro", goodPass, meta("127.0.0.2"))
	mustNoErr(t, err)
	ended := s.Revocations()

	gen, err := s.ResetPassword(ctx, tm.owner, tm.ro.User.ID, "")
	mustNoErr(t, err)
	if !regexp.MustCompile(`^[a-z2-9]{5}(-[a-z2-9]{5}){3}$`).MatchString(gen) {
		t.Fatalf("generated %q", gen)
	}
	select {
	case <-ended:
	default:
		t.Fatal("streams not woken")
	}
	for _, tok := range []string{tm.roIs.Token, second.Token} {
		if _, err := s.Authenticate(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("session after the reset: %v", err)
		}
	}
	if _, err := s.Login(ctx, "ro", goodPass, meta("127.0.0.1")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("old password: %v", err)
	}
	is, err := s.Login(ctx, "ro", gen, meta("127.0.0.1"))
	mustNoErr(t, err)
	ro := principalOf(t, s, is)

	// A typed password is checked like any other.
	_, err = s.ResetPassword(ctx, tm.owner, tm.ro.User.ID, "short")
	var fe *model.FieldError
	if !errors.As(err, &fe) || fe.Field != "password" {
		t.Fatalf("short password: %v", err)
	}

	// One's own change: the current password is checked, every session
	// ends and this browser gets a new one.
	other, _ := s.Login(ctx, "ro", gen, meta("127.0.0.2"))
	if _, err := s.ChangePassword(ctx, ro, "wrong password", "a new password 1", meta("127.0.0.1")); !errors.As(err, &fe) || fe.Field != "current" {
		t.Fatalf("wrong current: %v", err)
	}
	if _, err := s.ChangePassword(ctx, ro, gen, gen, meta("127.0.0.1")); !errors.As(err, &fe) || fe.Field != "password" {
		t.Fatalf("same password: %v", err)
	}
	fresh, err := s.ChangePassword(ctx, ro, gen, "a new password 1", meta("127.0.0.1"))
	mustNoErr(t, err)
	for _, tok := range []string{is.Token, other.Token} {
		if _, err := s.Authenticate(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("session after the change: %v", err)
		}
	}
	if p, err := s.Authenticate(ctx, fresh.Token); err != nil || p.User.ID != tm.ro.User.ID {
		t.Fatalf("new session: %+v %v", p, err)
	}
	if _, err := s.Login(ctx, "ro", "a new password 1", meta("127.0.0.1")); err != nil {
		t.Fatal(err)
	}

	// Block: sessions end, no login, until unblocked.
	is, _ = s.Login(ctx, "ro", "a new password 1", meta("127.0.0.1"))
	_, err = s.UpdateUser(ctx, tm.admin, tm.ro.User.ID, UserChange{Disabled: flag(true)})
	mustNoErr(t, err)
	if _, err := s.Authenticate(ctx, is.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("session of a blocked user: %v", err)
	}
	if _, err := s.Login(ctx, "ro", "a new password 1", meta("127.0.0.3")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("blocked user logs in: %v", err)
	}
	_, err = s.UpdateUser(ctx, tm.admin, tm.ro.User.ID, UserChange{Disabled: flag(false)})
	mustNoErr(t, err)
	if _, err := s.Authenticate(ctx, is.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("unblocking brought an old session back")
	}
	if _, err := s.Login(ctx, "ro", "a new password 1", meta("127.0.0.3")); err != nil {
		t.Fatalf("unblocked user: %v", err)
	}
	// A change of the role keeps the sessions: the role is read anew on
	// every request.
	_, err = s.UpdateUser(ctx, tm.owner, tm.admin.User.ID, UserChange{Role: role(model.RoleOperator)})
	mustNoErr(t, err)
	if p, err := s.Authenticate(ctx, tm.adminIs.Token); err != nil || p.User.Role != model.RoleOperator {
		t.Fatalf("%+v %v", p.User, err)
	}
}

// User management is audited without passwords.
func TestUserAudit(t *testing.T) {
	tm := newTeam(t)
	s, ctx := tm.s, context.Background()
	const canary = "canary-pass-7Hq2xZ"
	_, err := s.ResetPassword(ctx, tm.owner, tm.ro.User.ID, canary)
	mustNoErr(t, err)
	is, _ := s.Login(ctx, "ro", canary, meta("127.0.0.1"))
	ro := principalOf(t, s, is)
	s.ChangePassword(ctx, ro, canary+"x", canary+"2", meta("127.0.0.1"))
	_, err = s.ChangePassword(ctx, ro, canary, canary+"2", meta("127.0.0.1"))
	mustNoErr(t, err)
	gen, _ := s.ResetPassword(ctx, tm.owner, tm.op.User.ID, "")
	s.UpdateUser(ctx, tm.owner, tm.op.User.ID, UserChange{Role: role(model.RoleReadOnly), Disabled: flag(true)})
	s.UpdateUser(ctx, tm.owner, tm.op.User.ID, UserChange{Disabled: flag(false)})
	mustNoErr(t, s.DeleteUser(ctx, tm.owner, tm.op.User.ID))
	s.TransferOwner(ctx, tm.owner, tm.admin.User.ID)
	es, err := tm.db.ListAudit(ctx, 100)
	mustNoErr(t, err)
	var got []string
	for _, e := range es {
		line := e.Action + " " + e.Target + " " + e.Details
		if strings.Contains(line, canary) || strings.Contains(line, gen) {
			t.Fatalf("password in the audit: %q", line)
		}
		if strings.HasPrefix(e.Action, "user_") || strings.HasPrefix(e.Action, "owner_") || strings.HasPrefix(e.Action, "password_") {
			got = append(got, line)
		}
	}
	opID, roID, adminID := tm.op.User.ID, tm.ro.User.ID, tm.admin.User.ID
	want := []string{
		"owner_transferred " + userTarget(adminID) + " admin: owner; owner: admin",
		"user_deleted " + userTarget(opID) + " op",
		"user_unblocked " + userTarget(opID) + " op",
		"user_blocked " + userTarget(opID) + " op",
		"user_role_changed " + userTarget(opID) + " op: operator → readonly",
		"user_password_reset " + userTarget(opID) + " op (сгенерирован)",
		"user_password_changed " + userTarget(roID) + " ro",
		"password_change_failed " + userTarget(roID) + " from 127.0.0.1",
		"user_password_reset " + userTarget(roID) + " ro",
		"user_created " + userTarget(roID) + " ro: readonly, все серверы",
		"user_created " + userTarget(opID) + " op: operator, все серверы",
		"user_created " + userTarget(adminID) + " admin: admin, все серверы",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit:\n%s", strings.Join(got, "\n"))
	}
}

// A wrong current password counts against the login limits.
func TestChangePasswordRateLimited(t *testing.T) {
	s, _, _ := newService(t)
	ctx := context.Background()
	p := principalOf(t, s, setupOwner(t, s))
	var rl *RateLimitedError
	for i := range 30 {
		_, err := s.ChangePassword(ctx, p, "wrong password", "a new password 1", meta("127.0.0.1"))
		if errors.As(err, &rl) {
			if i < 5 {
				t.Fatalf("limited after %d tries", i)
			}
			return
		}
	}
	t.Fatal("never rate limited")
}

// Scopes (P4-04): narrowed for the roles below admin only, normalized,
// audited, and every change wakes the live streams to recheck.
func TestUserScope(t *testing.T) {
	tm := newTeam(t)
	s, ctx := tm.s, context.Background()
	de := model.Scope{Tags: []string{" de ", "DE", "nl"}}
	u, err := s.CreateUser(ctx, tm.admin, "helper", goodPass, model.RoleClients, de)
	mustNoErr(t, err)
	if got, _ := tm.db.UserByID(ctx, u.ID); got.Scope.All || len(got.Scope.Tags) != 2 || got.Scope.Tags[0] != "de" {
		t.Fatalf("stored scope %+v", got.Scope)
	}
	var fe *model.FieldError
	for name, sc := range map[string]model.Scope{"nothing": {}, "blank tags": {Tags: []string{" ", ""}}, "long tag": {Tags: []string{strings.Repeat("x", 33)}}} {
		if _, err := s.CreateUser(ctx, tm.owner, "x"+strings.ReplaceAll(name, " ", ""), goodPass, model.RoleOperator, sc); !errors.As(err, &fe) || fe.Field != "scope" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := s.CreateUser(ctx, tm.owner, "boss", goodPass, model.RoleAdmin, de); !errors.As(err, &fe) || fe.Field != "scope" {
		t.Fatalf("admin with a scope: %v", err)
	}

	woken := s.Revocations()
	nl := model.Scope{Tags: []string{"nl"}}
	got, err := s.UpdateUser(ctx, tm.owner, u.ID, UserChange{Scope: &nl})
	mustNoErr(t, err)
	if !got.Scope.Equal(nl) {
		t.Fatalf("%+v", got.Scope)
	}
	select {
	case <-woken:
	default:
		t.Fatal("a changed scope did not wake the streams")
	}
	// Made admin, the user reaches every server; an admin cannot be
	// narrowed.
	got, err = s.UpdateUser(ctx, tm.owner, u.ID, UserChange{Role: role(model.RoleAdmin)})
	mustNoErr(t, err)
	if !got.Scope.All {
		t.Fatalf("admin scope %+v", got.Scope)
	}
	_, err = s.UpdateUser(ctx, tm.owner, u.ID, UserChange{Scope: &nl})
	if !errors.As(err, &fe) || fe.Field != "scope" {
		t.Fatalf("narrowed an admin: %v", err)
	}
	_, err = s.UpdateUser(ctx, tm.owner, u.ID, UserChange{Role: role(model.RoleOperator), Scope: &nl})
	mustNoErr(t, err)
	// Readonly and operators manage no scopes.
	_, err = s.UpdateUser(ctx, tm.op, u.ID, UserChange{Scope: &de})
	wantErr(t, "operator changes a scope", err, ErrForbidden)
	// The owner role goes with every server.
	_, err = s.TransferOwner(ctx, tm.owner, u.ID)
	mustNoErr(t, err)
	if got, _ := tm.db.UserByID(ctx, u.ID); got.Role != model.RoleOwner || !got.Scope.All {
		t.Fatalf("new owner %+v", got)
	}
	es, _ := tm.db.QueryAudit(ctx, model.AuditFilter{Actions: []string{"user_scope_changed", "user_created"}, Target: userTarget(u.ID)})
	var lines []string
	for _, e := range es {
		lines = append(lines, e.Action+" "+e.Details)
	}
	// The owner role is audited as owner_transferred.
	want := []string{
		"user_scope_changed helper: все серверы → метки nl",
		"user_scope_changed helper: метки nl → все серверы",
		"user_scope_changed helper: метки de, nl → метки nl",
		"user_created helper: clients, метки de, nl",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit:\n%s", strings.Join(lines, "\n"))
	}
}

// hooked runs a function once in the middle of a login, after the
// password was verified, as a concurrent request would.
type hooked struct {
	*sqlite.DB
	onLastLogin  func()
	onUpdateHash func()
}

func (h *hooked) SetLastLogin(ctx context.Context, id int64, at time.Time) error {
	if f := h.onLastLogin; f != nil {
		h.onLastLogin = nil
		f()
	}
	return h.DB.SetLastLogin(ctx, id, at)
}

func (h *hooked) UpdatePasswordHash(ctx context.Context, id int64, old, hash string, at time.Time) error {
	if f := h.onUpdateHash; f != nil {
		h.onUpdateHash = nil
		f()
	}
	return h.DB.UpdatePasswordHash(ctx, id, old, hash, at)
}

// A reset, a change of the password or a block that commits while a
// login with the old password is being checked wins: the login opens no
// session (one opened after the revocation would outlive it, after an
// unblock too).
func TestLoginRacesUserChange(t *testing.T) {
	const newPass = "brand new password 1"
	for _, c := range []struct {
		name string
		race func(t *testing.T, tm *team)
		live int // sessions of the user left
	}{
		{"reset", func(t *testing.T, tm *team) {
			_, err := tm.s.ResetPassword(context.Background(), tm.owner, tm.ro.User.ID, newPass)
			mustNoErr(t, err)
		}, 0},
		{"change", func(t *testing.T, tm *team) {
			_, err := tm.s.ChangePassword(context.Background(), tm.ro, goodPass, newPass, meta("127.0.0.1"))
			mustNoErr(t, err)
		}, 1},
		{"block", func(t *testing.T, tm *team) {
			_, err := tm.s.UpdateUser(context.Background(), tm.owner, tm.ro.User.ID, UserChange{Disabled: flag(true)})
			mustNoErr(t, err)
		}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			tm := newTeam(t)
			ctx := context.Background()
			h := &hooked{DB: tm.db}
			tm.s.Store = h
			h.onLastLogin = func() { c.race(t, tm) }
			_, err := tm.s.Login(ctx, "ro", goodPass, meta("127.0.0.2"))
			wantErr(t, "login during the "+c.name, err, ErrBadCredentials)
			// Unblocked, the user has no session from the time of the block.
			_, err = tm.s.UpdateUser(ctx, tm.owner, tm.ro.User.ID, UserChange{Disabled: flag(false)})
			mustNoErr(t, err)
			if live, _ := tm.db.ListSessions(ctx, tm.ro.User.ID, tm.s.Now()); len(live) != c.live {
				t.Fatalf("%d live sessions, want %d", len(live), c.live)
			}
		})
	}
}

// With stale hash parameters a login rehashes the password it verified:
// a reset that committed meanwhile is not overwritten with the old one.
func TestRehashKeepsReset(t *testing.T) {
	tm := newTeam(t)
	ctx := context.Background()
	h := &hooked{DB: tm.db}
	tm.s.Store = h
	p := tm.s.Params
	p.Time++
	tm.s.Params = p // every stored hash is stale now
	const newPass = "brand new password 1"
	h.onUpdateHash = func() {
		_, err := tm.s.ResetPassword(ctx, tm.owner, tm.ro.User.ID, newPass)
		mustNoErr(t, err)
	}
	_, err := tm.s.Login(ctx, "ro", goodPass, meta("127.0.0.1"))
	wantErr(t, "login with the password before the reset", err, ErrBadCredentials)
	if _, err := tm.s.Login(ctx, "ro", newPass, meta("127.0.0.2")); err != nil {
		t.Fatalf("the reset password: %v", err)
	}
	if _, err := tm.s.Login(ctx, "ro", goodPass, meta("127.0.0.3")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("the old password after the reset: %v", err)
	}
	// Without a race the rehash is stored.
	u, _ := tm.db.UserByName(ctx, "op")
	mustNoErr(t, func() error { _, err := tm.s.Login(ctx, "op", goodPass, meta("127.0.0.4")); return err }())
	if got, _ := tm.db.UserByName(ctx, "op"); got.PasswordHash == u.PasswordHash {
		t.Fatal("not rehashed")
	}
}

// One's own change checked the current password against the hash read
// with the session: a reset or a logout that committed since wins.
func TestChangePasswordAfterReset(t *testing.T) {
	tm := newTeam(t)
	s, ctx := tm.s, context.Background()
	const reset, mine = "reset password 1", "my new password 1"
	// tm.ro is the request in flight, read before the reset.
	_, err := s.ResetPassword(ctx, tm.owner, tm.ro.User.ID, reset)
	mustNoErr(t, err)
	_, err = s.ChangePassword(ctx, tm.ro, goodPass, mine, meta("127.0.0.1"))
	wantErr(t, "change after a reset", err, ErrUnauthenticated)
	if _, err := s.Login(ctx, "ro", reset, meta("127.0.0.1")); err != nil {
		t.Fatalf("the reset password: %v", err)
	}
	if _, err := s.Login(ctx, "ro", mine, meta("127.0.0.1")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("the change overwrote the reset: %v", err)
	}

	// The session ended meanwhile: the password stays.
	mustNoErr(t, s.Logout(ctx, tm.op))
	_, err = s.ChangePassword(ctx, tm.op, goodPass, mine, meta("127.0.0.1"))
	wantErr(t, "change in a session that ended", err, ErrUnauthenticated)
	if _, err := s.Login(ctx, "op", goodPass, meta("127.0.0.1")); err != nil {
		t.Fatalf("the password changed: %v", err)
	}
}
