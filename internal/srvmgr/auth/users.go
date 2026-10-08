package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// User management. The rules live here, in one place:
//   - owners and admins manage users, operators and read-only users manage
//     nobody (ErrForbidden);
//   - only an owner makes an owner or touches one: changes their role,
//     password or block, deletes them;
//   - an admin manages the users below owner, admins included, as
//     CreateUser lets it create them;
//   - nobody blocks, deletes or resets the password of themselves
//     (ErrSelf): one's own password changes with the current one
//     (ChangePassword);
//   - no change leaves the panel without an owner who can log in
//     (ErrLastOwner); the owner role is handed over with TransferOwner.
//
// Checks across users run inside the store transaction of the change, on
// the users as they are then, the caller included: two changes at once
// cannot both take away the last owner, and a caller demoted meanwhile
// is refused.

var (
	// ErrLastOwner: the change would leave no owner who can log in.
	ErrLastOwner = errors.New("the last active owner")
	// ErrSelf: blocking, deleting or resetting the password of oneself.
	ErrSelf = errors.New("not allowed on one's own account")
	// ErrBlocked: the owner role is handed only to a user who can log in.
	ErrBlocked = errors.New("the user is blocked")
)

// mayManage: actor may change or delete target.
func mayManage(actor, target model.User) error {
	if !actor.Role.CanManageUsers() {
		return ErrForbidden
	}
	if target.Role == model.RoleOwner && actor.Role != model.RoleOwner {
		return ErrForbidden
	}
	return nil
}

// mayGrant: actor may give role to a user they manage.
func mayGrant(actor model.User, role model.Role) error {
	if !role.Valid() {
		return &model.FieldError{Field: "role", Msg: "Роль: owner, admin, operator или readonly."}
	}
	if role == model.RoleOwner && actor.Role != model.RoleOwner {
		return ErrForbidden
	}
	return nil
}

func activeOwners(us []model.User) int {
	n := 0
	for _, u := range us {
		if u.Role == model.RoleOwner && !u.Disabled {
			n++
		}
	}
	return n
}

// keepsOwner: all with changed in place of their users and without the
// user gone still has an owner who can log in, or never had one.
func keepsOwner(all, changed []model.User, gone int64) bool {
	after := make([]model.User, 0, len(all))
	for _, u := range all {
		if u.ID == gone {
			continue
		}
		for _, c := range changed {
			if c.ID == u.ID {
				u = c
			}
		}
		after = append(after, u)
	}
	return activeOwners(after) > 0 || activeOwners(all) == 0
}

func userIn(all []model.User, id int64) (model.User, bool) {
	for _, u := range all {
		if u.ID == id {
			return u, true
		}
	}
	return model.User{}, false
}

// userTarget is the audit target of a user.
func userTarget(id int64) string { return "user/" + strconv.FormatInt(id, 10) }

// caller is p's user as stored now; a user deleted or blocked meanwhile
// has no session any more.
func caller(all []model.User, p Principal) (model.User, error) {
	u, ok := userIn(all, p.User.ID)
	if !ok || u.Disabled {
		return model.User{}, ErrUnauthenticated
	}
	return u, nil
}

// change runs edit on the user id for the caller in one transaction:
// edit gets the caller and the user as stored now (the rules of mayManage
// already passed) and returns the users it changed and whose sessions
// end; the result must keep an owner.
func (s *Service) change(ctx context.Context, p Principal, id int64, edit func(actor, u model.User) ([]model.User, []int64, error)) error {
	return s.Store.ChangeUsers(ctx, s.Now(), func(all []model.User) ([]model.User, []int64, error) {
		actor, err := caller(all, p)
		if err != nil {
			return nil, nil, err
		}
		u, ok := userIn(all, id)
		if !ok {
			return nil, nil, store.ErrNotFound
		}
		if err := mayManage(actor, u); err != nil {
			return nil, nil, err
		}
		changed, revoke, err := edit(actor, u)
		if err != nil {
			return nil, nil, err
		}
		if !keepsOwner(all, changed, 0) {
			return nil, nil, ErrLastOwner
		}
		return changed, revoke, nil
	})
}

// hash hashes a password for a logged-in user (waiting for a slot).
func (s *Service) hash(ctx context.Context, password string) (string, error) {
	release, err := s.hashSlot(ctx, true)
	if err != nil {
		return "", err
	}
	defer release()
	return HashPassword(password, s.Params)
}

// UserChange changes the role or the block of a user; nil: unchanged.
type UserChange struct {
	Role     *model.Role
	Disabled *bool
}

// UpdateUser changes the role or the block of a user. A blocked user's
// sessions end at once and it cannot log in until unblocked.
func (s *Service) UpdateUser(ctx context.Context, p Principal, id int64, c UserChange) (model.User, error) {
	if !p.User.Role.CanManageUsers() {
		return model.User{}, ErrForbidden
	}
	if c.Role == nil && c.Disabled == nil {
		return model.User{}, &model.FieldError{Field: "role", Msg: "Укажите новую роль или блокировку."}
	}
	if c.Disabled != nil && *c.Disabled && id == p.User.ID {
		return model.User{}, ErrSelf
	}
	var before, after model.User
	err := s.change(ctx, p, id, func(actor, u model.User) ([]model.User, []int64, error) {
		before = u
		if c.Role != nil {
			if err := mayGrant(actor, *c.Role); err != nil {
				return nil, nil, err
			}
			u.Role = *c.Role
		}
		if c.Disabled != nil {
			u.Disabled = *c.Disabled
		}
		after = u
		var revoke []int64
		if u.Disabled && !before.Disabled {
			revoke = []int64{u.ID}
		}
		return []model.User{u}, revoke, nil
	})
	if err != nil {
		return model.User{}, err
	}
	if after.Role != before.Role {
		s.audit(ctx, p.User.ID, "user_role_changed", userTarget(id), after.Username+": "+string(before.Role)+" → "+string(after.Role))
	}
	switch {
	case after.Disabled && !before.Disabled:
		s.sessionsEnded()
		s.audit(ctx, p.User.ID, "user_blocked", userTarget(id), after.Username)
	case !after.Disabled && before.Disabled:
		s.audit(ctx, p.User.ID, "user_unblocked", userTarget(id), after.Username)
	}
	return after, nil
}

// TransferOwner hands the owner role of the caller to another user who
// can log in; the caller becomes an admin.
func (s *Service) TransferOwner(ctx context.Context, p Principal, id int64) (model.User, error) {
	if p.User.Role != model.RoleOwner {
		return model.User{}, ErrForbidden
	}
	if id == p.User.ID {
		return model.User{}, ErrSelf
	}
	var to, from model.User
	err := s.change(ctx, p, id, func(actor, u model.User) ([]model.User, []int64, error) {
		if actor.Role != model.RoleOwner {
			return nil, nil, ErrForbidden
		}
		if u.Disabled {
			return nil, nil, ErrBlocked
		}
		u.Role, actor.Role = model.RoleOwner, model.RoleAdmin
		to, from = u, actor
		return []model.User{u, actor}, nil, nil
	})
	if err != nil {
		return model.User{}, err
	}
	s.audit(ctx, p.User.ID, "owner_transferred", userTarget(id), to.Username+": owner; "+from.Username+": admin")
	return to, nil
}

// ResetPassword sets the password of another user: password, or when it
// is "" a generated one, returned to be shown once. Every session of the
// user ends.
func (s *Service) ResetPassword(ctx context.Context, p Principal, id int64, password string) (generated string, err error) {
	if !p.User.Role.CanManageUsers() {
		return "", ErrForbidden
	}
	if id == p.User.ID {
		return "", ErrSelf
	}
	// Refused before hashing too, not only in the transaction.
	if u, err := s.Store.UserByID(ctx, id); err != nil {
		return "", err
	} else if err := mayManage(p.User, u); err != nil {
		return "", err
	}
	if password == "" {
		if generated, err = GeneratePassword(); err != nil {
			return "", err
		}
		password = generated
	} else if err := validatePassword(password); err != nil {
		return "", err
	}
	hash, err := s.hash(ctx, password)
	if err != nil {
		return "", err
	}
	var name string
	err = s.change(ctx, p, id, func(_, u model.User) ([]model.User, []int64, error) {
		u.PasswordHash = hash
		name = u.Username
		return []model.User{u}, []int64{u.ID}, nil
	})
	if err != nil {
		return "", err
	}
	s.sessionsEnded()
	details := name
	if generated != "" {
		details += " (сгенерирован)"
	}
	s.audit(ctx, p.User.ID, "user_password_reset", userTarget(id), details)
	return generated, nil
}

// ChangePassword changes the caller's own password, checking the current
// one (rate limited like a login). Every session of the user ends, this
// one too: the browser gets the new session returned.
func (s *Service) ChangePassword(ctx context.Context, p Principal, current, password string, m Meta) (Issued, error) {
	if err := validatePassword(password); err != nil {
		return Issued{}, err
	}
	if len(current) > MaxPasswordLen {
		return Issued{}, errWrongCurrent
	}
	a, err := s.limits.reserve(s.Now, strings.ToLower(p.User.Username), addrKey(m.IP))
	if err != nil {
		return Issued{}, err
	}
	release, err := s.hashSlot(ctx, true)
	if err != nil {
		s.limits.cancel(a)
		return Issued{}, err
	}
	ok, _, verr := VerifyPassword(p.User.PasswordHash, current, s.Params)
	release()
	if !ok || verr != nil {
		// The reserved attempt stays as the failure.
		s.audit(ctx, p.User.ID, "password_change_failed", userTarget(p.User.ID), "from "+m.IP)
		return Issued{}, errWrongCurrent
	}
	s.limits.succeeded(a)
	if current == password {
		return Issued{}, &model.FieldError{Field: "password", Msg: "Новый пароль совпадает с текущим."}
	}
	hash, err := s.hash(ctx, password)
	if err != nil {
		return Issued{}, err
	}
	var me model.User
	err = s.Store.ChangeUsers(ctx, s.Now(), func(all []model.User) ([]model.User, []int64, error) {
		u, err := caller(all, p)
		if err != nil {
			return nil, nil, err
		}
		u.PasswordHash = hash
		me = u
		return []model.User{u}, []int64{u.ID}, nil
	})
	if err != nil {
		return Issued{}, err
	}
	s.sessionsEnded()
	s.audit(ctx, p.User.ID, "user_password_changed", userTarget(p.User.ID), me.Username)
	return s.issue(ctx, me, m, s.Now())
}

var errWrongCurrent = &model.FieldError{Field: "current", Msg: "Текущий пароль не подходит."}

// DeleteUser removes another user; its sessions end with it. What it made
// (jobs, revisions, presets, cascades) stays without an author, its audit
// entries stay.
func (s *Service) DeleteUser(ctx context.Context, p Principal, id int64) error {
	if !p.User.Role.CanManageUsers() {
		return ErrForbidden
	}
	if id == p.User.ID {
		return ErrSelf
	}
	var name string
	err := s.Store.DeleteUser(ctx, id, func(all []model.User) error {
		actor, err := caller(all, p)
		if err != nil {
			return err
		}
		u, ok := userIn(all, id)
		if !ok {
			return store.ErrNotFound
		}
		if err := mayManage(actor, u); err != nil {
			return err
		}
		if !keepsOwner(all, nil, id) {
			return ErrLastOwner
		}
		name = u.Username
		return nil
	})
	if err != nil {
		return err
	}
	s.sessionsEnded()
	s.audit(ctx, p.User.ID, "user_deleted", userTarget(id), name)
	return nil
}

// AuditEntries lists the audit log for owners and admins.
func (s *Service) AuditEntries(ctx context.Context, p Principal, f model.AuditFilter) ([]model.AuditEntry, error) {
	if !p.User.Role.CanManageUsers() {
		return nil, ErrForbidden
	}
	return s.Store.QueryAudit(ctx, f)
}

// genAlphabet has no look-alikes (0 and o, 1 and l): 32 symbols, so a
// random byte maps to one without bias.
const genAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

// GeneratePassword returns 20 random symbols of genAlphabet (100 bits) in
// groups of five: xxxxx-xxxxx-xxxxx-xxxxx.
func GeneratePassword() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%5 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(genAlphabet[int(c)%len(genAlphabet)])
	}
	return sb.String(), nil
}
