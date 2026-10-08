package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// ErrNoUser: no user with this name.
var ErrNoUser = errors.New("такого пользователя нет")

// ResetPasswordLocal sets a new password from the machine of the
// controller (hyroute-server reset-password), for an owner who forgot
// theirs: no session is needed, since only someone with the controller's
// files gets here. Every session of the user ends; the audit records the
// reset without a user.
func (s *Service) ResetPasswordLocal(ctx context.Context, username, password string) (model.User, error) {
	u, err := s.Store.UserByName(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		return model.User{}, fmt.Errorf("%w: %q", ErrNoUser, username)
	}
	if err != nil {
		return model.User{}, err
	}
	if err := validateCredentials(u.Username, password); err != nil {
		return model.User{}, err
	}
	hash, err := HashPassword(password, s.Params)
	if err != nil {
		return model.User{}, err
	}
	now := s.Now()
	if err := s.Store.UpdatePasswordHash(ctx, u.ID, hash, now); err != nil {
		return model.User{}, err
	}
	sessions, err := s.Store.ListSessions(ctx, u.ID, now)
	if err != nil {
		return model.User{}, err
	}
	for _, sess := range sessions {
		if err := s.Store.RevokeSession(ctx, sess.ID, now); err != nil {
			return model.User{}, err
		}
	}
	s.audit(ctx, 0, "user.password_reset", u.Username, "hyroute-server reset-password")
	return u, nil
}
