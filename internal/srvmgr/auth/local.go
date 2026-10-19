package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// ErrNoUser: no user with this name.
var ErrNoUser = errors.New("такого пользователя нет")

// ResetPasswordLocal sets a new password from the machine of the
// controller (hyroute-server reset-password), for an owner who forgot
// theirs: no session is needed, since only someone with the controller's
// files gets here. Every session of the user ends in the same
// transaction; the audit records the reset without a user.
func (s *Service) ResetPasswordLocal(ctx context.Context, username, password string) (model.User, error) {
	if err := validatePassword(password); err != nil {
		return model.User{}, err
	}
	hash, err := HashPassword(password, s.Params)
	if err != nil {
		return model.User{}, err
	}
	var u model.User
	err = s.Store.ChangeUsers(ctx, s.Now(), func(all []model.User) ([]model.User, []int64, error) {
		for _, c := range all {
			if strings.EqualFold(c.Username, username) {
				u = c
				u.PasswordHash = hash
				return []model.User{u}, []int64{u.ID}, nil
			}
		}
		return nil, nil, fmt.Errorf("%w: %q", ErrNoUser, username)
	})
	if err != nil {
		return model.User{}, err
	}
	s.sessionsEnded()
	s.audit(ctx, 0, "user_password_reset", userTarget(u.ID), u.Username+" (hyroute-server reset-password)")
	return u, nil
}
