// Package store holds the repository interfaces of the server manager.
// Business logic depends on these interfaces only; store/sqlite implements
// them. Repositories are added by the features that need them.
package store

import (
	"context"
	"errors"
)

var (
	// ErrNotFound: no row with this key.
	ErrNotFound = errors.New("not found")
	// ErrConflict: a unique key or a state precondition does not hold.
	ErrConflict = errors.New("conflict")
)

// Store is the whole persistent state of the controller.
type Store interface {
	// SchemaVersion is the newest applied migration.
	SchemaVersion(ctx context.Context) (int, error)
	Close() error
}
