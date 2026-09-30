// Package sqlite implements the store interfaces on SQLite
// (modernc.org/sqlite, no CGO). The schema is built by numbered migrations
// embedded from migrations/*.sql.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// DB is the SQLite store.
type DB struct {
	db *sql.DB
}

var _ store.Store = (*DB)(nil)

// Open opens (creating if needed) the database file and applies pending
// migrations. A database written by a newer controller is refused.
func Open(ctx context.Context, path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// The file holds sealed secrets and password hashes: owner only.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_txlock", "immediate")
	sqldb, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	d := &DB{db: sqldb}
	if err := d.migrate(ctx); err != nil {
		sqldb.Close()
		return nil, err
	}
	return d, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// SchemaVersion is the newest applied migration.
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := d.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

// tx runs fn in a transaction, committing when it returns nil.
func (d *DB) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	t, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(t); err != nil {
		t.Rollback()
		return err
	}
	return t.Commit()
}

// errNewerSchema: the file was migrated by a newer controller.
type errNewerSchema struct{ have, know int }

func (e errNewerSchema) Error() string {
	return fmt.Sprintf("database schema version %d is newer than this controller knows (%d): update hyroute-server", e.have, e.know)
}
