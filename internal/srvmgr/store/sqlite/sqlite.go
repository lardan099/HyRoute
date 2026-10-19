// Package sqlite implements the store interfaces on SQLite
// (modernc.org/sqlite, no CGO). The schema is built by numbered migrations
// embedded from migrations/*.sql.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

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
	return openFS(ctx, path, migrationFS)
}

// openFS is Open with the migrations of fsys (tests stop at a version).
func openFS(ctx context.Context, path string, fsys fs.FS) (*DB, error) {
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
	uri, err := fileURI(path)
	if err != nil {
		return nil, err
	}
	sqldb, err := sql.Open("sqlite", uri+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	d := &DB{db: sqldb}
	if err := d.migrateFS(ctx, fsys); err != nil {
		sqldb.Close()
		return nil, err
	}
	return d, nil
}

// fileURI is the SQLite URI of a database file: an absolute path with '/'
// separators (file:///var/lib/x.db, file:///C:/x.db) where %, ? and #,
// which escape or end the path in a URI, are percent-encoded: unescaped,
// SQLite cut the path at # or decoded %XX in it and opened another file
// than the owner-only one Open created.
func fileURI(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // C:/… → /C:/…, the Windows VFS drops the slash
	}
	return "file://" + uriEscaper.Replace(p), nil
}

var uriEscaper = strings.NewReplacer("%", "%25", "?", "%3F", "#", "%23")

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
