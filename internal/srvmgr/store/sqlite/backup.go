package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// KnownSchema is the newest schema version this controller builds.
func KnownSchema() int {
	ms, err := migrations(migrationFS)
	if err != nil {
		return 0
	}
	return len(ms)
}

// OpenExisting opens a database file that must exist, without applying
// migrations: the maintenance commands and the backup read a database as
// it is, also while a controller of another version uses it. A schema
// newer than this controller knows is refused like in Open; an older one
// is left alone (the controller migrates it when it starts).
func OpenExisting(ctx context.Context, path string) (*DB, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	q := url.Values{}
	q.Add("mode", "rw")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
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
	v, err := d.SchemaVersion(ctx)
	if err != nil {
		sqldb.Close()
		if strings.Contains(err.Error(), "no such table") {
			return nil, fmt.Errorf("%s is not a hyroute-server database", path)
		}
		return nil, err
	}
	if known := KnownSchema(); v > known {
		sqldb.Close()
		return nil, errNewerSchema{have: v, know: known}
	}
	return d, nil
}

// IsNewerSchema reports an error of Open or OpenExisting for a database
// written by a newer controller.
func IsNewerSchema(err error) bool {
	var e errNewerSchema
	return errors.As(err, &e)
}

// Snapshot writes a consistent copy of the database to path (VACUUM
// INTO): it runs while the controller works, and the copy has no WAL.
// path must not exist; it is created in its directory with the umask's
// mode, so the caller keeps it in an owner-only directory and narrows the
// file afterwards.
func (d *DB) Snapshot(ctx context.Context, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	_, err = d.db.ExecContext(ctx, `VACUUM INTO ?`, abs)
	return err
}

// IntegrityCheck runs PRAGMA integrity_check: nil when the database is
// sound, otherwise an error with the first problems found.
func (d *DB) IntegrityCheck(ctx context.Context) error {
	rows, err := d.db.QueryContext(ctx, `PRAGMA integrity_check(20)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return err
		}
		lines = append(lines, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(lines) == 1 && lines[0] == "ok" {
		return nil
	}
	return fmt.Errorf("integrity_check: %s", strings.Join(lines, "; "))
}

// InUse reports whether the database holds anything an admin made: a
// user or a server. A database a controller only started on is not in use.
func (d *DB) InUse(ctx context.Context) (bool, error) {
	var used bool
	err := d.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users) OR EXISTS (SELECT 1 FROM servers)`).Scan(&used)
	return used, err
}
