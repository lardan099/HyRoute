package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

// migrations lists migrations/NNNN_name.sql in order. Versions must be
// 1, 2, 3… without gaps: a gap means a file was renamed or lost.
func migrations(fsys fs.FS) ([]migration, error) {
	names, err := fs.Glob(fsys, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, n := range names {
		base := strings.TrimSuffix(n[len("migrations/"):], ".sql")
		num, name, ok := strings.Cut(base, "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("migration %s: want NNNN_name.sql", n)
		}
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: v, name: name, sql: string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("migration %04d_%s: expected version %d", m.version, m.name, i+1)
		}
	}
	return ms, nil
}

// migrateFS applies the migrations of fsys that are not applied yet, each
// in its own transaction.
func (d *DB) migrateFS(ctx context.Context, fsys fs.FS) error {
	ms, err := migrations(fsys)
	if err != nil {
		return err
	}
	if _, err := d.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return err
	}
	have, err := d.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if have > len(ms) {
		return errNewerSchema{have: have, know: len(ms)}
	}
	for _, m := range ms[have:] {
		if err := d.apply(ctx, m); err != nil {
			return fmt.Errorf("migration %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

// noForeignKeys starts a migration that rebuilds a table other tables
// reference (SQLite cannot change a constraint in place): with foreign
// keys on, dropping the old table would run their ON DELETE actions, and
// the rename would point the references at the old name. Such a migration
// runs with foreign keys off, as the SQLite documentation describes, and
// commits only when PRAGMA foreign_key_check finds nothing. It is the
// first line of the migration.
const noForeignKeys = "-- foreign_keys: off"

// apply runs one migration in its own transaction.
func (d *DB) apply(ctx context.Context, m migration) error {
	if first, _, _ := strings.Cut(m.sql, "\n"); strings.TrimSpace(first) != noForeignKeys {
		return d.tx(ctx, func(t *sql.Tx) error { return applyIn(ctx, t, m) })
	}
	// The pragma is not changed inside a transaction, and it holds for
	// one connection: the migration takes one of its own, which is closed
	// afterwards instead of going back to the pool with foreign keys off.
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() {
		conn.Raw(func(any) error { return driver.ErrBadConn })
		conn.Close()
	}()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
		return err
	}
	t, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	err = applyIn(ctx, t, m)
	if err == nil {
		err = foreignKeyCheck(ctx, t)
	}
	if err != nil {
		t.Rollback()
		return err
	}
	return t.Commit()
}

func applyIn(ctx context.Context, t *sql.Tx, m migration) error {
	if _, err := t.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	_, err := t.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, time.Now().Unix())
	return err
}

// foreignKeyCheck fails when a row references one that is not there.
func foreignKeyCheck(ctx context.Context, t *sql.Tx) error {
	rows, err := t.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return err
	}
	defer rows.Close()
	if rows.Next() {
		var table string
		var rowid sql.NullInt64
		var parent string
		var fk int
		if err := rows.Scan(&table, &rowid, &parent, &fk); err != nil {
			return err
		}
		return fmt.Errorf("foreign key check: a row of %s (rowid %d) references a missing row of %s", table, rowid.Int64, parent)
	}
	return rows.Err()
}
