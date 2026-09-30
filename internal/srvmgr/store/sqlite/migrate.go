package sqlite

import (
	"context"
	"database/sql"
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

func (d *DB) migrate(ctx context.Context) error {
	return d.migrateFS(ctx, migrationFS)
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
		err := d.tx(ctx, func(t *sql.Tx) error {
			if _, err := t.ExecContext(ctx, m.sql); err != nil {
				return err
			}
			_, err := t.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, time.Now().Unix())
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %04d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}
