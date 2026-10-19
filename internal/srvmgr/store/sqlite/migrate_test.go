package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"
)

func openTemp(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "data", "hyroute-server.db")
	d, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, path
}

func TestMigrationsApplyOnCleanDB(t *testing.T) {
	d, path := openTemp(t)
	ctx := context.Background()
	ms, err := migrations(migrationFS)
	if err != nil {
		t.Fatal(err)
	}
	v, err := d.SchemaVersion(ctx)
	if err != nil || v != len(ms) {
		t.Fatalf("version %d, %v; want %d", v, err, len(ms))
	}
	var n int
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil || n != len(ms) {
		t.Fatalf("schema_migrations rows %d, %v", n, err)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("db file mode %v, %v", st.Mode(), err)
		}
	}
	// Reopening applies nothing new.
	d.Close()
	d2, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if v2, _ := d2.SchemaVersion(ctx); v2 != v {
		t.Fatalf("version after reopen %d, want %d", v2, v)
	}
}

func TestMigrationsIncremental(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	have, _ := d.SchemaVersion(ctx)
	fsys := fstest.MapFS{}
	ms, _ := migrations(migrationFS)
	for _, m := range ms {
		fsys[filepathName(m)] = &fstest.MapFile{Data: []byte(m.sql)}
	}
	fsys[filepathName(migration{version: len(ms) + 1, name: "extra"})] = &fstest.MapFile{Data: []byte(`CREATE TABLE extra (id INTEGER PRIMARY KEY);`)}
	if err := d.migrateFS(ctx, fsys); err != nil {
		t.Fatal(err)
	}
	if v, _ := d.SchemaVersion(ctx); v != have+1 {
		t.Fatalf("version %d, want %d", v, have+1)
	}
	if _, err := d.db.ExecContext(ctx, `INSERT INTO extra (id) VALUES (1)`); err != nil {
		t.Fatal(err)
	}
}

func TestFailedMigrationRollsBack(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	have, _ := d.SchemaVersion(ctx)
	fsys := fstest.MapFS{}
	ms, _ := migrations(migrationFS)
	for _, m := range ms {
		fsys[filepathName(m)] = &fstest.MapFile{Data: []byte(m.sql)}
	}
	fsys[filepathName(migration{version: len(ms) + 1, name: "broken"})] = &fstest.MapFile{Data: []byte(`CREATE TABLE half (id INTEGER); THIS IS NOT SQL;`)}
	if err := d.migrateFS(ctx, fsys); err == nil {
		t.Fatal("broken migration applied")
	}
	if v, _ := d.SchemaVersion(ctx); v != have {
		t.Fatalf("version %d after failure, want %d", v, have)
	}
	var n int
	d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name = 'half'`).Scan(&n)
	if n != 0 {
		t.Fatal("table of a failed migration left behind")
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	d, path := openTemp(t)
	ctx := context.Background()
	if _, err := d.db.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (999, 'future', 0)`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	_, err := Open(ctx, path)
	var newer errNewerSchema
	if !errors.As(err, &newer) {
		t.Fatalf("err %v, want errNewerSchema", err)
	}
}

func TestMigrationNamesChecked(t *testing.T) {
	for _, fsys := range []fstest.MapFS{
		{"migrations/0002_gap.sql": {Data: []byte("SELECT 1;")}},
		{"migrations/init.sql": {Data: []byte("SELECT 1;")}},
		{"migrations/0001_a.sql": {Data: []byte("SELECT 1;")}, "migrations/0001_b.sql": {Data: []byte("SELECT 1;")}},
	} {
		if _, err := migrations(fsys); err == nil {
			t.Errorf("%v: no error", fsys)
		}
	}
}

func filepathName(m migration) string {
	return fmt.Sprintf("migrations/%04d_%s.sql", m.version, m.name)
}
