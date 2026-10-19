package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// A snapshot taken while another connection writes is a sound database
// with a prefix of the writes, and it opens without migrations.
func TestSnapshotWhileWriting(t *testing.T) {
	ctx := context.Background()
	d, path := openTemp(t)
	srv := addServers(t, d, "a")[0]

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c := model.ServerConfig{ServerID: srv, SHA256: fmt.Sprint(i), Source: model.ConfigEdit, At: time.Now()}
			if err := d.AddConfig(ctx, &c, func(int) ([]byte, error) { return sealedAs(1, "config"), nil }); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	out := filepath.Join(filepath.Dir(path), "snap.db")
	time.Sleep(20 * time.Millisecond)
	err := d.Snapshot(ctx, out)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenExisting(ctx, out)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.IntegrityCheck(ctx); err != nil {
		t.Fatal(err)
	}
	if v, err := s.SchemaVersion(ctx); err != nil || v != KnownSchema() {
		t.Fatalf("schema %d %v, want %d", v, err, KnownSchema())
	}
	if used, err := s.InUse(ctx); err != nil || !used {
		t.Fatalf("in use %v %v: the snapshot has the server", used, err)
	}
	// The snapshot does not exist twice.
	if err := d.Snapshot(ctx, out); err == nil {
		t.Fatal("a snapshot over an existing file")
	}
}

func TestOpenExisting(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if _, err := OpenExisting(ctx, filepath.Join(dir, "missing.db")); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.db")); !os.IsNotExist(err) {
		t.Fatal("OpenExisting created the file")
	}

	// An older schema stays as it is; a newer one is refused.
	raw := func(name string, version int) string {
		t.Helper()
		p := filepath.Join(dir, name)
		uri, _ := fileURI(p)
		db, err := sql.Open("sqlite", uri)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		for _, q := range []string{
			`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`,
			fmt.Sprintf(`INSERT INTO schema_migrations VALUES (%d, 'x', 0)`, version),
		} {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	old, err := OpenExisting(ctx, raw("old.db", 1))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := old.SchemaVersion(ctx); err != nil || v != 1 {
		t.Fatalf("old schema %d %v: OpenExisting migrated it", v, err)
	}
	old.Close()
	if _, err := OpenExisting(ctx, raw("new.db", KnownSchema()+1)); !IsNewerSchema(err) {
		t.Fatalf("newer schema: %v", err)
	}

	notDB := filepath.Join(dir, "text.db")
	os.WriteFile(notDB, []byte("this is not a database, just some text that is long enough to fill a header"), 0o600)
	if _, err := OpenExisting(ctx, notDB); err == nil {
		t.Fatal("a text file opened")
	}
}

func TestInUse(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	if used, err := d.InUse(ctx); err != nil || used {
		t.Fatalf("fresh database in use: %v %v", used, err)
	}
	if err := d.SetSetting(ctx, "master_key_check", "x", time.Now()); err != nil {
		t.Fatal(err)
	}
	if used, err := d.InUse(ctx); err != nil || used {
		t.Fatalf("a setting makes it in use: %v %v", used, err)
	}
	u := model.User{Username: "owner", PasswordHash: "h", Role: model.RoleOwner, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := d.CreateUser(ctx, &u); err != nil {
		t.Fatal(err)
	}
	if used, err := d.InUse(ctx); err != nil || !used {
		t.Fatalf("with a user: %v %v", used, err)
	}
}

// A deleted preset's ID is not given to the next one.
func TestPresetIDsNotReused(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	var ids []int64
	for _, n := range []string{"a", "b"} {
		p := model.Preset{Name: n, Config: "acl:\n", CreatedAt: time.Now(), UpdatedAt: time.Now()}
		if err := d.CreatePreset(ctx, &p); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, p.ID)
	}
	if err := d.DeletePreset(ctx, ids[1]); err != nil {
		t.Fatal(err)
	}
	p := model.Preset{Name: "c", Config: "acl:\n", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := d.CreatePreset(ctx, &p); err != nil {
		t.Fatal(err)
	}
	if p.ID == ids[1] {
		t.Fatalf("preset %d given again", p.ID)
	}
}
