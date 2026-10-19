package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

func addServers(t *testing.T, d *DB, names ...string) []int64 {
	t.Helper()
	var ids []int64
	for _, n := range names {
		s := model.Server{Name: n, Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
		if err := d.CreateServer(context.Background(), &s, nil); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s.ID)
	}
	return ids
}

func roleOf(t *testing.T, d *DB, id int64) model.ServerRole {
	t.Helper()
	s, err := d.ServerByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return s.Role
}

func twoNodes(name string, entry, exit int64) *model.Chain {
	now := time.Unix(1_700_000_000, 0)
	return &model.Chain{Name: name, Nodes: []int64{entry, exit}, Links: []model.ChainLink{{Params: []byte(`{"udp":true}`)}}, CreatedAt: now, UpdatedAt: now}
}

func TestChains(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	ids := addServers(t, d, "a", "b", "c")
	a, b, c := ids[0], ids[1], ids[2]

	var seen []model.Chain
	ch := twoNodes("Germany", a, b)
	if err := d.CreateChain(ctx, ch, func(existing []model.Chain) error { seen = existing; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 0 || ch.ID == 0 {
		t.Fatalf("first chain: saw %v, id %d", seen, ch.ID)
	}
	l := ch.Links[0]
	if l.ChainID != ch.ID || l.Idx != 0 || l.From != a || l.To != b || l.State != model.LinkNew || string(l.Params) != `{"udp":true}` {
		t.Fatalf("link %+v", l)
	}
	if roleOf(t, d, a) != model.RoleEntry || roleOf(t, d, b) != model.RoleExit || roleOf(t, d, c) != model.RoleStandalone {
		t.Fatal("roles do not follow the chain")
	}

	// The check sees every stored chain and can refuse; nothing is stored then.
	refused := errors.New("refused")
	err := d.CreateChain(ctx, twoNodes("second", c, b), func(existing []model.Chain) error {
		if len(existing) != 1 || existing[0].ID != ch.ID || len(existing[0].Links) != 1 || existing[0].Links[0].To != b {
			t.Fatalf("existing %+v", existing)
		}
		return refused
	})
	if !errors.Is(err, refused) || roleOf(t, d, c) != model.RoleStandalone {
		t.Fatalf("refused chain: %v, role %s", err, roleOf(t, d, c))
	}
	if cs, _ := d.ListChains(ctx); len(cs) != 1 {
		t.Fatalf("chains after refusal: %d", len(cs))
	}
	if err := d.CreateChain(ctx, twoNodes("germany", c, b), nil); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("name taken in another case: %v", err)
	}
	if err := d.CreateChain(ctx, twoNodes("ghost", c, 999), nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown server: %v", err)
	}
	if err := d.CreateChain(ctx, &model.Chain{Name: "one", Nodes: []int64{a}}, nil); err == nil {
		t.Fatal("a chain of one node stored")
	}

	// A server in a chain cannot be deleted.
	if err := d.DeleteServer(ctx, b); !errors.Is(err, store.ErrInChain) {
		t.Fatalf("delete exit: %v", err)
	}

	// Links and their secrets.
	l.State, l.FromRevision, l.ToRevision, l.ConfigSHA256, l.UpdatedAt = model.LinkActive, 3, 7, "abc", time.Unix(1_700_000_100, 0)
	if err := d.UpdateLink(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateLink(ctx, model.ChainLink{ChainID: ch.ID, Idx: 0, State: "bogus"}); err == nil {
		t.Fatal("unknown link state stored")
	}
	if err := d.UpdateLink(ctx, model.ChainLink{ChainID: ch.ID, Idx: 5, State: model.LinkNew}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing link: %v", err)
	}
	if s, err := d.LinkSecrets(ctx, ch.ID, 0); err != nil || s != nil {
		t.Fatalf("no secrets yet: %q, %v", s, err)
	}
	if err := d.SetLinkSecrets(ctx, ch.ID, 0, []byte("sealed"), time.Unix(1_700_000_200, 0)); err != nil {
		t.Fatal(err)
	}
	if s, err := d.LinkSecrets(ctx, ch.ID, 0); err != nil || string(s) != "sealed" {
		t.Fatalf("secrets %q, %v", s, err)
	}
	if _, err := d.LinkSecrets(ctx, ch.ID, 3); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("secrets of a missing link: %v", err)
	}
	got, err := d.ChainByID(ctx, ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	gl := got.Links[0]
	if got.Name != "Germany" || len(got.Nodes) != 2 || got.Entry() != a || got.Exit() != b ||
		gl.State != model.LinkActive || gl.FromRevision != 3 || gl.ToRevision != 7 || gl.ConfigSHA256 != "abc" || gl.From != a || gl.To != b {
		t.Fatalf("chain %+v", got)
	}

	// Name and notes.
	if err := d.UpdateChain(ctx, ch.ID, "Через Германию", "заметка", time.Unix(1_700_000_300, 0)); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.ChainByID(ctx, ch.ID); got.Name != "Через Германию" || got.Notes != "заметка" {
		t.Fatalf("renamed %+v", got)
	}
	if err := d.UpdateChain(ctx, 999, "x", "", time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rename missing: %v", err)
	}

	// An exit serves several entries and stays exit until its last chain goes.
	ch2 := twoNodes("second", c, b)
	if err := d.CreateChain(ctx, ch2, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteChain(ctx, ch.ID, time.Unix(1_700_000_400, 0)); err != nil {
		t.Fatal(err)
	}
	if roleOf(t, d, a) != model.RoleStandalone || roleOf(t, d, b) != model.RoleExit || roleOf(t, d, c) != model.RoleEntry {
		t.Fatal("roles after deleting a chain")
	}
	if _, err := d.ChainByID(ctx, ch.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted chain: %v", err)
	}
	if _, err := d.LinkSecrets(ctx, ch.ID, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("secrets outlived their chain: %v", err)
	}
	if err := d.DeleteChain(ctx, ch.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if err := d.DeleteServer(ctx, a); err != nil {
		t.Fatalf("server out of every chain: %v", err)
	}
	if err := d.DeleteChain(ctx, ch2.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if roleOf(t, d, b) != model.RoleStandalone || roleOf(t, d, c) != model.RoleStandalone {
		t.Fatal("roles after the last chain")
	}
}

// Roles set by hand before cascades had no chain behind them: the
// migration makes them standalone.
func TestChainsMigrationResetsRoles(t *testing.T) {
	ctx := context.Background()
	sqldb, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	d := &DB{db: sqldb}
	t.Cleanup(func() { d.Close() })
	ms, err := migrations(migrationFS)
	if err != nil {
		t.Fatal(err)
	}
	old, all := fstest.MapFS{}, fstest.MapFS{}
	for _, m := range ms {
		f := &fstest.MapFile{Data: []byte(m.sql)}
		all[filepathName(m)] = f
		if m.version < 16 {
			old[filepathName(m)] = f
		}
	}
	if err := d.migrateFS(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.ExecContext(ctx, `INSERT INTO servers (name, host, ssh_port, ssh_user, auth_type, role, state, created_at, updated_at) VALUES
		('a', '192.0.2.1', 22, 'root', 'password', 'exit', 'new', 1, 1),
		('b', '192.0.2.2', 22, 'root', 'password', 'standalone', 'new', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	if err := d.migrateFS(ctx, all); err != nil {
		t.Fatal(err)
	}
	rows, err := d.db.QueryContext(ctx, `SELECT name, role FROM servers ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, role string
		rows.Scan(&name, &role)
		if role != string(model.RoleStandalone) {
			t.Fatalf("%s kept role %s", name, role)
		}
	}
}
