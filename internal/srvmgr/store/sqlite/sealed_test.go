package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"testing/fstest"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

func sealedAs(v uint32, rest string) []byte {
	return append(binary.BigEndian.AppendUint32([]byte("HRS1"), v), rest...)
}

// sealedFixture stores a credential (v1), two config revisions (v1, v2),
// a job secret (v1) and link secrets (v3).
func sealedFixture(t *testing.T, d *DB) (srv, other int64, job model.Job, chain *model.Chain) {
	t.Helper()
	ctx := context.Background()
	ids := addServers(t, d, "a", "b")
	srv, other = ids[0], ids[1]
	s, err := d.ServerByID(ctx, srv)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateServer(ctx, &s, func(int64) ([]model.Credential, error) {
		return []model.Credential{{Kind: model.CredSSHPassword, Sealed: sealedAs(1, "credential")}}, nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	for _, v := range []uint32{1, 2} {
		c := model.ServerConfig{ServerID: srv, SHA256: "sum", Source: model.ConfigImport, At: time.Now()}
		if err := d.AddConfig(ctx, &c, func(r int) ([]byte, error) { return sealedAs(v, fmt.Sprint("config ", r)), nil }); err != nil {
			t.Fatal(err)
		}
	}
	job = model.Job{Kind: "deploy", ServerID: srv, State: model.JobCompleted, Params: []byte("{}"), CreatedAt: time.Now()}
	if err := d.CreateJob(ctx, &job, []model.JobStep{{Idx: 0, Name: "connect"}}, func(int64) ([]byte, error) { return sealedAs(1, "job"), nil }); err != nil {
		t.Fatal(err)
	}
	chain = twoNodes("c", srv, other)
	if err := d.CreateChain(ctx, chain, func([]model.Chain) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := d.SetLinkSecrets(ctx, chain.ID, 0, sealedAs(3, "link"), time.Now()); err != nil {
		t.Fatal(err)
	}
	return srv, other, job, chain
}

// Every key version in use has one sample, with the context of its row.
func TestSealedSamples(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	if got, err := d.SealedSamples(ctx); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	srv, _, _, chain := sealedFixture(t, d)
	got, err := d.SealedSamples(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []store.SealedValue{
		{Version: 1, Sealed: sealedAs(1, "credential"), Context: model.CredContext(srv, model.CredSSHPassword)},
		{Version: 2, Sealed: sealedAs(2, "config 2"), Context: model.ConfigContext(srv, 2)},
		{Version: 3, Sealed: sealedAs(3, "link"), Context: model.LinkSecretContext(chain.ID, 0)},
	}
	if len(got) != len(want) {
		t.Fatalf("%+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].Version != want[i].Version || !bytes.Equal(got[i].Sealed, want[i].Sealed) || got[i].Context != want[i].Context {
			t.Errorf("sample %d: %+v, want %+v", i, got[i], want[i])
		}
	}
}

// RewrapSealed rewrites the values of other versions with their contexts
// and leaves the current ones alone; an error stops it with the rows done
// so far kept, and a second run finishes.
func TestRewrapSealed(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	srv, _, job, chain := sealedFixture(t, d)

	var contexts []string
	fail := model.JobSecretContext(job.ID)
	rewrap := func(sealed []byte, c string) ([]byte, error) {
		if c == fail {
			return nil, errors.New("boom")
		}
		contexts = append(contexts, c)
		return sealedAs(2, "rewrapped "+c), nil
	}
	n, err := d.RewrapSealed(ctx, 2, rewrap)
	if err == nil || n != 2 {
		t.Fatalf("first run: %d %v, want 2 and the job's error", n, err)
	}
	// Config revision 2 is v2 already; the credential and revision 1 were
	// rewritten before the job failed, the link was not reached.
	fail = ""
	n, err = d.RewrapSealed(ctx, 2, rewrap)
	if err != nil || n != 2 {
		t.Fatalf("second run: %d %v, want 2", n, err)
	}
	wantCtx := []string{model.CredContext(srv, model.CredSSHPassword), model.ConfigContext(srv, 1), model.JobSecretContext(job.ID), model.LinkSecretContext(chain.ID, 0)}
	if !slices.Equal(contexts, wantCtx) {
		t.Fatalf("contexts %q, want %q", contexts, wantCtx)
	}
	vs, err := d.SealedVersions(ctx)
	if err != nil || !slices.Equal(vs, []uint32{2}) {
		t.Fatalf("versions after rekey %v %v", vs, err)
	}
	if n, err := d.RewrapSealed(ctx, 2, rewrap); err != nil || n != 0 {
		t.Fatalf("third run: %d %v, want nothing to do", n, err)
	}
}

// A value that does not rewrap stops RewrapSealed: the rows before it
// stay rewritten, and the error names the row.
func TestRewrapSealedStops(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	srv, _, _, _ := sealedFixture(t, d)
	bad := model.ConfigContext(srv, 1)
	n, err := d.RewrapSealed(ctx, 3, func(sealed []byte, c string) ([]byte, error) {
		if c == bad {
			return nil, errors.New("does not open")
		}
		return sealedAs(3, c), nil
	})
	if err == nil || n != 1 || !bytes.Contains([]byte(err.Error()), []byte(bad)) {
		t.Fatalf("%d %v, want 1 done and an error naming %s", n, err, bad)
	}
	vs, _ := d.SealedVersions(ctx)
	slices.Sort(vs)
	if !slices.Equal(vs, []uint32{1, 2, 3}) {
		t.Fatalf("versions %v: the credential moved to 3, the rest stayed", vs)
	}
}

// A database of an older schema has no tables of later migrations: the
// sealed values are read from the tables it has (a backup of it restores,
// backup and doctor read it before the controller migrates it).
func TestSealedOnOlderSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")
	uri, _ := fileURI(path)
	sqldb, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal(err)
	}
	d := &DB{db: sqldb}
	defer d.Close()
	ms, _ := migrations(migrationFS)
	fsys := fstest.MapFS{}
	for _, m := range ms[:20] { // before alert_channels and drift
		fsys[filepathName(m)] = &fstest.MapFile{Data: []byte(m.sql)}
	}
	if err := d.migrateFS(ctx, fsys); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.ExecContext(ctx, `INSERT INTO servers (name, host, ssh_port, ssh_user, auth_type, role, state, created_at, updated_at) VALUES ('a', '192.0.2.1', 22, 'root', 'password', 'standalone', 'new', 0, 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.ExecContext(ctx, `INSERT INTO server_credentials (server_id, kind, sealed, updated_at) VALUES (1, 'ssh_password', ?, 0)`, sealedAs(2, "old")); err != nil {
		t.Fatal(err)
	}
	if has, err := d.HasSealed(ctx); err != nil || !has {
		t.Fatalf("HasSealed %v %v", has, err)
	}
	if vs, err := d.SealedVersions(ctx); err != nil || !slices.Equal(vs, []uint32{2}) {
		t.Fatalf("SealedVersions %v %v", vs, err)
	}
	if ss, err := d.SealedSamples(ctx); err != nil || len(ss) != 1 {
		t.Fatalf("SealedSamples %v %v", ss, err)
	}
	if _, _, err := d.SealedSample(ctx); err != nil {
		t.Fatalf("SealedSample %v", err)
	}
	if n, err := d.RewrapSealed(ctx, 3, func(b []byte, _ string) ([]byte, error) { return sealedAs(3, "new"), nil }); err != nil || n != 1 {
		t.Fatalf("RewrapSealed %d %v", n, err)
	}
}
