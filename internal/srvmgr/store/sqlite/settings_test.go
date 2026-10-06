package sqlite

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

func TestSettings(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	if _, err := d.Setting(ctx, "k"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unset: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	for _, v := range []string{"one", "two"} {
		if err := d.SetSetting(ctx, "k", v, now); err != nil {
			t.Fatal(err)
		}
		if got, err := d.Setting(ctx, "k"); err != nil || got != v {
			t.Fatalf("%q %v, want %q", got, err, v)
		}
	}
}

// The master key check looks for sealed values in every table that has
// them.
func TestSealedData(t *testing.T) {
	ctx := context.Background()
	newServer := func(d *DB) model.Server {
		t.Helper()
		srv := model.Server{Name: "a", Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
		if err := d.CreateServer(ctx, &srv, nil); err != nil {
			t.Fatal(err)
		}
		return srv
	}
	check := func(d *DB, has bool, sealed, context string) {
		t.Helper()
		if got, err := d.HasSealed(ctx); err != nil || got != has {
			t.Fatalf("HasSealed %v %v, want %v", got, err, has)
		}
		b, c, err := d.SealedSample(ctx)
		if sealed == "" {
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("sample %q %q %v, want none", b, c, err)
			}
			return
		}
		if err != nil || string(b) != sealed || c != context {
			t.Fatalf("sample %q %q %v, want %q %q", b, c, err, sealed, context)
		}
	}

	d, _ := openTemp(t)
	check(d, false, "", "")
	srv := newServer(d)
	check(d, false, "", "") // a server without credentials
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "sum", Source: model.ConfigImport, At: time.Now()}
	if err := d.AddConfig(ctx, &c, func(int) ([]byte, error) { return []byte("sealed config"), nil }); err != nil {
		t.Fatal(err)
	}
	check(d, true, "sealed config", model.ConfigContext(srv.ID, 1))
	seal := func(id int64) ([]model.Credential, error) {
		return []model.Credential{{Kind: model.CredSSHPassword, Sealed: []byte("sealed password")}}, nil
	}
	if err := d.UpdateServer(ctx, &srv, seal, nil); err != nil {
		t.Fatal(err)
	}
	check(d, true, "sealed password", model.CredContext(srv.ID, model.CredSSHPassword))

	// A job secret has no sample (its context belongs to package jobs),
	// but it is sealed data.
	d, _ = openTemp(t)
	srv = newServer(d)
	j := model.Job{Kind: "deploy", ServerID: srv.ID, State: model.JobCompleted, Params: []byte("{}"), CreatedAt: time.Now()}
	if err := d.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "connect"}}, func(int64) ([]byte, error) { return []byte("sealed secret"), nil }); err != nil {
		t.Fatal(err)
	}
	check(d, true, "", "")
}

// SealedVersions reads the key version of the sealed values of every
// table that has them.
func TestSealedVersions(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	sealedAs := func(v uint32) []byte {
		return append(binary.BigEndian.AppendUint32([]byte("HRS1"), v), "the rest of the value"...)
	}
	versions := func(want ...uint32) {
		t.Helper()
		vs, err := d.SealedVersions(ctx)
		slices.Sort(vs)
		if err != nil || !slices.Equal(vs, want) {
			t.Fatalf("%v %v, want %v", vs, err, want)
		}
	}
	versions()
	srv := model.Server{Name: "a", Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	if err := d.CreateServer(ctx, &srv, nil); err != nil {
		t.Fatal(err)
	}
	for _, v := range []uint32{1, 1} {
		c := model.ServerConfig{ServerID: srv.ID, SHA256: "sum", Source: model.ConfigImport, At: time.Now()}
		if err := d.AddConfig(ctx, &c, func(int) ([]byte, error) { return sealedAs(v), nil }); err != nil {
			t.Fatal(err)
		}
	}
	versions(1)
	seal := func(int64) ([]model.Credential, error) {
		return []model.Credential{{Kind: model.CredSSHPassword, Sealed: sealedAs(2)}}, nil
	}
	if err := d.UpdateServer(ctx, &srv, seal, nil); err != nil {
		t.Fatal(err)
	}
	versions(1, 2)
	j := model.Job{Kind: "deploy", ServerID: srv.ID, State: model.JobCompleted, Params: []byte("{}"), CreatedAt: time.Now()}
	if err := d.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "connect"}}, func(int64) ([]byte, error) { return sealedAs(3), nil }); err != nil {
		t.Fatal(err)
	}
	versions(1, 2, 3)
}
