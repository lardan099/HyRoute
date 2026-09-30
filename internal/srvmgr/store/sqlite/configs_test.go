package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

func TestConfigsAndInstallations(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	srv := model.Server{Name: "a", Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	if err := d.CreateServer(ctx, &srv, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CurrentConfig(ctx, srv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no config: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	for i, src := range []model.ConfigSource{model.ConfigImport, model.ConfigDeploy} {
		c := model.ServerConfig{ServerID: srv.ID, SHA256: "sum", Meta: model.ConfigMeta{Ports: "443"}, Source: src, At: now}
		err := d.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return []byte{byte(rev)}, nil })
		if err != nil || c.Revision != i+1 {
			t.Fatalf("revision %d: %v", c.Revision, err)
		}
	}
	if cur, err := d.CurrentConfig(ctx, srv.ID); err != nil || cur.Revision != 2 || cur.Source != model.ConfigDeploy || cur.Sealed[0] != 2 || cur.Meta.Ports != "443" {
		t.Fatalf("current: %+v %v", cur, err)
	}

	if _, err := d.Installation(ctx, srv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no installation: %v", err)
	}
	in := model.Installation{ServerID: srv.ID, Binary: "/opt/hy/hysteria", Config: "/opt/hy/server.yaml", Unit: "hy2.service", Version: "v2.6.0", At: now}
	if err := d.SetInstallation(ctx, in); err != nil {
		t.Fatal(err)
	}
	in.Managed, in.Version = true, "v2.12.3"
	if err := d.SetInstallation(ctx, in); err != nil {
		t.Fatal(err)
	}
	if got, err := d.Installation(ctx, srv.ID); err != nil || got != in {
		t.Fatalf("%+v %v", got, err)
	}
	// Deleting the server deletes what belongs to it.
	if err := d.DeleteServer(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Installation(ctx, srv.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("installation outlived its server: %v", err)
	}
}
