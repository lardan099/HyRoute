package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// A note goes after the admin's notes as a paragraph of its own; the
// state and the rest of the server stay.
func TestAddServerNote(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	srv := model.Server{Name: "a", Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	if err := d.CreateServer(ctx, &srv, nil); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0)
	for _, n := range []string{"first", "second"} {
		if err := d.AddServerNote(ctx, srv.ID, n, at); err != nil {
			t.Fatal(err)
		}
	}
	got, err := d.ServerByID(ctx, srv.ID)
	if err != nil || got.Notes != "first\n\nsecond" || got.State != model.StateHealthy || got.Host != srv.Host || !got.UpdatedAt.Equal(at) {
		t.Fatalf("%q %s %v", got.Notes, got.State, err)
	}
	if err := d.AddServerNote(ctx, srv.ID+1, "x", at); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("no such server: %v", err)
	}
}
