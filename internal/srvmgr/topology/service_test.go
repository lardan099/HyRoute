package topology

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// servers makes a server per auth type ("" = no config) and returns the
// service and their IDs.
func servers(t *testing.T, auths ...string) (*Service, *sqlite.DB, []int64) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var ids []int64
	for i, a := range auths {
		srv := model.Server{Name: "S" + string(rune('A'+i)), Host: "192.0.2.10", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateHealthy}
		if err := db.CreateServer(ctx, &srv, nil); err != nil {
			t.Fatal(err)
		}
		if a != "" {
			c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Meta: model.ConfigMeta{Auth: a}, Source: model.ConfigDeploy, At: time.Now()}
			if err := db.AddConfig(ctx, &c, func(int) ([]byte, error) { return []byte("sealed"), nil }); err != nil {
				t.Fatal(err)
			}
		}
		ids = append(ids, srv.ID)
	}
	return &Service{Store: db, Now: func() time.Time { return time.Unix(1_700_000_000, 0) }}, db, ids
}

func fieldMsg(t *testing.T, err error, want string) {
	t.Helper()
	var fe *model.FieldError
	if !errors.As(err, &fe) || !strings.Contains(fe.Msg, want) {
		t.Fatalf("%v, want …%s…", err, want)
	}
}

func TestServiceCreate(t *testing.T) {
	ctx := context.Background()
	s, db, ids := servers(t, "password", "userpass", "http", "", "password")
	a, b, httpExit, noConfig, e := ids[0], ids[1], ids[2], ids[3], ids[4]

	c, err := s.Create(ctx, Input{Name: " Через Германию ", Nodes: []int64{a, b}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "Через Германию" || c.State != model.LinkNew || len(c.Links) != 1 || c.Links[0].From != a {
		t.Fatalf("%+v", c)
	}
	if srv, _ := db.ServerByID(ctx, a); srv.Role != model.RoleEntry {
		t.Fatalf("entry role %s", srv.Role)
	}

	_, err = s.Create(ctx, Input{Name: "x", Nodes: []int64{e, httpExit}}, 0)
	fieldMsg(t, err, "только password и userpass")
	_, err = s.Create(ctx, Input{Name: "x", Nodes: []int64{e, noConfig}}, 0)
	fieldMsg(t, err, "конфиг сервера выхода")
	_, err = s.Create(ctx, Input{Name: "x", Nodes: []int64{noConfig, b}}, 0)
	fieldMsg(t, err, "конфиг сервера входа")
	_, err = s.Create(ctx, Input{Name: "x", Nodes: []int64{e, 999}}, 0)
	fieldMsg(t, err, "не найден")
	_, err = s.Create(ctx, Input{Name: "через германию", Nodes: []int64{e, b}}, 0)
	fieldMsg(t, err, "названием")
	// The loop check runs in the store's transaction: B → A is refused.
	_, err = s.Create(ctx, Input{Name: "back", Nodes: []int64{b, a}}, 0)
	fieldMsg(t, err, "«SB» — выход каскада «Через Германию»")
	_, err = s.Create(ctx, Input{Name: "  ", Nodes: []int64{e, b}}, 0)
	fieldMsg(t, err, "Название каскада")
	_, err = s.Create(ctx, Input{Name: "x", Nodes: []int64{e, b}, Link: cascade.Params{Up: "10 mbps"}}, 0)
	fieldMsg(t, err, "обе скорости")

	// A second entry to the same exit. A local port given is dropped: the
	// first deployment picks a free one on the entry.
	second, err := s.Create(ctx, Input{Name: "second", Nodes: []int64{e, b}, Link: cascade.Params{LocalPort: 9999}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := cascade.ParseParams(second.Links[0].Params); err != nil || p.LocalPort != 0 {
		t.Fatalf("local port %d kept (%v)", p.LocalPort, err)
	}

	// Rename and notes; names compared in any script.
	if _, err := s.Update(ctx, c.ID, "SECOND", "", 0); err == nil {
		t.Fatal("name of another chain taken")
	}
	got, err := s.Update(ctx, c.ID, "DE", "заметка", 0)
	if err != nil || got.Name != "DE" || got.Notes != "заметка" {
		t.Fatalf("%+v, %v", got, err)
	}

	// A deployed chain is removed by a job only.
	l := c.Links[0]
	l.State = model.LinkActive
	if err := db.UpdateLink(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, c.ID, 0); !errors.Is(err, ErrDeployed) {
		t.Fatalf("delete deployed: %v", err)
	}
	if err := db.DeleteServer(ctx, a); !errors.Is(err, store.ErrInChain) {
		t.Fatalf("delete entry: %v", err)
	}
	l.State = model.LinkFailed
	db.UpdateLink(ctx, l)
	if err := s.Delete(ctx, c.ID, 0); err != nil {
		t.Fatal(err)
	}
	if srv, _ := db.ServerByID(ctx, a); srv.Role != model.RoleStandalone {
		t.Fatalf("role after delete %s", srv.Role)
	}
	if err := s.Delete(ctx, c.ID, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	audit, _ := db.ListAudit(ctx, 10)
	var actions []string
	for _, e := range audit {
		actions = append(actions, e.Action)
	}
	if got := strings.Join(actions, ","); got != "chain_deleted,chain_updated,chain_created,chain_created" {
		t.Fatalf("audit %s", got)
	}
}
