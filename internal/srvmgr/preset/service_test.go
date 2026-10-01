package preset

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

func service(t *testing.T) (*Service, int64) {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{5}, 32)})
	srv := model.Server{Name: "s", Host: "192.0.2.10", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	if err := db.CreateServer(ctx, &srv, nil); err != nil {
		t.Fatal(err)
	}
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigDeploy, At: time.Now()}
	if err := db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(full), model.ConfigContext(srv.ID, rev)) }); err != nil {
		t.Fatal(err)
	}
	return &Service{Store: db, Keys: keys}, srv.ID
}

// A preset made of a server, its clone, rename and delete; the stored
// preset has no secret or address of the server.
func TestServiceLifecycle(t *testing.T) {
	ctx := context.Background()
	s, srv := service(t)
	p, err := s.FromServer(ctx, " Быстрый ", srv, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Быстрый" || len(p.Sections) != 10 || len(p.Notes) == 0 {
		t.Fatalf("%+v", p)
	}
	if strings.Contains(p.Config, "fake-preset") || strings.Contains(p.Config, "192.0.2.10") {
		t.Fatalf("leak:\n%s", p.Config)
	}
	var fe *model.FieldError
	if _, err := s.FromServer(ctx, "быстрый", srv, 0); !errors.As(err, &fe) || fe.Field != "name" {
		t.Fatalf("same name: %v", err)
	}
	if _, err := s.FromServer(ctx, "x", 999, 0); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("no config: %v", err)
	}
	c, err := s.Clone(ctx, p.ID, "Быстрый 2", 0)
	if err != nil || c.Config != p.Config || c.ID == p.ID {
		t.Fatalf("clone %+v %v", c, err)
	}
	if r, err := s.Rename(ctx, c.ID, "Медленный", 0); err != nil || r.Name != "Медленный" {
		t.Fatalf("rename %+v %v", r, err)
	}
	if _, err := s.Rename(ctx, c.ID, "", 0); !errors.As(err, &fe) {
		t.Fatalf("empty name: %v", err)
	}
	if err := s.Delete(ctx, c.ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Store.PresetByID(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if a, _ := s.Store.ListAudit(ctx, 10); len(a) != 4 || a[0].Action != "preset.delete" {
		t.Fatalf("audit %+v", a)
	}
}

// Export and import keep the preset; a name in use gets a number, other
// formats and versions are refused, and secrets written into a file by
// hand do not get in.
func TestExportImport(t *testing.T) {
	ctx := context.Background()
	s, srv := service(t)
	p, _ := s.FromServer(ctx, "Быстрый", srv, 0)
	b, err := Export(p.Preset)
	if err != nil {
		t.Fatal(err)
	}
	var f File
	if json.Unmarshal(b, &f); f.Format != Format || f.Version != 1 || f.Name != "Быстрый" {
		t.Fatalf("%s", b)
	}
	in, err := s.Import(ctx, b, 0)
	if err != nil || in.Name != "Быстрый (2)" || in.Config != p.Config {
		t.Fatalf("%+v %v", in, err)
	}

	f.Name, f.Config = "Ручной", full
	b, _ = json.Marshal(f)
	in, err = s.Import(ctx, b, 0)
	if err != nil || strings.Contains(in.Config, "fake-preset") || strings.Contains(in.Config, "192.0.2.10") {
		t.Fatalf("%v\n%s", err, in.Config)
	}

	var fe *model.FieldError
	for _, bad := range []string{`{"format":"other","version":1}`, `{"format":"hyroute-preset","version":2,"name":"x","config":"listen: :443"}`, `not json`, `{"format":"hyroute-preset","version":1,"name":"x","config":"auth:\n  type: password\n"}`} {
		if _, err := s.Import(ctx, []byte(bad), 0); !errors.As(err, &fe) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
