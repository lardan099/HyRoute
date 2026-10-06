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

func TestSearchJobLogs(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	var ids []int64
	for _, name := range []string{"a", "b"} {
		srv := model.Server{Name: name, Host: "192.0.2.1", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
		if err := d.CreateServer(ctx, &srv, nil); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, srv.ID)
	}
	base := time.Unix(1_700_000_000, 0)
	for i, sid := range ids {
		j := model.Job{Kind: []string{"deploy", "import"}[i], ServerID: sid, State: model.JobCompleted, Params: []byte("{}"), CreatedAt: base}
		if err := d.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "connect"}}, nil); err != nil {
			t.Fatal(err)
		}
		for k, l := range []struct{ level, msg string }{{"info", "Подключено"}, {"warn", "Конфиг 100% читают все"}, {"error", "Служба упала"}} {
			if err := d.AppendJobLog(ctx, &model.JobLog{JobID: j.ID, Time: base.Add(time.Duration(i*10+k) * time.Second), Level: l.level, Step: "connect", Message: l.msg}); err != nil {
				t.Fatal(err)
			}
		}
	}
	all, err := d.SearchJobLogs(ctx, model.JobLogFilter{})
	if err != nil || len(all) != 6 || all[0].Message != "Служба упала" || all[0].ServerID != ids[1] || all[0].Kind != "import" {
		t.Fatalf("%+v %v", all, err)
	}
	// A cascade link changes its exit server too: its lines are found by
	// either server.
	link := model.Job{Kind: "link", ServerID: ids[0], Servers: []int64{ids[1]}, State: model.JobCompleted, Params: []byte("{}"), CreatedAt: base}
	if err := d.CreateJob(ctx, &link, []model.JobStep{{Idx: 0, Name: "exit-config"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := d.AppendJobLog(ctx, &model.JobLog{JobID: link.ID, Time: base.Add(time.Minute), Level: "info", Step: "exit-config", Message: "Конфиг выхода записан"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		f    model.JobLogFilter
		want int
	}{
		{model.JobLogFilter{ServerID: ids[0]}, 4},
		{model.JobLogFilter{ServerID: ids[1]}, 4},
		{model.JobLogFilter{ServerID: ids[1], Text: "выхода"}, 1},
		{model.JobLogFilter{Level: "warn"}, 4},
		{model.JobLogFilter{Level: "error", ServerID: ids[0]}, 1},
		{model.JobLogFilter{Text: "100%"}, 2},
		{model.JobLogFilter{Text: "%"}, 2},
		{model.JobLogFilter{Text: "_"}, 0},
		{model.JobLogFilter{Limit: 2}, 2},
	} {
		got, err := d.SearchJobLogs(ctx, c.f)
		if err != nil || len(got) != c.want {
			t.Errorf("%+v: %d %v", c.f, len(got), err)
		}
	}
}
