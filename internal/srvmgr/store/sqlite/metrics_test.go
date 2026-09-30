package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func f(v float64) *float64 { return &v }

func TestMetrics(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	srv := model.Server{Name: "m", Host: "192.0.2.7", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	if err := d.CreateServer(ctx, &srv, nil); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC) // a period start
	// Three samples in the first period, one in the next; the first has
	// no rates.
	for i, m := range []model.Metric{
		{At: base, MemUsedMiB: 100, MemTotalMiB: 1000, DiskUsedMiB: 10, DiskTotalMiB: 100, Load1: 1},
		{At: base.Add(5 * time.Minute), CPU: f(10), MemUsedMiB: 200, MemTotalMiB: 1000, DiskUsedMiB: 10, DiskTotalMiB: 100, Load1: 2, RxBps: f(100), TxBps: f(50)},
		{At: base.Add(10 * time.Minute), CPU: f(30), MemUsedMiB: 300, MemTotalMiB: 1000, DiskUsedMiB: 10, DiskTotalMiB: 100, Load1: 3, RxBps: f(300), TxBps: f(150)},
		{At: base.Add(16 * time.Minute), CPU: f(90), MemUsedMiB: 900, MemTotalMiB: 1000, DiskUsedMiB: 10, DiskTotalMiB: 100, Load1: 9},
	} {
		m.ServerID = srv.ID
		if err := d.AddMetric(ctx, m); err != nil {
			t.Fatal(i, err)
		}
	}
	got, err := d.Metrics(ctx, srv.ID, 0, base, base.Add(time.Hour))
	if err != nil || len(got) != 4 || got[0].CPU != nil || *got[1].CPU != 10 || !got[0].At.Equal(base) {
		t.Fatalf("%+v %v", got, err)
	}

	// Twenty minutes in: only the first period is finished.
	if err := d.CompactMetrics(ctx, base.Add(20*time.Minute), 48*time.Hour, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	avg, _ := d.Metrics(ctx, srv.ID, model.MetricStep, base, base.Add(time.Hour))
	if len(avg) != 1 || !avg[0].At.Equal(base) || *avg[0].CPU != 20 || avg[0].MemUsedMiB != 200 || avg[0].Load1 != 2 || *avg[0].RxBps != 200 {
		t.Fatalf("average %+v", avg)
	}

	// Two days later the samples are gone and the averages stay; the
	// second period was averaged while it was whole and is not redone
	// from what is left.
	if err := d.CompactMetrics(ctx, base.Add(40*time.Minute), 48*time.Hour, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.CompactMetrics(ctx, base.Add(49*time.Hour), 48*time.Hour, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.Metrics(ctx, srv.ID, 0, base, base.Add(time.Hour)); len(s) != 0 {
		t.Fatalf("samples left: %d", len(s))
	}
	avg, _ = d.Metrics(ctx, srv.ID, model.MetricStep, base, base.Add(time.Hour))
	if len(avg) != 2 || *avg[1].CPU != 90 {
		t.Fatalf("averages %+v", avg)
	}
	// A month later the averages go too.
	d.CompactMetrics(ctx, base.Add(31*24*time.Hour), 48*time.Hour, 30*24*time.Hour)
	if avg, _ = d.Metrics(ctx, srv.ID, model.MetricStep, base, base.Add(time.Hour)); len(avg) != 0 {
		t.Fatalf("old averages left: %d", len(avg))
	}
}

func TestSwapServerState(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	srv := model.Server{Name: "s", Host: "192.0.2.8", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateDeploying}
	d.CreateServer(ctx, &srv, nil)
	up := []model.ServerState{model.StateHealthy, model.StateDegraded}
	if ok, err := d.SwapServerState(ctx, srv.ID, up, model.StateOffline, time.Now()); ok || err != nil {
		t.Fatalf("deploying server swapped: %v %v", ok, err)
	}
	d.SetServerState(ctx, srv.ID, model.StateHealthy, time.Now())
	if ok, _ := d.SwapServerState(ctx, srv.ID, up, model.StateOffline, time.Now()); !ok {
		t.Fatal("not swapped")
	}
	if s, _ := d.ServerByID(ctx, srv.ID); s.State != model.StateOffline {
		t.Fatalf("state %s", s.State)
	}
}
