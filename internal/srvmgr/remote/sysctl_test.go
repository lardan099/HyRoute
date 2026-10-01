package remote_test

import (
	"context"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

func TestSysctlRead(t *testing.T) {
	ex := fake.New()
	ex.On("sysctl", "-e").Reply("net.core.rmem_max = 212992\nnet.ipv4.tcp_rmem = 4096\t131072\t6291456\nnet.ipv4.tcp_available_congestion_control = reno cubic\n", 255)
	got, err := remote.SysctlRead(context.Background(), ex, "net.core.rmem_max", "net.ipv4.tcp_rmem", "net.ipv4.tcp_available_congestion_control", "net.core.nope")
	if err != nil {
		t.Fatal(err)
	}
	if got["net.core.rmem_max"] != "212992" || got["net.ipv4.tcp_rmem"] != "4096 131072 6291456" || got["net.ipv4.tcp_available_congestion_control"] != "reno cubic" || len(got) != 3 {
		t.Fatalf("%v", got)
	}
}

func TestSysctlRefused(t *testing.T) {
	ctx := context.Background()
	ex := fake.New()
	for _, kv := range [][2]string{{"net.core.rmem_max; reboot", "1"}, {"net.core.rmem_max", "1;reboot"}, {"../etc", "1"}, {"net.core.rmem_max", "$(id)"}} {
		if err := remote.SysctlSet(ctx, ex, kv[0], kv[1], false); err == nil {
			t.Errorf("%q=%q accepted", kv[0], kv[1])
		}
	}
	if _, err := remote.SysctlRead(ctx, ex, "net core"); err == nil {
		t.Error("bad key read")
	}
	if _, err := remote.KernelModule(ctx, ex, "tcp_bbr; id"); err == nil {
		t.Error("bad module")
	}
	if len(ex.Calls()) != 0 {
		t.Fatalf("ran %v", ex.Commands())
	}
}
