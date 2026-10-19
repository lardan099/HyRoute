package remote_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

// Kernel parameters come from /proc/sys: no program runs (sysctl is in
// /usr/sbin, off a non-root session's PATH on Debian).
func TestSysctlRead(t *testing.T) {
	ex := fake.New()
	ex.SetFile("/proc/sys/net/core/rmem_max", []byte("212992\n"))
	ex.SetFile("/proc/sys/net/ipv4/tcp_rmem", []byte("4096\t131072\t6291456\n"))
	ex.SetFile("/proc/sys/net/ipv4/tcp_available_congestion_control", []byte("reno cubic\n"))
	got, err := remote.SysctlRead(context.Background(), ex, "net.core.rmem_max", "net.ipv4.tcp_rmem", "net.ipv4.tcp_available_congestion_control", "net.core.nope")
	if err != nil {
		t.Fatal(err)
	}
	if got["net.core.rmem_max"] != "212992" || got["net.ipv4.tcp_rmem"] != "4096 131072 6291456" || got["net.ipv4.tcp_available_congestion_control"] != "reno cubic" || len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if len(ex.Commands()) != 0 {
		t.Fatalf("ran %v", ex.Commands())
	}
}

// modinfo is looked up in the sbin directories too.
func TestKernelModule(t *testing.T) {
	ex := fake.New()
	ex.On("sh", "-c").Do(func(cmd remote.Cmd) (remote.Result, error) {
		if !strings.Contains(cmd.Args[2], "/usr/sbin:/sbin") || !strings.Contains(cmd.Args[2], "modinfo -F name") || cmd.Args[len(cmd.Args)-1] != "tcp_bbr" {
			return remote.Result{ExitCode: 1}, nil
		}
		return remote.Result{Stdout: []byte("tcp_bbr\n")}, nil
	})
	if ok, err := remote.KernelModule(context.Background(), ex, "tcp_bbr"); err != nil || !ok {
		t.Fatalf("%v %v (%v)", ok, err, ex.Commands())
	}
	if ok, err := remote.KernelModule(context.Background(), ex, "sch_fq"); err != nil || ok {
		t.Fatalf("missing module: %v %v", ok, err)
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
