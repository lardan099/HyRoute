package remote_test

import (
	"context"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

const headOut = `==> /proc/stat <==
cpu  4705 150 1120 16250 520 0 30 5 0 0
cpu0 2350 75 560 8125 260 0 15 2 0 0
intr 1 2 3

==> /proc/meminfo <==
MemTotal:        2014436 kB
MemFree:          300000 kB
MemAvailable:    1200000 kB

==> /proc/loadavg <==
0.25 0.10 0.05 1/180 4242

==> /proc/net/dev <==
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  900000    100    0    0    0     0          0         0   900000     100    0    0    0     0       0          0
  eth0: 5000000   4000    0    0    0     0          0         0  7000000    5000    0    0    0     0       0          0
docker0:  800000   700    0    0    0     0          0         0   800000     700    0    0    0     0       0          0
  ens4: 1000       10    0    0    0     0          0         0  2000        20    0    0    0     0       0          0

==> /proc/uptime <==
86400.50 170000.00
`

func TestReadSample(t *testing.T) {
	ex := fake.New()
	ex.On("head").Reply(headOut, 0)
	ex.On("df").Reply("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 20511312 3000000 16448592 16% /\n", 0)
	s, err := remote.ReadSample(context.Background(), ex)
	if err != nil {
		t.Fatal(err)
	}
	// total = 4705+150+1120+16250+520+0+30+5; busy = total-16250-520
	if s.CPUTotal != 22780 || s.CPUBusy != 6010 {
		t.Errorf("cpu %d/%d", s.CPUBusy, s.CPUTotal)
	}
	if s.MemTotalKiB != 2014436 || s.MemAvailKiB != 1200000 || s.Load != [3]float64{0.25, 0.10, 0.05} || s.UptimeSec != 86400.5 {
		t.Errorf("%+v", s)
	}
	if s.RxBytes != 5001000 || s.TxBytes != 7002000 {
		t.Errorf("net %d/%d (lo and docker0 must not count)", s.RxBytes, s.TxBytes)
	}
	if s.DiskTotalKiB != 20511312 || s.DiskUsedKiB != 3000000 {
		t.Errorf("disk %d/%d", s.DiskUsedKiB, s.DiskTotalKiB)
	}
	for _, bad := range []string{"", "==> /proc/stat <==\ncpu 1 2 3 4\n", headOut[:len(headOut)-40]} {
		ex := fake.New()
		ex.On("head").Reply(bad, 0)
		ex.On("df").Reply("x\n/dev/vda1 1 1 0 1% /\n", 0)
		if _, err := remote.ReadSample(context.Background(), ex); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
