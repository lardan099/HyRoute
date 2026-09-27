//go:build windows

package killswitch

import (
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// dial reaches a public address (not loopback, not LAN, not port 53).
func dial() error {
	c, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
	if err == nil {
		c.Close()
	}
	return err
}

// TestWFP installs the real filters, so it runs only where asked (CI
// Windows runners are elevated): the machine is offline for a moment.
func TestWFP(t *testing.T) {
	if os.Getenv("HYROUTE_WFP_TEST") != "1" || !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("set HYROUTE_WFP_TEST=1 and run elevated")
	}
	if err := dial(); err != nil {
		t.Skipf("no internet to test with: %v", err)
	}
	k := &Switch{}
	if err := k.Release(); err != nil {
		t.Fatal(err)
	}
	defer k.Release()
	if on, err := k.Engaged(); err != nil || on {
		t.Fatalf("engaged before Arm: %v %v", on, err)
	}

	if err := k.Arm(0); err != nil {
		t.Fatal(err)
	}
	if on, err := k.Engaged(); err != nil || !on {
		t.Fatalf("not engaged after Arm: %v", err)
	}
	if err := dial(); err != nil {
		t.Fatalf("blocked while the pass filters are on: %v", err)
	}
	if err := k.Arm(0); err != nil {
		t.Fatalf("second Arm: %v", err)
	}

	// The engine is gone: the block holds, loopback still works.
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dial(); err == nil {
		t.Fatal("not blocked after Close")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	if c, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second); err != nil {
		t.Fatalf("loopback blocked: %v", err)
	} else {
		c.Close()
	}

	// A new run finds the block and its own programs get through.
	exe, _ := os.Executable()
	t.Logf("test program: %s (long %s)", exe, longPath(exe))
	k2 := &Switch{Apps: func() []string { return []string{exe} }}
	if on, err := k2.Engaged(); err != nil || !on {
		t.Fatalf("a new run does not see the block: %v", err)
	}
	if err := k2.Arm(0); err != nil {
		t.Fatal(err)
	}
	if err := k2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dial(); err != nil {
		t.Fatalf("an allowed program is blocked: %v", err)
	}

	if err := k2.Release(); err != nil {
		t.Fatal(err)
	}
	if on, _ := k2.Engaged(); on {
		t.Fatal("engaged after Release")
	}
	if err := dial(); err != nil {
		t.Fatalf("still blocked after Release: %v", err)
	}
}

// TestArmUnderGC: building the filters while the garbage collector runs
// crashed the process when an allocation was misaligned.
func TestArmUnderGC(t *testing.T) {
	if os.Getenv("HYROUTE_WFP_TEST") != "1" || !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("set HYROUTE_WFP_TEST=1 and run elevated")
	}
	exe, _ := os.Executable()
	// Paths of odd length leave UTF-16 blobs of 2 mod 8 bytes.
	k := &Switch{Apps: func() []string { return []string{exe, `C:\Windows\notepad.exe`, `C:\Windows\regedit.exe`} }}
	k.Release()
	defer k.Release()
	defer debug.SetGCPercent(debug.SetGCPercent(1))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				runtime.GC()
			}
		}
	}()
	for i := 0; i < 40; i++ {
		if err := k.Arm(0); err != nil {
			t.Fatal(err)
		}
		if i%4 == 3 {
			k.Close()
		}
	}
	close(stop)
	<-done
}

// freePort is a TCP port nothing uses at the moment.
func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// dialFrom connects from local port port.
func dialFrom(port uint16, addr string) error {
	d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{Port: int(port)}}
	c, err := d.Dial("tcp", addr)
	if err == nil {
		c.Close()
	}
	return err
}

// TestWFPRelayPort: under the block HyRoute gets through, but not from
// its relay's port, where the peers are the real remote hosts; loopback
// stays open there.
func TestWFPRelayPort(t *testing.T) {
	if os.Getenv("HYROUTE_WFP_TEST") != "1" || !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("set HYROUTE_WFP_TEST=1 and run elevated")
	}
	if err := dial(); err != nil {
		t.Skipf("no internet to test with: %v", err)
	}
	exe, _ := os.Executable()
	k := &Switch{Self: exe, Apps: func() []string { return []string{exe} }}
	if err := k.Release(); err != nil {
		t.Fatal(err)
	}
	defer k.Release()

	// While routing works the relay's port is open.
	port := freePort(t)
	if err := k.Arm(port); err != nil {
		t.Fatal(err)
	}
	if err := dialFrom(port, "1.1.1.1:443"); err != nil {
		t.Fatalf("the relay's port is blocked under the pass filters: %v", err)
	}

	// A new session's relay (another port; the first one waits out its
	// closed connection), then the engine goes.
	port = freePort(t)
	if err := k.Arm(port); err != nil {
		t.Fatal(err)
	}
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	if err := dialFrom(port, "1.1.1.1:443"); err == nil {
		t.Fatal("the relay's port reaches the internet past the block")
	}
	if err := dial(); err != nil {
		t.Fatalf("HyRoute is blocked on its other ports: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	if err := dialFrom(port, ln.Addr().String()); err != nil {
		t.Fatalf("loopback blocked on the relay's port: %v", err)
	}
}
