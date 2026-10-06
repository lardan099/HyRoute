//go:build windows

package localproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/socks5"
)

// While a proxy's UDP socket holds a port, no other socket can bind it,
// not even with SO_REUSEADDR (SO_EXCLUSIVEADDRUSE).
func TestListenUDPExclusive(t *testing.T) {
	pc, err := socks5.ListenUDP("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		rc.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
		})
		return serr
	}}
	if other, err := lc.ListenPacket(context.Background(), "udp4", pc.LocalAddr().String()); err == nil {
		other.Close()
		t.Fatal("port shared with SO_REUSEADDR")
	}
}

func TestClassifyReadErr(t *testing.T) {
	wrap := func(e syscall.Errno) error { return &net.OpError{Op: "read", Err: fmt.Errorf("x: %w", e)} }
	if big, tr := classifyReadErr(wrap(windows.WSAEMSGSIZE)); !big || tr {
		t.Fatal("WSAEMSGSIZE")
	}
	for _, e := range []syscall.Errno{windows.WSAECONNRESET, windows.WSAENETRESET} {
		if big, tr := classifyReadErr(wrap(e)); big || !tr {
			t.Fatal(e)
		}
	}
	if big, tr := classifyReadErr(errors.New("x")); big || tr {
		t.Fatal("unknown")
	}
}
