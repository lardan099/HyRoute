//go:build windows

package socks5

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE (~SO_REUSEADDR), not in x/sys.
const soExclusiveAddrUse = ^4

// ListenUDP binds a UDP socket no other process can bind too: without
// SO_EXCLUSIVEADDRUSE a program could bind the same address with
// SO_REUSEADDR and take the datagrams. (Not for TCP listeners: one with it
// cannot bind its port again while connections of the previous one
// linger in TIME_WAIT.)
func ListenUDP(network, addr string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
