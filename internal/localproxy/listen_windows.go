//go:build windows

package localproxy

import (
	"context"
	"errors"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE (~SO_REUSEADDR), not in x/sys.
const soExclusiveAddrUse = ^4

// listenUDP binds a UDP socket no other process can bind too: without
// SO_EXCLUSIVEADDRUSE a program could bind the same address with
// SO_REUSEADDR and take the datagrams.
func listenUDP(network, addr string) (*net.UDPConn, error) {
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

// classifyReadErr sorts a UDP read error: WSAEMSGSIZE is a datagram too
// large for the buffer; WSAECONNRESET and WSAENETRESET report ICMP errors
// for an earlier send (Go disables SIO_UDP_CONNRESET but not
// SIO_UDP_NETRESET) and say nothing about the socket.
func classifyReadErr(err error) (tooLarge, transient bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false, false
	}
	switch errno {
	case windows.WSAEMSGSIZE:
		return true, false
	case windows.WSAECONNRESET, windows.WSAENETRESET:
		return false, true
	}
	return false, false
}
