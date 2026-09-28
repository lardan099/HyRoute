//go:build !windows

package localproxy

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// listenUDP binds a UDP socket (HyRoute ships for Windows; this is for the
// tests on other systems).
func listenUDP(network, addr string) (*net.UDPConn, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// classifyReadErr sorts a UDP read error: ECONNREFUSED reports an ICMP
// error for an earlier send.
func classifyReadErr(err error) (tooLarge, transient bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false, false
	}
	switch errno {
	case syscall.EMSGSIZE:
		return true, false
	case syscall.ECONNREFUSED:
		return false, true
	}
	return false, false
}
