//go:build !windows

package socks5

import (
	"context"
	"net"
)

// ListenUDP binds a UDP socket (HyRoute ships for Windows; this is for the
// tests on other systems).
func ListenUDP(network, addr string) (*net.UDPConn, error) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
