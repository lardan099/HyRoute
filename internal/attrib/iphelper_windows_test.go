//go:build windows

package attrib

import (
	"net"
	"net/netip"
	"os"
	"testing"
)

// The live tables list this process's loopback listener and connection.
func TestReadTCPTable(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if s := <-accepted; s != nil {
		defer s.Close()
	}
	local := netip.MustParseAddrPort(c.LocalAddr().String())
	remote := netip.MustParseAddrPort(ln.Addr().String())

	rows, err := ReadTCPTable()
	if err != nil {
		t.Fatal(err)
	}
	s := NewTCPSnapshot(rows)
	if pid, ok := s.Owner(local, remote); !ok || pid != uint32(os.Getpid()) {
		t.Fatalf("owner of %v -> %v: %d, %v", local, remote, pid, ok)
	}
	if !s.Listening(remote, uint32(os.Getpid())) {
		t.Fatalf("listener %v not found", remote)
	}
	if s.Listening(local, uint32(os.Getpid())) {
		t.Fatalf("client port %v taken for a server", local)
	}
	if pid, ok := LookupTCPOwner(local, remote); !ok || pid != uint32(os.Getpid()) {
		t.Fatalf("LookupTCPOwner: %d, %v", pid, ok)
	}
}
