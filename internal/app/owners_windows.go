//go:build windows

package app

import (
	"errors"
	"net/netip"

	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/localproxy"
)

// proxyOwners finds the owners of local sockets for the owner check of
// local proxies' UDP (Windows' socket tables). Tests replace it.
var proxyOwners localproxy.OwnerLookup = attribOwners{}

type attribOwners struct{}

// TCPOwner looks in the table of local's family, then in both: a client's
// dual-stack socket connected to 127.0.0.1 is listed in the IPv6 one.
func (attribOwners) TCPOwner(local, remote netip.AddrPort) (uint32, bool) {
	if pid, ok := attrib.LookupTCPOwner(local, remote); ok {
		return pid, true
	}
	if !local.Addr().Unmap().Is4() {
		return 0, false
	}
	rows, _ := attrib.ReadTCPTable()
	return attrib.OwnerOf(rows, local, remote)
}

func (attribOwners) UDPOwner(local netip.AddrPort) (uint32, error) {
	pid, err := attrib.LookupUDPOwnerStrict(local)
	if errors.Is(err, attrib.ErrNoOwner) {
		return 0, localproxy.ErrNoOwner
	}
	return pid, err
}
