package attrib

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// UDPRow is one row of the OS table of UDP sockets (IP Helper
// GetExtendedUdpTable, UDP_TABLE_OWNER_PID).
type UDPRow struct {
	Local netip.AddrPort
	PID   uint32
}

// Row sizes: MIB_UDPROW_OWNER_PID and MIB_UDP6ROW_OWNER_PID.
const (
	udpRowSize  = 12
	udp6RowSize = 28
)

// ErrNoOwner: the UDP table was read and no single process owns the
// source (none, or two).
var ErrNoOwner = errors.New("attrib: no single owner")

// parseUDPRows reads a MIB_UDPTABLE_OWNER_PID (v6: MIB_UDP6TABLE_OWNER_PID):
// the number of rows, then the rows. IPv4-mapped addresses are unmapped.
func parseUDPRows(buf []byte, v6 bool) []UDPRow {
	if len(buf) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(buf))
	size := udpRowSize
	if v6 {
		size = udp6RowSize
	}
	n = min(n, (len(buf)-4)/size)
	rows := make([]UDPRow, 0, n)
	for i := range n {
		r := buf[4+i*size:]
		if !v6 {
			// localAddr, localPort, pid.
			rows = append(rows, UDPRow{
				Local: netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[0:4])), binary.BigEndian.Uint16(r[4:])),
				PID:   binary.LittleEndian.Uint32(r[8:]),
			})
			continue
		}
		// localAddr[16], localScope, localPort, pid.
		rows = append(rows, UDPRow{
			Local: norm(netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[0:16])), binary.BigEndian.Uint16(r[20:]))),
			PID:   binary.LittleEndian.Uint32(r[24:]),
		})
	}
	return rows
}

// udpOwnerStrict is the single process that can own the UDP source local:
// every socket on local's port bound to local's address or to an
// unspecified one (of either family: a dual-stack [::] socket sends from
// IPv4 addresses too) must belong to it. Windows delivers to the most
// specific socket, but any of them can send from local, so with two owners
// the sender is unknown: ErrNoOwner (fail closed), as with none.
func udpOwnerStrict(rows []UDPRow, local netip.AddrPort) (uint32, error) {
	local = norm(local)
	var pid uint32
	found := false
	for _, r := range rows {
		a := r.Local.Addr().Unmap()
		if r.Local.Port() != local.Port() || (a != local.Addr() && !a.IsUnspecified()) {
			continue
		}
		if a == netip.IPv4Unspecified() && local.Addr().Is6() {
			continue // 0.0.0.0 does not send from an IPv6 address
		}
		if found && r.PID != pid {
			return 0, ErrNoOwner
		}
		pid, found = r.PID, true
	}
	if !found {
		return 0, ErrNoOwner
	}
	return pid, nil
}
