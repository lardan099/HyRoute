package attrib

import (
	"encoding/binary"
	"net/netip"
)

// TCPRow is one row of the OS table of TCP connections (IP Helper
// GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL).
type TCPRow struct {
	Local, Remote netip.AddrPort
	State         uint32 // MIB_TCP_STATE
	PID           uint32
}

// TCPStateListen is MIB_TCP_STATE_LISTEN.
const TCPStateListen = 2

// Row sizes: MIB_TCPROW_OWNER_PID and MIB_TCP6ROW_OWNER_PID.
const (
	tcpRowSize  = 24
	tcp6RowSize = 56
)

// parseTCPRows reads a MIB_TCPTABLE_OWNER_PID (v6: MIB_TCP6TABLE_OWNER_PID):
// the number of rows, then the rows.
func parseTCPRows(buf []byte, v6 bool) []TCPRow {
	if len(buf) < 4 {
		return nil
	}
	n := int(binary.LittleEndian.Uint32(buf))
	size := tcpRowSize
	if v6 {
		size = tcp6RowSize
	}
	n = min(n, (len(buf)-4)/size)
	rows := make([]TCPRow, 0, n)
	for i := range n {
		r := buf[4+i*size:]
		if !v6 {
			// state, localAddr, localPort, remoteAddr, remotePort, pid.
			rows = append(rows, TCPRow{
				Local:  netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[4:8])), binary.BigEndian.Uint16(r[8:])),
				Remote: netip.AddrPortFrom(netip.AddrFrom4([4]byte(r[12:16])), binary.BigEndian.Uint16(r[16:])),
				State:  binary.LittleEndian.Uint32(r[0:]),
				PID:    binary.LittleEndian.Uint32(r[20:]),
			})
			continue
		}
		// localAddr[16], localScope, localPort, remoteAddr[16], remoteScope,
		// remotePort, state, pid.
		rows = append(rows, TCPRow{
			Local:  norm(netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[0:16])), binary.BigEndian.Uint16(r[20:]))),
			Remote: norm(netip.AddrPortFrom(netip.AddrFrom16([16]byte(r[24:40])), binary.BigEndian.Uint16(r[44:]))),
			State:  binary.LittleEndian.Uint32(r[48:]),
			PID:    binary.LittleEndian.Uint32(r[52:]),
		})
	}
	return rows
}

// ownerOf is the owner of local -> remote among rows, the way the tables
// list it: a row with an unspecified local address matches any.
func ownerOf(rows []TCPRow, local, remote netip.AddrPort) (uint32, bool) {
	for _, r := range rows {
		if r.Local.Port() == local.Port() && r.Remote == remote && (r.Local.Addr() == local.Addr() || r.Local.Addr().IsUnspecified()) {
			return r.PID, true
		}
	}
	return 0, false
}

// TCPSnapshot indexes one read of the TCP tables, so that the segments of
// many connections cost one read: the owners of connections, and the
// sockets local servers listen on.
type TCPSnapshot struct {
	conns  map[connKey][]TCPRow  // by local port and remote
	listen map[uint16][]listener // by port
}

type connKey struct {
	port   uint16
	remote netip.AddrPort
}

type listener struct {
	addr netip.Addr
	pid  uint32
}

// NewTCPSnapshot indexes rows (both address families).
func NewTCPSnapshot(rows []TCPRow) *TCPSnapshot {
	s := &TCPSnapshot{conns: make(map[connKey][]TCPRow, len(rows)), listen: make(map[uint16][]listener)}
	for _, r := range rows {
		r.Local, r.Remote = norm(r.Local), norm(r.Remote)
		if r.State == TCPStateListen {
			s.listen[r.Local.Port()] = append(s.listen[r.Local.Port()], listener{r.Local.Addr(), r.PID})
			continue
		}
		k := connKey{r.Local.Port(), r.Remote}
		s.conns[k] = append(s.conns[k], r)
	}
	return s
}

// Owner is the owner PID of the connection local -> remote (0 for one in
// TIME_WAIT), as LookupTCPOwner finds it.
func (s *TCPSnapshot) Owner(local, remote netip.AddrPort) (uint32, bool) {
	local, remote = norm(local), norm(remote)
	return ownerOf(s.conns[connKey{local.Port(), remote}], local, remote)
}

// Listening reports whether process pid, the owner of a connection from
// local, listens on local's port at its address or at a wildcard one: the
// connection is then (almost surely) one its server accepted. A wildcard
// of either family counts (a dual-stack socket on [::] accepts IPv4 too),
// but only the owner's: another program's client connection may have got
// the same port as an ephemeral one where the listener does not take it
// (a [::] socket with IPV6_V6ONLY, the default on Windows).
func (s *TCPSnapshot) Listening(local netip.AddrPort, pid uint32) bool {
	local = norm(local)
	for _, l := range s.listen[local.Port()] {
		if l.pid == pid && (l.addr == local.Addr() || l.addr.IsUnspecified()) {
			return true
		}
	}
	return false
}

// OwnerOf is ownerOf for rows read by ReadTCPTable (both families, IPv6
// rows unmapped).
func OwnerOf(rows []TCPRow, local, remote netip.AddrPort) (uint32, bool) {
	return ownerOf(rows, norm(local), norm(remote))
}
