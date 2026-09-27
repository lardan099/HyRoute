//go:build windows

package attrib

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

// LookupTCPOwner finds the owner PID of a TCP connection in the system
// tables (GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL). It is the fallback
// when no SOCKET event arrived in time; SYN_SENT connections are listed.
func LookupTCPOwner(local, remote netip.AddrPort) (uint32, bool) {
	local, remote = norm(local), norm(remote)
	af := uint32(windows.AF_INET)
	if local.Addr().Is6() {
		af = windows.AF_INET6
	}
	buf, err := tcpTable(af)
	if err != nil {
		return 0, false
	}
	return ownerOf(parseTCPRows(buf, af == windows.AF_INET6), local, remote)
}

// ReadTCPTable reads the TCP tables of both address families, listening
// sockets included. On an error it returns what it could read.
func ReadTCPTable() ([]TCPRow, error) {
	var rows []TCPRow
	var first error
	for _, af := range []uint32{windows.AF_INET, windows.AF_INET6} {
		buf, err := tcpTable(af)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		rows = append(rows, parseTCPRows(buf, af == windows.AF_INET6)...)
	}
	return rows, first
}

// LookupUDPOwner finds the owner of a local UDP endpoint
// (GetExtendedUdpTable, UDP_TABLE_OWNER_PID).
func LookupUDPOwner(local netip.AddrPort) (uint32, bool) {
	local = norm(local)
	af := uint32(windows.AF_INET)
	if local.Addr().Is6() {
		af = windows.AF_INET6
	}
	buf, err := table(procGetExtendedUdpTable, af, udpTableOwnerPID)
	if err != nil || len(buf) < 4 {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(buf))
	if af == windows.AF_INET {
		// MIB_UDPROW_OWNER_PID: localAddr, localPort, pid.
		const size = 12
		for i := 0; i < n && 4+(i+1)*size <= len(buf); i++ {
			r := buf[4+i*size:]
			la := netip.AddrFrom4([4]byte(r[0:4]))
			if binary.BigEndian.Uint16(r[4:]) == local.Port() && (la == local.Addr() || la.IsUnspecified()) {
				return binary.LittleEndian.Uint32(r[8:]), true
			}
		}
		return 0, false
	}
	// MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, pid.
	const size = 28
	for i := 0; i < n && 4+(i+1)*size <= len(buf); i++ {
		r := buf[4+i*size:]
		la := netip.AddrFrom16([16]byte(r[0:16]))
		if binary.BigEndian.Uint16(r[20:]) == local.Port() && (la == local.Addr() || la.IsUnspecified()) {
			return binary.LittleEndian.Uint32(r[24:]), true
		}
	}
	return 0, false
}

func tcpTable(af uint32) ([]byte, error) {
	return table(procGetExtendedTcpTable, af, tcpTableOwnerPIDAll)
}

func table(proc *windows.LazyProc, af uint32, class uintptr) ([]byte, error) {
	size := uint32(64 * 1024)
	for tries := 0; tries < 4; tries++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0,
			uintptr(af), class, 0)
		switch windows.Errno(r) {
		case 0:
			return buf[:size], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size += 16 * 1024
			continue
		default:
			return nil, windows.Errno(r)
		}
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}
