//go:build windows

package netwatch

import (
	"encoding/binary"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetIpNetEntry2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetIpNetEntry2")

// mibIPNetRow2 is MIB_IPNET_ROW2 (88 bytes on 64-bit Windows).
type mibIPNetRow2 struct {
	Address               [28]byte // SOCKADDR_INET
	InterfaceIndex        uint32
	InterfaceLuid         uint64
	PhysicalAddress       [32]byte
	PhysicalAddressLength uint32
	State                 uint32 // NL_NEIGHBOR_STATE
	Flags                 uint8
	_                     [3]byte
	ReachabilityTime      uint32
}

// Neighbour states with a MAC worth trusting: Probe, Delay, Stale,
// Reachable, Permanent.
const (
	nlnsProbe     = 2
	nlnsPermanent = 6
)

// gatewayMAC is the MAC of gateway gw on interface ifIndex from the
// neighbour table ("" when it has none yet). It only looks: nothing is
// sent (no ResolveIpNetEntry2).
func gatewayMAC(gw netip.Addr, ifIndex uint32) string {
	var row mibIPNetRow2
	switch {
	case gw.Is4():
		binary.LittleEndian.PutUint16(row.Address[0:], windows.AF_INET)
		a := gw.As4()
		copy(row.Address[4:8], a[:])
	case gw.Is6():
		binary.LittleEndian.PutUint16(row.Address[0:], windows.AF_INET6)
		a := gw.As16()
		copy(row.Address[8:24], a[:])
		if gw.IsLinkLocalUnicast() {
			binary.LittleEndian.PutUint32(row.Address[24:], ifIndex) // scope ID
		}
	default:
		return ""
	}
	row.InterfaceIndex = ifIndex
	if r, _, _ := procGetIpNetEntry2.Call(uintptr(unsafe.Pointer(&row))); r != 0 {
		return ""
	}
	if row.State < nlnsProbe || row.State > nlnsPermanent || row.PhysicalAddressLength != 6 {
		return ""
	}
	return macString(row.PhysicalAddress[:6])
}
