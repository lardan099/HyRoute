// Package engine is the packet engine: it owns the WinDivert handles,
// decides routes for new flows and implements the reflect NAT into the relay
// and the packet-level UDP path into SOCKS5 UDP ASSOCIATE.
//
// core.go is platform independent (tested on any OS with synthetic
// packets); engine_windows.go wires it to the WinDivert handles.
package engine

import (
	"net/netip"
)

// WinDivert priorities. Higher values see packets first. DPI bypass tools
// (zapret winws, GoodbyeDPI) open their NETWORK handles at priority 0, so
// the main handle sits above them: Direct packets we reinject unchanged
// then continue down to them, while Tunnel packets are reflected before
// a DPI tool can split them or inject fake segments that our checksum
// recomputation would turn into valid data. Sniff handles get their own
// levels, because "a packet is only diverted once per priority level".
const (
	PrioMain    = 1000
	PrioMainAlt = 1001 // used while hot-swapping the main filter
	PrioDNS     = 1010
	PrioSocket  = 1020
	PrioFlow    = 1030
)

// DefaultExclusions reports whether dst never takes part in routing
// (defence in depth; the kernel filter already excludes these).
func DefaultExclusions(dst netip.Addr) bool {
	dst = dst.Unmap()
	return dst.IsLoopback() || dst.IsPrivate() || dst.IsLinkLocalUnicast() || dst.IsMulticast() ||
		dst.IsUnspecified() || dst.IsLinkLocalMulticast() || (dst.Is4() && dst.As4()[0] >= 240)
}
