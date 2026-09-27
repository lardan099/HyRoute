//go:build windows

// Package sysdns reads the DNS servers Windows uses: the packet engine
// recognizes the DNS client's encrypted queries to them, and the kill
// switch lets those queries through.
package sysdns

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Servers lists the DNS servers of the adapters that are up.
func Servers() (map[netip.Addr]bool, error) {
	const flags = windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_FRIENDLY_NAME
	size := uint32(16 << 10)
	for {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		out := map[netip.Addr]bool{}
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				if ip, ok := netip.AddrFromSlice(d.Address.IP()); ok {
					out[ip.Unmap()] = true
				}
			}
		}
		return out, nil
	}
}
