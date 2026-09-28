// Package netwatch reads the networks Windows is connected to for «Сети»
// (internal/netmode): the adapter of the default route, its gateway, what
// the Network List Manager (NLM) says about it and, when asked, the Wi-Fi
// name. It sends nothing and changes nothing. This file holds the parts
// that do not need Windows (tested on every system).
package netwatch

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/lardan099/hyroute/internal/netmode"
)

// IANA interface types (ifType).
const (
	ifTypeEthernet = 6
	ifTypeLoopback = 24
	ifTypeWiFi     = 71
	ifTypeWWANPP   = 243
	ifTypeWWANPP2  = 244
)

// adapterKind is the kind rules use for an interface type.
func adapterKind(ifType uint32) string {
	switch ifType {
	case ifTypeWiFi:
		return netmode.WiFi
	case ifTypeEthernet:
		return netmode.Ethernet
	case ifTypeWWANPP, ifTypeWWANPP2:
		return netmode.Mobile
	}
	return netmode.Other
}

// categoryName is NLM_NETWORK_CATEGORY as rules name it ("" unknown).
func categoryName(c uint32) string {
	switch c {
	case 0:
		return netmode.Public
	case 1:
		return netmode.Private
	case 2:
		return netmode.Domain
	}
	return ""
}

// ssidOffset is where WLAN_CONNECTION_ATTRIBUTES keeps its DOT11_SSID:
// after isState, wlanConnectionMode (4 bytes each) and strProfileName
// (WCHAR[256]).
const ssidOffset = 4 + 4 + 256*2

// parseConnectionAttributes takes the SSID out of a
// WLAN_CONNECTION_ATTRIBUTES buffer (bounds-checked; ok false when the
// buffer is short or the length is over 32).
func parseConnectionAttributes(b []byte) (ssid []byte, ok bool) {
	if len(b) < ssidOffset+4+32 {
		return nil, false
	}
	n := binary.LittleEndian.Uint32(b[ssidOffset:])
	if n > 32 {
		return nil, false
	}
	if n == 0 {
		return nil, true
	}
	return append([]byte(nil), b[ssidOffset+4:ssidOffset+4+int(n)]...), true
}

// adapter is one interface that is up.
type adapter struct {
	ifIndex, ipv6IfIndex uint32
	guid                 string // AdapterName, "{…}"
	ifType               uint32
	name                 string // friendly name
	gateways             []netip.Addr
}

// bestNetwork is the adapter the default route leaves through (index idx
// of GetBestInterfaceEx, IPv4 or IPv6), or nil.
func bestNetwork(ads []adapter, idx uint32) *adapter {
	if idx == 0 {
		return nil
	}
	for i := range ads {
		a := &ads[i]
		if a.ifType == ifTypeLoopback {
			continue
		}
		if a.ifIndex == idx || a.ipv6IfIndex == idx {
			return a
		}
	}
	return nil
}

// pickGateway is the lowest IPv4 gateway if any, else the lowest IPv6
// one ("" none): deterministic, and IPv4 first since IPv6 router
// advertisements may come later.
func pickGateway(v4, v6 []netip.Addr) string {
	for _, list := range [][]netip.Addr{v4, v6} {
		var best netip.Addr
		for _, a := range list {
			if !a.IsValid() {
				continue
			}
			a = a.WithZone("")
			if !best.IsValid() || a.Less(best) {
				best = a
			}
		}
		if best.IsValid() {
			return best.String()
		}
	}
	return ""
}

// splitGateways sorts gateways into IPv4 and IPv6.
func splitGateways(gws []netip.Addr) (v4, v6 []netip.Addr) {
	for _, a := range gws {
		a = a.Unmap()
		switch {
		case a.Is4():
			v4 = append(v4, a)
		case a.Is6() && !a.IsUnspecified():
			v6 = append(v6, a)
		}
	}
	return v4, v6
}

// macString is a 6-byte MAC as "aa-bb-cc-dd-ee-ff" ("" otherwise).
func macString(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	parts := make([]string, 6)
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, "-")
}

// guidString is a GUID in the registry's form: upper-case with braces.
func guidString(d1 uint32, d2, d3 uint16, d4 [8]byte) string {
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7])
}
