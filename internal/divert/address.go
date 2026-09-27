// Package divert is a cgo-free binding to WinDivert 2.2 (WinDivert.dll is
// loaded at runtime). This file holds the platform-independent parts: the
// WINDIVERT_ADDRESS layout, address conversion and batch splitting.
package divert

import (
	"encoding/binary"
	"net/netip"
)

type Layer uint8

const (
	LayerNetwork        Layer = 0
	LayerNetworkForward Layer = 1
	LayerFlow           Layer = 2
	LayerSocket         Layer = 3
	LayerReflect        Layer = 4
)

type Event uint8

const (
	EventNetworkPacket   Event = 0
	EventFlowEstablished Event = 1
	EventFlowDeleted     Event = 2
	EventSocketBind      Event = 3
	EventSocketConnect   Event = 4
	EventSocketListen    Event = 5
	EventSocketAccept    Event = 6
	EventSocketClose     Event = 7
)

const (
	FlagSniff     uint64 = 0x0001
	FlagDrop      uint64 = 0x0002
	FlagRecvOnly  uint64 = 0x0004
	FlagSendOnly  uint64 = 0x0008
	FlagNoInstall uint64 = 0x0010
	FlagFragments uint64 = 0x0020
)

type Param uint32

const (
	ParamQueueLength  Param = 0
	ParamQueueTime    Param = 1
	ParamQueueSize    Param = 2
	ParamVersionMajor Param = 3
	ParamVersionMinor Param = 4
)

type Shutdown uint32

const (
	ShutdownRecv Shutdown = 1
	ShutdownSend Shutdown = 2
	ShutdownBoth Shutdown = 3
)

const (
	PriorityHighest = 30000
	PriorityLowest  = -30000
)

// Address mirrors WINDIVERT_ADDRESS (80 bytes):
//
//	INT64  Timestamp;
//	UINT32 Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1,
//	       IPv6:1, IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:8;
//	UINT32 Reserved2;
//	union { NETWORK, FLOW, SOCKET, REFLECT; UINT8 Reserved3[64]; };
type Address struct {
	Timestamp int64
	bits      uint32
	reserved2 uint32
	union     [64]byte
}

const AddressSize = 80

const (
	bitSniffed     = 1 << 16
	bitOutbound    = 1 << 17
	bitLoopback    = 1 << 18
	bitImpostor    = 1 << 19
	bitIPv6        = 1 << 20
	bitIPChecksum  = 1 << 21
	bitTCPChecksum = 1 << 22
	bitUDPChecksum = 1 << 23
)

func (a *Address) Layer() Layer       { return Layer(a.bits) }
func (a *Address) Event() Event       { return Event(a.bits >> 8) }
func (a *Address) Sniffed() bool      { return a.bits&bitSniffed != 0 }
func (a *Address) Outbound() bool     { return a.bits&bitOutbound != 0 }
func (a *Address) Loopback() bool     { return a.bits&bitLoopback != 0 }
func (a *Address) Impostor() bool     { return a.bits&bitImpostor != 0 }
func (a *Address) IPv6() bool         { return a.bits&bitIPv6 != 0 }
func (a *Address) SetOutbound(v bool) { a.setBit(bitOutbound, v) }

// SetChecksumsValid marks IP/TCP/UDP checksums as already computed, so the
// driver does not treat them as offloaded.
func (a *Address) SetChecksumsValid() {
	a.bits |= bitIPChecksum | bitTCPChecksum | bitUDPChecksum
}

func (a *Address) setBit(b uint32, v bool) {
	if v {
		a.bits |= b
	} else {
		a.bits &^= b
	}
}

// IfIdx / SubIfIdx are valid for the NETWORK layer.
func (a *Address) IfIdx() uint32    { return binary.LittleEndian.Uint32(a.union[0:]) }
func (a *Address) SubIfIdx() uint32 { return binary.LittleEndian.Uint32(a.union[4:]) }

// SocketData is WINDIVERT_DATA_FLOW / WINDIVERT_DATA_SOCKET (same layout).
type SocketData struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        netip.Addr
	RemoteAddr       netip.Addr
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
}

// Socket decodes the FLOW/SOCKET layer union.
func (a *Address) Socket() SocketData {
	u := a.union[:]
	return SocketData{
		EndpointID:       binary.LittleEndian.Uint64(u[0:]),
		ParentEndpointID: binary.LittleEndian.Uint64(u[8:]),
		ProcessID:        binary.LittleEndian.Uint32(u[16:]),
		LocalAddr:        AddrFromRaw([16]byte(u[20:36])),
		RemoteAddr:       AddrFromRaw([16]byte(u[36:52])),
		LocalPort:        binary.LittleEndian.Uint16(u[52:]),
		RemotePort:       binary.LittleEndian.Uint16(u[54:]),
		Protocol:         u[56],
	}
}

// AddrFromRaw converts WinDivert's host-order UINT32[4] address (as it lies
// in memory) to netip.Addr. WinDivert stores the address as the 128-bit
// byte-swap of the network-order address (WinDivertHelperNtohIPv6Address),
// and IPv4 as IPv4-mapped IPv6. IPv4 results are unmapped.
func AddrFromRaw(raw [16]byte) netip.Addr {
	var n [16]byte
	for i := range raw {
		n[i] = raw[15-i]
	}
	return netip.AddrFrom16(n).Unmap()
}

// RawFromAddr is the inverse of AddrFromRaw.
func RawFromAddr(a netip.Addr) [16]byte {
	n := a.As16()
	var raw [16]byte
	for i := range n {
		raw[i] = n[15-i]
	}
	return raw
}

// SplitBatch splits the concatenated packets returned by a batched RecvEx.
func SplitBatch(buf []byte) [][]byte {
	var out [][]byte
	for len(buf) > 0 {
		var n int
		switch buf[0] >> 4 {
		case 4:
			if len(buf) < 20 {
				return out
			}
			n = int(binary.BigEndian.Uint16(buf[2:]))
		case 6:
			if len(buf) < 40 {
				return out
			}
			n = 40 + int(binary.BigEndian.Uint16(buf[4:]))
		default:
			return out
		}
		if n == 0 || n > len(buf) {
			return out
		}
		out = append(out, buf[:n:n])
		buf = buf[n:]
	}
	return out
}
