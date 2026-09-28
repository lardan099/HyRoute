//go:build windows

package relay

import (
	"net"
	"syscall"
	"unsafe"
)

// sioTCPInfo is SIO_TCP_INFO, _WSAIORW(IOC_VENDOR, 39) (Windows 10 1703
// and later).
const sioTCPInfo = 0xD8000027

// tcpInfo is TCP_INFO_v0 (mstcpip.h).
type tcpInfo struct {
	State             uint32
	Mss               uint32
	ConnectionTimeMs  uint64
	TimestampsEnabled bool
	RttUs             uint32
	MinRttUs          uint32
	BytesInFlight     uint32
	Cwnd              uint32
	SndWnd            uint32
	RcvWnd            uint32
	RcvBuf            uint32
	BytesOut          uint64
	BytesIn           uint64
	BytesReordered    uint32
	BytesRetrans      uint32
	FastRetrans       uint32
	DupAcksIn         uint32
	TimeoutEpisodes   uint32
	SynRetrans        uint8
}

// sendProgress reads c's send side from the kernel: acked is how many
// bytes the peer has acknowledged (BytesOut counts a retransmission again,
// in-flight bytes are not acknowledged yet), window what it advertises,
// state the connection's TCP state. ok is false when the system cannot
// tell (no SIO_TCP_INFO, c closed).
func sendProgress(c net.Conn) (p progress, ok bool) {
	sc, isSC := c.(syscall.Conn)
	if !isSC {
		return p, false
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return p, false
	}
	err = rc.Control(func(fd uintptr) {
		var version uint32 // TCP_INFO_v0
		var info tcpInfo
		var n uint32
		if syscall.WSAIoctl(syscall.Handle(fd), sioTCPInfo,
			(*byte)(unsafe.Pointer(&version)), uint32(unsafe.Sizeof(version)),
			(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), &n, nil, 0) != nil {
			return
		}
		p = progress{
			state:    info.State,
			acked:    int64(info.BytesOut) - int64(info.BytesRetrans) - int64(info.BytesInFlight),
			inFlight: info.BytesInFlight,
			window:   info.SndWnd,
		}
		ok = true
	})
	return p, err == nil && ok
}
