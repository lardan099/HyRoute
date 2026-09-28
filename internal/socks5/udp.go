package socks5

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
)

// UDPAssoc is an established UDP ASSOCIATE session. The association lives as
// long as the control TCP connection; Close tears down both.
type UDPAssoc struct {
	ctrl  net.Conn
	pc    *net.UDPConn
	relay *net.UDPAddr
}

// UDPAssociate opens an association. Hysteria binds the association to the
// first sender address, so one UDPAssoc must be used from one local socket.
func (c *Client) UDPAssociate(ctx context.Context) (*UDPAssoc, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	local := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	ctrl, bound, err := c.request(ctx, CmdUDPAssociate, AddrFromAddrPort(local))
	if err != nil {
		pc.Close()
		return nil, err
	}
	ra, err := relayAddr(bound, c.Server)
	if err != nil {
		ctrl.Close()
		pc.Close()
		return nil, err
	}
	a := &UDPAssoc{ctrl: ctrl, pc: pc, relay: ra}
	// The association ends when the server closes the control connection.
	go func() {
		var b [1]byte
		_, _ = ctrl.Read(b[:])
		a.Close()
	}()
	return a, nil
}

func relayAddr(bound Addr, server string) (*net.UDPAddr, error) {
	ip := bound.IP
	if bound.Host != "" || !ip.IsValid() || ip.IsUnspecified() {
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			return nil, err
		}
		if ip, err = netip.ParseAddr(host); err != nil {
			return nil, errors.New("socks5: cannot determine UDP relay address")
		}
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip.Unmap(), bound.Port)), nil
}

// WriteTo sends payload to dst through the association.
func (a *UDPAssoc) WriteTo(payload []byte, dst Addr) error {
	b, err := AppendAddr([]byte{0, 0, 0}, dst)
	if err != nil {
		return err
	}
	_, err = a.pc.WriteToUDP(append(b, payload...), a.relay)
	return err
}

// ReadFrom reads one datagram; from is the remote peer reported by the server.
func (a *UDPAssoc) ReadFrom(buf []byte) (int, Addr, error) {
	for {
		n, src, err := a.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return 0, Addr{}, err
		}
		if src.Addr().Unmap() != a.relay.AddrPort().Addr().Unmap() || src.Port() != uint16(a.relay.Port) {
			continue
		}
		if n < 4 || buf[2] != 0 { // fragmented datagrams are not supported
			continue
		}
		from, hl, err := ParseAddr(buf[3:n])
		if err != nil {
			continue
		}
		m := copy(buf, buf[3+hl:n])
		return m, from, nil
	}
}

// Close ends the association.
func (a *UDPAssoc) Close() error {
	a.ctrl.Close()
	return a.pc.Close()
}

// hysteriaUDPBuffer: Hysteria (app/v2.x) carries a UDP datagram only if it
// fits two 4096-byte buffers, on the client and on the server: its SOCKS5
// relay's (app/internal/socks5 udpBufferSize, SOCKS5 header included) and
// the QUIC UDP message's (core/internal/protocol MaxUDPSize: 8 bytes +
// varint + "host:port" + data). Over the second one Hysteria drops the
// datagram silently. Over the first one it is worse: udpServer's
// ReadFromUDP fails (WSAEMSGSIZE on Windows) and Hysteria closes the whole
// association, i.e. every tunneled destination of that socket. So
// MaxUDPPayload must never overestimate, and nothing may send Hysteria a
// SOCKS5 UDP datagram it has not checked. Re-check both constants when the
// bundled Hysteria version is bumped.
const hysteriaUDPBuffer = 4096

// UDPPayloadAlways is the payload every IP destination carries (the IPv6
// address with the longest text form); IPv4 destinations carry at least 4066.
const UDPPayloadAlways = 4040

// MaxUDPPayload is the largest payload Hysteria carries to dst; 0 when dst
// cannot be sent at all. It counts the bytes AppendAddr puts on the wire
// (IPv4-mapped addresses unmapped, zones dropped) and the "host:port" text
// Hysteria makes of them.
func MaxUDPPayload(dst Addr) int {
	var socks, hp int
	if dst.Host != "" {
		if len(dst.Host) > 255 {
			return 0
		}
		socks = 3 + 1 + 1 + len(dst.Host) + 2 // RSV FRAG ATYP LEN host PORT
		hp = len(net.JoinHostPort(dst.Host, strconv.Itoa(int(dst.Port))))
	} else {
		ip := dst.IP.Unmap().WithZone("")
		if !ip.IsValid() {
			return 0
		}
		socks = 3 + 1 + 16 + 2
		if ip.Is4() {
			socks = 3 + 1 + 4 + 2
		}
		hp = len(Addr{IP: ip, Port: dst.Port}.String())
	}
	varint := 1 // QUIC variable-length integer of len(hp)
	if hp > 63 {
		varint = 2
	}
	return min(hysteriaUDPBuffer-socks, hysteriaUDPBuffer-(8+varint+hp))
}
