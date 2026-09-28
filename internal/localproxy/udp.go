package localproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// SOCKS5 UDP ASSOCIATE. The datagrams of every association come to one UDP
// port, the proxy's own port number (so a firewall rule for the port covers
// them), and are told apart by the client's address: an association takes
// datagrams only from the address of its control connection (the client's
// IP, and the port it named in the request or else the port of its first
// datagram). Each association has its own association through the tunnel.

// UDPTunnel is one association through the tunnel (*socks5.UDPAssoc).
type UDPTunnel interface {
	WriteTo(payload []byte, dst socks5.Addr) error
	ReadFrom(buf []byte) (int, socks5.Addr, error)
	Close() error
}

// Associator opens an association through the tunnel.
type Associator func(ctx context.Context) (UDPTunnel, error)

// maxPendingPerIP caps the associations waiting for their first datagram
// from one IP (each holds a tunnel association).
const maxPendingPerIP = 16

type assoc struct {
	ip     netip.Addr // the client's IP (control connection)
	port   uint16     // expected source port, 0 = the first datagram's
	client netip.AddrPort
	up     UDPTunnel
}

// listenUDP opens the UDP side on the TCP listener's address; without it
// UDP ASSOCIATE is refused.
func (s *Server) listenUDP() {
	if s.Associate == nil {
		return
	}
	ap, err := netip.ParseAddrPort(s.ln.Addr().String())
	if err != nil {
		return
	}
	nw := "udp"
	if ap.Addr().Unmap().Is4() {
		nw = "udp4"
	}
	pc, err := net.ListenUDP(nw, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		s.UDPError = err.Error()
		return
	}
	s.udp = pc
	s.byAddr = map[netip.AddrPort]*assoc{}
	s.wg.Add(1)
	go s.serveUDP()
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, src, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.ctx.Err() != nil {
				return
			}
			continue // e.g. ICMP port unreachable reported on Windows
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		a := s.assocFor(src)
		if a == nil || n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue // unknown sender, or a fragment (not supported)
		}
		dst, hl, err := socks5.ParseAddr(buf[3:n])
		if err != nil {
			continue
		}
		payload := buf[3+hl : n]
		s.Sent.Add(int64(len(payload)))
		a.up.WriteTo(payload, dst)
	}
}

// assocFor finds the association of a sender, binding a waiting one of the
// same IP on its first datagram.
func (s *Server) assocFor(src netip.AddrPort) *assoc {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a := s.byAddr[src]; a != nil {
		return a
	}
	for i, a := range s.pendingUDP {
		if a.ip == src.Addr() && (a.port == 0 || a.port == src.Port()) {
			s.pendingUDP = append(s.pendingUDP[:i], s.pendingUDP[i+1:]...)
			a.client = src
			s.byAddr[src] = a
			go s.udpDown(a)
			return a
		}
	}
	return nil
}

// udpDown sends the tunnel's datagrams to the client.
func (s *Server) udpDown(a *assoc) {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.up.ReadFrom(buf[:len(buf)-300])
		if err != nil {
			return
		}
		hdr, err := socks5.AppendAddr([]byte{0, 0, 0}, from)
		if err != nil {
			continue
		}
		s.Recv.Add(int64(n))
		s.udp.WriteToUDPAddrPort(append(hdr, buf[:n]...), a.client)
	}
}

// associate serves a UDP ASSOCIATE request on control connection c; want is
// the client's address from the request (often zero).
func (s *Server) associate(c net.Conn, want socks5.Addr) {
	if s.udp == nil {
		socksReply(c, 7)
		return
	}
	remote, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		socksReply(c, 1)
		return
	}
	a := &assoc{ip: remote.Addr().Unmap()}
	// A named port is kept; a named IP other than the connection's is not
	// trusted (another host could send in its name): the connection's IP
	// counts.
	if want.Host == "" {
		a.port = want.Port
	}
	s.mu.Lock()
	waiting := 0
	for _, p := range s.pendingUDP {
		if p.ip == a.ip {
			waiting++
		}
	}
	s.mu.Unlock()
	if waiting >= maxPendingPerIP {
		socksReply(c, 1)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 20*time.Second)
	up, err := s.Associate(ctx)
	cancel()
	if err != nil {
		if s.OnError != nil {
			s.OnError("UDP", err)
		}
		socksReply(c, replyCode(err))
		return
	}
	a.up = up
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		up.Close()
		return
	}
	s.pendingUDP = append(s.pendingUDP, a)
	s.mu.Unlock()
	defer s.endAssoc(a)

	// BND: the address the client reached the proxy at, the proxy's port.
	local, _ := netip.ParseAddrPort(c.LocalAddr().String())
	bound := socks5.AddrFromAddrPort(netip.AddrPortFrom(local.Addr().Unmap(), uint16(s.udp.LocalAddr().(*net.UDPAddr).Port)))
	b, _ := socks5.AppendAddr([]byte{5, 0, 0}, bound)
	if _, err := c.Write(b); err != nil {
		return
	}
	// The association lives as long as the control connection.
	c.SetDeadline(time.Time{})
	var one [512]byte
	for {
		if _, err := c.Read(one[:]); err != nil {
			return
		}
	}
}

func (s *Server) endAssoc(a *assoc) {
	s.mu.Lock()
	for i, p := range s.pendingUDP {
		if p == a {
			s.pendingUDP = append(s.pendingUDP[:i], s.pendingUDP[i+1:]...)
			break
		}
	}
	if a.client.IsValid() && s.byAddr[a.client] == a {
		delete(s.byAddr, a.client)
	}
	s.mu.Unlock()
	a.up.Close()
}
