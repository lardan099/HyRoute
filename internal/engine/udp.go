package engine

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/socks5"
)

// A udpSession carries the tunneled datagrams of one application socket
// (L:lp) through one SOCKS5 UDP association. Hysteria binds an association
// to its first sender and multiplexes destinations, so every tunneled
// destination of that socket shares it. Replies are rebuilt as packets
// from the remote to L:lp and injected inbound.
type udpSession struct {
	c     *Core
	local netip.AddrPort
	tun   Tunnel

	mu       sync.Mutex
	addr     divert.Address // latest outbound address: interface for injection
	assoc    *socks5.UDPAssoc
	state    sessState
	queue    []queuedDatagram
	last     time.Time // latest datagram either way (idle expiry)
	failedAt time.Time
}

type sessState uint8

const (
	sessConnecting sessState = iota
	sessReady
	sessFailed
	sessClosed
)

type queuedDatagram struct {
	payload []byte
	dst     netip.AddrPort
	rec     *flows.Record
}

// retryAfterFailure throttles association attempts when Hysteria refuses.
const retryAfterFailure = 2 * time.Second

func (c *Core) udpSend(uf *udpFlow, payload []byte, addr *divert.Address, key nat.FlowKey) {
	tun := c.tunnel(uf.profile)
	if tun == nil || !tun.Available() || !tun.UDPAvailable() {
		c.UDPDropped.Add(1)
		return
	}
	if len(payload) > maxSOCKSPayload {
		if !c.bigWarn.Swap(true) {
			c.Log.Warn("UDP datagram too large for Hysteria SOCKS5 (4 KB buffer, no fragmentation): dropped",
				"size", len(payload), "dst", key.Dst)
		}
		c.UDPDropped.Add(1)
		return
	}
	now := time.Now()
	sk := sessKey{key.Src, uf.profile}
	c.mu.Lock()
	s := c.sessions[sk]
	if s == nil || s.replaceable(now) || s.tun != tun {
		if s != nil {
			go s.close()
		}
		s = &udpSession{c: c, local: key.Src, tun: tun, last: now}
		c.sessions[sk] = s
		go s.connect()
	}
	c.mu.Unlock()
	s.send(payload, key.Dst, addr, uf.rec, now)
}

func (s *udpSession) replaceable(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == sessClosed || (s.state == sessFailed && now.Sub(s.failedAt) > retryAfterFailure)
}

func (s *udpSession) lastUsed() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func (s *udpSession) send(payload []byte, dst netip.AddrPort, addr *divert.Address, rec *flows.Record, now time.Time) {
	s.mu.Lock()
	s.addr = *addr
	s.last = now
	switch s.state {
	case sessConnecting:
		if len(s.queue) < sessionQueueMax {
			s.queue = append(s.queue, queuedDatagram{append([]byte(nil), payload...), dst, rec})
		} else {
			s.c.UDPDropped.Add(1)
		}
		s.mu.Unlock()
		return
	case sessReady:
		a := s.assoc
		s.mu.Unlock()
		s.write(a, payload, dst, rec)
	default:
		s.mu.Unlock()
		s.c.UDPDropped.Add(1)
	}
}

func (s *udpSession) write(a *socks5.UDPAssoc, payload []byte, dst netip.AddrPort, rec *flows.Record) {
	if err := a.WriteTo(payload, socks5.AddrFromAddrPort(dst)); err != nil {
		s.c.UDPDropped.Add(1)
		return
	}
	s.c.UDPTunneled.Add(1)
	rec.Sent.Add(int64(len(payload)))
	if cnt, ok := s.tun.(counting); ok {
		cnt.NoteTraffic(int64(len(payload)), 0)
	}
}

func (s *udpSession) connect() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	a, err := s.tun.UDPAssociate(ctx)
	cancel()
	s.mu.Lock()
	if s.state == sessClosed {
		s.mu.Unlock()
		if a != nil {
			a.Close()
		}
		return
	}
	if err != nil {
		s.state, s.failedAt = sessFailed, time.Now()
		dropped := len(s.queue)
		s.queue = nil
		s.mu.Unlock()
		s.c.UDPDropped.Add(int64(dropped))
		s.c.Log.Warn("UDP associate failed", "local", s.local, "err", err)
		return
	}
	s.assoc, s.state = a, sessReady
	q := s.queue
	s.queue = nil
	s.mu.Unlock()
	for _, d := range q {
		s.write(a, d.payload, d.dst, d.rec)
	}
	go s.read(a)
}

func (s *udpSession) read(a *socks5.UDPAssoc) {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.ReadFrom(buf)
		if err != nil {
			s.mu.Lock()
			if s.state == sessReady {
				// The association ended (Hysteria restarted): the next
				// datagram opens a new one.
				s.state, s.failedAt = sessFailed, time.Time{}
			}
			s.mu.Unlock()
			return
		}
		if from.Host != "" || !from.IP.IsValid() {
			continue
		}
		src := netip.AddrPortFrom(from.IP.Unmap(), from.Port)
		if src.Addr().Is4() != s.local.Addr().Unmap().Is4() {
			continue
		}
		payload := buf[:n]
		pkt := packet.BuildUDP(src, s.local, payload)
		s.mu.Lock()
		addr := s.addr
		s.last = time.Now() // replies keep the association alive too
		s.mu.Unlock()
		addr.SetOutbound(false)
		addr.SetChecksumsValid()
		s.c.Inject(pkt, &addr)

		s.c.mu.Lock()
		uf := s.c.udp[nat.FlowKey{Src: s.local, Dst: src}]
		if uf != nil {
			uf.last = time.Now()
		}
		s.c.mu.Unlock()
		if uf != nil {
			uf.rec.Recv.Add(int64(n))
		}
		if cnt, ok := s.tun.(counting); ok {
			cnt.NoteTraffic(0, int64(n))
		}
		if src.Port() == 53 {
			// Tunneled DNS answers never pass the DNS sniff handle (it sits
			// above the handle that injects them), so feed the cache here.
			s.c.DNS.AddResponse(payload)
		}
	}
}

func (s *udpSession) close() {
	s.mu.Lock()
	s.state = sessClosed
	a := s.assoc
	s.assoc = nil
	s.mu.Unlock()
	if a != nil {
		a.Close()
	}
}
