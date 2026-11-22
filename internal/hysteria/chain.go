package hysteria

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// Upstream is the first VPN's local SOCKS5 endpoint.
type Upstream interface {
	Available() bool
	UDPAvailable() bool
	SOCKS() socks5.Client
}

func (s *Supervisor) waitUpstream(ctx context.Context) (socks5.Client, error) {
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.Via != nil {
			if ep := s.Via(); ep != nil && ep.Available() {
				if !s.Profile.IsVLESS() && !ep.UDPAvailable() {
					return socks5.Client{}, errors.New("первый VPN не пропускает UDP, необходимый для " + s.Profile.ProtocolName())
				}
				if cl := ep.SOCKS(); cl.Server != "" {
					return cl, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return socks5.Client{}, ctx.Err()
		case <-deadline.C:
			return socks5.Client{}, errors.New("первый VPN цепочки недоступен")
		case <-ticker.C:
		}
	}
}

// udpChain relays QUIC to one fixed peer via the first VPN's UDP association.
// The local socket remembers the QUIC client's source port for replies.
type udpChain struct {
	local *net.UDPConn
	assoc *socks5.UDPAssoc
	peer  atomic.Pointer[netip.AddrPort]
	wg    sync.WaitGroup
	once  sync.Once
	done  chan struct{}
}

func startUDPChain(ctx context.Context, cl socks5.Client, dst socks5.Addr) (*udpChain, error) {
	maxPayload := socks5.MaxUDPPayload(dst)
	if maxPayload == 0 {
		return nil, errors.New("недопустимый адрес выходного VPN")
	}
	local, err := socks5.ListenUDP("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	assoc, err := cl.UDPAssociate(ctx)
	if err != nil {
		local.Close()
		return nil, err
	}
	c := &udpChain{local: local, assoc: assoc, done: make(chan struct{})}
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		defer c.close()
		buf := make([]byte, 65536)
		for {
			n, from, err := local.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n > maxPayload {
				continue
			}
			peer := c.peer.Load()
			if peer == nil {
				addr := from
				peer = &addr
				c.peer.Store(peer)
			}
			if from == *peer && assoc.WriteTo(buf[:n], dst) != nil {
				return
			}
		}
	}()
	go func() {
		defer c.wg.Done()
		defer c.close()
		buf := make([]byte, 65536)
		for {
			n, _, err := assoc.ReadFrom(buf)
			if err != nil {
				return
			}
			if peer := c.peer.Load(); peer != nil {
				if _, err := local.WriteToUDPAddrPort(buf[:n], *peer); err != nil {
					return
				}
			}
		}
	}()
	return c, nil
}

func (c *udpChain) close() {
	c.once.Do(func() {
		close(c.done)
		c.local.Close()
		c.assoc.Close()
	})
}
