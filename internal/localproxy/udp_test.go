package localproxy

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// echoUDP answers every datagram with "echo:" + it.
func echoUDP(t *testing.T) netip.AddrPort {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			pc.WriteToUDPAddrPort(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestSOCKS5UDP(t *testing.T) {
	echo := echoUDP(t)
	// The in-process SOCKS5 server stands for Hysteria.
	tunnel := &socks5.Server{}
	if err := tunnel.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tunnel.Close() })
	var assocs atomic.Int32
	s := &Server{Username: "u", Password: "p", Dial: dialer(nil), Associate: func(ctx context.Context) (UDPTunnel, error) {
		assocs.Add(1)
		cl := socks5.Client{Server: tunnel.Addr()}
		return cl.UDPAssociate(ctx)
	}}
	addr := start(t, s)
	if s.UDPError != "" {
		t.Fatal(s.UDPError)
	}

	cl := socks5.Client{Server: addr, Username: "u", Password: "p"}
	a, err := cl.UDPAssociate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	buf := make([]byte, 2048)
	for _, msg := range []string{"one", "two"} {
		if err := a.WriteTo([]byte(msg), socks5.AddrFromAddrPort(echo)); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		var got string
		var from socks5.Addr
		go func() {
			n, f, err := a.ReadFrom(buf)
			if err == nil {
				got, from = string(buf[:n]), f
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("no answer")
		}
		if got != "echo:"+msg || from.IP != echo.Addr() || from.Port != echo.Port() {
			t.Fatalf("%q from %v", got, from)
		}
	}
	if assocs.Load() != 1 || s.Sent.Load() != 6 || s.Recv.Load() != 16 {
		t.Fatalf("assocs %d sent %d recv %d", assocs.Load(), s.Sent.Load(), s.Recv.Load())
	}

	// A stranger's datagram to the port is dropped: it is not the client.
	stranger, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer stranger.Close()
	hdr, _ := socks5.AppendAddr([]byte{0, 0, 0}, socks5.AddrFromAddrPort(echo))
	stranger.WriteToUDPAddrPort(append(hdr, "x"...), netip.MustParseAddrPort(addr))
	stranger.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := stranger.ReadFromUDPAddrPort(buf); err == nil {
		t.Fatal("a stranger got an answer")
	}

	// Closing the control connection ends the association.
	a.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.byAddr) + len(s.pendingUDP)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("association left behind")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSOCKS5UDPRefused(t *testing.T) {
	addr := start(t, &Server{Dial: dialer(nil)})
	cl := socks5.Client{Server: addr}
	if _, err := cl.UDPAssociate(context.Background()); err == nil {
		t.Fatal("UDP ASSOCIATE accepted without a tunnel for it")
	}
}
