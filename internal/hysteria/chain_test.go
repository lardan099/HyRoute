package hysteria

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/vless"
)

func TestVPNChainUDP(t *testing.T) {
	echo, err := socks5.ListenUDP("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		if n, from, err := echo.ReadFromUDP(buf); err == nil {
			echo.WriteToUDP(buf[:n], from)
		}
	}()
	proxy := &socks5.Server{Username: "first", Password: "password"}
	if err := proxy.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	cl := socks5.Client{Server: proxy.Addr(), Username: proxy.Username, Password: proxy.Password}
	dst := socks5.AddrFromAddrPort(echo.LocalAddr().(*net.UDPAddr).AddrPort())
	bridge, err := startUDPChain(context.Background(), cl, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		bridge.close()
		bridge.wg.Wait()
	}()
	socket, err := net.DialUDP("udp4", nil, bridge.local.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := socket.Write([]byte("quic")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	if n, err := socket.Read(buf); err != nil || string(buf[:n]) != "quic" {
		t.Fatalf("UDP via first VPN: %q, %v", buf[:n], err)
	}
	proxy.Close()
	select {
	case <-bridge.done:
	case <-time.After(2 * time.Second):
		t.Fatal("bridge survived the end of its UDP association")
	}
}

func TestVPNChainHysteriaTLS(t *testing.T) {
	p := Profile{Host: "exit.example", Ports: "443", Via: "first", PinServerIP: true}
	if _, err := BuildConfig(&p, RunOptions{}); err == nil {
		t.Fatal("generated a direct config for a chained profile")
	}
	cfg, err := BuildConfig(&p, RunOptions{UDPRelay: "127.0.0.1:5678"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"server: 127.0.0.1:5678", "sni: exit.example"} {
		if !strings.Contains(string(cfg), want) {
			t.Fatalf("config missing %q", want)
		}
	}
}

type chainTestIngress struct{ client socks5.Client }

func (u chainTestIngress) Available() bool      { return true }
func (u chainTestIngress) UDPAvailable() bool   { return true }
func (u chainTestIngress) SOCKS() socks5.Client { return u.client }

func TestVPNChainVLESSPinSkipsLocalDNS(t *testing.T) {
	dir := t.TempDir()
	s := Supervisor{
		Exe:    filepath.Join(dir, "no-core"),
		RunDir: dir,
		Profile: Profile{
			ID: "exit", Via: "first", Host: "exit.invalid", Ports: "443", PinServerIP: true,
			Protocol: ProtoVLESS,
			VLESS:    vless.Settings{ID: "test-user", Security: "tls"},
		},
		Via: func() Upstream {
			return chainTestIngress{socks5.Client{Server: "127.0.0.1:12345", Username: "first", Password: "secret"}}
		},
		Resolve: func(context.Context, string) ([]netip.Addr, error) {
			t.Fatal("resolved the exit server locally")
			return nil, nil
		},
		SetServerIPs: func(ips []netip.Addr) error {
			if len(ips) > 0 {
				t.Fatal("added a direct route to the exit server")
			}
			return nil
		},
	}
	_, _, msg := s.runOnce(context.Background())
	if !strings.Contains(msg, "Не удалось запустить") {
		t.Fatalf("did not reach core startup: %s", msg)
	}
}
