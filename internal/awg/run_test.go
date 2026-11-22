package awg

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"

	"github.com/lardan099/hyroute/internal/socks5"
)

func mustAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func keyPair(t *testing.T) (priv, pub string) {
	t.Helper()
	var k [32]byte
	rand.Read(k[:])
	k[0] &= 248
	k[31] = k[31]&127 | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p)
}

func hexOf(t *testing.T, b64 string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startServer runs an AmneziaWG server for the test on the loopback: its
// network stack is 10.66.0.1, answers HTTP on port 80 with 204 and echoes
// UDP on port 7. extra is its device configuration (the obfuscation).
func startServer(t *testing.T, priv, clientPub, extra string) netip.AddrPort {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.1")}, nil, DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewStdNetBind(), &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf})
	uapi := "private_key=" + hexOf(t, priv) + "\nlisten_port=0\n" + extra +
		"public_key=" + hexOf(t, clientPub) + "\nallowed_ip=10.66.0.2/32\n"
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	st, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, l := range strings.Split(st, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			port, _ = strconv.Atoi(v)
		}
	}
	if port == 0 {
		t.Fatalf("no listen port in\n%s", st)
	}
	ln, err := tnet.ListenTCPAddrPort(mustAddrPort("10.66.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	pc, err := tnet.ListenUDPAddrPort(mustAddrPort("10.66.0.1:7"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
}

// The client reaches a server through its SOCKS5 port, TCP and UDP, as
// plain WireGuard and with the obfuscation of AmneziaWG 2 and 3.
func TestClientThroughServer(t *testing.T) {
	hpk := key(9)
	headers := func(s *Settings) { s.H1, s.H2, s.H3, s.H4 = "1000-1100", "2000-2100", "3000-3100", "4000-4100" }
	const serverHeaders = "h1=1000-1100\nh2=2000-2100\nh3=3000-3100\nh4=4000-4100\n"
	cases := []struct {
		name   string
		set    func(*Settings)
		server string
	}{
		{"WireGuard", func(*Settings) {}, ""},
		{"AmneziaWG 2", func(s *Settings) {
			s.Jc, s.Jmin, s.Jmax = 3, 10, 50
			s.S1, s.S2, s.S3, s.S4 = 20, 30, 14, 8
			headers(s)
			s.I1 = "<b 0xc0ffee><r 8><t>"
		}, "s1=20\ns2=30\ns3=14\ns4=8\n" + serverHeaders},
		{"AmneziaWG 3", func(s *Settings) {
			s.Jc, s.Jmin, s.Jmax = 2, 20, 40
			s.S1, s.S2, s.S3, s.S4 = 16, 16, 16, 16
			headers(s)
			s.HeaderProtectionKey, s.RandomTrailers = hpk, true
		}, "s1=16\ns2=16\ns3=16\ns4=16\n" + serverHeaders + "header_protection_key=" + hexOf(t, hpk) + "\nrandom_trailers=true\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spriv, spub := keyPair(t)
			cpriv, cpub := keyPair(t)
			ep := startServer(t, spriv, cpub, tc.server)
			s := Settings{PrivateKey: cpriv, PublicKey: spub, Address: "10.66.0.2/32", Keepalive: "25"}
			tc.set(&s)
			raw, err := s.Run(ep, "127.0.0.1:0", "user", "pass")
			if err != nil {
				t.Fatal(err)
			}
			var rc RunConfig
			if err := json.Unmarshal(raw, &rc); err != nil {
				t.Fatal(err)
			}
			var out syncBuf
			c, err := Start(rc, NewLog(&out))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(c.Close)
			cl := socks5.Client{Server: c.Addr(), Username: "user", Password: "pass"}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			tcp, err := cl.Connect(ctx, socks5.Addr{IP: netip.MustParseAddr("10.66.0.1"), Port: 80})
			if err != nil {
				t.Fatalf("CONNECT: %v\n%s", err, out.String())
			}
			tcp.SetDeadline(time.Now().Add(15 * time.Second))
			fmt.Fprintf(tcp, "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
			line, err := bufio.NewReader(tcp).ReadString('\n')
			tcp.Close()
			if !strings.HasPrefix(line, "HTTP/1.1 204") {
				t.Fatalf("HTTP through the tunnel: %q %v\n%s", line, err, out.String())
			}

			a, err := cl.UDPAssociate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			got := make(chan string, 1)
			go func() {
				buf := make([]byte, 100)
				n, from, err := a.ReadFrom(buf)
				if err != nil {
					got <- err.Error()
					return
				}
				got <- from.String() + " " + string(buf[:n])
			}()
			echo := socks5.Addr{IP: netip.MustParseAddr("10.66.0.1"), Port: 7}
			// A datagram may go before the association's socket is ready:
			// send until one comes back.
			for i := 0; ; i++ {
				if err := a.WriteTo([]byte("ping"), echo); err != nil {
					t.Fatal(err)
				}
				select {
				case r := <-got:
					if r != "10.66.0.1:7 ping" {
						t.Fatalf("UDP echo: %q", r)
					}
				case <-time.After(time.Second):
					if i < 10 {
						continue
					}
					t.Fatalf("no UDP echo\n%s", out.String())
				}
				break
			}
			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(out.String(), `"event":"`+EventHandshake+`"`) {
				if time.Now().After(deadline) {
					t.Fatalf("no handshake event in\n%s", out.String())
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

// A server that does not answer is reported as silent; the client still
// serves SOCKS5 (connections fail).
func TestClientSilentServer(t *testing.T) {
	old := silentAfter
	silentAfter = 300 * time.Millisecond
	defer func() { silentAfter = old }()
	cpriv, _ := keyPair(t)
	_, spub := keyPair(t)
	// A UDP port with nothing behind it that answers.
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	s := Settings{PrivateKey: cpriv, PublicKey: spub, Address: "10.66.0.2/32", Keepalive: "1"}
	raw, err := s.Run(dead.LocalAddr().(*net.UDPAddr).AddrPort(), "127.0.0.1:0", "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	var rc RunConfig
	json.Unmarshal(raw, &rc)
	var out syncBuf
	c, err := Start(rc, NewLog(&out))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), `"event":"`+EventSilent+`"`) {
		if time.Now().After(deadline) {
			t.Fatalf("no silent event in\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestStartErrors(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cpriv, _ := keyPair(t)
	_, spub := keyPair(t)
	good := Settings{PrivateKey: cpriv, PublicKey: spub, Address: "10.66.0.2/32"}
	cfg := func(listen string) RunConfig {
		raw, err := good.Run(mustAddrPort("127.0.0.1:9"), listen, "u", "p")
		if err != nil {
			t.Fatal(err)
		}
		var rc RunConfig
		json.Unmarshal(raw, &rc)
		return rc
	}
	badUAPI := cfg("127.0.0.1:0")
	badUAPI.UAPI += "h1=5\nh2=5\n"
	for name, tc := range map[string]struct {
		rc   RunConfig
		kind string
	}{
		"device refuses": {badUAPI, KindConfig},
		"no address":     {RunConfig{UAPI: badUAPI.UAPI, Listen: "127.0.0.1:0"}, KindConfig},
		"port busy":      {cfg(busy.Addr().String()), KindPort},
	} {
		c, err := Start(tc.rc, NewLog(&syncBuf{}))
		if err == nil {
			c.Close()
			t.Errorf("%s: started", name)
			continue
		}
		var se *StartError
		if !errors.As(err, &se) || se.Kind != tc.kind {
			t.Errorf("%s: %v, want kind %q", name, err, tc.kind)
		}
	}
}
