package hysteria

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"

	"github.com/lardan099/hyroute/internal/awg"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/socks5"
)

// With FAKE_AWG set the test binary is HyRoute's AmneziaWG child (TestMain):
// the real one, awg.Main.
func fakeAWG() { os.Exit(awg.Main(os.Args[len(os.Args)-1])) }

func awgKeyPair(t *testing.T) (priv, pub string) {
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

func awgHex(t *testing.T, b64 string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// startAWGServer runs an AmneziaWG server on the loopback whose network
// stack (10.66.0.1) answers HTTP on port 80 with 204.
func startAWGServer(t *testing.T, priv, clientPub, extra string) uint16 {
	t.Helper()
	tdev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.66.0.1")}, nil, awg.DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tdev, conn.NewStdNetBind(), &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf})
	if err := dev.IpcSet("private_key=" + awgHex(t, priv) + "\nlisten_port=0\n" + extra +
		"public_key=" + awgHex(t, clientPub) + "\nallowed_ip=10.66.0.2/32\n"); err != nil {
		dev.Close()
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.Fatal(err)
	}
	t.Cleanup(dev.Close)
	st, _ := dev.IpcGet()
	port := 0
	for _, l := range strings.Split(st, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			port, _ = strconv.Atoi(v)
		}
	}
	if port == 0 {
		t.Fatal("no listen port")
	}
	ln, err := tnet.ListenTCPAddrPort(netip.MustParseAddrPort("10.66.0.1:80"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return uint16(port)
}

func newAWGSupervisor(t *testing.T, p Profile) (*Supervisor, chan Status, func() []string) {
	t.Helper()
	t.Setenv("FAKE_AWG", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan Status, 256)
	var mu sync.Mutex
	var lines []string
	s := &Supervisor{
		Exe:         exe,
		RunDir:      t.TempDir(),
		Profile:     p,
		Redactor:    &logx.Redactor{},
		RedactGroup: "awg",
		OnStatus:    func(st Status) { ch <- st },
		LogLine: func(l LogLine) {
			mu.Lock()
			lines = append(lines, l.Raw)
			mu.Unlock()
		},
		ProbeURLs: []string{"http://10.66.0.1/generate_204"},
	}
	return s, ch, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func waitAWG(t *testing.T, ch chan Status, want State, lines func() []string) Status {
	t.Helper()
	deadline := time.After(40 * time.Second)
	for {
		select {
		case st := <-ch:
			if st.State == want {
				return st
			}
		case <-deadline:
			t.Fatalf("no %v; the child said:\n%s", want, strings.Join(lines(), "\n"))
		}
	}
}

// A profile runs in the child process like Hysteria: HyRoute resolves and
// excludes the server, the child connects with the obfuscation, a request
// through it makes the run available, and traffic goes through.
func TestSupervisorAWG(t *testing.T) {
	spriv, spub := awgKeyPair(t)
	cpriv, cpub := awgKeyPair(t)
	port := startAWGServer(t, spriv, cpub, "s1=20\ns2=30\nh1=1000-1100\nh2=2000-2100\nh3=3000-3100\nh4=4000-4100\n")
	p := Profile{Name: "awg", Host: "awg.example", Ports: strconv.Itoa(int(port)), Protocol: ProtoAWG, AWG: awg.Settings{
		PrivateKey: cpriv, PublicKey: spub, Address: "10.66.0.2/32", Keepalive: "25",
		Jc: 3, Jmin: 10, Jmax: 40, S1: 20, S2: 30, H1: "1000-1100", H2: "2000-2100", H3: "3000-3100", H4: "4000-4100",
	}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	s, ch, lines := newAWGSupervisor(t, p)
	var gotIPs []netip.Addr
	s.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	s.SetServerIPs = func(ips []netip.Addr) error { gotIPs = ips; return nil }
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	st := waitAWG(t, ch, Connected, lines)
	if !s.Available() || !st.UDPEnabled || st.PinnedIP != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("status %+v", st)
	}
	if len(gotIPs) != 1 || gotIPs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("excluded %v", gotIPs)
	}
	c, err := s.Dial(context.Background(), socks5.Addr{IP: netip.MustParseAddr("10.66.0.1"), Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if !strings.HasPrefix(line, "HTTP/1.1 204") {
		t.Fatalf("through the tunnel: %q", line)
	}
	// The config with the keys goes once the server answered.
	if left, _ := filepath.Glob(filepath.Join(s.RunDir, "hy-*")); len(left) != 0 {
		t.Errorf("config left: %v", left)
	}
	for _, l := range lines() {
		for _, k := range []string{cpriv, awgHex(t, cpriv)} {
			if strings.Contains(l, k) {
				t.Fatalf("the private key in the log: %s", l)
			}
		}
	}
}

// A server that does not answer the handshake fails with that reason.
func TestSupervisorAWGSilentServer(t *testing.T) {
	oldTimeout, oldRetry := vlessProbeTimeout, vlessRetryEvery
	vlessProbeTimeout, vlessRetryEvery = time.Second, 50*time.Millisecond
	defer func() { vlessProbeTimeout, vlessRetryEvery = oldTimeout, oldRetry }()
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	cpriv, _ := awgKeyPair(t)
	_, spub := awgKeyPair(t)
	p := Profile{Name: "awg", Host: "127.0.0.1", Ports: strconv.Itoa(dead.LocalAddr().(*net.UDPAddr).Port), Protocol: ProtoAWG,
		AWG: awg.Settings{PrivateKey: cpriv, PublicKey: spub, Address: "10.66.0.2/32"}}
	s, ch, lines := newAWGSupervisor(t, p)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	st := waitAWG(t, ch, Failed, lines)
	if st.Kind != ErrTimeout || !strings.Contains(st.Message, "рукопожатие") {
		t.Fatalf("status %+v", st)
	}
}

func TestInterpretAndClassifyAWG(t *testing.T) {
	ev, ok := InterpretAWG(ParseLogLine(`{"level":"fatal","time":1,"msg":"AmneziaWG не принял параметры: headers must not overlap","kind":"config"}`))
	if !ok || !ev.Fatal || ev.Kind != ErrConfig || !strings.Contains(ev.Message, "overlap") {
		t.Fatalf("%+v", ev)
	}
	if ev, _ := InterpretAWG(ParseLogLine(`{"level":"fatal","msg":"port","kind":"port"}`)); ev.Kind != ErrPortBusy {
		t.Fatalf("%+v", ev)
	}
	if _, ok := InterpretAWG(ParseLogLine(`{"level":"warn","msg":"x"}`)); ok {
		t.Fatal("a warning ends the run")
	}
	for _, c := range []struct {
		handshake, dns bool
		kind           ErrorKind
		has            string
	}{
		{false, false, ErrTimeout, "рукопожатие"},
		{true, true, ErrOther, "DNS"},
		{true, false, ErrOther, "трафик"},
	} {
		if k, m := ClassifyAWG(errors.New("i/o timeout"), c.handshake, c.dns); k != c.kind || !strings.Contains(m, c.has) {
			t.Errorf("%+v: %d %q", c, k, m)
		}
	}
}

func TestAWGProfile(t *testing.T) {
	cpriv, _ := awgKeyPair(t)
	_, spub := awgKeyPair(t)
	conf := "# Name = Мой AWG\n[Interface]\nPrivateKey = " + cpriv + "\nAddress = 10.8.1.2/32\nJc = 4\nJmin = 10\nJmax = 50\nH1 = 5\n\n[Peer]\nPublicKey = " +
		spub + "\nEndpoint = awg.example:51820\nAllowedIPs = 0.0.0.0/0\n"
	p, warns, err := ParseAWGConf(conf)
	if err != nil || len(warns) != 0 {
		t.Fatal(err, warns)
	}
	if p.Name != "Мой AWG" || p.Host != "awg.example" || p.Ports != "51820" || !p.IsAWG() || p.ProtocolName() != "AmneziaWG" || p.Transport() != "" {
		t.Fatalf("%+v", p)
	}
	// The export is the configuration, and it reads back the same.
	back, _, err := ParseAWGConf(p.URI())
	if err != nil || !SameConnection(back, p) || back.Name != p.Name {
		t.Fatalf("%v\n%+v\n%+v", err, back, p)
	}
	// vpn:// keys too.
	key, _, err := ParseURI(awg.VPNKey(awg.Conf{Name: "k", Host: p.Host, Port: 51820, Settings: p.AWG}))
	if err != nil || !SameConnection(key, p) {
		t.Fatalf("%v %+v", err, key)
	}
	if !p.HasSecrets() || !slicesContain(p.Secrets(), cpriv) {
		t.Fatal("the private key is no secret")
	}
	q := p
	q.ClearSecrets()
	if q.AWG.PrivateKey != "" || q.AWG.PublicKey != spub {
		t.Fatalf("%+v", q.AWG)
	}
	q.CopySecrets(p)
	if q.AWG != p.AWG {
		t.Fatal("secrets not copied")
	}
	// Plain WireGuard is shown as such.
	plain := p
	plain.AWG = awg.Settings{PrivateKey: cpriv, PublicKey: spub, Address: "10.8.1.2/32"}
	if plain.Transport() != "WireGuard" {
		t.Fatal(plain.Transport())
	}
	// No settings of the other protocols, one port.
	for name, edit := range map[string]func(*Profile){
		"auth":   func(p *Profile) { p.Auth = "x" },
		"vless":  func(p *Profile) { p.VLESS.ID = "x" },
		"ports":  func(p *Profile) { p.Ports = "51820-51830" },
		"no key": func(p *Profile) { p.AWG.PrivateKey = "" },
	} {
		r := p
		edit(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
	// Normalize drops what an editor sent for the other protocols.
	n := p
	n.Auth, n.VLESS.ID, n.PinServerIP, n.AWG.Address = "x", "y", true, " 10.8.1.2/32 "
	n.Normalize()
	if n.Auth != "" || n.VLESS.ID != "" || n.PinServerIP || n.AWG.Address != "10.8.1.2/32" || n.Validate() != nil {
		t.Fatalf("%+v", n)
	}
	h := Profile{Host: "h.example", Ports: "443", AWG: p.AWG}
	h.Normalize()
	if h.AWG != (awg.Settings{}) {
		t.Fatal("a Hysteria profile kept AmneziaWG settings")
	}
}

func slicesContain(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
