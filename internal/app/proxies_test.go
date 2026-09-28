package app

import (
	"io"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/relay"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// LAN proxies listen on loopback in tests: a test binary listening on
// every address makes Windows Firewall ask the user.
func init() { lanHost = "127.0.0.1" }

// freePort finds a free port below the relay's range, where a LAN proxy
// may listen (port 0 would pick one from the range on Windows).
func freePort(t *testing.T) int {
	for p := 20000 + rand.IntN(20000); p < relay.PortMin; p++ {
		if ln, err := net.Listen("tcp", "127.0.0.1:"+itoa(p)); err == nil {
			ln.Close()
			return p
		}
	}
	t.Fatal("no free port")
	return 0
}

func TestLocalProxies(t *testing.T) {
	c, started := newCtl(t)
	res, err := c.ImportURIs(link + "\nhy2://x@h2.example:8443#NL")
	if err != nil || len(res.Added) != 2 {
		t.Fatal(res, err)
	}
	nl := res.Added[1].ID
	var fw [][]int
	c.ProxyFirewall = func(p []int) error { fw = append(fw, p); return nil }

	port := freePort(t)
	bad := []ProxyInput{
		{LocalProxy: store.LocalProxy{Port: 80}},
		{LocalProxy: store.LocalProxy{Port: port, Username: "u"}},
		{LocalProxy: store.LocalProxy{Port: port, LAN: true}},
		{LocalProxy: store.LocalProxy{Port: port, Profile: "nope"}},
	}
	for _, in := range bad {
		if _, err := c.SaveProxy(in); err == nil {
			t.Fatalf("accepted %+v", in)
		}
	}
	v, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Enabled: true, Profile: nl, Port: port, Username: "u"}, Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if v.State != "waiting" || v.Name == "" || v.Password != "p" || v.ProfileName != "NL" || v.Addresses[0] != "127.0.0.1:"+itoa(port) {
		t.Fatalf("%+v", v)
	}
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Port: port}}); err == nil || !strings.Contains(err.Error(), "занят") {
		t.Fatalf("duplicate port: %v", err)
	}

	// Connecting starts the proxy's server (no rule uses it) and opens
	// the port.
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if got := ids((*started)[0].cfg.Profiles); got != "NL" {
		t.Fatalf("profiles started: %s", got)
	}
	v = c.Proxies()[0]
	if v.State != "listening" {
		t.Fatalf("%+v", v)
	}
	cl := socks5.Client{Server: "127.0.0.1:" + itoa(port), Username: "u", Password: "p"}
	if _, err := cl.Connect(t.Context(), socks5.Addr{Host: "example.com", Port: 443}); err == nil {
		t.Fatal("dial without a running server succeeded")
	}

	// The saved password survives a reload.
	c2, _ := newCtlAt(t, c.Store)
	if p := c2.Proxies(); len(p) != 1 || p[0].Password != "p" {
		t.Fatalf("%+v", p)
	}

	// Disconnect closes the port.
	c.Disconnect()
	if c.Proxies()[0].State != "waiting" {
		t.Fatal(c.Proxies()[0].State)
	}
	if ln, err := net.Listen("tcp", "127.0.0.1:"+itoa(port)); err != nil {
		t.Fatalf("port still open: %v", err)
	} else {
		ln.Close()
	}

	// LAN: firewall rule follows.
	id := v.ID
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{ID: id, Enabled: true, Port: port, LAN: true, Username: "u"}, Password: "p"}); err != nil {
		t.Fatal(err)
	}
	c.Connect()
	if len(fw) == 0 || len(fw[len(fw)-1]) != 1 || fw[len(fw)-1][0] != port {
		t.Fatalf("firewall: %v", fw)
	}
	// Every Connect sets the rule again: "Remove firewall rule" may have
	// deleted it while disconnected.
	n := len(fw)
	c.Disconnect()
	c.Connect()
	if len(fw) != n+1 || len(fw[n]) != 1 || fw[n][0] != port {
		t.Fatalf("firewall after reconnect: %v", fw)
	}
	if err := c.DeleteProxy(id); err != nil {
		t.Fatal(err)
	}
	if len(fw[len(fw)-1]) != 0 || len(c.Proxies()) != 0 {
		t.Fatalf("after delete: %v", fw)
	}
	c.Disconnect()
}

// A LAN proxy never listens in the relay's port range: its firewall rule
// is open in public networks too.
func TestLANProxyRelayPorts(t *testing.T) {
	c, _ := newCtl(t)
	var fw [][]int
	c.ProxyFirewall = func(p []int) error { fw = append(fw, p); return nil }
	lan := store.LocalProxy{Enabled: true, Port: relay.PortMin, LAN: true, Username: "u"}
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: lan, Password: "p"}); err == nil || !strings.Contains(err.Error(), "49151") {
		t.Fatalf("LAN proxy in the relay's range: %v", err)
	}
	// Off, or local only: allowed.
	off := lan
	off.Enabled = false
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: off, Password: "p"}); err != nil {
		t.Fatal(err)
	}
	local := store.LocalProxy{Enabled: true, Port: relay.PortMax, Username: "u"}
	if _, err := c.SaveProxy(ProxyInput{LocalProxy: local, Password: "p"}); err != nil {
		t.Fatal(err)
	}

	// Saved by an older version: not opened.
	lan.ID = "old"
	if err := c.Store.SaveProxies([]store.LocalProxy{lan}); err != nil {
		t.Fatal(err)
	}
	c, _ = newCtlAt(t, c.Store)
	c.ProxyFirewall = func(p []int) error { fw = append(fw, p); return nil }
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	if v := c.Proxies()[0]; v.State != "error" || !strings.Contains(v.Error, "49151") {
		t.Fatalf("%+v", v)
	}
	for _, ports := range fw {
		if len(ports) != 0 {
			t.Fatalf("firewall: %v", fw)
		}
	}
}

// The LAN rule is set again on every Connect after LAN ports were open:
// "Remove firewall rule" may have deleted it while disconnected. A LAN
// proxy deleted while disconnected takes its port out of the rule.
func TestProxyFirewallRule(t *testing.T) {
	c, _ := newCtl(t)
	var fw [][]int
	c.ProxyFirewall = func(p []int) error { fw = append(fw, p); return nil }
	last := func() []int {
		t.Helper()
		if len(fw) == 0 {
			t.Fatal("firewall rule never set")
		}
		return fw[len(fw)-1]
	}
	port := freePort(t)
	v, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Enabled: true, Port: port, LAN: true, Username: "u"}, Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fw) != 0 {
		t.Fatalf("rule set while disconnected: %v", fw)
	}
	for i := range 2 {
		if err := c.Connect(); err != nil {
			t.Fatal(err)
		}
		if len(fw) != i+1 || !equalInts(last(), []int{port}) {
			t.Fatalf("connect %d: %v", i, fw)
		}
		if st := c.Proxies()[0].State; st != "listening" {
			t.Fatal(st)
		}
		c.Disconnect()
	}
	if err := c.DeleteProxy(v.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if len(fw) != 3 || len(last()) != 0 {
		t.Fatalf("after delete: %v", fw)
	}
	// Known to be absent: not asked again.
	c.Disconnect()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.Disconnect()
	if len(fw) != 3 {
		t.Fatalf("without LAN proxies: %v", fw)
	}
}

type endpointSession struct {
	*fakeSession
	ep *tunnels.Endpoint
}

func (s endpointSession) Endpoint(string) *tunnels.Endpoint { return s.ep }

// Proxy traffic and failed dials count in the server's figures, like
// intercepted connections do.
func TestProxyTrafficCounted(t *testing.T) {
	stub := &socks5.Server{}
	if err := stub.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	c, _ := newCtl(t)
	m := &tunnels.Manager{Log: c.Log, New: func(hysteria.Profile, tunnels.Hooks) tunnels.Runner {
		return &stubRunner{c: socks5.Client{Server: stub.Addr()}}
	}}
	m.Sync([]hysteria.Profile{{ID: "p1", Name: "P"}})
	defer m.StopAll()
	c.mu.Lock()
	c.sess = endpointSession{fakeSession: &fakeSession{}, ep: m.Get("p1")}
	c.mu.Unlock()
	dial := c.proxyDialer(store.LocalProxy{Profile: "p1"})
	conn, err := dial(t.Context(), socks5.AddrFromAddrPort(echo.Addr().(*net.TCPAddr).AddrPort()))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "hello")
	b := make([]byte, 5)
	if _, err := io.ReadFull(conn, b); err != nil {
		t.Fatal(err)
	}
	conn.(interface{ CloseWrite() error }).CloseWrite()
	conn.Close()
	// Nothing listens on port 1: the dial fails.
	if _, err := dial(t.Context(), socks5.Addr{Host: "127.0.0.1", Port: 1}); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	st := m.Statuses()[0]
	if st.Sent != 5 || st.Recv != 5 || st.Rejected != 1 {
		t.Fatalf("sent %d recv %d rejected %d", st.Sent, st.Recv, st.Rejected)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// The tunnel side of a proxy connection resets through its wrapper
// (socks5.Abort): a broken stream must not reach Hysteria as a clean end.
func TestTunnelConnResets(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	socks5.Abort(&tunnelConn{Conn: c})
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil || err == io.EOF {
		t.Fatalf("want a reset, got %v", err)
	}
}
