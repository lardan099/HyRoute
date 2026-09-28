package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/localproxy"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// socks-udp: the app side of SOCKS5 UDP ASSOCIATE in local proxies. Every
// test sets proxyOwners, so Windows runs never read the real socket tables.

func setOwners(t *testing.T, o localproxy.OwnerLookup) {
	old := proxyOwners
	proxyOwners = o
	t.Cleanup(func() { proxyOwners = old })
}

type appOwners struct {
	mu  sync.Mutex
	tcp uint32
	udp uint32
}

func (f *appOwners) TCPOwner(_, _ netip.AddrPort) (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tcp, f.tcp != 0
}

func (f *appOwners) UDPOwner(netip.AddrPort) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.udp == 0 {
		return 0, localproxy.ErrNoOwner
	}
	return f.udp, nil
}

// udpRig is a connected controller whose every proxy goes through one
// endpoint backed by the socks5 stub, and a UDP echo behind it.
func udpRig(t *testing.T, noUDP bool) (*Controller, *tunnels.Manager, netip.AddrPort) {
	t.Helper()
	setOwners(t, nil)
	stub := &socks5.Server{}
	if err := stub.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stub.Close() })
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			echo.WriteToUDPAddrPort(append([]byte("echo:"), b[:n]...), from)
		}
	}()
	c, _ := newCtl(t)
	m := &tunnels.Manager{Log: c.Log, New: func(hysteria.Profile, tunnels.Hooks) tunnels.Runner {
		return &stubRunner{c: socks5.Client{Server: stub.Addr()}, noUDP: noUDP}
	}}
	m.Sync([]hysteria.Profile{{ID: "p1", Name: "P"}})
	t.Cleanup(m.StopAll)
	c.mu.Lock()
	c.sess = endpointSession{fakeSession: &fakeSession{}, ep: m.Get("p1")}
	c.mu.Unlock()
	t.Cleanup(c.stopProxies)
	return c, m, echo.LocalAddr().(*net.UDPAddr).AddrPort()
}

func setProxies(c *Controller, list ...store.LocalProxy) {
	c.mu.Lock()
	c.proxies = list
	c.mu.Unlock()
	c.syncProxiesLife()
}

func echoThrough(t *testing.T, a *socks5.UDPAssoc, echo netip.AddrPort, msg string) {
	t.Helper()
	if err := a.WriteTo([]byte(msg), socks5.AddrFromAddrPort(echo)); err != nil {
		t.Fatal(err)
	}
	type res struct {
		s   string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		b := make([]byte, 2048)
		n, _, err := a.ReadFrom(b)
		ch <- res{string(b[:n]), err}
	}()
	select {
	case r := <-ch:
		if r.err != nil || r.s != "echo:"+msg {
			t.Fatalf("%q %v", r.s, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no echo")
	}
}

// proxyUDPViews are a proxy's UDP statistics records by ID: the live ones,
// or the closed ones.
func proxyUDPViews(c *Controller, id string, closed bool) []flows.View {
	vs := c.proxyFlows.Active(time.Now())
	if closed {
		vs = c.proxyFlows.Closed()
	}
	var out []flows.View
	for _, v := range vs {
		if v.Proto == "udp" && v.Path == "proxy:"+id {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// countCloses counts the proxy records closed from now on (set before any
// proxy runs, so no goroutine reads the hook yet).
func countCloses(c *Controller) *atomic.Int32 {
	n := &atomic.Int32{}
	prev := c.proxyFlows.OnClose
	c.proxyFlows.OnClose = func(v flows.View) {
		n.Add(1)
		if prev != nil {
			prev(v)
		}
	}
	return n
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out: " + what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A proxy on this computer serves UDP by default, through its server; the
// server's figures grow; UDP sessions are not counted as connections. The
// association is one statistics record, closed exactly once.
func TestProxyUDPEndToEnd(t *testing.T) {
	c, m, echo := udpRig(t, false)
	closes := countCloses(c)
	port := freePort(t)
	setProxies(c, store.LocalProxy{ID: "x", Name: "Игры", Enabled: true, Port: port, Profile: "p1"})
	v := c.Proxies()[0]
	if v.State != "listening" || !v.UDPEffective || !v.UDPServed {
		t.Fatalf("%+v", v)
	}
	cl := socks5.Client{Server: "127.0.0.1:" + itoa(port)}
	a, err := cl.UDPAssociate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	echoThrough(t, a, echo, "ping")
	if st := m.Statuses()[0]; st.Sent != 4 || st.Recv != 9 {
		t.Fatalf("server figures %d/%d", st.Sent, st.Recv)
	}
	v = c.Proxies()[0]
	if v.Active != 0 || v.UDPActive != 1 || v.Sent != 4 || v.Recv != 9 {
		t.Fatalf("%+v", v)
	}
	recs := proxyUDPViews(c, "x", false)
	if len(recs) != 1 || recs[0].Route != "tunnel" || recs[0].Profile != "p1" || recs[0].Group != "" ||
		recs[0].Outcome != "proxied" || recs[0].Sent != 4 || recs[0].Recv != 9 || recs[0].Domain != "" {
		t.Fatalf("%+v", recs)
	}
	a.Close()
	waitUntil(t, "session end", func() bool { v = c.Proxies()[0]; return v.UDPActive == 0 })
	if v.Total != 0 || v.UDPTotal != 1 {
		t.Fatalf("%+v", v)
	}
	waitUntil(t, "record closed", func() bool { return len(proxyUDPViews(c, "x", true)) == 1 })
	c.stopProxies()
	if n := closes.Load(); n != 1 || len(proxyUDPViews(c, "x", false)) != 0 {
		t.Fatalf("%d closes", n)
	}
	if !strings.Contains(proxyUDPDiag(v), "UDP вкл, UDP-сессий 1") {
		t.Fatal(proxyUDPDiag(v))
	}
}

// A server that does not allow UDP: reply 2 and a note on the card.
func TestProxyUDPServerForbids(t *testing.T) {
	c, _, _ := udpRig(t, true)
	port := freePort(t)
	setProxies(c, store.LocalProxy{ID: "x", Enabled: true, Port: port, Profile: "p1"})
	cl := socks5.Client{Server: "127.0.0.1:" + itoa(port)}
	if _, err := cl.UDPAssociate(t.Context()); !errors.Is(err, socks5.ReplyError(2)) {
		t.Fatal(err)
	}
	if v := c.Proxies()[0]; v.UDPBlocked != "server" {
		t.Fatalf("%+v", v)
	}
	// Counted as a refused connection of the server.
	recs := proxyUDPViews(c, "x", true)
	if len(recs) != 1 || recs[0].Outcome != "dropped: tunnel unavailable" || recs[0].Profile != "p1" || !recs[0].Failed() {
		t.Fatalf("%+v", recs)
	}
}

// failRunner's UDP associate fails.
type failRunner struct{ stubRunner }

func (r *failRunner) UDPAssociate(context.Context) (*socks5.UDPAssoc, error) {
	return nil, errors.New("associate failed")
}

// A failed associate is a refused record; without a connection there is
// no record at all.
func TestProxyUDPFailedRecords(t *testing.T) {
	setOwners(t, nil)
	c, _ := newCtl(t)
	p := store.LocalProxy{ID: "x", Name: "Игры", Profile: "p1"}
	if _, err := c.proxyUDPDialer(p)(t.Context()); err == nil {
		t.Fatal("associated while not connected")
	}
	if len(proxyUDPViews(c, "x", true))+len(proxyUDPViews(c, "x", false)) != 0 {
		t.Fatal("record while not connected")
	}
	m := &tunnels.Manager{Log: c.Log, New: func(hysteria.Profile, tunnels.Hooks) tunnels.Runner { return &failRunner{} }}
	m.Sync([]hysteria.Profile{{ID: "p1", Name: "P"}})
	t.Cleanup(m.StopAll)
	c.mu.Lock()
	c.sess = endpointSession{fakeSession: &fakeSession{}, ep: m.Get("p1")}
	c.mu.Unlock()
	if _, err := c.proxyUDPDialer(p)(t.Context()); err == nil {
		t.Fatal("associated")
	}
	recs := proxyUDPViews(c, "x", true)
	if len(recs) != 1 || recs[0].Outcome != "dropped: socks5 associate failed" || recs[0].Route != "tunnel" ||
		recs[0].Profile != "p1" || !recs[0].Failed() || len(proxyUDPViews(c, "x", false)) != 0 {
		t.Fatalf("%+v", recs)
	}
}

// "off": reply 7 as before UDP existed; switching restarts the proxy.
func TestProxyUDPSwitch(t *testing.T) {
	c, _, echo := udpRig(t, false)
	port := freePort(t)
	p := store.LocalProxy{ID: "x", Enabled: true, Port: port, UDP: "off"}
	setProxies(c, p)
	cl := socks5.Client{Server: "127.0.0.1:" + itoa(port)}
	if _, err := cl.UDPAssociate(t.Context()); !errors.Is(err, socks5.ReplyError(7)) {
		t.Fatal(err)
	}
	if v := c.Proxies()[0]; v.UDPEffective || v.UDPServed {
		t.Fatalf("%+v", v)
	}
	c.proxyMu.Lock()
	before := c.proxyRuns["x"].srv
	c.proxyMu.Unlock()
	p.UDP = ""
	setProxies(c, p)
	c.proxyMu.Lock()
	after := c.proxyRuns["x"].srv
	c.proxyMu.Unlock()
	if before == after {
		t.Fatal("not restarted")
	}
	a, err := cl.UDPAssociate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	echoThrough(t, a, echo, "on")
}

// A LAN proxy: UDP off by default; on, it shares the TCP port number, and
// a session from this computer is owner-checked (fails closed).
func TestLANProxyUDP(t *testing.T) {
	c, _, echo := udpRig(t, false)
	owners := &appOwners{}
	setOwners(t, owners)
	port := freePort(t)
	p := store.LocalProxy{ID: "x", Enabled: true, Port: port, LAN: true, Username: "u", Password: "p"}
	setProxies(c, p)
	cl := socks5.Client{Server: "127.0.0.1:" + itoa(port), Username: "u", Password: "p"}
	if _, err := cl.UDPAssociate(t.Context()); !errors.Is(err, socks5.ReplyError(7)) {
		t.Fatal(err)
	}
	p.UDP = "on"
	setProxies(c, p)
	c.proxyMu.Lock()
	srv := c.proxyRuns["x"].srv
	c.proxyMu.Unlock()
	if !srv.SharedUDP || srv.Owners == nil || srv.MaxUDP != lanMaxUDP {
		t.Fatalf("shared %v owners %v max %d", srv.SharedUDP, srv.Owners, srv.MaxUDP)
	}
	if pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err == nil {
		pc.Close()
		t.Fatal("the TCP port number is not the UDP one")
	}
	if _, err := cl.UDPAssociate(t.Context()); !errors.Is(err, socks5.ReplyError(1)) {
		t.Fatal(err)
	}
	var owner, socket bool
	for _, e := range c.EngineLog.Since(0, 1000) {
		owner = owner || strings.Contains(e.Msg, "owner of the control connection not found")
		socket = socket || strings.Contains(e.Msg, "socket not opened")
	}
	if !owner || socket {
		t.Fatalf("log: owner %v socket %v", owner, socket)
	}
	owners.mu.Lock()
	owners.tcp, owners.udp = 7, 7
	owners.mu.Unlock()
	a, err := cl.UDPAssociate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	echoThrough(t, a, echo, "lan")
	if !strings.Contains(proxyUDPDiag(c.Proxies()[0]), "проверка программы для этого ПК") {
		t.Fatal(proxyUDPDiag(c.Proxies()[0]))
	}

	// A proxy on this computer without a password has no owner check.
	setProxies(c, store.LocalProxy{ID: "y", Enabled: true, Port: freePort(t)})
	c.proxyMu.Lock()
	srv = c.proxyRuns["y"].srv
	c.proxyMu.Unlock()
	if srv.Owners != nil || srv.SharedUDP {
		t.Fatal("owner check without a password")
	}
}

// SaveProxy stores an explicit value equal to the default as the default;
// validateProxy refuses unknown values (backup's import calls it too).
func TestSaveProxyUDP(t *testing.T) {
	c, _ := newCtl(t)
	setOwners(t, nil)
	local, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Port: freePort(t), UDP: "on"}})
	if err != nil || local.UDP != "" || !local.UDPEffective {
		t.Fatalf("%+v %v", local, err)
	}
	lan, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Port: freePort(t), LAN: true, Username: "u", UDP: "off"}, Password: "p"})
	if err != nil || lan.UDP != "" || lan.UDPEffective {
		t.Fatalf("%+v %v", lan, err)
	}
	on, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{ID: lan.ID, Port: lan.Port, LAN: true, Username: "u", UDP: "on"}, Password: "p"})
	if err != nil || on.UDP != "on" || !on.UDPEffective {
		t.Fatalf("%+v %v", on, err)
	}
	b, _ := os.ReadFile(filepath.Join(c.Store.Dir, "proxies.json"))
	if strings.Count(string(b), `"udp"`) != 1 {
		t.Fatalf("%s", b)
	}
	for _, m := range []store.UDPMode{"", "on", "off", "maybe", "ON"} {
		err := validateProxy(store.LocalProxy{Port: 20000, UDP: m}, nil)
		if bad := m != "" && m != "on" && m != "off"; bad != (err != nil) {
			t.Errorf("%q: %v", m, err)
		}
	}
}

// The firewall rules are set before any port opens: TCP for every LAN
// proxy, UDP for those with UDP on; loopback proxies need neither.
func TestProxyFirewallUDP(t *testing.T) {
	c, _, _ := udpRig(t, false)
	p1, p2, p3 := freePort(t), freePort(t), freePort(t)
	type call struct {
		tcp, udp []int
		free     bool
	}
	var calls []call
	c.ProxyFirewall = func(tcp, udp []int) error {
		free := true
		for _, p := range append(append([]int{}, tcp...), udp...) {
			ln, err := net.Listen("tcp4", "127.0.0.1:"+itoa(p))
			if err != nil {
				free = false
				continue
			}
			ln.Close()
		}
		calls = append(calls, call{tcp, udp, free})
		return nil
	}
	setProxies(c,
		store.LocalProxy{ID: "a", Enabled: true, Port: p1, LAN: true, Username: "u", Password: "p", UDP: "on"},
		store.LocalProxy{ID: "b", Enabled: true, Port: p2, LAN: true, Username: "u", Password: "p"},
		store.LocalProxy{ID: "c", Enabled: true, Port: p3})
	if len(calls) != 1 || !calls[0].free {
		t.Fatalf("%+v", calls)
	}
	wantTCP := []int{p1, p2}
	if calls[0].tcp[0] != p1 { // sorted by proxy ID
		t.Fatalf("%+v", calls)
	}
	if !equalInts(calls[0].tcp, wantTCP) || !equalInts(calls[0].udp, []int{p1}) {
		t.Fatalf("%+v", calls)
	}
	// UDP off everywhere: the UDP rule goes.
	setProxies(c,
		store.LocalProxy{ID: "a", Enabled: true, Port: p1, LAN: true, Username: "u", Password: "p"},
		store.LocalProxy{ID: "b", Enabled: true, Port: p2, LAN: true, Username: "u", Password: "p"})
	if len(calls) != 2 || !equalInts(calls[1].tcp, wantTCP) || len(calls[1].udp) != 0 {
		t.Fatalf("%+v", calls)
	}

	// Disconnected with the rules unknown: no call, no panic.
	c2, _ := newCtl(t)
	n := 0
	c2.ProxyFirewall = func(_, _ []int) error { n++; return nil }
	if _, err := c2.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{Enabled: true, Port: freePort(t), LAN: true, Username: "u", UDP: "on"}, Password: "p"}); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("rule set while disconnected")
	}
}

// The view's "udpOn" is UDPEffective; the embedded method still resolves.
func TestProxyViewUDPJSON(t *testing.T) {
	v := ProxyView{LocalProxy: store.LocalProxy{LAN: true, UDP: "on"}, UDPEffective: true}
	b, _ := json.Marshal(v)
	if !strings.Contains(string(b), `"udpOn":true`) || !strings.Contains(string(b), `"udp":"on"`) || !v.LocalProxy.UDPOn() {
		t.Fatalf("%s", b)
	}
}

// v1.2.0 served UDP on every LAN proxy, enabled or not: its rule (without
// our mark) keeps UDP on for them, once, at the start: before the window
// can show or edit a proxy, and without a connection.
func TestKeepV12ProxyUDP(t *testing.T) {
	c, _ := newCtl(t)
	setOwners(t, nil)
	calls := 0
	legacy := true
	start := func() {
		t.Helper()
		c, _ = newCtlAt(t, c.Store)
		c.ProxyFirewall = func(_, _ []int) error { return nil }
		c.LegacyProxyUDP = func() bool { calls++; return legacy }
		c.KeepV12ProxyUDP()
	}
	lanPort, offPort, localPort := freePort(t), freePort(t), freePort(t)
	if err := c.Store.SaveProxies([]store.LocalProxy{
		{ID: "a", Name: "Телефон", Enabled: true, Port: lanPort, LAN: true, Username: "u", Password: "p"},
		{ID: "b", Name: "Здесь", Enabled: true, Port: localPort},
		{ID: "c", Name: "Планшет", Port: offPort, LAN: true, Username: "u", Password: "p"},
	}); err != nil {
		t.Fatal(err)
	}
	start()
	// Shown before any connection; a second call does nothing.
	if v := c.Proxies(); !v[0].UDPEffective || v[1].UDP != "" || !v[2].UDPEffective {
		t.Fatalf("%+v", v)
	}
	c.KeepV12ProxyUDP()
	if calls != 1 {
		t.Fatal(calls)
	}
	// Turned off before the first Connect: it stays off.
	v, err := c.SaveProxy(ProxyInput{LocalProxy: store.LocalProxy{ID: "a", Name: "Телефон", Enabled: true, Port: lanPort, LAN: true, Username: "u", UDP: "off"}, Password: "p"})
	if err != nil || v.UDPEffective {
		t.Fatalf("%+v %v", v, err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	c.Disconnect()
	list, err := c.Store.LoadProxies()
	if err != nil || calls != 1 || list[0].UDP != "" || list[1].UDP != "" || list[2].UDP != "on" {
		t.Fatalf("calls %d, %+v %v", calls, list, err)
	}
	// A file this version wrote (a "udp" value) is not v1.2.0's.
	calls = 0
	start()
	if calls != 0 {
		t.Fatal("checked again")
	}
	// No v1.2.0 rule: the default (off) stays.
	list[2].UDP = ""
	c.Store.SaveProxies(list)
	legacy = false
	start()
	if list, _ := c.Store.LoadProxies(); calls != 1 || list[0].UDP != "" || list[2].UDP != "" {
		t.Fatalf("%+v", list)
	}
}

// A LAN proxy whose firewall rule could not be set serves TCP but binds no
// UDP socket (it would make Windows Firewall ask); the next successful set
// reopens it with UDP.
func TestLANProxyUDPNoRule(t *testing.T) {
	c, _, _ := udpRig(t, false)
	fail := true
	c.ProxyFirewall = func(_, _ []int) error {
		if fail {
			return errors.New("netsh failed")
		}
		return nil
	}
	port := freePort(t)
	setProxies(c, store.LocalProxy{ID: "x", Enabled: true, Port: port, LAN: true, Username: "u", Password: "p", UDP: "on"})
	v := c.Proxies()[0]
	if v.State != "listening" || v.UDPServed || !strings.Contains(v.UDPError, "брандмауэра") {
		t.Fatalf("%+v", v)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal("UDP socket bound without a rule:", err)
	}
	pc.Close()
	fail = false
	c.syncProxiesLife() // the rules are still unknown: set again
	if v := c.Proxies()[0]; v.State != "listening" || !v.UDPServed || v.UDPError != "" {
		t.Fatalf("%+v", v)
	}
}

// ---- the group branch of proxyUDPDialer ----

// udpGroupRig is a controller with a failover group of one member whose
// trial is due (two failures, then PenaltyFor): the next pick claims it.
// dials counts the member's reports to the group.
func udpGroupRig(t *testing.T, run tunnels.Runner) (c *Controller, g, member string, ep *tunnels.Endpoint, dials *atomic.Int32) {
	t.Helper()
	setOwners(t, nil)
	c, _ = newCtl(t)
	member, _, _ = servers(t, c)
	g = saveGroup(t, c, "Авто", groups.Failover, member)
	c.mu.Lock()
	gf := c.groupsFile.Clone()
	gf.Groups[0].SwitchAfterErrors = 2
	c.mu.Unlock()
	c.groupsRT.SetGroups([]groups.Group{gf.Groups[0]})
	now := time.Unix(1_000_000, 0)
	c.groupsRT.SetClock(func() time.Time { return now })
	c.groupsRT.NoteDial(member, "x:1", errors.New("fail"))
	c.groupsRT.NoteDial(member, "y:1", errors.New("fail"))
	now = now.Add(groups.PenaltyFor)
	dials = &atomic.Int32{}
	m := &tunnels.Manager{Log: c.Log, New: func(hysteria.Profile, tunnels.Hooks) tunnels.Runner { return run },
		OnDial: func(id, dst string, err error) { dials.Add(1); c.groupsRT.NoteDial(id, dst, err) }}
	m.Sync([]hysteria.Profile{{ID: member, Name: "DE1"}})
	t.Cleanup(m.StopAll)
	return c, g, member, m.Get(member), dials
}

// groupState is the member's reason and error streak and the group's
// refusal count.
func groupState(c *Controller, g string) (string, int, int64) {
	h := c.groupsRT.Snapshot(g, func(string) bool { return true })
	return h.Members[0].Reason, h.Members[0].Errors, h.Rejected
}

// flipSession gives the endpoint for the choice, then runs gone before
// the second lookup (the member goes away or loses UDP in between).
type flipSession struct {
	*fakeSession
	ep    *tunnels.Endpoint
	gone  func() *tunnels.Endpoint
	calls atomic.Int32
}

func (s *flipSession) Endpoint(string) *tunnels.Endpoint {
	if s.calls.Add(1) > 1 {
		return s.gone()
	}
	return s.ep
}

// A member whose endpoint disappears, or stops carrying UDP, between the
// choice and the associate releases its trial (a TCP pick can take it
// again), reports no dial to the group and counts no group refusal.
func TestProxyUDPGroupAbandons(t *testing.T) {
	for _, name := range []string{"endpoint gone", "UDP gone"} {
		t.Run(name, func(t *testing.T) {
			run := &stubRunner{}
			c, g, member, ep, dials := udpGroupRig(t, run)
			s := &flipSession{fakeSession: &fakeSession{}, ep: ep, gone: func() *tunnels.Endpoint { return nil }}
			if name == "UDP gone" {
				s.gone = func() *tunnels.Endpoint { run.noUDP = true; return ep }
			}
			c.mu.Lock()
			c.sess = s
			c.mu.Unlock()
			if _, err := c.proxyUDPDialer(store.LocalProxy{ID: "p", Name: "Игры", Profile: g})(t.Context()); err == nil {
				t.Fatal("associated")
			}
			if reason, errs, rejected := groupState(c, g); reason == "trial" || errs != 2 || rejected != 0 || dials.Load() != 0 {
				t.Fatalf("reason %q errors %d rejected %d dials %d", reason, errs, rejected, dials.Load())
			}
			if pk, ok := c.groupsRT.Choose(g, groups.Hint{}, func(string) bool { return true }); !ok || pk.Member != member {
				t.Fatal("trial not released")
			}
			if reason, _, _ := groupState(c, g); reason != "trial" {
				t.Fatalf("TCP pick took no trial: %q", reason)
			}
		})
	}
}

// blockRunner's UDP associate waits until its context ends.
type blockRunner struct {
	stubRunner
	started chan struct{}
}

func (r *blockRunner) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	close(r.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

// An association cancelled while the server is asked (the proxy closing)
// releases the trial, reports no dial and warns of nothing.
func TestProxyUDPGroupCancelled(t *testing.T) {
	run := &blockRunner{started: make(chan struct{})}
	c, g, _, ep, dials := udpGroupRig(t, run)
	c.mu.Lock()
	c.sess = endpointSession{fakeSession: &fakeSession{}, ep: ep}
	c.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	go func() { <-run.started; cancel() }()
	if _, err := c.proxyUDPDialer(store.LocalProxy{ID: "p", Name: "Игры", Profile: g})(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if reason, errs, rejected := groupState(c, g); reason == "trial" || errs != 2 || rejected != 0 || dials.Load() != 0 {
		t.Fatalf("reason %q errors %d rejected %d dials %d", reason, errs, rejected, dials.Load())
	}
	for _, e := range c.EngineLog.Since(0, 1000) {
		if strings.Contains(e.Msg, "local proxy") {
			t.Fatal("warned: " + e.Msg)
		}
	}
	if len(proxyUDPViews(c, "p", true))+len(proxyUDPViews(c, "p", false)) != 0 {
		t.Fatal("a cancelled association left a record")
	}
}

// A group with members up but none carrying UDP shows udpBlocked "group".
func TestProxyUDPBlockedGroup(t *testing.T) {
	setOwners(t, nil)
	c, _ := newCtl(t)
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.Failover, de1, de2)
	m := &tunnels.Manager{Log: c.Log, New: func(hysteria.Profile, tunnels.Hooks) tunnels.Runner { return &stubRunner{noUDP: true} }}
	m.Sync([]hysteria.Profile{{ID: de1, Name: "DE1"}, {ID: de2, Name: "DE2"}})
	t.Cleanup(m.StopAll)
	c.mu.Lock()
	c.sess = &liveSession{fakeSession: &fakeSession{}, mgr: m}
	c.mu.Unlock()
	t.Cleanup(c.stopProxies)
	setProxies(c, store.LocalProxy{ID: "x", Name: "Игры", Enabled: true, Port: freePort(t), Profile: g})
	if v := c.Proxies()[0]; v.State != "listening" || v.UDPBlocked != "group" {
		t.Fatalf("%+v", v)
	}
}

// Each association asks the group once and keeps its member: round robin
// alternates per association, not per datagram.
func TestProxyUDPGroupOncePerAssociation(t *testing.T) {
	r := newLiveRig(t)
	c := r.c
	setOwners(t, nil)
	de1, de2, _ := servers(t, c)
	g := saveGroup(t, c, "Авто", groups.RoundRobin, de1, de2)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect()
	p := store.LocalProxy{ID: "p1", Name: "Биржа", Enabled: true, Profile: g}
	c.mu.Lock()
	c.proxies = []store.LocalProxy{p}
	c.applyRoutingLocked()
	s := c.sess
	c.mu.Unlock()
	assoc := c.proxyUDPDialer(p)
	var got []*tunnels.Endpoint
	for range 3 {
		u, err := assoc(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		got = append(got, u.(*tunnelUDP).ep)
	}
	if got[0] == got[1] || got[0] != got[2] || (got[0] != s.Endpoint(de1) && got[0] != s.Endpoint(de2)) {
		t.Fatal("not one pick per association")
	}
	// One record per association, under the member it went through.
	recs := proxyUDPViews(c, "p1", false)
	if len(recs) != 3 {
		t.Fatalf("%+v", recs)
	}
	for i, v := range recs {
		if v.Group != g || v.Profile != got[i].Profile.ID || v.Outcome != "proxied" {
			t.Fatalf("%d: %+v", i, v)
		}
	}
}
