package engine

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

// udpEcho starts a loopback UDP server that answers "re:"+datagram after
// delay, and a loopback SOCKS5 server to reach it. It returns the echo
// address and a client of the SOCKS5 server.
func udpEcho(t *testing.T, delay time.Duration) (netip.AddrPort, *socks5.Client) {
	t.Helper()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			reply := append([]byte("re:"), b[:n]...)
			time.AfterFunc(delay, func() { echo.WriteToUDP(reply, a) })
		}
	}()
	stub := &socks5.Server{}
	if err := stub.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stub.Close() })
	return echo.LocalAddr().(*net.UDPAddr).AddrPort(), &socks5.Client{Server: stub.Addr()}
}

// A UDP flow whose profile was stopped (the rules moved on) is decided
// again by the current rules instead of losing every datagram for as long
// as the socket keeps sending.
func TestUDPFlowLeavesStoppedProfile(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "game", App: &rules.AppMatch{Pattern: "game.exe"}, Protocol: "udp", Action: rules.Tunnel, Profile: "a"},
	}}
	h := newHarness(t, cfg, Options{})
	a := &fakeTunnel{}
	a.up.Store(true) // no UDP: the datagram is dropped, no association
	h.extra["a"] = a
	const dst = "93.184.216.34:3478"
	h.own(17, L, dst, 400)
	h.sendUDP(L, dst, []byte("1"))
	h.none(t)
	old := lastRecord(t, h.c)

	set, err := rules.Compile(rules.Config{DefaultAction: rules.Direct})
	if err != nil {
		t.Fatal(err)
	}
	h.c.Rules.Swap(set)
	delete(h.extra, "a") // tunnels.Manager.Sync stopped it
	h.sendUDP(L, dst, []byte("2"))
	if i := h.next(t); !i.addr.Outbound() || string(i.pkt.Payload()) != "2" {
		t.Fatalf("datagram after the profile stopped: outbound=%v %q", i.addr.Outbound(), i.pkt.Payload())
	}
	active := h.c.Flows.Active(time.Now())
	if len(active) != 1 || active[0].ID == old.ID || active[0].Route != "direct" || h.c.UDPDropped.Load() != 1 {
		t.Fatalf("records %+v, dropped %d", active, h.c.UDPDropped.Load())
	}
	// With the profile still in the rules and every server down, the flow
	// stays on it (Tunnel never falls back to Direct).
	h.c.Rules.Swap(mustCompile(t, cfg))
	h.own(17, "192.168.1.5:40001", dst, 400)
	for range 2 {
		h.sendUDP("192.168.1.5:40001", dst, []byte("x"))
	}
	h.none(t)
	if h.c.UDPDropped.Load() != 3 {
		t.Fatalf("dropped %d", h.c.UDPDropped.Load())
	}
}

// A UDP flow on a server that went down moves to the rule's fallback
// server once that one can carry it.
func TestUDPFlowMovesToFallback(t *testing.T) {
	dst, client := udpEcho(t, 0)
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "game", App: &rules.AppMatch{Pattern: "game.exe"}, Protocol: "udp", Action: rules.Tunnel, Profile: "a", Fallback: []string{"b"}},
	}}
	h := newHarness(t, cfg, Options{NoDefaultExclusions: true})
	a, b := &fakeTunnel{client: client}, &fakeTunnel{client: client}
	a.up.Store(true)
	b.up.Store(true)
	h.extra["a"], h.extra["b"] = a, b
	const app = "10.0.0.2:5000"
	h.own(17, app, dst.String(), 400)
	h.sendUDP(app, dst.String(), []byte("1")) // both without UDP: stays on "a", dropped
	h.none(t)

	b.udp.Store(true)
	h.sendUDP(app, dst.String(), []byte("2"))
	if i := h.next(t); i.addr.Outbound() || string(i.pkt.Payload()) != "re:2" {
		t.Fatalf("reply through the fallback: outbound=%v %q", i.addr.Outbound(), i.pkt.Payload())
	}
	h.c.mu.Lock()
	uf := h.c.udp[flowKey(app, dst.String())]
	h.c.mu.Unlock()
	if uf == nil || uf.profile != "b" {
		t.Fatalf("flow %+v", uf)
	}
	if v := lastRecord(t, h.c); v.Profile != "b" || v.Rule != "game (fallback)" {
		t.Fatalf("%+v", v)
	}
}

// Replies keep a tunnel UDP association alive: a socket that only
// receives must not lose it after the idle timeout.
func TestUDPSessionIdleCountsReplies(t *testing.T) {
	dst, client := udpEcho(t, 100*time.Millisecond)
	h := newHarness(t, appRules, Options{NoDefaultExclusions: true})
	h.tun.client = client
	const app = "10.0.0.2:5000"
	h.own(17, app, dst.String(), 400) // game.exe: UDP tunnel
	sent := time.Now()
	h.sendUDP(app, dst.String(), []byte("ping"))
	if i := h.next(t); string(i.pkt.Payload()) != "re:ping" {
		t.Fatalf("reply %q", i.pkt.Payload())
	}
	h.c.mu.Lock()
	s := h.c.sessions[sessKey{netip.MustParseAddrPort(app), ""}]
	h.c.mu.Unlock()
	if s == nil {
		t.Fatal("no session")
	}
	if d := s.lastUsed().Sub(sent); d < 50*time.Millisecond {
		t.Fatalf("session last used %v after the send, before the reply", d)
	}
}

func mustCompile(t *testing.T, cfg rules.Config) *rules.Set {
	t.Helper()
	set, err := rules.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return set
}
