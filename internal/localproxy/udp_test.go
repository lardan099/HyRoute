package localproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// Every socket here is on loopback: a test listening on other addresses
// makes Windows Firewall ask the user.

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

// fakeUp is an in-memory association through the tunnel: it records what
// it is sent and, with echo, answers "echo:" + payload from the
// destination.
type fakeUp struct {
	mu     sync.Mutex
	got    []socks5.Addr
	sizes  []int
	echo   bool
	rep    chan dgram
	done   chan struct{}
	once   sync.Once
	closes atomic.Int32
}

type dgram struct {
	b    []byte
	from socks5.Addr
}

func (u *fakeUp) WriteTo(b []byte, dst socks5.Addr) error {
	select {
	case <-u.done:
		return net.ErrClosed
	default:
	}
	u.mu.Lock()
	u.got = append(u.got, dst)
	u.sizes = append(u.sizes, len(b))
	u.mu.Unlock()
	if u.echo {
		select {
		case u.rep <- dgram{append([]byte("echo:"), b...), dst}:
		default:
		}
	}
	return nil
}

func (u *fakeUp) ReadFrom(buf []byte) (int, socks5.Addr, error) {
	select {
	case d := <-u.rep:
		return copy(buf, d.b), d.from, nil
	case <-u.done:
		return 0, socks5.Addr{}, net.ErrClosed
	}
}

func (u *fakeUp) Close() error {
	u.closes.Add(1)
	u.once.Do(func() { close(u.done) })
	return nil
}

func (u *fakeUp) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.got)
}

// ups opens fake upstreams and keeps them in order.
type ups struct {
	mu   sync.Mutex
	list []*fakeUp
	echo bool
	err  error
}

func (s *ups) dial(ctx context.Context) (UDPUpstream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	u := &fakeUp{echo: s.echo, rep: make(chan dgram, 64), done: make(chan struct{})}
	s.list = append(s.list, u)
	return u, nil
}

func (s *ups) get(i int) *fakeUp {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list[i]
}

func (s *ups) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.list)
}

// events records the UDP callbacks.
type events struct {
	mu     sync.Mutex
	ev     map[UDPEvent]int64
	ports  []error
	limits []int64
}

func hook(s *Server) *events {
	e := &events{ev: map[UDPEvent]int64{}}
	s.OnUDPEvent = func(ev UDPEvent, n int64, _ int) { e.mu.Lock(); e.ev[ev] += n; e.mu.Unlock() }
	s.OnUDPPort = func(err error) { e.mu.Lock(); e.ports = append(e.ports, err); e.mu.Unlock() }
	s.OnUDPLimit = func(n int64) { e.mu.Lock(); e.limits = append(e.limits, n); e.mu.Unlock() }
	return e
}

func (e *events) has(ev UDPEvent) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ev[ev] > 0
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for " + what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var anyAddr = socks5.Addr{IP: netip.IPv4Unspecified()}

// rawAssoc sends UDP ASSOCIATE for req over a new control connection (from
// laddr if set) and returns it, BND and REP.
func rawAssoc(t *testing.T, addr, user, pass string, req socks5.Addr, laddr string) (net.Conn, netip.AddrPort, byte) {
	t.Helper()
	d := net.Dialer{}
	if laddr != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(laddr)}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(15 * time.Second))
	method := byte(0)
	if user != "" {
		method = 2
	}
	c.Write([]byte{5, 1, method})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != method {
		t.Fatalf("method: %v %v", m, err)
	}
	if user != "" {
		b := append(append(append([]byte{1, byte(len(user))}, user...), byte(len(pass))), pass...)
		c.Write(b)
		if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != 0 {
			t.Fatalf("auth: %v %v", m, err)
		}
	}
	b, _ := socks5.AppendAddr([]byte{5, socks5.CmdUDPAssociate, 0}, req)
	c.Write(b)
	var h [3]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		t.Fatal(err)
	}
	bnd, err := socks5.ReadAddr(c)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Time{})
	return c, netip.AddrPortFrom(bnd.IP, bnd.Port), h[1]
}

func udpSock(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func portOf(pc *net.UDPConn) uint16 { return uint16(pc.LocalAddr().(*net.UDPAddr).Port) }

var dst1 = socks5.Addr{IP: netip.MustParseAddr("1.2.3.4"), Port: 53}

func sendU(t *testing.T, pc *net.UDPConn, to netip.AddrPort, dst socks5.Addr, payload string) {
	t.Helper()
	b, err := socks5.AppendUDPHeader(nil, dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteToUDPAddrPort(append(b, payload...), to); err != nil {
		t.Fatal(err)
	}
}

// reply reads one SOCKS5 UDP datagram within d.
func reply(pc *net.UDPConn, d time.Duration) (socks5.Addr, string, bool) {
	buf := make([]byte, 70000)
	pc.SetReadDeadline(time.Now().Add(d))
	n, _, err := pc.ReadFromUDPAddrPort(buf)
	if err != nil {
		return socks5.Addr{}, "", false
	}
	from, payload, err := socks5.ParseUDPHeader(buf[:n])
	if err != nil {
		return socks5.Addr{}, "", false
	}
	return from, string(payload), true
}

func expectEcho(t *testing.T, pc *net.UDPConn, bnd netip.AddrPort, msg string) {
	t.Helper()
	sendU(t, pc, bnd, dst1, msg)
	from, got, ok := reply(pc, 5*time.Second)
	if !ok || got != "echo:"+msg || from != dst1 {
		t.Fatalf("echo %q: %q from %v (%v)", msg, got, from, ok)
	}
}

func expectNothing(t *testing.T, pc *net.UDPConn) {
	t.Helper()
	if _, got, ok := reply(pc, 200*time.Millisecond); ok {
		t.Fatalf("unexpected reply %q", got)
	}
}

// End to end through the socks5 stub (standing for Hysteria) and a real
// echo, both modes: a socket per association on loopback, the TCP port
// number when shared.
func TestUDPEndToEnd(t *testing.T) {
	for _, shared := range []bool{false, true} {
		echo := echoUDP(t)
		tunnel := &socks5.Server{}
		if err := tunnel.Listen("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tunnel.Close() })
		var opened atomic.Int32
		s := &Server{Username: "u", Password: "p", Dial: dialer(nil), SharedUDP: shared, AssociateUDP: func(ctx context.Context) (UDPUpstream, error) {
			opened.Add(1)
			cl := socks5.Client{Server: tunnel.Addr()}
			return cl.UDPAssociate(ctx)
		}}
		addr := start(t, s)
		if s.UDPError() != nil || !s.UDP() {
			t.Fatal(s.UDPError())
		}
		tcpPort := netip.MustParseAddrPort(addr).Port()
		cl := socks5.Client{Server: addr, Username: "u", Password: "p"}
		var bnd []uint16
		for range 2 {
			a, err := cl.UDPAssociate(t.Context())
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
					defer close(done)
					if n, f, err := a.ReadFrom(buf); err == nil {
						got, from = string(buf[:n]), f
					}
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
			s.udpMu.Lock()
			if s.shared != nil {
				bnd = append(bnd, s.shared.portNum())
			}
			s.udpMu.Unlock()
		}
		if shared && (len(bnd) != 2 || bnd[0] != tcpPort) {
			t.Fatalf("shared: %v, tcp %d", bnd, tcpPort)
		}
		// Sent grows after the forward returns, which can be after the echo
		// already reached the client: wait for the counters to settle.
		settled := func() bool {
			return opened.Load() == 2 && s.UDPActive.Load() == 2 && s.UDPTotal.Load() == 2 && s.Sent.Load() == 12 && s.Recv.Load() == 32
		}
		for deadline := time.Now().Add(5 * time.Second); !settled() && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		if !settled() {
			t.Fatalf("opened %d active %d total %d sent %d recv %d", opened.Load(), s.UDPActive.Load(), s.UDPTotal.Load(), s.Sent.Load(), s.Recv.Load())
		}
	}
}

// BND.PORT: its own port per association on loopback (never the TCP
// port), the TCP port when shared.
func TestUDPBoundPorts(t *testing.T) {
	var u ups
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial}
	addr := start(t, s)
	tcp := netip.MustParseAddrPort(addr).Port()
	_, b1, r1 := rawAssoc(t, addr, "", "", anyAddr, "")
	_, b2, r2 := rawAssoc(t, addr, "", "", anyAddr, "")
	if r1 != 0 || r2 != 0 || b1.Addr() != netip.MustParseAddr("127.0.0.1") || b1.Port() == tcp || b2.Port() == tcp || b1.Port() == b2.Port() {
		t.Fatalf("%v %v (%d %d), tcp %d", b1, b2, r1, r2, tcp)
	}
	sh := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: true}
	addr = start(t, sh)
	if _, b, r := rawAssoc(t, addr, "", "", anyAddr, ""); r != 0 || b != netip.MustParseAddrPort(addr) {
		t.Fatalf("shared: %v %d", b, r)
	}
}

// A domain destination goes to the tunnel as a name (no local DNS).
func TestUDPDomainPassedThrough(t *testing.T) {
	u := ups{echo: true}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial}
	addr := start(t, s)
	_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
	pc := udpSock(t, "127.0.0.1")
	dst := socks5.Addr{Host: "stun.example.com", Port: 3478}
	sendU(t, pc, bnd, dst, "x")
	if from, got, ok := reply(pc, 5*time.Second); !ok || got != "echo:x" || from != dst {
		t.Fatalf("%q from %v", got, from)
	}
	up := u.get(0)
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.got) != 1 || up.got[0] != dst {
		t.Fatalf("upstream got %v", up.got)
	}
}

// With a password, UDP ASSOCIATE without it fails at the method stage and
// nothing is opened.
func TestUDPNeedsPassword(t *testing.T) {
	var u ups
	s := &Server{Username: "u", Password: "p", Dial: dialer(nil), AssociateUDP: u.dial}
	addr := start(t, s)
	cl := socks5.Client{Server: addr}
	if _, err := cl.UDPAssociate(t.Context()); err == nil {
		t.Fatal("associated without a password")
	}
	if u.n() != 0 {
		t.Fatal("upstream opened")
	}
}

// Without AssociateUDP: reply 7, and no UDP socket (the port number stays
// free for UDP even in shared mode).
func TestUDPOff(t *testing.T) {
	s := &Server{Dial: dialer(nil), SharedUDP: true}
	addr := start(t, s)
	if _, _, rep := rawAssoc(t, addr, "", "", anyAddr, ""); rep != 7 {
		t.Fatalf("REP %d", rep)
	}
	pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(addr)))
	if err != nil {
		t.Fatalf("UDP port taken: %v", err)
	}
	pc.Close()
	if s.UDP() || s.UDPState() != "off" {
		t.Fatal(s.UDPState())
	}
}

// freeBoth finds a port free for TCP and UDP and returns the UDP socket
// holding it.
func freeBoth(t *testing.T) *net.UDPConn {
	for range 50 {
		pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp4", pc.LocalAddr().String())
		if err == nil {
			ln.Close()
			return pc
		}
		pc.Close()
	}
	t.Fatal("no port free for both")
	return nil
}

// The shared UDP port taken by another program: TCP works, UDP ASSOCIATE
// gets REP 1, and the bind is retried until it succeeds.
func TestUDPSharedPortRetry(t *testing.T) {
	old := udpRetryEvery
	udpRetryEvery = 20 * time.Millisecond
	t.Cleanup(func() { udpRetryEvery = old })
	blocker := freeBoth(t)
	u := ups{echo: true}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: true}
	ev := hook(s)
	if err := s.Listen(blocker.LocalAddr().String()); err != nil {
		blocker.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	addr := s.Addr()
	if s.UDPError() == nil || s.UDP() || s.UDPState() != "retrying" {
		t.Fatal("shared UDP port opened twice")
	}
	var seen []string
	s.Dial = direct(&seen)
	if _, _, rep := rawAssoc(t, addr, "", "", anyAddr, ""); rep != 1 {
		t.Fatalf("REP %d", rep)
	}
	blocker.Close()
	waitFor(t, "the retry", func() bool { return s.UDP() && s.UDPError() == nil })
	_, bnd, rep := rawAssoc(t, addr, "", "", anyAddr, "")
	if rep != 0 || bnd != netip.MustParseAddrPort(addr) {
		t.Fatalf("after retry: %v %d", bnd, rep)
	}
	expectEcho(t, udpSock(t, "127.0.0.1"), bnd, "hi")
	ev.mu.Lock()
	if len(ev.ports) != 1 || ev.ports[0] != nil {
		t.Fatalf("OnUDPPort: %v", ev.ports)
	}
	ev.mu.Unlock()

	// Close while retrying returns at once.
	blocker2 := freeBoth(t)
	defer blocker2.Close()
	s2 := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: true}
	if err := s2.Listen(blocker2.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { s2.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hangs while retrying")
	}
}

// A named port pins at once; after it was heard, another port of the same
// IP is a stranger.
func TestUDPNamedPort(t *testing.T) {
	for _, shared := range []bool{false, true} {
		u := ups{echo: true}
		s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: shared}
		ev := hook(s)
		addr := start(t, s)
		pc := udpSock(t, "127.0.0.1")
		_, bnd, _ := rawAssoc(t, addr, "", "", socks5.Addr{IP: netip.IPv4Unspecified(), Port: portOf(pc)}, "")
		expectEcho(t, pc, bnd, "a")
		other := udpSock(t, "127.0.0.1")
		sendU(t, other, bnd, dst1, "b")
		expectNothing(t, other)
		if !ev.has(DropStranger) || ev.has(EventRepin) {
			t.Fatalf("shared %v: %v", shared, ev.ev)
		}
	}
}

// A named port nobody uses is a preference: the client's real socket takes
// the association (not when another association of the IP waits, shared).
func TestUDPNamedPortPreference(t *testing.T) {
	for _, shared := range []bool{false, true} {
		u := ups{echo: true}
		s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: shared}
		ev := hook(s)
		addr := start(t, s)
		unused := udpSock(t, "127.0.0.1")
		named := portOf(unused)
		unused.Close()
		_, bnd, _ := rawAssoc(t, addr, "", "", socks5.Addr{IP: netip.MustParseAddr("10.9.9.9"), Port: named}, "")
		pc := udpSock(t, "127.0.0.1")
		expectEcho(t, pc, bnd, "a")
		if !ev.has(EventRepin) {
			t.Fatal("re-pin not reported")
		}
		if !shared {
			continue
		}
		// Two named associations of one IP, both unheard: a third port may
		// be either's, so it takes none.
		s2 := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: true}
		addr2 := start(t, s2)
		_, bnd2, _ := rawAssoc(t, addr2, "", "", socks5.Addr{IP: netip.IPv4Unspecified(), Port: named}, "")
		_, _, _ = rawAssoc(t, addr2, "", "", socks5.Addr{IP: netip.IPv4Unspecified(), Port: named + 1}, "")
		third := udpSock(t, "127.0.0.1")
		sendU(t, third, bnd2, dst1, "x")
		expectNothing(t, third)
		if s2.UDPDropped.Load() != 1 {
			t.Fatal("re-pinned with two associations of the IP")
		}
		// Design test 8 as written: A names a port nobody uses, B of the
		// same IP is pinned and heard; a datagram from a third port is not
		// A's (A is not the only association of the IP): dropped, no re-pin.
		s3 := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: true}
		ev3 := hook(s3)
		addr3 := start(t, s3)
		_, bnd3, _ := rawAssoc(t, addr3, "", "", socks5.Addr{IP: netip.IPv4Unspecified(), Port: named}, "")
		_, _, _ = rawAssoc(t, addr3, "", "", anyAddr, "")
		expectEcho(t, udpSock(t, "127.0.0.1"), bnd3, "b") // B pins and is heard
		third3 := udpSock(t, "127.0.0.1")
		sendU(t, third3, bnd3, dst1, "x")
		expectNothing(t, third3)
		if s3.UDPDropped.Load() != 1 || ev3.has(EventRepin) {
			t.Fatalf("re-pinned beside a heard association: dropped %d, %v", s3.UDPDropped.Load(), ev3.ev)
		}
	}
}

// Unpinned (DST 0.0.0.0:0): the first datagram pins, another source port
// is dropped.
func TestUDPFirstDatagramPins(t *testing.T) {
	u := ups{echo: true}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial}
	addr := start(t, s)
	_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
	pc := udpSock(t, "127.0.0.1")
	expectEcho(t, pc, bnd, "a")
	other := udpSock(t, "127.0.0.1")
	sendU(t, other, bnd, dst1, "b")
	expectNothing(t, other)
	if s.UDPDropped.Load() != 1 {
		t.Fatal(s.UDPDropped.Load())
	}
}

// A fragment or junk never takes a waiting association (pitfall #25).
func TestUDPJunkDoesNotPin(t *testing.T) {
	u := ups{echo: true}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial}
	ev := hook(s)
	addr := start(t, s)
	_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
	junk := udpSock(t, "127.0.0.1")
	frag, _ := socks5.AppendUDPHeader(nil, dst1)
	frag[2] = 1
	junk.WriteToUDPAddrPort(append(frag, 'x'), bnd)
	junk.WriteToUDPAddrPort([]byte{0, 0}, bnd)
	waitFor(t, "drops", func() bool { return s.UDPDropped.Load() == 2 })
	expectEcho(t, udpSock(t, "127.0.0.1"), bnd, "real")
	if !ev.has(DropFragmented) || !ev.has(DropMalformed) {
		t.Fatal(ev.ev)
	}
}

// Shared mode, two unpinned associations of one IP swapped by their first
// datagrams: when one closes, the other re-pins to its own socket and is
// never left dead while its control connection is open.
func TestUDPAmbiguousRelease(t *testing.T) {
	u := ups{echo: true}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: true}
	addr := start(t, s)
	ctrlA, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
	_, _, _ = rawAssoc(t, addr, "", "", anyAddr, "")
	sockA, sockB := udpSock(t, "127.0.0.1"), udpSock(t, "127.0.0.1")
	// B sends first and takes A's association (the oldest waiting one).
	expectEcho(t, sockB, bnd, "b1")
	expectEcho(t, sockA, bnd, "a1")
	if u.get(0).count() != 1 || u.get(1).count() != 1 {
		t.Fatal("setup")
	}
	s.shared.mu.Lock()
	swapped := s.shared.byAddr[netip.MustParseAddrPort(sockB.LocalAddr().String())] == s.shared.perIP[netip.MustParseAddr("127.0.0.1")][0]
	s.shared.mu.Unlock()
	if !swapped {
		t.Fatal("B did not take the oldest association")
	}
	// A's client closes: B's pin (on A's association) goes, and B's own
	// association is released back to waiting.
	ctrlA.Close()
	waitFor(t, "release", func() bool { return s.UDPActive.Load() == 1 })
	expectEcho(t, sockB, bnd, "b2")
	if u.get(1).count() != 2 {
		t.Fatal("B's datagram did not reach B's association")
	}
}

// A datagram from another IP than the control connection's is dropped.
func TestUDPStrangerIP(t *testing.T) {
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skip("127.0.0.2 not available:", err)
	}
	probe.Close()
	u := ups{echo: true}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: true}
	ev := hook(s)
	addr := start(t, s)
	_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
	stranger := udpSock(t, "127.0.0.2")
	sendU(t, stranger, bnd, dst1, "x")
	expectNothing(t, stranger)
	if !ev.has(DropStranger) {
		t.Fatal(ev.ev)
	}
	// The other way round: a control connection from 127.0.0.2.
	_, bnd2, rep := rawAssoc(t, addr, "", "", anyAddr, "127.0.0.2")
	if rep != 0 {
		t.Fatal(rep)
	}
	expectEcho(t, stranger, bnd2, "y")
}

// The same address named again (a client re-associating before closing
// the old control connection): the new association wins, the old one's
// control connection closes.
func TestUDPNamedTakeover(t *testing.T) {
	u := ups{echo: true}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: true}
	addr := start(t, s)
	pc := udpSock(t, "127.0.0.1")
	req := socks5.Addr{IP: netip.IPv4Unspecified(), Port: portOf(pc)}
	old, bnd, _ := rawAssoc(t, addr, "", "", req, "")
	_, _, _ = rawAssoc(t, addr, "", "", req, "")
	old.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := old.Read(make([]byte, 1)); err == nil {
		t.Fatal("old control connection still open")
	}
	expectEcho(t, pc, bnd, "x")
	if u.get(1).count() != 1 {
		t.Fatal("the new association did not get the datagram")
	}
}

// The association lives as long as the control connection, and a tunnel
// side that ends closes the control connection (pitfall #5).
func TestUDPLifetime(t *testing.T) {
	u := ups{echo: true}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial}
	addr := start(t, s)
	ctrl, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
	expectEcho(t, udpSock(t, "127.0.0.1"), bnd, "x")
	ctrl.Close()
	waitFor(t, "upstream closed", func() bool { return u.get(0).closes.Load() > 0 && s.UDPActive.Load() == 0 })
	// The per-association socket is gone.
	if pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(bnd)); err != nil {
		t.Fatalf("socket still bound: %v", err)
	} else {
		pc.Close()
	}

	ctrl, _, _ = rawAssoc(t, addr, "", "", anyAddr, "")
	u.get(1).Close() // Hysteria restarted
	ctrl.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := ctrl.Read(make([]byte, 1)); err == nil {
		t.Fatal("control connection open after the tunnel side ended")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("control connection not closed")
	}
}

// An association without datagrams for udpIdle is closed; traffic keeps it.
func TestUDPIdle(t *testing.T) {
	old := udpIdle
	udpIdle = 150 * time.Millisecond
	t.Cleanup(func() { udpIdle = old })
	u := ups{echo: true}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial}
	ev := hook(s)
	addr := start(t, s)
	ctrl, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
	pc := udpSock(t, "127.0.0.1")
	for range 12 {
		expectEcho(t, pc, bnd, "keep")
		time.Sleep(40 * time.Millisecond)
	}
	if s.UDPActive.Load() != 1 {
		t.Fatal("closed despite traffic")
	}
	ctrl.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := ctrl.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle association kept")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle association kept")
	}
	waitFor(t, "idle event", func() bool { return ev.has(EventIdle) })
}

// MaxUDP: over it REP 1 and one report; a slot comes back on close.
func TestUDPLimit(t *testing.T) {
	var u ups
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, MaxUDP: 2}
	ev := hook(s)
	addr := start(t, s)
	c1, _, r1 := rawAssoc(t, addr, "", "", anyAddr, "")
	_, _, r2 := rawAssoc(t, addr, "", "", anyAddr, "")
	_, _, r3 := rawAssoc(t, addr, "", "", anyAddr, "")
	_, _, r4 := rawAssoc(t, addr, "", "", anyAddr, "")
	if r1 != 0 || r2 != 0 || r3 != 1 || r4 != 1 || u.n() != 2 {
		t.Fatalf("%d %d %d %d, opened %d", r1, r2, r3, r4, u.n())
	}
	ev.mu.Lock()
	if len(ev.limits) != 1 {
		t.Fatalf("limit reports %v", ev.limits)
	}
	ev.mu.Unlock()
	c1.Close()
	waitFor(t, "slot", func() bool { return s.UDPActive.Load() == 1 })
	if _, _, rep := rawAssoc(t, addr, "", "", anyAddr, ""); rep != 0 {
		t.Fatal(rep)
	}
}

// Parallel requests cannot pass the limit together (pitfall #26).
func TestUDPLimitParallel(t *testing.T) {
	var u ups
	release := make(chan struct{})
	s := &Server{Dial: dialer(nil), MaxUDP: 3, AssociateUDP: func(ctx context.Context) (UDPUpstream, error) {
		<-release
		return u.dial(ctx)
	}}
	addr := start(t, s)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			c.Write([]byte{5, 1, 0})
			var m [2]byte
			io.ReadFull(c, m[:])
			b, _ := socks5.AppendAddr([]byte{5, 3, 0}, anyAddr)
			c.Write(b)
			var h [3]byte
			if _, err := io.ReadFull(c, h[:]); err == nil && h[1] == 0 {
				ok.Add(1)
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	if ok.Load() != 3 || u.n() != 3 {
		t.Fatalf("served %d, opened %d", ok.Load(), u.n())
	}
}

// Oversize datagrams are dropped by socks5.MaxUDPPayload (the IP fast path
// only for IP destinations); a real 60 000-byte one is read whole and the
// association keeps working; fragments and junk are dropped by kind.
func TestUDPSizes(t *testing.T) {
	u := ups{}
	s := &Server{Dial: dialer(nil), AssociateUDP: u.dial}
	ev := hook(s)
	addr := start(t, s)
	_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
	pc := udpSock(t, "127.0.0.1")
	sendU(t, pc, bnd, dst1, "pin")
	waitFor(t, "pin", func() bool { return u.n() == 1 && u.get(0).count() == 1 })
	up := u.get(0)
	long := socks5.Addr{Host: strings.Repeat("a", 190) + ".example.com", Port: 443}
	for _, d := range []socks5.Addr{dst1, long} {
		max := socks5.MaxUDPPayload(d)
		if d.Host != "" && max+1 >= socks5.UDPPayloadAlways {
			t.Fatalf("long name allows %d", max)
		}
		dropped := s.UDPDropped.Load()
		sendU(t, pc, bnd, d, strings.Repeat("x", max+1))
		waitFor(t, "drop", func() bool { return s.UDPDropped.Load() == dropped+1 })
		n := up.count()
		sendU(t, pc, bnd, d, strings.Repeat("x", max))
		waitFor(t, "delivery", func() bool { return up.count() == n+1 })
	}
	dropped := s.UDPDropped.Load()
	if _, err := pc.WriteToUDPAddrPort(make([]byte, 60000), bnd); err != nil {
		t.Skip("no 60 000-byte datagrams here:", err)
	}
	waitFor(t, "big drop", func() bool { return s.UDPDropped.Load() == dropped+1 })
	n := up.count()
	sendU(t, pc, bnd, dst1, "small")
	waitFor(t, "after the big one", func() bool { return up.count() == n+1 })
	up.mu.Lock()
	for i, sz := range up.sizes {
		if sz+3+1+1+len(long.Host)+2 > 4096 && up.got[i].Host != "" {
			t.Fatalf("datagram of %d to a name", sz)
		}
	}
	up.mu.Unlock()
	if !ev.has(DropTooLarge) {
		t.Fatal(ev.ev)
	}
}

// The reporter coalesces: one callback, then counts until the next report.
func TestUDPReporter(t *testing.T) {
	var r reporter
	reports := 0
	for i := range 100 {
		if ok, n, ex := r.note("k", 10+i); ok {
			reports++
			if n != 1 || ex != 10 {
				t.Fatal(n, ex)
			}
		}
	}
	if reports != 1 || r.keys["k"].pending != 99 {
		t.Fatal(reports, r.keys["k"].pending)
	}
}

// fakeOwners attributes sockets by port.
type fakeOwners struct {
	mu       sync.Mutex
	tcp      []uint32 // owners of the next control connections, in order
	tcpDef   uint32
	udp      map[uint16]uint32
	failNext int
	calls    int
}

func (f *fakeOwners) TCPOwner(local, remote netip.AddrPort) (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pid := f.tcpDef
	if len(f.tcp) > 0 {
		pid, f.tcp = f.tcp[0], f.tcp[1:]
	}
	return pid, pid != 0
}

func (f *fakeOwners) UDPOwner(src netip.AddrPort) (uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failNext > 0 {
		f.failNext--
		return 0, errors.New("table not read")
	}
	if pid, ok := f.udp[src.Port()]; ok {
		return pid, nil
	}
	return 0, ErrNoOwner
}

func (f *fakeOwners) set(pc *net.UDPConn, pid uint32) {
	f.mu.Lock()
	f.udp[portOf(pc)] = pid
	f.mu.Unlock()
}

func (f *fakeOwners) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Owner check on a loopback proxy with a password: only a socket of the
// process that owns the control connection may use the association.
func TestUDPOwnerCheck(t *testing.T) {
	newSrv := func(t *testing.T) (*Server, *fakeOwners, *events, string) {
		f := &fakeOwners{tcpDef: 100, udp: map[uint16]uint32{}}
		u := &ups{echo: true}
		s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, Owners: f}
		ev := hook(s)
		return s, f, ev, start(t, s)
	}
	t.Run("other program", func(t *testing.T) {
		old := ownerNegTTL
		// Far longer than the test: its last datagram must still meet the
		// cached answer on a slow runner (nothing waits for it to expire).
		ownerNegTTL = 2 * time.Second
		t.Cleanup(func() { ownerNegTTL = old })
		s, f, ev, addr := newSrv(t)
		_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
		evil, good := udpSock(t, "127.0.0.1"), udpSock(t, "127.0.0.1")
		f.set(evil, 200)
		f.set(good, 100)
		sendU(t, evil, bnd, dst1, "x")
		expectNothing(t, evil)
		expectEcho(t, good, bnd, "ok")
		calls := f.n()
		sendU(t, evil, bnd, dst1, "x")
		// The cached answer only drops: S turned 100 still waits for the TTL.
		f.set(evil, 100)
		sendU(t, evil, bnd, dst1, "x")
		expectNothing(t, evil)
		if f.n() != calls || !ev.has(DropOwner) {
			t.Fatalf("calls %d -> %d, %v", calls, f.n(), ev.ev)
		}
		_ = s
	})
	t.Run("named port", func(t *testing.T) {
		_, f, _, addr := newSrv(t)
		evil, good := udpSock(t, "127.0.0.1"), udpSock(t, "127.0.0.1")
		f.set(evil, 200)
		f.set(good, 100)
		_, bnd, _ := rawAssoc(t, addr, "", "", socks5.Addr{IP: netip.IPv4Unspecified(), Port: portOf(evil)}, "")
		sendU(t, evil, bnd, dst1, "x")
		expectNothing(t, evil)
		expectEcho(t, good, bnd, "ok")
		calls := f.n()
		sendU(t, evil, bnd, dst1, "x")
		expectNothing(t, evil)
		if f.n() != calls {
			t.Fatal("cached owner looked up again")
		}
		// A named port of the right process: one lookup, then none.
		_, f2, _, addr2 := newSrv(t)
		own := udpSock(t, "127.0.0.1")
		f2.set(own, 100)
		_, bnd2, _ := rawAssoc(t, addr2, "", "", socks5.Addr{IP: netip.IPv4Unspecified(), Port: portOf(own)}, "")
		expectEcho(t, own, bnd2, "a")
		expectEcho(t, own, bnd2, "b")
		if f2.n() != 1 {
			t.Fatalf("lookups %d", f2.n())
		}
	})
	t.Run("lookup failure", func(t *testing.T) {
		old := ownerRetry
		ownerRetry = 200 * time.Millisecond
		t.Cleanup(func() { ownerRetry = old })
		s, f, ev, addr := newSrv(t)
		_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
		good := udpSock(t, "127.0.0.1")
		f.set(good, 100)
		f.mu.Lock()
		f.failNext = 1
		f.mu.Unlock()
		sendU(t, good, bnd, dst1, "x")
		waitFor(t, "drop", func() bool { return s.UDPDropped.Load() == 1 })
		sendU(t, good, bnd, dst1, "x")
		waitFor(t, "drop", func() bool { return s.UDPDropped.Load() == 2 })
		if f.n() != 1 || !ev.has(DropOwnerRead) || ev.has(DropOwner) {
			t.Fatalf("calls %d, %v", f.n(), ev.ev)
		}
		time.Sleep(250 * time.Millisecond)
		expectEcho(t, good, bnd, "ok")
		if f.n() != 2 {
			t.Fatal(f.n())
		}
	})
	t.Run("no single owner", func(t *testing.T) {
		_, _, ev, addr := newSrv(t)
		_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
		nobody := udpSock(t, "127.0.0.1")
		sendU(t, nobody, bnd, dst1, "x")
		expectNothing(t, nobody)
		if !ev.has(DropOwner) {
			t.Fatal(ev.ev)
		}
	})
	t.Run("budget", func(t *testing.T) {
		s, f, _, addr := newSrv(t)
		_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
		for range 60 {
			pc := udpSock(t, "127.0.0.1")
			f.set(pc, 300)
			sendU(t, pc, bnd, dst1, "x")
		}
		waitFor(t, "drops", func() bool { return s.UDPDropped.Load() == 60 })
		if n := f.n(); n >= 60 || n > ownerRate+5 { // a few tokens refill during the burst
			t.Fatalf("%d lookups", n)
		}
	})
	t.Run("control owner unknown", func(t *testing.T) {
		f := &fakeOwners{udp: map[uint16]uint32{}}
		var u ups
		s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, Owners: f}
		ev := hook(s)
		addr := start(t, s)
		if _, _, rep := rawAssoc(t, addr, "", "", anyAddr, ""); rep != 1 {
			t.Fatal(rep)
		}
		ev.mu.Lock()
		defer ev.mu.Unlock()
		if u.n() != 0 || ev.ev[EventOwnerUnknown] != 1 || len(ev.ports) != 0 {
			t.Fatalf("opened %d, %v %v", u.n(), ev.ev, ev.ports)
		}
	})
}

// Read errors: closed ends the loop; a transient one is followed by the
// next read at once; an unknown one by a pause and a report.
func TestUDPReadErrors(t *testing.T) {
	old := readErrPause
	readErrPause = 300 * time.Millisecond
	t.Cleanup(func() { readErrPause = old })
	s := &Server{Dial: dialer(nil)}
	ev := hook(s)
	start(t, s)
	pc := udpSock(t, "127.0.0.1")
	p := s.newPort(pc, false)
	transient := error(syscall.ECONNREFUSED)
	if runtime.GOOS == "windows" {
		transient = syscall.Errno(10052) // WSAENETRESET
	}
	calls := make(chan time.Time, 16)
	results := make(chan error, 16)
	p.read = func(b []byte) (int, netip.AddrPort, error) {
		calls <- time.Now()
		return 0, netip.AddrPort{}, <-results
	}
	served := make(chan struct{})
	s.wg.Add(1)
	go func() { p.serve(); close(served) }()
	next := func() time.Time {
		select {
		case at := <-calls:
			return at
		case <-time.After(5 * time.Second):
			t.Fatal("no read")
		}
		return time.Time{}
	}
	t0 := next()
	results <- transient
	if d := next().Sub(t0); d > 150*time.Millisecond {
		t.Fatalf("transient error paused %v", d)
	}
	t1 := time.Now()
	results <- errors.New("strange")
	if d := next().Sub(t1); d < 250*time.Millisecond {
		t.Fatalf("unknown error paused only %v", d)
	}
	if !ev.has(EventReadError) {
		t.Fatal(ev.ev)
	}
	// Close: the flag comes first, so the loop never sleeps on it.
	p.closed.Store(true)
	t2 := time.Now()
	results <- errors.New("strange")
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("loop still running")
	}
	pc.Close()
	if d := time.Since(t2); d > 250*time.Millisecond {
		t.Fatalf("slept %v after close", d)
	}
}

// Close with open associations returns, frees every UDP socket and closes
// the upstreams.
func TestUDPClose(t *testing.T) {
	for _, shared := range []bool{false, true} {
		u := ups{echo: true}
		s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: shared}
		listenFree(t, s)
		addr := s.Addr()
		var bnds []netip.AddrPort
		for range 3 {
			_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
			expectEcho(t, udpSock(t, "127.0.0.1"), bnd, "x")
			bnds = append(bnds, bnd)
		}
		done := make(chan struct{})
		go func() { s.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Close hangs")
		}
		for i := range 3 {
			if u.get(i).closes.Load() == 0 {
				t.Fatal("upstream left open")
			}
		}
		for _, b := range bnds {
			pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(b))
			if err != nil {
				t.Fatalf("shared %v: %v still bound: %v", shared, b, err)
			}
			pc.Close()
		}
		if s.UDPActive.Load() != 0 {
			t.Fatal(s.UDPActive.Load())
		}
	}
}

// Owner check in shared mode (a LAN proxy used from this PC): pinning
// stays within the process of each control connection.
func TestUDPSharedOwners(t *testing.T) {
	old := localPeer
	localPeer = func(peer, _ netip.Addr) bool { return peer == netip.MustParseAddr("127.0.0.1") }
	t.Cleanup(func() { localPeer = old })
	newSrv := func(t *testing.T, tcp ...uint32) (*Server, *fakeOwners, *ups, string) {
		f := &fakeOwners{tcp: tcp, udp: map[uint16]uint32{}}
		u := &ups{echo: true}
		s := &Server{Dial: dialer(nil), AssociateUDP: u.dial, SharedUDP: true, Owners: f}
		return s, f, u, start(t, s)
	}
	t.Run("per process FIFO", func(t *testing.T) {
		_, f, u, addr := newSrv(t, 100, 200)
		_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "") // A, PID 100
		_, _, _ = rawAssoc(t, addr, "", "", anyAddr, "")    // B, PID 200
		evil, sa, sb := udpSock(t, "127.0.0.1"), udpSock(t, "127.0.0.1"), udpSock(t, "127.0.0.1")
		f.set(evil, 300)
		f.set(sa, 100)
		f.set(sb, 200)
		sendU(t, evil, bnd, dst1, "x")
		expectNothing(t, evil)
		expectEcho(t, sb, bnd, "b")
		if u.get(1).count() != 1 || u.get(0).count() != 0 {
			t.Fatal("B's socket did not take B's association")
		}
		expectEcho(t, sa, bnd, "a")
		if u.get(0).count() != 1 {
			t.Fatal("A's socket did not take A's association")
		}
	})
	t.Run("named port of another process", func(t *testing.T) {
		s, f, u, addr := newSrv(t, 200, 100)
		_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "") // B, PID 200
		sb, other, sa := udpSock(t, "127.0.0.1"), udpSock(t, "127.0.0.1"), udpSock(t, "127.0.0.1")
		f.set(sb, 200)
		f.set(other, 200)
		f.set(sa, 100)
		expectEcho(t, sb, bnd, "b")
		// A (PID 100) names a port a PID 200 socket holds.
		_, _, _ = rawAssoc(t, addr, "", "", socks5.Addr{IP: netip.IPv4Unspecified(), Port: portOf(other)}, "")
		sendU(t, other, bnd, dst1, "x")
		expectNothing(t, other)
		expectEcho(t, sb, bnd, "b2")
		expectEcho(t, sa, bnd, "a")
		if u.get(1).count() != 1 || u.get(0).count() != 2 {
			t.Fatal("wrong associations")
		}
		_ = s
	})
	t.Run("cache never admits", func(t *testing.T) {
		_, f, u, addr := newSrv(t, 100, 300)
		_, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "") // A, PID 100
		src := udpSock(t, "127.0.0.1")
		f.set(src, 300)
		sendU(t, src, bnd, dst1, "x")
		expectNothing(t, src)
		calls := f.n()
		_, _, _ = rawAssoc(t, addr, "", "", anyAddr, "") // C, PID 300
		expectEcho(t, src, bnd, "c")
		if f.n() != calls+1 || u.get(1).count() != 1 {
			t.Fatal("cached answer admitted a source")
		}
	})
	t.Run("no eviction across processes", func(t *testing.T) {
		_, f, u, addr := newSrv(t, 100, 200)
		sa := udpSock(t, "127.0.0.1")
		f.set(sa, 100)
		_, bnd, _ := rawAssoc(t, addr, "", "", socks5.Addr{IP: netip.IPv4Unspecified(), Port: portOf(sa)}, "") // A
		expectEcho(t, sa, bnd, "a")
		ctrlB, _, rep := rawAssoc(t, addr, "", "", socks5.Addr{IP: netip.IPv4Unspecified(), Port: portOf(sa)}, "") // B
		if rep != 0 {
			t.Fatal(rep)
		}
		expectEcho(t, sa, bnd, "a2")
		if u.get(0).count() != 2 || u.get(1).count() != 0 {
			t.Fatal("B took A's pin")
		}
		ctrlB.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := ctrlB.Read(make([]byte, 1)); err == nil {
			t.Fatal("B got data")
		} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatal("B closed:", err)
		}
	})
	t.Run("ambiguity per process", func(t *testing.T) {
		s, f, _, addr := newSrv(t, 100, 100, 200)
		ctrlA1, bnd, _ := rawAssoc(t, addr, "", "", anyAddr, "")
		_, _, _ = rawAssoc(t, addr, "", "", anyAddr, "")
		_, _, _ = rawAssoc(t, addr, "", "", anyAddr, "")
		s1, s2, sb := udpSock(t, "127.0.0.1"), udpSock(t, "127.0.0.1"), udpSock(t, "127.0.0.1")
		f.set(s1, 100)
		f.set(s2, 100)
		f.set(sb, 200)
		expectEcho(t, sb, bnd, "b")
		expectEcho(t, s2, bnd, "2") // takes A1: ambiguous
		expectEcho(t, s1, bnd, "1")
		ctrlA1.Close()
		waitFor(t, "close", func() bool { return s.UDPActive.Load() == 2 })
		p := s.shared
		p.mu.Lock()
		var bPinned, amb bool
		for _, a := range p.perIP[netip.MustParseAddr("127.0.0.1")] {
			if a.ctrlPID == 200 && a.pin.IsValid() {
				bPinned = true
			}
			amb = amb || a.amb
		}
		p.mu.Unlock()
		if !bPinned || amb {
			t.Fatalf("B pinned %v, marks left %v", bPinned, amb)
		}
		expectEcho(t, s1, bnd, "1b")
		expectEcho(t, sb, bnd, "b2")
	})
	t.Run("remote peer by IP", func(t *testing.T) {
		probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
		if err != nil {
			t.Skip("127.0.0.2 not available:", err)
		}
		probe.Close()
		_, f, _, addr := newSrv(t)
		_, bnd, rep := rawAssoc(t, addr, "", "", anyAddr, "127.0.0.2")
		if rep != 0 {
			t.Fatal(rep)
		}
		expectEcho(t, udpSock(t, "127.0.0.2"), bnd, "r")
		if f.n() != 0 {
			t.Fatal("remote peer owner-checked")
		}
	})
}

// Every UDP ASSOCIATE control connection counts in UDPCtl*, refused ones
// too, so Total minus UDPCtlTotal is the TCP connections.
func TestUDPControlCounted(t *testing.T) {
	s := &Server{Dial: dialer(nil)} // UDP off: reply 7
	addr := start(t, s)
	if _, _, rep := rawAssoc(t, addr, "", "", anyAddr, ""); rep != 7 {
		t.Fatalf("REP %d", rep)
	}
	waitFor(t, "counted", func() bool { return s.UDPCtlTotal.Load() == 1 && s.UDPCtlActive.Load() == 0 && s.Active.Load() == 0 })
	if s.Total.Load() != 1 || s.UDPTotal.Load() != 0 {
		t.Fatalf("total %d udp %d", s.Total.Load(), s.UDPTotal.Load())
	}
}
