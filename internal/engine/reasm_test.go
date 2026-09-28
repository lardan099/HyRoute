package engine

// bigudp: reassembly of fragmented UDP datagrams (frag.go).

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/socks5"
)

// socksRelay is a loopback SOCKS5 server for UDP ASSOCIATE that never
// forwards anything: it records every datagram and answers with
// reply(dst, payload) from dst when that is not nil. Tests can use any
// destination address without sending a packet off the machine.
type socksRelay struct {
	addr  string
	reply func(dst socks5.Addr, p []byte) []byte
	mu    sync.Mutex
	got   []relayed
	conns []io.Closer
}

type relayed struct {
	dst     socks5.Addr
	payload []byte
}

func newSocksRelay(t *testing.T, reply func(dst socks5.Addr, p []byte) []byte) *socksRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &socksRelay{addr: ln.Addr().String(), reply: reply}
	t.Cleanup(func() {
		ln.Close()
		r.mu.Lock()
		for _, c := range r.conns {
			c.Close()
		}
		r.mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return r
}

func (r *socksRelay) serve(c net.Conn) {
	defer c.Close()
	var h [3]byte
	if _, err := io.ReadFull(c, h[:2]); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, h[1])); err != nil {
		return
	}
	c.Write([]byte{5, 0})
	if _, err := io.ReadFull(c, h[:3]); err != nil || h[1] != socks5.CmdUDPAssociate {
		return
	}
	if _, err := socks5.ReadAddr(c); err != nil {
		return
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	pc.SetReadBuffer(8 << 20)
	r.mu.Lock()
	r.conns = append(r.conns, c, pc)
	r.mu.Unlock()
	rep, _ := socks5.AppendAddr([]byte{5, 0, 0}, socks5.AddrFromAddrPort(pc.LocalAddr().(*net.UDPAddr).AddrPort()))
	c.Write(rep)
	go func() {
		io.Copy(io.Discard, c)
		pc.Close()
	}()
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if n < 4 || buf[2] != 0 {
			continue
		}
		dst, hl, err := socks5.ParseAddr(buf[3:n])
		if err != nil {
			continue
		}
		p := append([]byte(nil), buf[3+hl:n]...)
		r.mu.Lock()
		r.got = append(r.got, relayed{dst, p})
		r.mu.Unlock()
		if r.reply != nil {
			if ans := r.reply(dst, p); ans != nil {
				hdr, _ := socks5.AppendAddr([]byte{0, 0, 0}, dst)
				pc.WriteToUDPAddrPort(append(hdr, ans...), from)
			}
		}
	}
}

func (r *socksRelay) client() *socks5.Client { return &socks5.Client{Server: r.addr} }

func (r *socksRelay) received() []relayed {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]relayed(nil), r.got...)
}

// waitRelay waits until the relay holds n datagrams (and fails on more).
func (r *socksRelay) waitRelay(t *testing.T, n int) []relayed {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := r.received()
		if len(got) >= n || time.Now().After(deadline) {
			if len(got) == n {
				time.Sleep(20 * time.Millisecond) // nothing more on its way
				got = r.received()
			}
			if len(got) != n {
				t.Fatalf("relay received %d datagrams, want %d", len(got), n)
			}
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func echoReply(_ socks5.Addr, p []byte) []byte { return p }

// injLog records every injection with its address (it replaces the
// harness's channels, which a test with many packets would fill).
type injLog struct {
	mu   sync.Mutex
	pkts []injRec
}

type injRec struct {
	raw  []byte
	addr divert.Address
}

func (h *harness) record() *injLog {
	l := &injLog{}
	h.c.Inject = func(b []byte, a *divert.Address) {
		l.mu.Lock()
		l.pkts = append(l.pkts, injRec{append([]byte(nil), b...), *a})
		l.mu.Unlock()
	}
	return l
}

// take returns and forgets what was injected so far.
func (l *injLog) take() []injRec {
	l.mu.Lock()
	defer l.mu.Unlock()
	p := l.pkts
	l.pkts = nil
	return p
}

// outbound returns the outbound injections so far (and forgets all).
func (l *injLog) outbound() (out []injRec) {
	for _, r := range l.take() {
		if r.addr.Outbound() {
			out = append(out, r)
		}
	}
	return out
}

// waitOutbound collects outbound injections until there are n.
func (l *injLog) waitOutbound(t *testing.T, n int) []injRec {
	t.Helper()
	var out []injRec
	deadline := time.Now().Add(3 * time.Second)
	for len(out) < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		out = append(out, l.outbound()...)
	}
	time.Sleep(20 * time.Millisecond)
	return append(out, l.outbound()...)
}

// waitInbound waits for an inbound whole packet.
func (l *injLog) waitInbound(t *testing.T) packet.Packet {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		l.mu.Lock()
		for i, r := range l.pkts {
			if !r.addr.Outbound() {
				l.pkts = append(l.pkts[:i:i], l.pkts[i+1:]...)
				l.mu.Unlock()
				p, err := packet.Parse(r.raw)
				if err != nil {
					t.Fatal(err)
				}
				return p
			}
		}
		l.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no inbound packet")
	return packet.Packet{}
}

func quiet(h *harness) { h.c.Log = slog.New(slog.NewTextHandler(io.Discard, nil)) }

// capture sends the engine log to a buffer; the function returned reads it.
func capture(h *harness) func() string {
	var buf bytes.Buffer
	var mu sync.Mutex
	h.c.Log = slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(p)
	}), nil))
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return buf.String()
	}
}

func testPayload(n, seed int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*13 + seed)
	}
	return b
}

// splitIP cuts a whole IPv4 or IPv6 packet into fragments: sizes are the
// data lengths of all fragments but the last, which takes the rest; with
// no sizes, 1480 (IPv4) or 1232 (IPv6) bytes each. IPv4 options stay in
// the first fragment only; IPv6 gets a fragment header right after the
// fixed header.
func splitIP(whole []byte, id uint32, sizes ...int) [][]byte {
	v6 := whole[0]>>4 == 6
	hl, def := int(whole[0]&0x0f)*4, 1480
	if v6 {
		hl, def = 40, 1232
	}
	body := whole[hl:]
	var out [][]byte
	for i, off := 0, 0; off < len(body); i++ {
		n := min(def, len(body)-off)
		if i < len(sizes) {
			n = sizes[i]
		}
		more := off+n < len(body)
		if v6 {
			b := make([]byte, 48+n)
			copy(b, whole[:40])
			binary.BigEndian.PutUint16(b[4:], uint16(8+n))
			b[6], b[40] = 44, whole[6]
			fo := uint16(off/8) << 3
			if more {
				fo |= 1
			}
			binary.BigEndian.PutUint16(b[42:], fo)
			binary.BigEndian.PutUint32(b[44:], id)
			copy(b[48:], body[off:off+n])
			out = append(out, b)
		} else {
			h := whole[:hl]
			if off > 0 {
				h = whole[:20]
			}
			b := append(append([]byte(nil), h...), body[off:off+n]...)
			b[0] = 0x40 | byte(len(h)/4)
			binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
			binary.BigEndian.PutUint16(b[4:], uint16(id))
			fl := uint16(off / 8)
			if more {
				fl |= 0x2000
			}
			binary.BigEndian.PutUint16(b[6:], fl)
			out = append(out, b)
		}
		off += n
	}
	return out
}

// udpFrags fragments a UDP datagram src -> dst.
func udpFrags(src, dst string, payload []byte, id uint32, sizes ...int) [][]byte {
	return splitIP(packet.BuildUDP(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst), payload), id, sizes...)
}

// addrN is an outbound address told apart by its timestamp and flags.
func addrN(n int) *divert.Address {
	a := outAddr()
	a.Timestamp = int64(1000 + n)
	if n%2 == 1 {
		a.SetChecksumsValid()
	}
	return a
}

// sendFrags handles the fragments in the given order (default: in order),
// fragment i with addrN(i).
func (h *harness) sendFrags(frs [][]byte, order ...int) {
	if len(order) == 0 {
		for i := range frs {
			order = append(order, i)
		}
	}
	for _, i := range order {
		h.c.HandlePacket(frs[i], addrN(i))
	}
}

// sameOriginals checks that exactly the fragments frs left, unchanged, each
// with its own address, in order.
func sameOriginals(t *testing.T, got []injRec, frs [][]byte) {
	t.Helper()
	if len(got) != len(frs) {
		t.Fatalf("%d packets out, want the %d original fragments", len(got), len(frs))
	}
	for i, r := range got {
		if !bytes.Equal(r.raw, frs[i]) || r.addr != *addrN(i) {
			t.Fatalf("fragment %d changed (timestamp %d)", i, r.addr.Timestamp)
		}
	}
}

func (h *harness) fragCounters() (held, bytes, entries int) {
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	return h.c.fragHeldN, h.c.fragBytes, len(h.c.frags)
}

const (
	fApp  = "192.168.1.5:41000"
	fDst  = "93.184.216.34:3478"
	fApp6 = "[2a00::5]:41000"
	fDst6 = "[2606:4700::1111]:3478"
)

// A fragmented datagram of a Tunnel flow reaches the server whole (in
// order and reversed); nothing leaves directly, and the reply comes back
// as one packet.
func TestFragmentedUDPThroughTunnel(t *testing.T) {
	relay := newSocksRelay(t, echoReply)
	h := newHarness(t, appRules, Options{})
	quiet(h)
	h.tun.client = relay.client()
	l := h.record()
	h.own(17, fApp, fDst, 400) // game.exe: UDP tunnel
	for k, order := range [][]int{{0, 1, 2}, {2, 1, 0}} {
		pl := testPayload(3000, k)
		h.sendFrags(udpFrags(fApp, fDst, pl, uint32(10+k)), order...)
		got := relay.waitRelay(t, k+1)
		if !bytes.Equal(got[k].payload, pl) || got[k].dst.String() != fDst {
			t.Fatalf("relay got %d bytes to %v", len(got[k].payload), got[k].dst)
		}
		p := l.waitInbound(t)
		if len(p.Buf) != 3028 || !bytes.Equal(p.Payload(), pl) || !p.VerifyChecksums() || p.Src().String() != fDst {
			t.Fatalf("reply: %d bytes from %v", len(p.Buf), p.Src())
		}
		if out := l.outbound(); len(out) != 0 {
			t.Fatalf("%d packets left directly", len(out))
		}
	}
	if n := h.c.FragReassembled.Load(); n != 2 {
		t.Fatalf("reassembled %d", n)
	}
	if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
		t.Fatalf("held %d, bytes %d", held, b)
	}
}

// A new Direct flow's first datagram is decided whole, then its original
// fragments leave unchanged, each with its own address; later datagrams of
// the flow pass fragment by fragment.
func TestFragmentedNewDirectFlowOriginals(t *testing.T) {
	for i, c := range []struct {
		name     string
		src, dst string
		sizes    []int
		zeroSum  bool
	}{
		{"v4", "192.168.1.5:42000", fDst, nil, false},
		{"v4 unequal", "192.168.1.5:42001", fDst, []int{1000, 16, 1480}, false},
		{"v4 checksum 0", "192.168.1.5:42002", fDst, nil, true},
		{"v6 600", "[2a00::5]:42003", fDst6, []int{600, 600, 600, 600}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, appRules, Options{})
			quiet(h)
			l := h.record()
			h.own(17, c.src, c.dst, 200) // chrome.exe: default Direct
			whole := packet.BuildUDP(netip.MustParseAddrPort(c.src), netip.MustParseAddrPort(c.dst), testPayload(3000, i))
			if c.zeroSum {
				p, _ := packet.Parse(whole)
				whole[p.L4+6], whole[p.L4+7] = 0, 0
			}
			frs := splitIP(whole, 77, c.sizes...)
			h.sendFrags(frs)
			sameOriginals(t, l.outbound(), frs)
			if h.c.FragReassembled.Load() != 1 {
				t.Fatal("first datagram not reassembled")
			}
			if v := lastRecord(t, h.c); v.Route != "direct" || v.Sent != 3000 {
				t.Fatalf("%+v", v)
			}
			// The flow exists now: fast path.
			frs = udpFrags(c.src, c.dst, testPayload(2500, i), 78, c.sizes...)
			for k := range frs {
				h.c.HandlePacket(frs[k], addrN(k))
				if out := l.outbound(); len(out) != 1 || !bytes.Equal(out[0].raw, frs[k]) {
					t.Fatalf("fragment %d not passed at once", k)
				}
			}
			if h.c.FragReassembled.Load() != 1 {
				t.Fatal("fast-path datagram reassembled")
			}
		})
	}
}

// A reassembled datagram parked while its owner is unknown carries its
// originals: Direct sends them (never one oversize packet), Tunnel sends
// the whole; a second parked datagram goes through replayWhole.
func TestFragmentedPendingCarriesOrigin(t *testing.T) {
	for _, c := range []struct {
		name string
		pid  uint32
	}{{"direct", 200}, {"tunnel", 400}} {
		t.Run(c.name, func(t *testing.T) {
			relay := newSocksRelay(t, nil)
			h := newHarness(t, appRules, Options{})
			quiet(h)
			h.tun.client = relay.client()
			l := h.record()
			a := udpFrags(fApp, fDst, testPayload(3000, 1), 1)
			b := udpFrags(fApp, fDst, testPayload(2000, 2), 2)
			h.sendFrags(a)
			h.sendFrags(b)
			if out := l.outbound(); len(out) != 0 {
				t.Fatalf("%d packets left before the decision", len(out))
			}
			h.own(17, fApp, fDst, c.pid)
			if c.pid == 400 {
				got := relay.waitRelay(t, 2)
				if len(got[0].payload) != 3000 || len(got[1].payload) != 2000 {
					t.Fatalf("relay got %d and %d bytes", len(got[0].payload), len(got[1].payload))
				}
				if out := l.outbound(); len(out) != 0 {
					t.Fatalf("%d packets left directly", len(out))
				}
				return
			}
			out := l.waitOutbound(t, 5)
			if len(out) != 5 {
				t.Fatalf("%d packets out, want the 5 original fragments", len(out))
			}
			sameOriginals(t, out[:3], a)
			sameOriginals(t, out[3:], b)
		})
	}
}

// Sustained fragmented traffic of Direct flows never fills the table: old
// decisions expire or are evicted oldest-first, nothing is refused, IDs
// wrap and are reused by another flow.
func TestFragTableSustainedLoad(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	quiet(h)
	var injected atomic.Int64
	h.c.Inject = func([]byte, *divert.Address) { injected.Add(1) }
	const app2 = "192.168.1.5:41001"
	h.own(17, fApp, fDst, 200)
	h.own(17, app2, fDst, 200)
	h.sendUDP(fApp, fDst, []byte("hello"))
	h.sendUDP(app2, fDst, []byte("hello"))
	one := udpFrags(fApp, fDst, testPayload(3000, 0), 0)
	two := udpFrags(app2, fDst, testPayload(2000, 0), 0)
	sent := int64(2)
	send := func(frs [][]byte, id int) {
		for _, f := range frs {
			binary.BigEndian.PutUint16(f[4:], uint16(id))
			h.c.HandlePacket(f, outAddr())
			sent++
		}
	}
	// IDs 0…9999, then 70 000 datagrams with IDs wrapping mod 65536: more
	// keys than fragMax, far quicker than any lifetime.
	for i := range 80000 {
		id := i
		if i >= 10000 {
			id = (i - 10000) % 65536
		}
		if i%10 == 5 {
			send(two, id+1)
		}
		send(one, id)
	}
	if injected.Load() != sent || h.c.FragDropped.Load() != 0 {
		t.Fatalf("injected %d of %d, dropped %d", injected.Load(), sent, h.c.FragDropped.Load())
	}
	if _, _, n := h.fragCounters(); n > fragMax {
		t.Fatalf("%d entries", n)
	}
	h.c.mu.Lock()
	q, qc := len(h.c.fragQ)-h.c.fragQHead, cap(h.c.fragQ)
	h.c.mu.Unlock()
	// The evicted prefix is compacted away too: memory does not grow with
	// the rate.
	if q > 2*fragMax || qc > 4*fragMax {
		t.Fatalf("eviction queue %d, capacity %d", q, qc)
	}
}

// Two flows between the same hosts share the IPv4 ID space: an offset-0
// fragment always starts a new datagram, so a Direct decision never lets a
// Tunnel or Block datagram's fragments out.
func TestFragIDReuseAcrossRoutes(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "game", App: &rules.AppMatch{Pattern: "game.exe"}, Protocol: "udp", Action: rules.Tunnel},
		{Name: "svc", App: &rules.AppMatch{Pattern: "svchost.exe"}, Protocol: "udp", Action: rules.Block},
	}}
	relay := newSocksRelay(t, nil)
	h := newHarness(t, cfg, Options{})
	quiet(h)
	h.tun.client = relay.client()
	l := h.record()
	const a, b, c = "192.168.1.5:40010", "192.168.1.5:40011", "192.168.1.5:40012"
	h.own(17, a, fDst, 200) // Direct
	h.own(17, b, fDst, 400) // Tunnel
	h.own(17, c, fDst, 300) // Block
	for _, src := range []string{a, b, c} {
		h.sendUDP(src, fDst, []byte("x"))
	}
	relay.waitRelay(t, 1)
	l.take()

	fa := func(id uint32) [][]byte { return udpFrags(a, fDst, testPayload(3000, 1), id) }
	fb := func(id uint32) [][]byte { return udpFrags(b, fDst, testPayload(2500, 2), id) }
	// A then B, same ID.
	h.sendFrags(fa(7))
	sameOriginals(t, l.outbound(), fa(7))
	h.sendFrags(fb(7))
	if got := relay.waitRelay(t, 2); len(got[1].payload) != 2500 {
		t.Fatalf("B: %d bytes", len(got[1].payload))
	}
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("B leaked %d fragments", len(out))
	}
	// B then A.
	h.sendFrags(fb(8))
	h.sendFrags(fa(8))
	relay.waitRelay(t, 3)
	sameOriginals(t, l.outbound(), fa(8))
	// Block: C dropped, A still passes.
	h.sendFrags(udpFrags(c, fDst, testPayload(2500, 3), 9))
	h.sendFrags(fa(9))
	sameOriginals(t, l.outbound(), fa(9))
	// Reordered: B's later fragment first, then A's first fragment with the
	// same ID: the geometry does not match, both are dropped.
	inc := h.c.FragIncomplete.Load()
	h.sendFrags(fb(10), 1)
	h.c.HandlePacket(fa(10)[0], addrN(0))
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d fragments left", len(out))
	}
	if h.c.FragIncomplete.Load() != inc+1 {
		t.Fatalf("incomplete +%d", h.c.FragIncomplete.Load()-inc)
	}
	relay.waitRelay(t, 3)
}

// A panic in fragStep poisons the datagram and leaves Core.mu usable; the
// counters are clean after the sweep and nothing is refused later.
func TestFragStepPanicReleasesLock(t *testing.T) {
	for _, second := range []bool{false, true} {
		h := newHarness(t, appRules, Options{})
		logged := capture(h)
		l := h.record()
		h.own(17, fApp, fDst, 200)
		frs := udpFrags(fApp, fDst, testPayload(3000, 0), 5)
		var arm atomic.Bool
		h.c.fragHook = func() {
			if arm.CompareAndSwap(true, false) {
				panic("test")
			}
		}
		if second {
			h.c.HandlePacket(frs[2], outAddr()) // held
			arm.Store(true)
			h.c.HandlePacket(frs[1], outAddr()) // the held entry is poisoned
		} else {
			arm.Store(true)
			h.c.HandlePacket(frs[0], outAddr()) // a new entry, never inserted
		}
		if h.c.Panics.Load() != 1 {
			t.Fatalf("panics %d", h.c.Panics.Load())
		}
		// The poisoned datagram is logged with its reason, after the unlock.
		if n := strings.Count(logged(), `not reassembled: dropped" dst=93.184.216.34 reason=panic`); n != 1 {
			t.Fatalf("%d panic lines:\n%s", n, logged())
		}
		fk := packet.FragKey{Src: netip.MustParseAddr("192.168.1.5"), Dst: netip.MustParseAddr("93.184.216.34"), ID: 5, Proto: 17}
		h.c.mu.Lock()
		e := h.c.frags[fk]
		h.c.mu.Unlock()
		if e == nil || e.state != fragDrop {
			t.Fatalf("entry %+v", e)
		}
		done := make(chan struct{})
		go func() {
			h.c.HandlePacket(frs[0], outAddr())
			h.c.Maintain(time.Now())
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("engine blocked after a panic")
		}
		if !h.c.mu.TryLock() {
			t.Fatal("Core.mu held")
		}
		h.c.mu.Unlock()
		h.c.Maintain(time.Now().Add(6 * time.Second))
		if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
			t.Fatalf("held %d, bytes %d", held, b)
		}
		// The replayed first fragment started a new datagram (never
		// completed): nothing of the poisoned one left.
		if out := l.outbound(); len(out) != 0 {
			t.Fatalf("%d fragments left", len(out))
		}
		// 300 new-flow datagrams later: none refused.
		for i := range 300 {
			src := fmt.Sprintf("192.168.1.5:%d", 43000+i)
			h.own(17, src, fDst, 200)
			h.sendFrags(udpFrags(src, fDst, testPayload(2000, i), uint32(100+i)))
		}
		if n := h.c.FragReassembled.Load(); n != 300 {
			t.Fatalf("reassembled %d of 300", n)
		}
		if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
			t.Fatalf("held %d, bytes %d", held, b)
		}
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// A drift of the budget counters (a bug) is corrected by the next sweep,
// with one warning.
func TestFragCountersHeal(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	var logBuf bytes.Buffer
	var logMu sync.Mutex
	h.c.Log = slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return logBuf.Write(p)
	}), nil))
	l := h.record()
	h.c.mu.Lock()
	h.c.fragHeldN, h.c.fragBytes = fragHeldMax, fragBytesMax
	h.c.mu.Unlock()
	h.c.Maintain(time.Now())
	if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
		t.Fatalf("held %d, bytes %d", held, b)
	}
	h.c.mu.Lock()
	h.c.fragHeldN = 3
	h.c.mu.Unlock()
	h.c.Maintain(time.Now())
	logMu.Lock()
	n := strings.Count(logBuf.String(), "fragment table counters corrected")
	logMu.Unlock()
	if n != 1 {
		t.Fatalf("%d warnings", n)
	}
	h.own(17, fApp, fDst, 200)
	frs := udpFrags(fApp, fDst, testPayload(3000, 0), 1)
	h.sendFrags(frs)
	if h.c.FragReassembled.Load() != 1 {
		t.Fatal("not reassembled")
	}
	sameOriginals(t, l.outbound(), frs)
}

// A panic while replaying one parked reassembled datagram costs only that
// datagram.
func TestReplayWholeGuard(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	quiet(h)
	l := h.record()
	var calls atomic.Int64
	h.c.replayHook = func() {
		if calls.Add(1) == 1 {
			panic("test")
		}
	}
	var dgs [][][]byte
	for i := range 3 {
		dgs = append(dgs, udpFrags(fApp, fDst, testPayload(2000+i*100, i), uint32(20+i)))
		h.sendFrags(dgs[i])
	}
	h.own(17, fApp, fDst, 200)
	out := l.waitOutbound(t, 4)
	if len(out) != 4 {
		t.Fatalf("%d fragments out, want datagrams 1 and 3", len(out))
	}
	sameOriginals(t, out[:2], dgs[0])
	sameOriginals(t, out[2:], dgs[2])
	if h.c.Panics.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("panics %d, replays %d", h.c.Panics.Load(), calls.Load())
	}
	h.c.mu.Lock()
	pb := h.c.pendBytes
	h.c.mu.Unlock()
	if pb != 0 {
		t.Fatalf("pendBytes %d", pb)
	}
}

// The Direct fast path counts the datagram's payload once (from the UDP
// length) and keeps the flow alive; a malformed UDP length never passes.
func TestFragDirectFastPathCounts(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	quiet(h)
	l := h.record()
	h.own(17, fApp, fDst, 200)
	h.sendUDP(fApp, fDst, []byte("hello"))
	l.take()
	key := flowKey(fApp, fDst)
	h.c.mu.Lock()
	h.c.udp[key].last = time.Now().Add(-2 * h.c.Opt.UDPIdle)
	h.c.mu.Unlock()
	for i := range 3 {
		h.sendFrags(udpFrags(fApp, fDst, testPayload(3000, i), uint32(30+i)))
	}
	if out := l.outbound(); len(out) != 9 {
		t.Fatalf("%d fragments out", len(out))
	}
	if v := lastRecord(t, h.c); v.Sent != 5+3*3000 {
		t.Fatalf("sent %d", v.Sent)
	}
	h.c.Maintain(time.Now().Add(h.c.Opt.UDPIdle - time.Second))
	h.c.mu.Lock()
	kept := h.c.udp[key] != nil
	h.c.mu.Unlock()
	if !kept || len(h.c.Flows.Active(time.Now())) != 1 {
		t.Fatal("flow expired while sending fragmented datagrams")
	}
	// UDP length 4, and a first fragment with only 6 bytes of UDP header.
	inc := h.c.FragIncomplete.Load()
	bad := udpFrags(fApp, fDst, testPayload(3000, 9), 40)
	binary.BigEndian.PutUint16(bad[0][24:], 4)
	h.c.HandlePacket(bad[0], outAddr())
	six := append([]byte(nil), udpFrags(fApp, fDst, testPayload(3000, 9), 41)[0][:26]...)
	binary.BigEndian.PutUint16(six[2:], 26)
	h.c.HandlePacket(six, outAddr())
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d malformed fragments passed", len(out))
	}
	if v := lastRecord(t, h.c); v.Sent != 5+3*3000 {
		t.Fatalf("sent %d", v.Sent)
	}
	if h.c.FragIncomplete.Load() != inc+2 {
		t.Fatalf("incomplete +%d", h.c.FragIncomplete.Load()-inc)
	}
}

// A Tunnel flow whose tunnel is down: its fragmented datagram is assembled
// (never dropped early as too big) and follows udpOut: moved to Direct by
// a new decision, or dropped as unavailable.
func TestFragTunnelDownFragmented(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "game", App: &rules.AppMatch{Pattern: "game.exe"}, Protocol: "udp", Action: rules.Tunnel, Profile: "a"},
	}}
	for _, moved := range []bool{true, false} {
		relay := newSocksRelay(t, nil)
		h := newHarness(t, cfg, Options{})
		quiet(h)
		a := &fakeTunnel{client: relay.client()}
		a.up.Store(true)
		a.udp.Store(true)
		h.extra["a"] = a
		l := h.record()
		h.own(17, fApp, fDst, 400)
		h.sendUDP(fApp, fDst, []byte("x"))
		relay.waitRelay(t, 1)
		a.up.Store(false)
		a.udp.Store(false)
		if moved {
			h.c.Rules.Swap(mustCompile(t, rules.Config{DefaultAction: rules.Direct}))
		}
		frs := udpFrags(fApp, fDst, testPayload(9000, 0), 50)
		h.sendFrags(frs)
		out := l.outbound()
		if moved {
			sameOriginals(t, out, frs)
		} else if len(out) != 0 || h.c.UDPDropped.Load() != 1 {
			t.Fatalf("%d fragments out, dropped %d", len(out), h.c.UDPDropped.Load())
		}
		if h.c.UDPTooBig.Load() != 0 || h.c.FragReassembled.Load() != 1 {
			t.Fatalf("too big %d, reassembled %d", h.c.UDPTooBig.Load(), h.c.FragReassembled.Load())
		}
		for _, v := range append(h.c.Flows.Active(time.Now()), h.c.Flows.Closed()...) {
			if v.TooBig != 0 {
				t.Fatalf("%+v", v)
			}
		}
	}
}

// An existing Tunnel flow whose tunnel is up drops a datagram over the
// limit at its first fragment (the UDP length announces it); the rest is
// dropped without being held.
func TestFragTooBigEarlyDrop(t *testing.T) {
	relay := newSocksRelay(t, nil)
	h := newHarness(t, appRules, Options{})
	quiet(h)
	h.tun.client = relay.client()
	l := h.record()
	h.own(17, fApp, fDst, 400)
	h.sendUDP(fApp, fDst, []byte("x"))
	relay.waitRelay(t, 1)
	frs := udpFrags(fApp, fDst, testPayload(9000, 0), 60)
	h.sendFrags(frs)
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d fragments left", len(out))
	}
	if h.c.UDPTooBig.Load() != 1 || h.c.FragDropped.Load() != int64(len(frs)) {
		t.Fatalf("too big %d, dropped %d", h.c.UDPTooBig.Load(), h.c.FragDropped.Load())
	}
	if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
		t.Fatalf("held %d, bytes %d", held, b)
	}
	if v := lastRecord(t, h.c); v.TooBig != 1 || v.Outcome != "tunneled" {
		t.Fatalf("%+v", v)
	}
	relay.waitRelay(t, 1)
	// A flow recorded as refused (its tunnel could not carry UDP) whose
	// tunnel is back: its outcome follows, as for a whole datagram.
	const app2 = "192.168.1.5:41005"
	h.tun.udp.Store(false)
	h.own(17, app2, fDst, 400)
	h.sendUDP(app2, fDst, []byte("x"))
	if v := lastRecord(t, h.c); v.Outcome != "dropped: tunnel unavailable" {
		t.Fatalf("%+v", v)
	}
	h.tun.udp.Store(true)
	h.sendFrags(udpFrags(app2, fDst, testPayload(9000, 1), 61))
	if v := lastRecord(t, h.c); v.TooBig != 1 || v.Outcome != flows.OutcomeTooBig {
		t.Fatalf("%+v", v)
	}
	// Hysteria down while UDP is still reported up: udpSend's availability
	// check comes first, as for a whole datagram (not too big).
	h.tun.up.Store(false)
	dropped := h.c.UDPDropped.Load()
	h.sendFrags(udpFrags(fApp, fDst, testPayload(9000, 2), 62))
	if h.c.UDPTooBig.Load() != 2 || h.c.UDPDropped.Load() != dropped+1 || h.c.FragReassembled.Load() != 1 {
		t.Fatalf("too big %d, dropped +%d, reassembled %d",
			h.c.UDPTooBig.Load(), h.c.UDPDropped.Load()-dropped, h.c.FragReassembled.Load())
	}
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d fragments left", len(out))
	}
}

// An IPv4 first fragment with options, arriving last: reassembled with its
// options and routed.
func TestFragIPv4OptionsFirst(t *testing.T) {
	relay := newSocksRelay(t, nil)
	h := newHarness(t, appRules, Options{})
	quiet(h)
	h.tun.client = relay.client()
	l := h.record()
	for i, c := range []struct {
		src string
		pid uint32
	}{{"192.168.1.5:44000", 400}, {"192.168.1.5:44001", 200}} {
		h.own(17, c.src, fDst, c.pid)
		w := packet.BuildUDP(netip.MustParseAddrPort(c.src), netip.MustParseAddrPort(fDst), testPayload(3000, i))
		w = append(append(append([]byte(nil), w[:20]...), 0x44, 4, 5, 0), w[20:]...)
		w[0] = 0x46
		binary.BigEndian.PutUint16(w[2:], uint16(len(w)))
		frs := splitIP(w, uint32(70+i), 1472)
		h.sendFrags(frs, 2, 1, 0)
		if c.pid == 400 {
			if got := relay.waitRelay(t, 1); !bytes.Equal(got[0].payload, testPayload(3000, i)) {
				t.Fatal("tunnel payload differs")
			}
			if out := l.outbound(); len(out) != 0 {
				t.Fatalf("%d fragments left", len(out))
			}
		} else {
			out := l.outbound()
			if len(out) != 3 || !bytes.Equal(out[0].raw, frs[2]) || !bytes.Equal(out[2].raw, frs[0]) {
				t.Fatalf("%d originals", len(out))
			}
		}
		if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
			t.Fatalf("held %d, bytes %d", held, b)
		}
	}
}

// IPv6: Simple later fragments held, then a first fragment with a
// destination-options header in front of the fragment header: the held
// data is released and counted, the legacy decision applies.
func TestFragIPv6Inconsistent(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	quiet(h)
	l := h.record()
	h.own(17, fApp6, fDst6, 400) // Tunnel: the legacy path drops it
	frs := udpFrags(fApp6, fDst6, testPayload(3000, 0), 90)
	h.sendFrags(frs, 1, 2)
	if held, _, _ := h.fragCounters(); held != 1 {
		t.Fatalf("held %d", held)
	}
	first := frs[0]
	opt := append(append(append([]byte(nil), first[:40]...), 44, 0, 1, 4, 0, 0, 0, 0), first[40:]...)
	opt[6] = 60
	binary.BigEndian.PutUint16(opt[4:], uint16(len(opt)-40))
	h.c.HandlePacket(opt, outAddr())
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d fragments left", len(out))
	}
	if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
		t.Fatalf("held %d, bytes %d", held, b)
	}
	if h.c.FragIncomplete.Load() != 1 || h.c.FragDropped.Load() != 3 || h.c.FragLegacy.Load() != 1 {
		t.Fatalf("incomplete %d, dropped %d, legacy %d", h.c.FragIncomplete.Load(), h.c.FragDropped.Load(), h.c.FragLegacy.Load())
	}
}

// Held, incomplete and overlapping datagrams: nothing leaves before the
// datagram is whole and decided.
func TestFragHeldIncompleteOverlap(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	quiet(h)
	l := h.record()
	h.own(17, fApp, fDst, 200)
	h.sendUDP(fApp, fDst, []byte("hello")) // an existing Direct flow
	l.take()
	// Later fragments first, then the first within 5 s: all pass.
	frs := udpFrags(fApp, fDst, testPayload(3000, 0), 1)
	h.sendFrags(frs, 1, 2)
	if out := l.outbound(); len(out) != 0 {
		t.Fatal("held fragments passed before the first")
	}
	h.c.HandlePacket(frs[0], addrN(0))
	if out := l.outbound(); len(out) != 3 {
		t.Fatalf("%d fragments out", len(out))
	}
	// A new flow, 2 of 3 fragments: dropped after 5 s.
	const n2 = "192.168.1.5:41002"
	h.own(17, n2, fDst, 200)
	h.sendFrags(udpFrags(n2, fDst, testPayload(3000, 1), 2), 0, 1)
	h.c.Maintain(time.Now().Add(6 * time.Second))
	if out := l.outbound(); len(out) != 0 || h.c.FragIncomplete.Load() != 1 {
		t.Fatalf("%d out, incomplete %d", len(out), h.c.FragIncomplete.Load())
	}
	// Overlap.
	ov := udpFrags(n2, fDst, testPayload(3000, 2), 3)
	shifted := append([]byte(nil), ov[1]...)
	binary.BigEndian.PutUint16(shifted[6:], 0x2000|uint16((1480-8)/8))
	h.c.HandlePacket(ov[0], outAddr())
	h.c.HandlePacket(shifted, outAddr())
	h.c.HandlePacket(ov[2], outAddr())
	if out := l.outbound(); len(out) != 0 || h.c.FragIncomplete.Load() != 2 {
		t.Fatalf("%d out, incomplete %d", len(out), h.c.FragIncomplete.Load())
	}
	if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
		t.Fatalf("held %d, bytes %d", held, b)
	}
}

// The data budgets bound what is held; overflow is dropped, never passed,
// and existing Direct flows keep their fast path.
func TestFragBudgets(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	quiet(h)
	l := h.record()
	const direct = "192.168.1.5:41003"
	h.own(17, direct, fDst, 200)
	h.sendUDP(direct, fDst, []byte("hello"))
	l.take()
	h.own(17, fApp, fDst, 200)
	for i := range 300 {
		frs := udpFrags(fApp, fDst, testPayload(3000, i), uint32(1000+i))
		h.sendFrags(frs, 0, 1) // never the last one
	}
	held, b, _ := h.fragCounters()
	if held > fragHeldMax || b > fragBytesMax {
		t.Fatalf("held %d, bytes %d", held, b)
	}
	if h.c.FragIncomplete.Load() < 300-fragHeldMax || h.c.FragDropped.Load() < 300-fragHeldMax {
		t.Fatalf("overflow not counted: incomplete %d, dropped %d", h.c.FragIncomplete.Load(), h.c.FragDropped.Load())
	}
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d fragments left", len(out))
	}
	frs := udpFrags(direct, fDst, testPayload(3000, 0), 5000)
	h.sendFrags(frs)
	sameOriginals(t, l.outbound(), frs)
}

// ednsQuery is a DNS query padded (EDNS padding) to about size bytes.
func ednsQuery(t *testing.T, name string, size int) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAdditionals()
	var rh dnsmessage.ResourceHeader
	if err := rh.SetEDNS0(4096, dnsmessage.RCodeSuccess, false); err != nil {
		t.Fatal(err)
	}
	b.OPTResource(rh, dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: make([]byte, size-60)}}})
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A fragmented DNS query to a Tunnel resolver reaches it whole, and its
// answer feeds the cache (the query was recorded whole).
func TestFragmentedDNSQuery(t *testing.T) {
	answer := dnsResponse(t, "big.test.", "198.51.100.60")
	relay := newSocksRelay(t, func(dst socks5.Addr, p []byte) []byte {
		if dst.Port != 53 {
			return nil
		}
		return answer
	})
	h := newHarness(t, appRules, Options{})
	quiet(h)
	h.tun.client = relay.client()
	l := h.record()
	const res = "8.8.8.8:53"
	h.own(17, fApp, res, 400)
	q := ednsQuery(t, "big.test.", 2000)
	h.sendFrags(udpFrags(fApp, res, q, 1))
	if got := relay.waitRelay(t, 1); !bytes.Equal(got[0].payload, q) {
		t.Fatal("query not whole")
	}
	l.waitInbound(t)
	if names := h.c.DNS.Names(netip.MustParseAddr("198.51.100.60")); len(names) != 1 || names[0] != "big.test" {
		t.Fatalf("names %v", names)
	}
}

// A fragmented DNS query to a Direct resolver is assembled (never the fast
// path, also for an existing Direct flow), leaves as its fragments, and is
// recorded, so that its sniffed answer is accepted.
func TestFragmentedDNSQueryDirect(t *testing.T) {
	for _, existing := range []bool{false, true} {
		h := newHarness(t, appRules, Options{})
		quiet(h)
		l := h.record()
		const res = "1.1.1.1:53"
		h.own(17, fApp, res, 200)
		if existing {
			h.sendUDP(fApp, res, dnsQuery(t, "small.test."))
			l.take()
		}
		frs := udpFrags(fApp, res, ednsQuery(t, "big.test.", 2000), 2)
		h.sendFrags(frs)
		if h.c.FragReassembled.Load() != 1 {
			t.Fatal("DNS query not assembled")
		}
		sameOriginals(t, l.outbound(), frs)
		h.c.HandleDNS(packet.BuildUDP(netip.MustParseAddrPort(res), netip.MustParseAddrPort(fApp), dnsResponse(t, "big.test.", "198.51.100.61")), false)
		if names := h.c.DNS.Names(netip.MustParseAddr("198.51.100.61")); len(names) != 1 {
			t.Fatalf("existing %v: answer not cached", existing)
		}
	}
}

// A fragmented DNS query of a Block flow is assembled and dropped whole.
func TestFragmentedDNSBlockFlow(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "svc", App: &rules.AppMatch{Pattern: "svchost.exe"}, Protocol: "udp", Action: rules.Block},
	}}
	h := newHarness(t, cfg, Options{})
	quiet(h)
	l := h.record()
	const res = "1.1.1.1:53"
	h.own(17, fApp, res, 300)
	h.sendUDP(fApp, res, dnsQuery(t, "small.test."))
	h.sendFrags(udpFrags(fApp, res, ednsQuery(t, "big.test.", 2000), 3))
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d packets out", len(out))
	}
	if h.c.FragReassembled.Load() != 1 {
		t.Fatal("not assembled")
	}
}

// Two packet loops feeding interleaved fragments: every datagram arrives
// once.
func TestFragmentsConcurrentLoops(t *testing.T) {
	relay := newSocksRelay(t, nil)
	h := newHarness(t, appRules, Options{})
	quiet(h)
	h.tun.client = relay.client()
	h.record()
	h.own(17, fApp, fDst, 400)
	h.sendUDP(fApp, fDst, []byte("x"))
	relay.waitRelay(t, 1)
	var dgs [][][]byte
	for i := range 100 {
		pl := testPayload(1600, i)
		pl[0], pl[1] = byte(i), 0xAB
		dgs = append(dgs, udpFrags(fApp, fDst, pl, uint32(200+i)))
	}
	var wg sync.WaitGroup
	for g := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, d := range dgs {
				h.c.HandlePacket(d[g], outAddr())
			}
		}()
	}
	wg.Wait()
	got := relay.waitRelay(t, 101)
	seen := map[byte]int{}
	for _, r := range got[1:] {
		if len(r.payload) != 1600 || r.payload[1] != 0xAB {
			t.Fatalf("datagram of %d bytes", len(r.payload))
		}
		seen[r.payload[0]]++
	}
	if len(seen) != 100 {
		t.Fatalf("%d distinct datagrams", len(seen))
	}
}

// pendState reads the parked-packet accounting.
func (h *harness) pendState() (bytes, flows int) {
	h.c.mu.Lock()
	defer h.c.mu.Unlock()
	return h.c.pendBytes, len(h.c.pending)
}

// waitPend waits until the parked bytes are back to want and no flow is
// parked.
func (h *harness) waitPend(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, n := h.pendState()
		if b == want && n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pendBytes %d (want %d), %d flows parked", b, want, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The parked-packet byte budget counts a reassembled datagram with its
// originals. Over it, a new flow is decided at once ("pending-full") and a
// parked flow's next datagram is not parked; the bytes are given back
// after every decision, a panicking one included.
func TestFragPendingBudget(t *testing.T) {
	h := newHarness(t, appRules, Options{PendingTimeout: 10 * time.Second})
	quiet(h)
	l := h.record()
	const parked, full = "192.168.1.5:45000", "192.168.1.5:45001"
	whole := packet.BuildUDP(netip.MustParseAddrPort(parked), netip.MustParseAddrPort(fDst), testPayload(3000, 1))
	a := splitIP(whole, 1)
	h.sendFrags(a) // the owner is not known yet: parked
	want := len(whole)
	for _, f := range a {
		want += len(f)
	}
	if b, n := h.pendState(); b != want || n != 1 {
		t.Fatalf("parked %d bytes in %d flows, want %d in 1", b, n, want)
	}
	// Less room left than one more datagram takes.
	pad := pendingMaxBytes - want - 1000
	h.c.mu.Lock()
	h.c.pendBytes += pad
	h.c.mu.Unlock()
	h.sendFrags(udpFrags(parked, fDst, testPayload(2000, 2), 2))
	h.c.mu.Lock()
	kept := len(h.c.pending[pendKey{17, flowKey(parked, fDst)}].pkts)
	h.c.mu.Unlock()
	if kept != 1 || h.c.PendingFull.Load() != 1 {
		t.Fatalf("%d packets parked, pending full %d", kept, h.c.PendingFull.Load())
	}
	c := udpFrags(full, fDst, testPayload(3000, 3), 3)
	h.sendFrags(c)
	if h.c.PendingFull.Load() != 2 {
		t.Fatalf("pending full %d", h.c.PendingFull.Load())
	}
	if v := lastRecord(t, h.c); v.Attrib != "pending-full" || v.Route != "direct" {
		t.Fatalf("%+v", v)
	}
	sameOriginals(t, l.outbound(), c)
	h.own(17, parked, fDst, 200)
	sameOriginals(t, l.waitOutbound(t, 3), a)
	h.waitPend(t, pad)
	h.c.mu.Lock()
	h.c.pendBytes -= pad
	h.c.mu.Unlock()
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d more packets out: the unparked datagram left", len(out))
	}

	// A panic while deciding a parked flow: its bytes are given back too.
	h = newHarness(t, appRules, Options{PendingTimeout: 10 * time.Second})
	quiet(h)
	l = h.record()
	h.c.OwnerFallback = func(uint8, netip.AddrPort, netip.AddrPort) (uint32, bool) { panic("test") }
	h.sendFrags(udpFrags(parked, fDst, testPayload(3000, 4), 4))
	h.waitPend(t, 0)
	if h.c.Panics.Load() != 1 {
		t.Fatalf("panics %d", h.c.Panics.Load())
	}
	h.own(17, parked, fDst, 200)
	d := udpFrags(parked, fDst, testPayload(3000, 5), 5)
	h.sendFrags(d)
	sameOriginals(t, l.outbound(), d)
}

// The byte budget: large incomplete datagrams fill 4 MiB before 256
// entries; the rest are refused ("budget"), nothing leaves, and everything
// is released when they expire.
func TestFragByteBudget(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	logged := capture(h)
	l := h.record()
	h.own(17, fApp, fDst, 200)
	const dgs, per = 80, 40 // 41 fragments each, all but the last sent
	for i := range dgs {
		frs := udpFrags(fApp, fDst, testPayload(60000, i), uint32(300+i))
		if len(frs) != per+1 {
			t.Fatalf("%d fragments", len(frs))
		}
		h.sendFrags(frs[:per])
	}
	fit := fragBytesMax / (per * 1500)
	held, b, _ := h.fragCounters()
	if held != fit || b != fit*per*1500 || held >= fragHeldMax {
		t.Fatalf("held %d, bytes %d", held, b)
	}
	refused := int64(dgs - fit)
	if h.c.FragIncomplete.Load() != refused || h.c.FragDropped.Load() != refused*per {
		t.Fatalf("incomplete %d, dropped %d", h.c.FragIncomplete.Load(), h.c.FragDropped.Load())
	}
	if !strings.Contains(logged(), "reason=budget") {
		t.Fatal("budget not logged")
	}
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d fragments left", len(out))
	}
	h.c.Maintain(time.Now().Add(6 * time.Second))
	if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
		t.Fatalf("held %d, bytes %d", held, b)
	}
	if h.c.FragIncomplete.Load() != dgs {
		t.Fatalf("incomplete %d", h.c.FragIncomplete.Load())
	}
	frs := udpFrags(fApp, fDst, testPayload(60000, 0), 900)
	h.sendFrags(frs)
	sameOriginals(t, l.outbound(), frs)
}

// An entry lives its TTL, not until the next sweep: a later fragment after
// an expired Direct decision is held, never passed, and an expired
// assembly is dropped when its next fragment comes.
func TestFragExpiredEntry(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	quiet(h)
	l := h.record()
	h.own(17, fApp, fDst, 200)
	h.sendUDP(fApp, fDst, []byte("hello")) // an existing Direct flow
	l.take()
	expire := func(id uint32) {
		fk := packet.FragKey{Src: netip.MustParseAddr("192.168.1.5"), Dst: netip.MustParseAddr("93.184.216.34"), ID: id, Proto: 17}
		h.c.mu.Lock()
		h.c.frags[fk].exp = time.Now().Add(-time.Millisecond)
		h.c.mu.Unlock()
	}
	frs := udpFrags(fApp, fDst, testPayload(3000, 0), 7)
	h.c.HandlePacket(frs[0], addrN(0)) // fast path: passed, decision stored
	if out := l.outbound(); len(out) != 1 {
		t.Fatalf("%d fragments out", len(out))
	}
	expire(7)
	h.c.HandlePacket(frs[1], addrN(1))
	if out := l.outbound(); len(out) != 0 {
		t.Fatal("a fragment passed on an expired decision")
	}
	if held, _, _ := h.fragCounters(); held != 1 {
		t.Fatalf("held %d", held)
	}
	// A new flow's assembly, 2 of 3 fragments, expired.
	const n2 = "192.168.1.5:41004"
	h.own(17, n2, fDst, 200)
	two := udpFrags(n2, fDst, testPayload(3000, 1), 8)
	h.sendFrags(two, 0, 1)
	expire(8)
	h.c.HandlePacket(two[2], addrN(2))
	if out := l.outbound(); len(out) != 0 || h.c.FragReassembled.Load() != 0 {
		t.Fatalf("%d out, reassembled %d", len(out), h.c.FragReassembled.Load())
	}
	if h.c.FragIncomplete.Load() != 1 || h.c.FragDropped.Load() != 2 {
		t.Fatalf("incomplete %d, dropped %d", h.c.FragIncomplete.Load(), h.c.FragDropped.Load())
	}
	if held, _, _ := h.fragCounters(); held != 2 {
		t.Fatalf("held %d", held)
	}
}

// A first fragment too short to carry ports: dropped with the rest of its
// datagram (held fragments included), not counted as a legacy decision.
func TestFragPortlessFirst(t *testing.T) {
	h := newHarness(t, appRules, Options{})
	quiet(h)
	l := h.record()
	h.own(17, fApp, fDst, 200)
	frs := udpFrags(fApp, fDst, testPayload(3000, 0), 9)
	h.c.HandlePacket(frs[1], addrN(1)) // held
	short := append([]byte(nil), frs[0][:22]...)
	binary.BigEndian.PutUint16(short[2:], 22)
	h.c.HandlePacket(short, addrN(0))
	h.c.HandlePacket(frs[2], addrN(2))
	if out := l.outbound(); len(out) != 0 {
		t.Fatalf("%d fragments left", len(out))
	}
	if h.c.FragDropped.Load() != 3 || h.c.FragIncomplete.Load() != 1 || h.c.FragLegacy.Load() != 0 {
		t.Fatalf("dropped %d, incomplete %d, legacy %d", h.c.FragDropped.Load(), h.c.FragIncomplete.Load(), h.c.FragLegacy.Load())
	}
	if held, b, _ := h.fragCounters(); held != 0 || b != 0 {
		t.Fatalf("held %d, bytes %d", held, b)
	}
}
