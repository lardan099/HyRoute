package localproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/socks5"
)

// SOCKS5 UDP ASSOCIATE (RFC 1928 §7). Each association gets its own
// association through the tunnel (AssociateUDP) and lives as long as its
// TCP control connection. Datagrams arrive on a socket of its own (a proxy
// on this computer: 127.0.0.1:<port chosen by Windows>) or on one socket
// shared by all associations on the TCP port number (SharedUDP, LAN
// proxies: the firewall rule stays exact). A datagram is taken only from
// the IP of the control connection, and, when the association is
// owner-checked (Owners), only from a socket of the process that owns the
// control connection. Its source address pins the association: the port
// the request named (a preference), else the first datagram's.

// UDPUpstream is one UDP association through the tunnel (the app wraps a
// *socks5.UDPAssoc of the proxy's server).
type UDPUpstream interface {
	WriteTo(payload []byte, dst socks5.Addr) error
	ReadFrom(buf []byte) (n int, from socks5.Addr, err error)
	Close() error // idempotent
}

// UDPDialer opens an association through the tunnel for one client
// association. Errors become the SOCKS5 reply (socks5.ReplyError keeps its
// code, anything else is 1).
type UDPDialer func(ctx context.Context) (UDPUpstream, error)

// OwnerLookup finds the process owning a local socket (Windows: the IP
// helper tables; tests: a fake).
type OwnerLookup interface {
	// TCPOwner: the PID owning the TCP endpoint local connected to remote.
	TCPOwner(local, remote netip.AddrPort) (uint32, bool)
	// UDPOwner: the single process that can own the UDP source local.
	// Every socket that could have sent from local counts: one bound to
	// local's address and one bound to the unspecified address on its
	// port. err == nil: exactly that PID owns every such socket. ErrNoOwner:
	// the table was read and no single owner exists. Any other error: the
	// table could not be read (retry later).
	UDPOwner(local netip.AddrPort) (uint32, error)
}

// ErrNoOwner: UDPOwner read the table and found no single owner.
var ErrNoOwner = errors.New("localproxy: no single owner of the UDP source")

// UDPEvent says what happened to datagrams or associations (OnUDPEvent).
type UDPEvent string

const (
	DropTooLarge      UDPEvent = "too large"                          // over socks5.MaxUDPPayload(dst), or longer than the read buffer
	DropStranger      UDPEvent = "no association"                     // source matches no association and may pin none
	DropOwner         UDPEvent = "other program"                      // owner-checked: the source belongs to another process (or to no single one)
	DropOwnerRead     UDPEvent = "owner lookup failed"                // owner-checked: the UDP table could not be read (retried after ownerRetry)
	DropFragmented    UDPEvent = "fragmented"                         // FRAG != 0
	DropMalformed     UDPEvent = "malformed"                          // short header, bad ATYP
	DropUpstream      UDPEvent = "tunnel"                             // write to the tunnel failed
	DropUnpinned      UDPEvent = "reply before request"               // a reply while the association has no client address
	EventRepin        UDPEvent = "re-pinned to the sender's port"     // not a drop
	EventIdle         UDPEvent = "idle association closed"            // not a drop
	EventReadError    UDPEvent = "read error"                         // unknown socket read error (retried after 50 ms)
	EventOwnerUnknown UDPEvent = "control connection owner not found" // UDP ASSOCIATE refused (REP 1); not a datagram drop
)

const (
	// DefaultMaxUDP caps simultaneous associations when Server.MaxUDP is 0.
	DefaultMaxUDP = 128
	// udpReadBuf (client -> tunnel) holds any UDP datagram whole: an
	// oversize one is read and then dropped by the size check, never a
	// read error that could disturb the loop.
	udpReadBuf  = 64 << 10
	udpReplyBuf = 64 << 10 // tunnel -> client; never smaller than any datagram UDPAssoc may return
	// ownerCacheMax caps the owner answers kept for sources that did not
	// pin; ownerRate is the table walks a port may make per second (and
	// its burst).
	ownerCacheMax = 64
	ownerRate     = 50
)

// Timing (variables for tests).
var (
	associateTimeout = 10 * time.Second       // opening the association through the tunnel
	udpIdle          = 10 * time.Minute       // no datagram either way: the association is closed
	udpRetryEvery    = 30 * time.Second       // SharedUDP: rebinding a port that did not open
	ownerNegTTL      = 5 * time.Second        // a source whose owner was read is not looked up again for this long, as long as the cached answer rejects it
	ownerRetry       = 250 * time.Millisecond // a source whose lookup failed (table not read) is looked up again after this
	readErrPause     = 50 * time.Millisecond  // after an unknown socket read error
)

// localPeer reports whether a control connection's peer is this computer:
// loopback, the address the connection reached (a program using the LAN
// proxy through the PC's own address), or any other address of this PC.
// If the interfaces cannot be listed the peer counts as local: it is then
// owner-checked, which fails closed for another device. Tests replace it.
var localPeer = func(peer, local netip.Addr) bool {
	if peer.IsLoopback() || peer == local {
		return true
	}
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range ifs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap() == peer {
				return true
			}
		}
	}
	return false
}

// udpPort is one UDP socket and the associations it serves: all of a
// SharedUDP server's, or the single one of a per-association socket.
type udpPort struct {
	s      *Server
	pc     *net.UDPConn
	shared bool
	closed atomic.Bool
	read   func(b []byte) (int, netip.AddrPort, error) // pc.ReadFromUDPAddrPort; tests inject errors

	mu      sync.Mutex
	byAddr  map[netip.AddrPort]*assoc    // pinned client source -> association
	waiting map[netip.Addr][]*assoc      // unpinned associations per peer IP, oldest first
	perIP   map[netip.Addr][]*assoc      // every association per peer IP, oldest first
	owner   map[netip.AddrPort]ownerSeen // owner-checked sources looked up but not pinned
	tokens  float64                      // owner lookup budget
	refill  time.Time
}

// ownerSeen caches one UDPOwner answer for a source that did not pin. It
// can only make a datagram be dropped, never accepted.
type ownerSeen struct {
	pid    uint32    // valid when !failed; 0 = ErrNoOwner (matches no association)
	failed bool      // the table could not be read
	at     time.Time // valid for ownerNegTTL (found) or ownerRetry (failed)
}

// ownerAns is the owner of a source as one lookup call knows it.
type ownerAns struct {
	pid    uint32 // 0: no single owner
	failed bool   // the table could not be read
	cached bool   // from p.owner: may only drop
}

type assoc struct {
	seq     uint64     // age (FIFO order)
	ctrl    net.Conn   // the TCP control connection (tracked in s.conn)
	peer    netip.Addr // its remote IP, unmapped
	checked bool       // owner-checked; fixed at ASSOCIATE
	ctrlPID uint32     // checked: owner of the control connection's client end; else 0
	up      UDPUpstream
	port    *udpPort
	last    atomic.Int64 // unix nanos of the last datagram either way (idle timeout)

	// under port.mu:
	pin     netip.AddrPort // client source; zero until pinned
	named   bool           // pin came from the request's DST.PORT (a preference)
	fifo    bool           // pin came from a first datagram
	heard   bool           // a datagram from pin has arrived (and, if checked, passed the owner check)
	ownerOK bool           // checked: the owner of pin was verified to be ctrlPID
	amb     bool           // pinned (or waiting) while another of the same group waited: may be swapped
}

// UDPError is why the shared UDP socket is not open (nil when it is, or
// when the server has none).
func (s *Server) UDPError() error {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	return s.udpErr
}

// UDP reports whether UDP ASSOCIATE is served now.
func (s *Server) UDP() bool {
	if s.AssociateUDP == nil {
		return false
	}
	if !s.SharedUDP {
		return true
	}
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	return s.shared != nil
}

func (s *Server) maxUDP() int {
	if s.MaxUDP > 0 {
		return s.MaxUDP
	}
	return DefaultMaxUDP
}

func udpNetwork(host netip.Addr) string {
	if host.Unmap().Is4() {
		return "udp4"
	}
	return "udp"
}

// tcpHostPort is the address the TCP listener is bound to.
func (s *Server) tcpHostPort() netip.AddrPort {
	if a, ok := s.ln.Addr().(*net.TCPAddr); ok {
		ap := a.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	ap, _ := netip.ParseAddrPort(s.ln.Addr().String())
	return ap
}

// startUDP opens the shared socket (Listen, after the TCP listener). A
// failure does not fail Listen: TCP is served, and the bind is retried.
func (s *Server) startUDP() {
	if s.AssociateUDP == nil || !s.SharedUDP {
		return
	}
	hp := s.tcpHostPort()
	pc, err := listenUDP(udpNetwork(hp.Addr()), hp.String())
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	if err != nil {
		s.udpErr = err
		s.wg.Add(1)
		go s.retryUDP(hp)
		return
	}
	s.shared = s.newPort(pc, true)
	s.wg.Add(1)
	go s.shared.serve()
}

// retryUDP binds the shared socket again every udpRetryEvery until it
// opens or the server closes.
func (s *Server) retryUDP(hp netip.AddrPort) {
	defer s.wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-time.After(udpRetryEvery):
		}
		pc, err := listenUDP(udpNetwork(hp.Addr()), hp.String())
		if err != nil {
			continue
		}
		s.udpMu.Lock()
		if s.ctx.Err() != nil { // Close ran
			s.udpMu.Unlock()
			pc.Close()
			return
		}
		s.shared, s.udpErr = s.newPort(pc, true), nil
		s.wg.Add(1)
		go s.shared.serve()
		s.udpMu.Unlock()
		if s.OnUDPPort != nil {
			s.OnUDPPort(nil)
		}
		return
	}
}

// closeUDP closes the shared socket (Close, after the context is
// cancelled). Per-association sockets close with their associations.
func (s *Server) closeUDP() {
	s.udpMu.Lock()
	p := s.shared
	s.shared = nil
	s.udpMu.Unlock()
	if p != nil {
		p.close()
	}
}

func (s *Server) newPort(pc *net.UDPConn, shared bool) *udpPort {
	return &udpPort{
		s: s, pc: pc, shared: shared, read: pc.ReadFromUDPAddrPort,
		byAddr: map[netip.AddrPort]*assoc{}, waiting: map[netip.Addr][]*assoc{}, perIP: map[netip.Addr][]*assoc{},
		owner: map[netip.AddrPort]ownerSeen{}, tokens: ownerRate, refill: time.Now(),
	}
}

// close sets closed before closing the socket, so the read loop never
// takes the error for one to retry.
func (p *udpPort) close() {
	p.closed.Store(true)
	p.pc.Close()
}

func (p *udpPort) portNum() uint16 {
	if a, ok := p.pc.LocalAddr().(*net.UDPAddr); ok {
		return uint16(a.Port)
	}
	return 0
}

// reserveUDP takes a slot for a new association before anything is opened
// for it, so that parallel requests cannot pass the limit together.
func (s *Server) reserveUDP() bool {
	s.udpMu.Lock()
	if s.nassoc < s.maxUDP() {
		s.nassoc++
		s.udpMu.Unlock()
		return true
	}
	s.udpMu.Unlock()
	if ok, n, _ := s.udpRep.note("limit", 0); ok && s.OnUDPLimit != nil {
		s.OnUDPLimit(n)
	}
	return false
}

func (s *Server) releaseUDP() {
	s.udpMu.Lock()
	s.nassoc--
	s.udpMu.Unlock()
}

// udpDrop counts a dropped datagram and reports it (rate-limited).
func (s *Server) udpDrop(ev UDPEvent, size int) {
	s.UDPDropped.Add(1)
	s.udpEvent(ev, size)
}

// udpEvent reports an event (rate-limited per kind).
func (s *Server) udpEvent(ev UDPEvent, size int) {
	if ok, n, ex := s.udpRep.note(string(ev), size); ok && s.OnUDPEvent != nil {
		s.OnUDPEvent(ev, n, ex)
	}
}

// udpPortErr reports a socket that did not open (rate-limited).
func (s *Server) udpPortErr(err error) {
	if ok, _, _ := s.udpRep.note("port", 0); ok && s.OnUDPPort != nil {
		s.OnUDPPort(err)
	}
}

var assocSeq atomic.Uint64

func unmapAP(a net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	switch v := a.(type) {
	case *net.TCPAddr:
		ap = v.AddrPort()
	case *net.UDPAddr:
		ap = v.AddrPort()
	default:
		ap, _ = netip.ParseAddrPort(a.String())
	}
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}

// associate serves UDP ASSOCIATE on the (authenticated) control connection
// c; req is the client's address from the request (often zero).
func (s *Server) associate(c net.Conn, req socks5.Addr) {
	if s.AssociateUDP == nil {
		socksReply(c, 7)
		return
	}
	var shared *udpPort
	if s.SharedUDP {
		s.udpMu.Lock()
		shared = s.shared
		s.udpMu.Unlock()
		if shared == nil {
			socksReply(c, 1)
			return
		}
	}
	remote, local := unmapAP(c.RemoteAddr()), unmapAP(c.LocalAddr())
	peer := remote.Addr()
	checked := s.Owners != nil && (!s.SharedUDP || localPeer(peer, local.Addr()))
	var pid uint32
	if checked {
		var ok bool
		// The client's end: its address is local there, ours remote.
		if pid, ok = s.Owners.TCPOwner(remote, local); !ok || pid == 0 {
			s.udpEvent(EventOwnerUnknown, 0)
			socksReply(c, 1)
			return
		}
	}
	if !s.reserveUDP() {
		socksReply(c, 1)
		return
	}
	p := shared
	if p == nil {
		h := s.tcpHostPort().Addr()
		pc, err := listenUDP(udpNetwork(h), netip.AddrPortFrom(h, 0).String())
		if err != nil {
			s.releaseUDP()
			s.udpPortErr(err)
			socksReply(c, 1)
			return
		}
		p = s.newPort(pc, false)
	}
	ctx, cancel := context.WithTimeout(s.ctx, associateTimeout)
	up, err := s.AssociateUDP(ctx)
	cancel()
	if err != nil {
		if !p.shared {
			p.close()
		}
		s.releaseUDP()
		if s.OnError != nil {
			s.OnError("udp", err)
		}
		socksReply(c, replyCode(err))
		return
	}
	a := &assoc{seq: assocSeq.Add(1), ctrl: c, peer: peer, checked: checked, ctrlPID: pid, up: up, port: p}
	a.last.Store(time.Now().UnixNano())
	if req.Host == "" && req.Port != 0 {
		// Only the peer's IP is accepted: a named IP is ignored (a client
		// behind NAT does not know its outside address).
		a.pin, a.named = netip.AddrPortFrom(peer, req.Port), true
	}
	if !s.addAssoc(a) {
		up.Close()
		if !p.shared {
			p.close()
		}
		s.releaseUDP()
		return
	}
	defer s.removeAssoc(a)

	bnd := socks5.Addr{IP: local.Addr(), Port: p.portNum()}
	if err := socksReplyAddr(c, 0, bnd); err != nil {
		return
	}
	if !p.shared {
		s.wg.Add(1)
		go p.serve()
	}
	s.wg.Add(1)
	go s.udpReplies(a)

	// The association lives as long as the control connection; a client
	// sends nothing more on it (RFC 1928), so whatever comes is discarded.
	var b [512]byte
	for {
		c.SetReadDeadline(time.Unix(0, a.last.Load()).Add(udpIdle))
		_, err := c.Read(b[:])
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			if time.Since(time.Unix(0, a.last.Load())) < udpIdle {
				continue // traffic since the deadline was set
			}
			s.udpEvent(EventIdle, 0)
		}
		return // EOF, reset, Close's sweep, the tunnel side ended, or idle
	}
}

// socksReplyAddr answers a request with a bound address.
func socksReplyAddr(c net.Conn, code byte, bnd socks5.Addr) error {
	b, err := socks5.AppendAddr([]byte{5, code, 0}, bnd)
	if err != nil {
		return err
	}
	_, err = c.Write(b)
	return err
}

// addAssoc registers a with its port; false once the server is closing.
func (s *Server) addAssoc(a *assoc) bool {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return false
	}
	p := a.port
	var evict *assoc
	p.mu.Lock()
	if a.named {
		if old := p.byAddr[a.pin]; old != nil {
			if old.peer == a.peer && old.ctrlPID == a.ctrlPID {
				// The same client associating again: the new one wins.
				delete(p.byAddr, a.pin)
				old.pin, old.named, old.fifo, old.heard, old.ownerOK = netip.AddrPort{}, false, false, false, false
				evict = old
			} else {
				// Another process's pin is never taken over: wait.
				a.pin, a.named = netip.AddrPort{}, false
			}
		}
	}
	if a.pin.IsValid() {
		p.byAddr[a.pin] = a
	} else {
		p.waiting[a.peer] = append(p.waiting[a.peer], a)
	}
	p.perIP[a.peer] = append(p.perIP[a.peer], a)
	p.mu.Unlock()
	if evict != nil {
		evict.ctrl.Close()
	}
	s.UDPActive.Add(1)
	s.UDPTotal.Add(1)
	return true
}

// removeAssoc ends a (the handler's cleanup): the other ambiguous
// first-datagram pins of its group go back to waiting, so a swap never
// outlives the association that caused it.
func (s *Server) removeAssoc(a *assoc) {
	p := a.port
	p.mu.Lock()
	if a.pin.IsValid() && p.byAddr[a.pin] == a {
		delete(p.byAddr, a.pin)
	}
	p.dropFrom(p.waiting, a)
	p.dropFrom(p.perIP, a)
	if a.amb {
		n := 0
		for _, b := range p.perIP[a.peer] {
			if b.ctrlPID != a.ctrlPID || !b.amb {
				continue
			}
			if b.fifo {
				if p.byAddr[b.pin] == b {
					delete(p.byAddr, b.pin)
				}
				b.pin, b.fifo, b.heard, b.ownerOK = netip.AddrPort{}, false, false, false
				p.insertWaiting(b)
			}
			n++
		}
		if n <= 1 {
			for _, b := range p.perIP[a.peer] {
				if b.ctrlPID == a.ctrlPID {
					b.amb = false
				}
			}
		}
	}
	p.mu.Unlock()
	a.up.Close()
	if !p.shared {
		p.close()
	}
	s.releaseUDP()
	s.UDPActive.Add(-1)
}

// dropFrom removes a from its peer's list in m (p.mu held).
func (p *udpPort) dropFrom(m map[netip.Addr][]*assoc, a *assoc) {
	l := m[a.peer]
	if i := slices.Index(l, a); i >= 0 {
		l = slices.Delete(l, i, i+1)
	}
	if len(l) == 0 {
		delete(m, a.peer)
	} else {
		m[a.peer] = l
	}
}

// insertWaiting puts a back among its peer's waiting associations in age
// order (p.mu held).
func (p *udpPort) insertWaiting(a *assoc) {
	l := p.waiting[a.peer]
	i, _ := slices.BinarySearchFunc(l, a.seq, func(b *assoc, seq uint64) int {
		switch {
		case b.seq < seq:
			return -1
		case b.seq > seq:
			return 1
		}
		return 0
	})
	p.waiting[a.peer] = slices.Insert(l, i, a)
}

// lookup finds the association of a datagram from src (p.mu held). ans is
// src's owner as this call knows it (nil: unknown). need: the owner is
// needed for a decision. A cached answer decides only drops: whatever it
// would admit needs a fresh one, and nothing changes on it.
func (p *udpPort) lookup(src netip.AddrPort, ans *ownerAns) (a *assoc, why UDPEvent, need bool) {
	dry := ans != nil && ans.cached
	if a := p.byAddr[src]; a != nil {
		if !a.checked || a.ownerOK {
			a.heard = true
			return a, "", false
		}
		// A checked association's tentative named pin.
		switch {
		case ans == nil:
			return nil, "", true
		case ans.failed:
			return nil, DropOwnerRead, false
		case ans.pid == a.ctrlPID:
			if dry {
				return nil, "", true
			}
			a.ownerOK, a.heard = true, true
			return a, "", false
		case dry:
			return nil, DropOwner, false
		}
		// The name was wrong: the pin goes back to waiting, and src is
		// judged within its own process.
		delete(p.byAddr, src)
		a.pin, a.named = netip.AddrPort{}, false
		p.insertWaiting(a)
	}
	list := p.perIP[src.Addr()]
	if len(list) == 0 {
		return nil, DropStranger, false
	}
	var pid uint32
	if list[0].checked {
		switch {
		case ans == nil:
			return nil, "", true
		case ans.failed:
			return nil, DropOwnerRead, false
		case ans.pid == 0:
			return nil, DropOwner, false
		}
		pid = ans.pid
	}
	var g, w []*assoc
	for _, b := range list {
		if b.ctrlPID == pid {
			g = append(g, b)
		}
	}
	if len(g) == 0 {
		return nil, DropOwner, false
	}
	for _, b := range p.waiting[src.Addr()] {
		if b.ctrlPID == pid {
			w = append(w, b)
		}
	}
	if len(w) > 0 {
		if dry {
			return nil, "", true
		}
		a := w[0]
		if len(w) > 1 {
			for _, b := range w {
				b.amb = true
			}
		}
		p.dropFrom(p.waiting, a)
		a.pin, a.fifo, a.heard, a.ownerOK = src, true, true, a.checked
		p.byAddr[src] = a
		return a, "", false
	}
	if a := g[0]; len(g) == 1 && a.named && !a.heard {
		// The named port was a preference: the client sends from another.
		if dry {
			return nil, "", true
		}
		if p.byAddr[a.pin] == a {
			delete(p.byAddr, a.pin)
		}
		a.pin, a.named, a.heard, a.ownerOK = src, false, true, a.checked
		p.byAddr[src] = a
		return a, EventRepin, false
	}
	return nil, DropStranger, false
}

// pinFor is lookup with the owner round trip: the table walk runs with
// p.mu released, and the decision is taken again afterwards. Only the
// port's serve goroutine calls it.
func (p *udpPort) pinFor(src netip.AddrPort) (*assoc, UDPEvent) {
	p.mu.Lock()
	a, why, need := p.lookup(src, nil)
	if need {
		now := time.Now()
		if c, ok := p.owner[src]; ok && (c.failed && now.Sub(c.at) < ownerRetry || !c.failed && now.Sub(c.at) < ownerNegTTL) {
			a, why, need = p.lookup(src, &ownerAns{pid: c.pid, failed: c.failed, cached: true})
		}
	}
	if need {
		if !p.takeToken() {
			p.mu.Unlock()
			return nil, DropOwnerRead
		}
		p.mu.Unlock()
		pid, err := p.s.Owners.UDPOwner(src)
		ans := &ownerAns{pid: pid, failed: err != nil && !errors.Is(err, ErrNoOwner)}
		if err != nil {
			ans.pid = 0
		}
		p.mu.Lock()
		a, why, _ = p.lookup(src, ans)
		if a != nil {
			delete(p.owner, src)
		} else {
			p.cacheOwner(src, ownerSeen{pid: ans.pid, failed: ans.failed, at: time.Now()})
		}
	}
	p.mu.Unlock()
	if why == EventRepin {
		p.s.udpEvent(EventRepin, 0)
		why = ""
	}
	return a, why
}

// takeToken spends one owner lookup of the port's budget (p.mu held).
func (p *udpPort) takeToken() bool {
	now := time.Now()
	p.tokens = min(ownerRate, p.tokens+now.Sub(p.refill).Seconds()*ownerRate)
	p.refill = now
	if p.tokens < 1 {
		return false
	}
	p.tokens--
	return true
}

// cacheOwner keeps an answer that dropped a datagram (p.mu held).
func (p *udpPort) cacheOwner(src netip.AddrPort, e ownerSeen) {
	if _, ok := p.owner[src]; !ok && len(p.owner) >= ownerCacheMax {
		var oldest netip.AddrPort
		var at time.Time
		for k, v := range p.owner {
			if at.IsZero() || v.at.Before(at) {
				oldest, at = k, v.at
			}
		}
		delete(p.owner, oldest)
	}
	p.owner[src] = e
}

// pinOf is where replies of a go: its pin, once a datagram came from it.
func (p *udpPort) pinOf(a *assoc) (netip.AddrPort, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return a.pin, a.pin.IsValid() && a.heard
}

// serve relays the port's datagrams (client -> tunnel). A datagram is
// checked whole before it may pin an association, so a fragment or junk
// never takes one.
func (p *udpPort) serve() {
	defer p.s.wg.Done()
	s := p.s
	buf := make([]byte, udpReadBuf)
	for {
		n, src, err := p.read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || p.closed.Load() {
				return
			}
			switch tooLarge, transient := classifyReadErr(err); {
			case tooLarge:
				s.udpDrop(DropTooLarge, n) // defensive: buf holds any UDP datagram
				continue
			case transient:
				continue // about one earlier send: next read at once
			}
			s.udpEvent(EventReadError, 0)
			time.Sleep(readErrPause)
			continue
		}
		if n == len(buf) { // defensive: possibly truncated
			s.udpDrop(DropTooLarge, n)
			continue
		}
		dst, payload, err := socks5.ParseUDPHeader(buf[:n])
		switch {
		case errors.Is(err, socks5.ErrFragmented):
			s.udpDrop(DropFragmented, n)
			continue
		case err != nil:
			s.udpDrop(DropMalformed, n)
			continue
		}
		// The fast path holds only for IP destinations: a long domain name
		// allows less than UDPPayloadAlways.
		if (len(payload) > socks5.UDPPayloadAlways || dst.Host != "") && len(payload) > socks5.MaxUDPPayload(dst) {
			s.udpDrop(DropTooLarge, n)
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		a, why := p.pinFor(src)
		if a == nil {
			s.udpDrop(why, n)
			continue
		}
		a.last.Store(time.Now().UnixNano())
		if err := a.up.WriteTo(payload, dst); err != nil {
			s.udpDrop(DropUpstream, n)
			continue
		}
		s.Sent.Add(int64(len(payload)))
	}
}

// udpReplies relays the tunnel's datagrams to the client. When the tunnel
// side ends (Hysteria restarted, server stopped), the control connection
// is closed, so the client learns that its association is gone.
func (s *Server) udpReplies(a *assoc) {
	defer s.wg.Done()
	buf := make([]byte, udpReplyBuf)
	for {
		n, from, err := a.up.ReadFrom(buf)
		if err != nil {
			a.ctrl.Close()
			return
		}
		to, ok := a.port.pinOf(a)
		if !ok {
			s.udpDrop(DropUnpinned, n)
			continue
		}
		pkt, err := socks5.AppendUDPHeader(make([]byte, 0, 262+n), from)
		if err != nil {
			continue
		}
		pkt = append(pkt, buf[:n]...)
		a.last.Store(time.Now().UnixNano())
		if _, err := a.port.pc.WriteToUDPAddrPort(pkt, to); err == nil {
			s.Recv.Add(int64(n))
		}
	}
}

// reporter rate-limits the UDP callbacks: per key at most once per
// limitReport, with the count since the last report and one example size.
type reporter struct {
	mu   sync.Mutex
	keys map[string]*repState
}

type repState struct {
	pending int64
	size    int
	at      time.Time
}

func (r *reporter) note(key string, size int) (report bool, count int64, example int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys == nil {
		r.keys = map[string]*repState{}
	}
	k := r.keys[key]
	if k == nil {
		k = &repState{}
		r.keys[key] = k
	}
	k.pending++
	if k.size == 0 {
		k.size = size
	}
	if !k.at.IsZero() && time.Since(k.at) < limitReport {
		return false, 0, 0
	}
	count, example = k.pending, k.size
	k.pending, k.size, k.at = 0, 0, time.Now()
	return true, count, example
}

// UDPState describes how the server serves UDP (logs).
func (s *Server) UDPState() string {
	switch {
	case s.AssociateUDP == nil:
		return "off"
	case s.SharedUDP && !s.UDP():
		return "retrying"
	case s.SharedUDP && s.Owners != nil:
		return "shared, owner-checked locally"
	case s.SharedUDP:
		return "shared"
	case s.Owners != nil:
		return "owner-checked"
	}
	return "per-association"
}
