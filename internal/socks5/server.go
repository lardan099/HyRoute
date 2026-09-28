package socks5

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

var netipV4zero = netip.IPv4Unspecified()

// Server is a small SOCKS5 server that connects directly. It stands in for
// Hysteria in tests and in the PoC "--socks-stub" mode; it is not meant to
// be exposed beyond loopback.
type Server struct {
	Username, Password string
	// Dial overrides the outbound dialer (tests).
	Dial func(network, addr string) (net.Conn, error)
	// OnConnect is called for every CONNECT request (logging, tests).
	OnConnect func(dst Addr)

	ln     net.Listener
	wg     sync.WaitGroup
	mu     sync.Mutex
	conn   map[net.Conn]struct{}
	closed bool // Close has run: a connection accepted later is dropped
}

// Listen starts serving on addr (e.g. "127.0.0.1:0").
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.conn = make(map[net.Conn]struct{})
	s.wg.Add(1)
	go s.serve()
	return nil
}

func (s *Server) Addr() string { return s.ln.Addr().String() }

func (s *Server) Close() error {
	err := s.ln.Close()
	s.mu.Lock()
	s.closed = true
	for c := range s.conn {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		// A connection Accept returned while Close ran would miss Close's
		// sweep and keep Close waiting for its handler forever.
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			c.Close()
			return
		}
		s.conn[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			defer c.Close()
			s.handle(c)
		}()
	}
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conn, c)
}

func (s *Server) handle(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != ver5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	want := byte(methodNone)
	if s.Username != "" {
		want = methodUserPass
	}
	ok := false
	for _, m := range methods {
		ok = ok || m == want
	}
	if !ok {
		c.Write([]byte{ver5, methodNoAccept})
		return
	}
	c.Write([]byte{ver5, want})
	if want == methodUserPass {
		if !s.auth(c) {
			return
		}
	}
	var r [3]byte
	if _, err := io.ReadFull(c, r[:]); err != nil {
		return
	}
	dst, err := readAddr(c)
	if err != nil {
		return
	}
	switch r[1] {
	case CmdConnect:
		s.connect(c, dst)
	case CmdUDPAssociate:
		s.associate(c)
	default:
		reply(c, 7, Addr{})
	}
}

func (s *Server) auth(c net.Conn) bool {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return false
	}
	u := make([]byte, h[1])
	if _, err := io.ReadFull(c, u); err != nil {
		return false
	}
	if _, err := io.ReadFull(c, h[:1]); err != nil {
		return false
	}
	p := make([]byte, h[0])
	if _, err := io.ReadFull(c, p); err != nil {
		return false
	}
	if string(u) != s.Username || string(p) != s.Password {
		c.Write([]byte{1, 1})
		return false
	}
	c.Write([]byte{1, 0})
	return true
}

func reply(c net.Conn, code byte, bound Addr) {
	if !bound.IP.IsValid() && bound.Host == "" {
		bound.IP = netipV4zero
	}
	b, _ := AppendAddr([]byte{ver5, code, 0}, bound)
	c.Write(b)
}

func (s *Server) connect(c net.Conn, dst Addr) {
	if s.OnConnect != nil {
		s.OnConnect(dst)
	}
	dial := s.Dial
	if dial == nil {
		dial = func(n, a string) (net.Conn, error) { return net.DialTimeout(n, a, 10*time.Second) }
	}
	up, err := dial("tcp", dst.String())
	if err != nil {
		reply(c, 5, Addr{})
		return
	}
	defer up.Close()
	reply(c, 0, AddrFromAddrPort(up.LocalAddr().(*net.TCPAddr).AddrPort()))
	_ = c.SetDeadline(time.Time{})
	Pipe(c, up)
}

// associate relays UDP datagrams for one client until the control
// connection closes.
func (s *Server) associate(c net.Conn) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: c.LocalAddr().(*net.TCPAddr).IP})
	if err != nil {
		reply(c, 1, Addr{})
		return
	}
	defer pc.Close()
	reply(c, 0, AddrFromAddrPort(pc.LocalAddr().(*net.UDPAddr).AddrPort()))
	_ = c.SetDeadline(time.Time{})
	go func() {
		io.Copy(io.Discard, c)
		pc.Close()
	}()
	var client *net.UDPAddr
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if client == nil || (from.IP.Equal(client.IP) && from.Port == client.Port) {
			client = from
			dst, payload, err := ParseUDPHeader(buf[:n])
			if err != nil {
				continue
			}
			ua, err := net.ResolveUDPAddr("udp", dst.String())
			if err != nil {
				continue
			}
			pc.WriteToUDP(payload, ua)
			continue
		}
		// Reply from a remote: wrap and send to the client.
		hdr, _ := AppendAddr([]byte{0, 0, 0}, AddrFromAddrPort(from.AddrPort()))
		pc.WriteToUDP(append(hdr, buf[:n]...), client)
	}
}

// Pipe copies both directions with half-close and returns when both
// directions are done. It returns bytes a->b and b->a. An error in either
// direction (as opposed to EOF) resets both (see Abort): a broken stream
// must not reach the other peer as a clean end of stream, where a
// truncated download would look complete.
func Pipe(a, b net.Conn) (ab, ba int64) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		ba, err = io.Copy(a, b)
		finish(a, b, err)
	}()
	var err error
	ab, err = io.Copy(b, a)
	finish(b, a, err)
	wg.Wait()
	return ab, ba
}

func finish(dst, src net.Conn, err error) {
	if err != nil {
		Abort(dst)
		Abort(src)
		return
	}
	closeWrite(dst)
}

// Abort closes c with RST instead of FIN (SO_LINGER 0): the peer sees the
// connection reset, and nothing queued is sent afterwards. Wrappers are
// looked through with a NetConn method, as for crypto/tls.Conn.
func Abort(c net.Conn) {
	for inner := c; inner != nil; {
		if l, ok := inner.(interface{ SetLinger(int) error }); ok {
			_ = l.SetLinger(0)
			break
		}
		u, ok := inner.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		inner = u.NetConn()
	}
	c.Close()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
