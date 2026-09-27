// Package socks5 implements the SOCKS5 client used to reach Hysteria's local
// SOCKS5 inbound (CONNECT + UDP ASSOCIATE, RFC 1928/1929) and a minimal
// server used as a stand-in for Hysteria in tests and in the PoC stub mode.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const (
	ver5 = 5

	methodNone     = 0x00
	methodUserPass = 0x02
	methodNoAccept = 0xff

	CmdConnect      = 0x01
	CmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// Addr is a SOCKS5 destination: either an IP or a domain name, plus port.
type Addr struct {
	IP   netip.Addr
	Host string // used when non-empty (ATYP=DOMAIN)
	Port uint16
}

func AddrFromAddrPort(ap netip.AddrPort) Addr {
	return Addr{IP: ap.Addr().Unmap(), Port: ap.Port()}
}

func (a Addr) String() string {
	h := a.Host
	if h == "" {
		h = a.IP.String()
	}
	return net.JoinHostPort(h, strconv.Itoa(int(a.Port)))
}

// AppendAddr appends ATYP|ADDR|PORT.
func AppendAddr(b []byte, a Addr) ([]byte, error) {
	switch {
	case a.Host != "":
		if len(a.Host) > 255 {
			return nil, errors.New("socks5: hostname too long")
		}
		b = append(b, atypDomain, byte(len(a.Host)))
		b = append(b, a.Host...)
	case a.IP.Unmap().Is4():
		ip := a.IP.Unmap().As4()
		b = append(b, atypIPv4)
		b = append(b, ip[:]...)
	case a.IP.Is6():
		ip := a.IP.As16()
		b = append(b, atypIPv6)
		b = append(b, ip[:]...)
	default:
		return nil, errors.New("socks5: empty address")
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// ParseAddr parses ATYP|ADDR|PORT from b and returns the address and the
// number of bytes consumed.
func ParseAddr(b []byte) (Addr, int, error) {
	if len(b) < 1 {
		return Addr{}, 0, io.ErrUnexpectedEOF
	}
	var a Addr
	n := 1
	switch b[0] {
	case atypIPv4:
		if len(b) < 1+4+2 {
			return a, 0, io.ErrUnexpectedEOF
		}
		a.IP = netip.AddrFrom4([4]byte(b[1:5]))
		n += 4
	case atypIPv6:
		if len(b) < 1+16+2 {
			return a, 0, io.ErrUnexpectedEOF
		}
		a.IP = netip.AddrFrom16([16]byte(b[1:17]))
		n += 16
	case atypDomain:
		if len(b) < 2 || len(b) < 2+int(b[1])+2 {
			return a, 0, io.ErrUnexpectedEOF
		}
		a.Host = string(b[2 : 2+int(b[1])])
		n += 1 + int(b[1])
	default:
		return a, 0, fmt.Errorf("socks5: bad ATYP %d", b[0])
	}
	a.Port = binary.BigEndian.Uint16(b[n:])
	return a, n + 2, nil
}

func readAddr(r io.Reader) (Addr, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:1]); err != nil {
		return Addr{}, err
	}
	var rest int
	switch h[0] {
	case atypIPv4:
		rest = 4 + 2
	case atypIPv6:
		rest = 16 + 2
	case atypDomain:
		if _, err := io.ReadFull(r, h[1:2]); err != nil {
			return Addr{}, err
		}
		rest = int(h[1]) + 2
	default:
		return Addr{}, fmt.Errorf("socks5: bad ATYP %d", h[0])
	}
	buf := make([]byte, 2+rest)
	copy(buf, h[:])
	off := 1
	if h[0] == atypDomain {
		off = 2
	}
	if _, err := io.ReadFull(r, buf[off:off+rest]); err != nil {
		return Addr{}, err
	}
	a, _, err := ParseAddr(buf[:off+rest])
	return a, err
}

// ReplyError is a non-zero REP code from the server.
type ReplyError byte

var replyText = map[ReplyError]string{
	1: "general SOCKS server failure",
	2: "connection not allowed by ruleset",
	3: "network unreachable",
	4: "host unreachable",
	5: "connection refused",
	6: "TTL expired",
	7: "command not supported",
	8: "address type not supported",
}

func (e ReplyError) Error() string {
	if s, ok := replyText[e]; ok {
		return "socks5: " + s
	}
	return fmt.Sprintf("socks5: reply code %d", byte(e))
}

// ErrAuth means the server rejected our credentials or methods.
var ErrAuth = errors.New("socks5: authentication rejected")

// Client dials through a SOCKS5 server.
type Client struct {
	Server   string // host:port
	Username string
	Password string
	// HandshakeTimeout bounds greeting+auth+request (default 10s).
	HandshakeTimeout time.Duration
}

func (c *Client) timeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return 10 * time.Second
}

// Connect opens a TCP connection to dst through the proxy.
func (c *Client) Connect(ctx context.Context, dst Addr) (net.Conn, error) {
	conn, _, err := c.request(ctx, CmdConnect, dst)
	return conn, err
}

func (c *Client) request(ctx context.Context, cmd byte, dst Addr) (net.Conn, Addr, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.Server)
	if err != nil {
		return nil, Addr{}, err
	}
	deadline := time.Now().Add(c.timeout())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	bound, err := c.handshake(conn, cmd, dst)
	stop()
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, Addr{}, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, bound, nil
}

func (c *Client) handshake(conn net.Conn, cmd byte, dst Addr) (Addr, error) {
	methods := []byte{methodNone}
	if c.Username != "" {
		methods = []byte{methodUserPass}
	}
	req := append([]byte{ver5, byte(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		return Addr{}, err
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return Addr{}, err
	}
	if resp[0] != ver5 {
		return Addr{}, fmt.Errorf("socks5: bad version %d", resp[0])
	}
	switch resp[1] {
	case methodNone:
	case methodUserPass:
		if c.Username == "" {
			return Addr{}, ErrAuth
		}
		if len(c.Username) > 255 || len(c.Password) > 255 {
			return Addr{}, errors.New("socks5: credentials too long")
		}
		a := []byte{1, byte(len(c.Username))}
		a = append(a, c.Username...)
		a = append(a, byte(len(c.Password)))
		a = append(a, c.Password...)
		if _, err := conn.Write(a); err != nil {
			return Addr{}, err
		}
		if _, err := io.ReadFull(conn, resp[:]); err != nil {
			return Addr{}, err
		}
		if resp[1] != 0 {
			return Addr{}, ErrAuth
		}
	default:
		return Addr{}, ErrAuth
	}
	r, err := AppendAddr([]byte{ver5, cmd, 0}, dst)
	if err != nil {
		return Addr{}, err
	}
	if _, err := conn.Write(r); err != nil {
		return Addr{}, err
	}
	var h [3]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return Addr{}, err
	}
	if h[0] != ver5 {
		return Addr{}, fmt.Errorf("socks5: bad version %d", h[0])
	}
	bound, err := readAddr(conn)
	if err != nil {
		return Addr{}, err
	}
	if h[1] != 0 {
		return Addr{}, ReplyError(h[1])
	}
	return bound, nil
}

// ReadAddr reads ATYP|ADDR|PORT from r.
func ReadAddr(r io.Reader) (Addr, error) { return readAddr(r) }

// ParseHostPort turns "host:port" into an Addr (an IP when host is one).
func ParseHostPort(s string) (Addr, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return Addr{}, fmt.Errorf("socks5: bad port in %q", s)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return Addr{IP: ip.Unmap(), Port: uint16(p)}, nil
	}
	if host == "" || len(host) > 255 {
		return Addr{}, fmt.Errorf("socks5: bad host in %q", s)
	}
	return Addr{Host: host, Port: uint16(p)}, nil
}
