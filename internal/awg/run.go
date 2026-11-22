package awg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"

	"github.com/lardan099/hyroute/internal/localproxy"
	"github.com/lardan099/hyroute/internal/socks5"
)

// RunConfig is what the child reads: the device's configuration and the
// SOCKS5 server it opens. HyRoute writes it to a file only HyRoute can
// read (hysteria.Supervisor) and removes it once the server answers.
type RunConfig struct {
	UAPI    string   `json:"uapi"`
	Address []string `json:"address"`
	DNS     []string `json:"dns,omitempty"`
	MTU     int      `json:"mtu,omitempty"`
	Listen  string   `json:"listen"`
	User    string   `json:"user"`
	Pass    string   `json:"pass"`
}

// Run is the child's configuration for a server at endpoint, served as
// SOCKS5 on listen with user and pass.
func (s *Settings) Run(endpoint netip.AddrPort, listen, user, pass string) ([]byte, error) {
	uapi, err := s.UAPI(endpoint)
	if err != nil {
		return nil, err
	}
	addrs, _ := s.Addrs()
	dns, _ := s.DNSServers()
	rc := RunConfig{UAPI: uapi, MTU: s.MTU, Listen: listen, User: user, Pass: pass}
	for _, a := range addrs {
		rc.Address = append(rc.Address, a.String())
	}
	for _, a := range dns {
		rc.DNS = append(rc.DNS, a.String())
	}
	return json.Marshal(rc)
}

// Log writes the child's log lines as Hysteria's JSON log does
// (hysteria.ParseLogLine reads both): {"level":…,"time":ms,"msg":…}.
type Log struct {
	mu sync.Mutex
	w  io.Writer
}

func NewLog(w io.Writer) *Log { return &Log{w: w} }

func (l *Log) line(level, msg string, kv ...string) {
	m := map[string]any{"level": level, "time": time.Now().UnixMilli(), "msg": msg}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	b, _ := json.Marshal(m)
	l.mu.Lock()
	l.w.Write(append(b, '\n'))
	l.mu.Unlock()
}

func (l *Log) Info(msg string, kv ...string)  { l.line("info", msg, kv...) }
func (l *Log) Warn(msg string, kv ...string)  { l.line("warn", msg, kv...) }
func (l *Log) Fatal(msg string, kv ...string) { l.line("fatal", msg, kv...) }

// Fatal kinds: the supervisor tells a profile's error (wait long) from a
// busy local port (retry at once).
const (
	KindConfig = "config"
	KindPort   = "port"
)

// StartError is a failed start and its kind.
type StartError struct {
	Kind string
	Err  error
}

func (e *StartError) Error() string { return e.Err.Error() }

// Event values of the log lines the supervisor acts on.
const (
	EventListening = "listening"
	EventHandshake = "handshake"
	EventSilent    = "no-handshake"
	EventDNS       = "dns"
)

// silentAfter: without a handshake this long the server does not answer
// (WireGuard retries every 5 s).
var silentAfter = 12 * time.Second

// Client is one running AmneziaWG client behind a SOCKS5 server.
type Client struct {
	dev  *device.Device
	tnet *netstack.Net
	srv  *localproxy.Server
	v4   netip.Addr // the tunnel's own addresses (UDP sockets bind them)
	v6   netip.Addr
	log  *Log
	dns  []string // for the warning about them
	stop chan struct{}
	once sync.Once
	wg   sync.WaitGroup

	dnsMu     sync.Mutex
	dnsWarned time.Time
}

// Start brings the device up and opens the SOCKS5 server.
func Start(cfg RunConfig, log *Log) (*Client, error) {
	var addrs, dns []netip.Addr
	c := &Client{log: log, stop: make(chan struct{})}
	for _, s := range cfg.Address {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, &StartError{KindConfig, fmt.Errorf("адрес в туннеле %q", s)}
		}
		addrs = append(addrs, a)
		if a.Is4() && !c.v4.IsValid() {
			c.v4 = a
		} else if a.Is6() && !c.v6.IsValid() {
			c.v6 = a
		}
	}
	for _, s := range cfg.DNS {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, &StartError{KindConfig, fmt.Errorf("DNS %q", s)}
		}
		dns = append(dns, a)
	}
	if len(addrs) == 0 {
		return nil, &StartError{KindConfig, errors.New("нет адреса в туннеле (Address)")}
	}
	if len(dns) == 0 {
		dns = DefaultDNS
	}
	for _, a := range dns {
		c.dns = append(c.dns, a.String())
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	tdev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, &StartError{KindConfig, fmt.Errorf("сетевой стек: %w", err)}
	}
	c.tnet = tnet
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(format string, args ...any) { log.Warn(fmt.Sprintf(format, args...)) },
	}
	c.dev = device.NewDevice(tdev, conn.NewStdNetBind(), logger)
	if err := c.dev.IpcSet(cfg.UAPI); err != nil {
		c.dev.Close()
		return nil, &StartError{KindConfig, fmt.Errorf("AmneziaWG не принял параметры: %w", err)}
	}
	if err := c.dev.Up(); err != nil {
		c.dev.Close()
		return nil, &StartError{"", fmt.Errorf("AmneziaWG не запустился: %w", err)}
	}
	c.srv = &localproxy.Server{
		Username:     cfg.User,
		Password:     cfg.Pass,
		Dial:         c.dial,
		AssociateUDP: c.associate,
		OnError:      c.dialFailed,
	}
	if err := c.srv.Listen(cfg.Listen); err != nil {
		c.dev.Close()
		return nil, &StartError{KindPort, fmt.Errorf("локальный порт SOCKS5: %w", err)}
	}
	log.Info("SOCKS5 открыт", "event", EventListening, "addr", c.srv.Addr())
	c.wg.Add(1)
	go c.watchHandshake()
	return c, nil
}

// Addr is the SOCKS5 server's address.
func (c *Client) Addr() string { return c.srv.Addr() }

// Close stops the SOCKS5 server and the device.
func (c *Client) Close() {
	c.once.Do(func() {
		close(c.stop)
		c.srv.Close()
		c.dev.Close()
	})
	c.wg.Wait()
}

// watchHandshake reports the first handshake, and a server that has not
// answered one for silentAfter.
func (c *Client) watchHandshake() {
	defer c.wg.Done()
	start := time.Now()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	silent := false
	for {
		select {
		case <-c.stop:
			return
		case <-t.C:
		}
		if c.handshake() {
			c.log.Info("Рукопожатие с сервером AmneziaWG прошло", "event", EventHandshake)
			return
		}
		if !silent && time.Since(start) >= silentAfter {
			silent = true
			c.log.Warn(fmt.Sprintf("Сервер не ответил на рукопожатие за %d с", int(silentAfter/time.Second)), "event", EventSilent)
		}
	}
}

// handshake: the peer has completed a handshake.
func (c *Client) handshake() bool {
	st, err := c.dev.IpcGet()
	if err != nil {
		return false
	}
	for _, l := range strings.Split(st, "\n") {
		if v, ok := strings.CutPrefix(l, "last_handshake_time_sec="); ok {
			if n, _ := strconv.ParseInt(v, 10, 64); n > 0 {
				return true
			}
		}
	}
	return false
}

// DNSWarning starts the warning that the tunnel's DNS does not answer.
const DNSWarning = "DNS через туннель не отвечает"

// dialFailed reports DNS through the tunnel that fails, at most once a
// minute. Failed connections are the user's traffic: the line names no
// destination.
func (c *Client) dialFailed(_ string, err error) {
	var de *net.DNSError
	if !errors.As(err, &de) || de.IsNotFound {
		return
	}
	c.dnsMu.Lock()
	defer c.dnsMu.Unlock()
	if time.Since(c.dnsWarned) < time.Minute {
		return
	}
	c.dnsWarned = time.Now()
	c.log.Warn(DNSWarning+" ("+strings.Join(c.dns, ", ")+")", "event", EventDNS)
}

func (c *Client) dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	if dst.Host != "" {
		return c.tnet.DialContext(ctx, "tcp", dst.String())
	}
	tc, err := c.tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(dst.IP.Unmap(), dst.Port))
	if err != nil {
		return nil, err
	}
	return tc, nil
}

// udpPacket is one datagram from the tunnel.
type udpPacket struct {
	b    []byte
	from netip.AddrPort
}

// udpAssoc is one SOCKS5 association: a socket of the network stack per
// address family, opened on first use.
type udpAssoc struct {
	c     *Client
	mu    sync.Mutex
	socks [2]net.PacketConn // IPv4, IPv6
	names map[string]netip.Addr
	in    chan udpPacket
	done  chan struct{}
	once  sync.Once
}

func (c *Client) associate(ctx context.Context) (localproxy.UDPUpstream, error) {
	return &udpAssoc{c: c, names: map[string]netip.Addr{}, in: make(chan udpPacket, 64), done: make(chan struct{})}, nil
}

func (a *udpAssoc) WriteTo(payload []byte, dst socks5.Addr) error {
	ip := dst.IP.Unmap()
	if dst.Host != "" {
		var err error
		if ip, err = a.resolve(dst.Host); err != nil {
			return err
		}
	}
	pc, err := a.sock(ip.Is6())
	if err != nil {
		return err
	}
	_, err = pc.WriteTo(payload, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, dst.Port)))
	return err
}

func (a *udpAssoc) ReadFrom(buf []byte) (int, socks5.Addr, error) {
	select {
	case p := <-a.in:
		return copy(buf, p.b), socks5.AddrFromAddrPort(p.from), nil
	case <-a.done:
		return 0, socks5.Addr{}, net.ErrClosed
	}
}

func (a *udpAssoc) Close() error {
	a.once.Do(func() {
		close(a.done)
		a.mu.Lock()
		for _, pc := range a.socks {
			if pc != nil {
				pc.Close()
			}
		}
		a.mu.Unlock()
	})
	return nil
}

// resolve asks the tunnel's DNS once per name and association.
func (a *udpAssoc) resolve(host string) (netip.Addr, error) {
	a.mu.Lock()
	ip, ok := a.names[host]
	a.mu.Unlock()
	if ok {
		return ip, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	list, err := a.c.tnet.LookupContextHost(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, s := range list {
		cand, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if cand.Is4() && a.c.v4.IsValid() || cand.Is6() && a.c.v6.IsValid() {
			a.mu.Lock()
			a.names[host] = cand.Unmap()
			a.mu.Unlock()
			return cand.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s: нет адреса, доступного через туннель", host)
}

func (a *udpAssoc) sock(v6 bool) (net.PacketConn, error) {
	i, local := 0, a.c.v4
	if v6 {
		i, local = 1, a.c.v6
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case <-a.done:
		return nil, net.ErrClosed
	default:
	}
	if a.socks[i] != nil {
		return a.socks[i], nil
	}
	if !local.IsValid() {
		return nil, errors.New("у туннеля нет адреса этого семейства (IPv4 или IPv6)")
	}
	pc, err := a.c.tnet.ListenUDPAddrPort(netip.AddrPortFrom(local, 0))
	if err != nil {
		return nil, err
	}
	a.socks[i] = pc
	go a.read(pc)
	return pc, nil
}

func (a *udpAssoc) read(pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			a.Close()
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := ua.AddrPort()
		p := udpPacket{b: append([]byte(nil), buf[:n]...), from: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
		select {
		case a.in <- p:
		case <-a.done:
			return
		default:
			// The client reads slower than the tunnel delivers: drop, as
			// a full socket buffer would.
		}
	}
}

// Main is the child process: HyRoute starts itself with
// "--awg <config>" for one server and reads the log lines on stdout. It
// returns the exit code.
func Main(cfgPath string) int {
	log := NewLog(os.Stdout)
	b, err := os.ReadFile(cfgPath)
	var cfg RunConfig
	if err == nil {
		err = json.Unmarshal(b, &cfg)
	}
	if err != nil {
		log.Fatal("Не удалось прочитать конфиг AmneziaWG: "+err.Error(), "kind", KindConfig)
		return 2
	}
	c, err := Start(cfg, log)
	if err != nil {
		kind := ""
		var se *StartError
		if errors.As(err, &se) {
			kind = se.Kind
		}
		log.Fatal(err.Error(), "kind", kind)
		return 2
	}
	defer c.Close()
	waitParent()
	return 0
}

// waitParent returns when HyRoute is gone. On Windows HyRoute's job
// object ends the child with it; elsewhere a child whose parent died is
// adopted by init or launchd.
func waitParent() {
	if runtime.GOOS == "windows" {
		select {}
	}
	parent := os.Getppid()
	for os.Getppid() == parent {
		time.Sleep(2 * time.Second)
	}
}
