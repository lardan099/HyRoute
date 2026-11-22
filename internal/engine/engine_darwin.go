//go:build darwin

package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/sysdns"
)

type Config struct {
	// DLLDir is unused on macOS (no driver).
	DLLDir  string
	Options Options
	Tunnels Tunnels
	Log     *slog.Logger
	// OnFail is called once when the engine stops routing after an error.
	OnFail func()
	Groups *groups.Runtime
}

// Engine wires the platform-independent Core to a utun device: the routes
// 0.0.0.0/1 and 128.0.0.0/1 (and ::/1, 8000::/1 when the Mac has IPv6)
// send every connection that has no more specific route (the local
// network has one) into the device, so the engine reads the
// applications' packets. TCP goes through the relay, which listens on the
// device's address and dials the Direct ones from the physical interface
// (IP_BOUND_IF); Direct UDP is sent again from a socket on that interface
// (udpForwarder); tunnel UDP goes the Core's SOCKS5 way. The servers'
// addresses get host routes through the physical gateway, so Hysteria
// and Xray reach them outside the device.
//
// The routes go with the device: should HyRoute die, the kernel destroys
// the device and traffic goes direct again (the kill switch is pf's).
type Engine struct {
	*Core
	cfg Config
	log *slog.Logger

	dev  *tunDevice
	fwd  *udpForwarder
	icmp *icmpForwarder

	netMu sync.Mutex // guards the fields below and the routes
	def4  defaultRoute
	def6  defaultRoute
	// hostRoutes are the server routes in place, by address, with the
	// gateway they go through.
	hostRoutes map[netip.Addr]defaultRoute
	serverIPs  []netip.Addr
	routes6    bool
	// scoped4 and scoped6 are the scoped default routes HyRoute added on
	// the physical interface (see syncScopedLocked).
	scoped4, scoped6 defaultRoute
	dnsCapture       bool
	dnsRoutes        []netip.Addr

	bound4, bound6 atomic.Int32 // physical interface indexes for IP_BOUND_IF

	TUNDropped atomic.Int64 // packets the device gave that cannot go anywhere (not TCP or UDP)

	failed  atomic.Bool
	running atomic.Bool
	stop    chan struct{}
	wg      sync.WaitGroup
}

func New(cfg Config) *Engine {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	cfg.Options.ReflectDirect = true
	if cfg.Options.IPHelperAfter == 0 {
		// No socket events: the kernel's list has the socket by the time
		// its first packet reaches the device.
		cfg.Options.IPHelperAfter = time.Microsecond
	}
	e := &Engine{cfg: cfg, log: cfg.Log, hostRoutes: map[netip.Addr]defaultRoute{}}
	e.Core = NewCore(cfg.Options, cfg.Tunnels, procinfo.NewCache(), e.inject)
	e.Core.Log = cfg.Log
	e.Core.SelfPID = uint32(os.Getpid())
	e.Core.SelfName = SelfName()
	e.Core.OwnerFallback = attrib.LookupOwner
	e.Core.Groups = cfg.Groups
	e.Core.SysDNS = NewSysDNSView(sysdns.Snapshot, cfg.Log)
	e.Core.SystemDNS = func(a netip.Addr) bool {
		info := e.Core.SysDNS.Get()
		return info != nil && info.All[a]
	}
	e.Core.IPv4Route = func() bool {
		e.netMu.Lock()
		defer e.netMu.Unlock()
		return e.def4.Index != 0
	}
	e.fwd = &udpForwarder{listen: e.listenUDP, deliver: e.deliver, log: cfg.Log}
	e.icmp = &icmpForwarder{e: e}
	return e
}

// Open creates the TUN device. The relay listens on ListenIPs before
// Start sends traffic to the device.
func (e *Engine) Open() error {
	if e.dev != nil {
		return nil
	}
	dev, err := openTUN()
	if err != nil {
		return err
	}
	e.dev = dev
	e.log.Info("TUN device", "name", dev.name, "ipv6", dev.v6)
	return nil
}

// ListenIPs are the device's addresses (where the relay listens).
func (e *Engine) ListenIPs() []netip.Addr {
	ips := []netip.Addr{tunAddr4}
	if e.dev != nil && e.dev.v6 {
		ips = append(ips, tunAddr6)
	}
	return ips
}

// ServerIPRoom: host routes have no fixed limit.
func (e *Engine) ServerIPRoom() int { return 4096 }

// DriverVersion names the device ("utun5").
func (e *Engine) DriverVersion() string {
	if e.dev == nil {
		return ""
	}
	return e.dev.name
}

func (e *Engine) Failed() bool { return e.failed.Load() }

// Start routes the traffic into the device and starts the packet loop.
func (e *Engine) Start() error {
	if err := e.Open(); err != nil {
		return err
	}
	if e.Opt.RelayPort == 0 {
		return errors.New("engine: no relay port")
	}
	if pid := mdnsResponderPID(); pid != 0 {
		// The system resolver: its DNS is never routed (the exclusion
		// Windows makes for Dnscache).
		e.DnscachePID.Store(pid)
	}
	e.SysDNS.Refresh()
	e.stop = make(chan struct{})
	e.running.Store(true)
	e.netMu.Lock()
	e.refreshNetLocked()
	e.log.Info("physical network", "v4", e.def4.Name, "gw4", e.def4.Gateway, "v6", e.def6.Name, "gw6", e.def6.Gateway)
	if e.def4.Index == 0 && e.def6.Index == 0 {
		e.log.Warn("no default route: direct connections fail until the network is up")
	}
	err := e.routeAllLocked()
	e.netMu.Unlock()
	if err != nil {
		e.Stop()
		return err
	}
	e.wg.Add(3)
	go e.readLoop()
	go e.maintainLoop()
	go func() { defer e.wg.Done(); e.Procs.Run(e.stop) }()
	return nil
}

// routeAllLocked adds the routes that send the internet into the device,
// after the server routes (already known servers keep reaching Hysteria).
func (e *Engine) routeAllLocked() error {
	e.syncScopedLocked()
	e.syncHostRoutesLocked()
	if e.dnsCapture {
		e.syncDNSRoutesLocked()
	}
	name := e.dev.name
	for _, n := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("/sbin/route", "-q", "-n", "add", "-inet", n, "-interface", name); err != nil {
			return fmt.Errorf("маршрут через %s не добавлен: %w", name, err)
		}
	}
	e.addRoutes6Locked()
	return nil
}

// addRoutes6Locked sends IPv6 into the device when the network has an
// IPv6 default: at the start, or later, once one appears (a network
// change, an RA after the connect). Without the routes IPv6 would leave by
// the physical default, past the rules.
func (e *Engine) addRoutes6Locked() {
	if e.routes6 || !e.dev.v6 || e.def6.Index == 0 {
		return
	}
	nets := []string{"::/1", "8000::/1"}
	for _, n := range nets {
		// Half of the pair may be there from a try that failed.
		run("/sbin/route", "-q", "-n", "delete", "-inet6", n, "-interface", e.dev.name)
	}
	ok := true
	for _, n := range nets {
		if err := run("/sbin/route", "-q", "-n", "add", "-inet6", n, "-interface", e.dev.name); err != nil {
			e.log.Warn("IPv6 route not added; IPv6 goes direct", "err", err)
			ok = false
		}
	}
	e.routes6 = ok
}

// refreshNetLocked reads the physical defaults and binds new direct
// sockets to them. It reports whether they changed.
func (e *Engine) refreshNetLocked() bool {
	v4, v6 := readDefaults(e.dev.index())
	changed := v4 != e.def4 || v6 != e.def6
	e.def4, e.def6 = v4, v6
	e.bound4.Store(int32(v4.Index))
	e.bound6.Store(int32(v6.Index))
	return changed
}

// syncScopedLocked keeps a default route scoped to the physical interface.
// A socket bound to an interface (IP_BOUND_IF) looks its routes up in that
// interface's scope; macOS has a scoped default for every interface but
// the primary one, whose sockets look up the unscoped routes, and those
// lead into the device. Without it the relay's Direct dials and the
// forwarder's UDP fail with "network is unreachable".
func (e *Engine) syncScopedLocked() {
	sync := func(have *defaultRoute, want defaultRoute, v6 bool) {
		if *have == want {
			return
		}
		if have.Index != 0 {
			run("/sbin/route", scopedArgs("delete", *have, v6)...)
		}
		*have = defaultRoute{}
		if want.Index == 0 {
			return
		}
		err := run("/sbin/route", scopedArgs("add", want, v6)...)
		switch {
		case err == nil:
			*have = want // ours: removed with the device
		case strings.Contains(err.Error(), "File exists"):
			// The system's own (a secondary interface): not ours to remove.
		default:
			e.log.Warn("scoped default route not added; direct connections may fail", "err", err)
		}
	}
	sync(&e.scoped4, e.def4, false)
	sync(&e.scoped6, e.def6, true)
}

func scopedArgs(op string, via defaultRoute, v6 bool) []string {
	fam := "-inet"
	if v6 {
		fam = "-inet6"
	}
	args := []string{"-q", "-n", op, fam, "-ifscope", via.Name, "default"}
	switch {
	case via.Gateway.IsValid() && via.Gateway.Is6() && via.Gateway.IsLinkLocalUnicast():
		return append(args, via.Gateway.String()+"%"+via.Name)
	case via.Gateway.IsValid():
		return append(args, via.Gateway.String())
	}
	return append(args, "-interface", via.Name)
}

// SetServerIPs routes the servers' addresses through the physical
// gateway before Hysteria dials them (the tunnels manager calls it first).
func (e *Engine) SetServerIPs(ips []netip.Addr) error {
	ips = slices.Clone(ips)
	for i := range ips {
		ips[i] = ips[i].Unmap().WithZone("")
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	ips = slices.Compact(ips)
	e.netMu.Lock()
	defer e.netMu.Unlock()
	e.serverIPs = ips
	if e.running.Load() && !e.failed.Load() {
		e.syncHostRoutesLocked()
	}
	return nil
}

func (e *Engine) syncHostRoutesLocked() {
	want := map[netip.Addr]bool{}
	for _, ip := range e.serverIPs {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue // the local network has its own route
		}
		want[ip] = true
	}
	for ip, via := range e.hostRoutes {
		d := e.def4
		if ip.Is6() {
			d = e.def6
		}
		if !want[ip] || via != d {
			e.delHostRoute(ip, via)
			delete(e.hostRoutes, ip)
		}
	}
	for ip := range want {
		if _, ok := e.hostRoutes[ip]; ok {
			continue
		}
		d := e.def4
		if ip.Is6() {
			d = e.def6
		}
		if d.Index == 0 {
			continue
		}
		if err := e.addHostRoute(ip, d); err != nil {
			// Its packets reach the device then and go out direct as
			// HyRoute's own (exclusion: hysteria), only slower.
			e.log.Warn("server route not added", "err", err)
			continue
		}
		e.hostRoutes[ip] = d
	}
}

func hostRouteArgs(op string, ip netip.Addr, via defaultRoute) []string {
	fam := "-inet"
	if ip.Is6() {
		fam = "-inet6"
	}
	args := []string{"-q", "-n", op, fam, "-host", ip.String()}
	switch {
	case via.Gateway.IsValid() && via.Gateway.Is6() && via.Gateway.IsLinkLocalUnicast():
		args = append(args, via.Gateway.String()+"%"+via.Name)
	case via.Gateway.IsValid():
		args = append(args, via.Gateway.String())
	default:
		args = append(args, "-interface", via.Name)
	}
	return args
}

func (e *Engine) addHostRoute(ip netip.Addr, via defaultRoute) error {
	run("/sbin/route", hostRouteArgs("delete", ip, via)...) // a stale one from a crash
	return run("/sbin/route", hostRouteArgs("add", ip, via)...)
}

func (e *Engine) delHostRoute(ip netip.Addr, via defaultRoute) {
	if err := run("/sbin/route", hostRouteArgs("delete", ip, via)...); err != nil {
		e.log.Debug("server route not removed", "err", err)
	}
}

// SetDNSCapture sends the system's DNS servers on the local network
// (whose own routes keep them outside the device) into the device while a
// DNS policy is on.
func (e *Engine) SetDNSCapture(on bool) error {
	e.netMu.Lock()
	defer e.netMu.Unlock()
	e.dnsCapture = on
	if e.running.Load() && !e.failed.Load() {
		e.syncDNSRoutesLocked()
	}
	return nil
}

func (e *Engine) syncDNSRoutesLocked() {
	var want []netip.Addr
	if e.dnsCapture {
		if info := e.SysDNS.Get(); info != nil {
			for a := range info.All {
				if a.IsPrivate() || a.IsLinkLocalUnicast() {
					want = append(want, a.WithZone(""))
				}
			}
		}
	}
	slices.SortFunc(want, netip.Addr.Compare)
	if slices.Equal(want, e.dnsRoutes) {
		return
	}
	for _, a := range e.dnsRoutes {
		run("/sbin/route", "-q", "-n", "delete", famFlag(a), "-host", a.String(), "-interface", e.dev.name)
	}
	e.dnsRoutes = nil
	for _, a := range want {
		if a.Is6() && !e.routes6 {
			continue
		}
		if err := run("/sbin/route", "-q", "-n", "add", famFlag(a), "-host", a.String(), "-interface", e.dev.name); err != nil {
			e.log.Warn("DNS server route not added", "err", err)
			continue
		}
		e.dnsRoutes = append(e.dnsRoutes, a)
	}
}

func famFlag(a netip.Addr) string {
	if a.Is6() {
		return "-inet6"
	}
	return "-inet"
}

// bindControl binds a socket to the physical interface: its packets never
// reach the device, whatever the routes say.
func (e *Engine) bindControl(v6 bool) (func(network, address string, c syscall.RawConn) error, error) {
	idx := int(e.bound4.Load())
	if v6 {
		idx = int(e.bound6.Load())
	}
	if idx == 0 {
		return nil, errors.New("нет подключения к сети")
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if v6 {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
			} else {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}, nil
}

// DialDirect is the relay's Direct dial: from the physical interface.
func (e *Engine) DialDirect(ctx context.Context, _ netip.Addr, dst netip.AddrPort) (net.Conn, error) {
	v6 := dst.Addr().Unmap().Is6()
	ctl, err := e.bindControl(v6)
	if err != nil {
		e.log.Debug("direct dial refused", "dst", dst, "err", err)
		return nil, err
	}
	d := net.Dialer{Control: ctl}
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	c, err := d.DialContext(ctx, network, netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()).String())
	if err != nil {
		e.log.Debug("direct dial failed", "dst", dst, "err", err)
	}
	return c, err
}

func (e *Engine) listenUDP(v6 bool) (*net.UDPConn, error) {
	ctl, err := e.bindControl(v6)
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: ctl}
	network, addr := "udp4", "0.0.0.0:0"
	if v6 {
		network, addr = "udp6", "[::]:0"
	}
	c, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}
	return c.(*net.UDPConn), nil
}

var outbound = func() divert.Address {
	var a divert.Address
	a.SetOutbound(true)
	return a
}()

func (e *Engine) readLoop() {
	defer e.wg.Done()
	buf := make([]byte, 4+0xFFFF+40)
	for {
		n, err := e.dev.read(buf)
		if err != nil {
			select {
			case <-e.stop:
			default:
				e.log.Error("TUN device read failed", "err", err)
				e.fail()
			}
			return
		}
		if n <= 4 {
			continue
		}
		pkt := buf[4:n]
		if e.icmp.handle(pkt) {
			continue // pings go direct, never routed
		}
		if isDNSQuery(pkt) {
			e.HandleDNS(pkt, true) // before HandlePacket rewrites it
		}
		addr := outbound
		e.HandlePacket(pkt, &addr)
	}
}

// inject: an inbound packet goes to the applications through the device;
// an outbound one goes to the network direct (UDP only, see
// Options.ReflectDirect).
func (e *Engine) inject(pkt []byte, addr *divert.Address) {
	if !addr.Outbound() {
		e.deliver(pkt)
		return
	}
	p, err := packet.Parse(pkt)
	if err != nil || p.Proto != packet.ProtoUDP {
		e.TUNDropped.Add(1)
		return
	}
	e.fwd.send(&p)
}

// deliver writes a packet into the device. DNS answers feed the cache, as
// the DNS sniff does on Windows.
func (e *Engine) deliver(pkt []byte) {
	if isDNSAnswer(pkt) {
		e.HandleDNS(pkt, false)
	}
	if err := e.dev.write(pkt); err != nil {
		e.log.Debug("TUN write failed", "err", err)
	}
}

// udpPorts reads the ports of an unfragmented UDP packet.
func udpPorts(pkt []byte) (src, dst uint16, ok bool) {
	if len(pkt) < 1 {
		return 0, 0, false
	}
	var l4 int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 || pkt[9] != packet.ProtoUDP || pkt[6]&0x3f != 0 || pkt[7] != 0 {
			return 0, 0, false
		}
		l4 = int(pkt[0]&0xf) * 4
	case 6:
		if len(pkt) < 40 || pkt[6] != packet.ProtoUDP {
			return 0, 0, false
		}
		l4 = 40
	default:
		return 0, 0, false
	}
	if len(pkt) < l4+8 {
		return 0, 0, false
	}
	return uint16(pkt[l4])<<8 | uint16(pkt[l4+1]), uint16(pkt[l4+2])<<8 | uint16(pkt[l4+3]), true
}

func isDNSQuery(pkt []byte) bool {
	_, dst, ok := udpPorts(pkt)
	return ok && dst == 53
}

func isDNSAnswer(pkt []byte) bool {
	src, _, ok := udpPorts(pkt)
	return ok && src == 53
}

func (e *Engine) maintainLoop() {
	defer e.wg.Done()
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-e.stop:
			return
		case now := <-t.C:
			n++
			if n%2 == 0 {
				e.Maintain(now)
			}
			e.fwd.sweep(now)
			e.watchNetwork()
		}
	}
}

// watchNetwork follows the physical network (Wi-Fi to Ethernet, another
// Wi-Fi): new direct sockets bind to the new interface, the server routes
// move to the new gateway, the DNS routes to the new servers.
func (e *Engine) watchNetwork() {
	e.netMu.Lock()
	defer e.netMu.Unlock()
	if e.failed.Load() || !e.running.Load() {
		return
	}
	if e.refreshNetLocked() {
		e.log.Info("network changed", "v4", e.def4.Name, "gw4", e.def4.Gateway, "v6", e.def6.Name)
		e.fwd.reset()
		e.syncScopedLocked()
		e.syncHostRoutesLocked()
		e.addRoutes6Locked() // after the servers' routes, as at the start
		e.SysDNS.Kick()
	}
	if e.dnsCapture {
		e.syncDNSRoutesLocked()
	}
}

// fail stops routing after an error: the reflected connections are
// reset, OnFail runs (the kill switch closes the internet), and the device
// goes, with its routes.
func (e *Engine) fail() {
	if !e.failed.CompareAndSwap(false, true) {
		return
	}
	e.ResetReflected()
	if e.cfg.OnFail != nil {
		e.cfg.OnFail()
	}
	e.teardown()
}

// ResetConnections resets the reflected connections now.
func (e *Engine) ResetConnections() {
	if e.running.Load() && !e.failed.Load() {
		e.ResetReflected()
	}
}

// teardown removes the server and DNS routes and the device (and with it
// the routes into it).
func (e *Engine) teardown() {
	e.netMu.Lock()
	for ip, via := range e.hostRoutes {
		e.delHostRoute(ip, via)
	}
	e.hostRoutes = map[netip.Addr]defaultRoute{}
	e.def4, e.def6 = defaultRoute{}, defaultRoute{}
	e.syncScopedLocked()
	if e.dev != nil {
		for _, a := range e.dnsRoutes {
			run("/sbin/route", "-q", "-n", "delete", famFlag(a), "-host", a.String(), "-interface", e.dev.name)
		}
	}
	e.dnsRoutes = nil
	e.netMu.Unlock()
	e.fwd.close()
	e.icmp.close()
	if e.dev != nil {
		e.dev.close()
	}
}

// Stop resets the reflected connections while the device still carries
// the resets, then removes the device and its routes.
func (e *Engine) Stop() {
	if !e.running.Swap(false) {
		if e.dev != nil && !e.failed.Load() {
			e.dev.close() // opened, never started
		}
		return
	}
	close(e.stop)
	if !e.failed.Load() {
		e.ResetReflected()
		e.teardown()
	}
	e.Core.Close()
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		e.log.Error("engine goroutines still running after Stop")
	}
}

// mdnsResponderPID finds the system resolver.
func mdnsResponderPID() uint32 {
	all, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return 0
	}
	for i := range all {
		if comm := unix.ByteSliceToString(all[i].Proc.P_comm[:]); comm == "mDNSResponder" {
			return uint32(all[i].Proc.P_pid)
		}
	}
	return 0
}

// engineSlot: one engine per process; lockFile: one per machine.
var engineSlot = make(chan struct{}, 1)

const lockFile = "/var/run/hyroute-engine.lock"

// ErrOtherEngine: another HyRoute routes this Mac.
var ErrOtherEngine = errors.New("HyRoute уже подключён в другой копии программы: отключите её и подключитесь снова")

// LockMachine claims the single engine a machine may run.
func LockMachine() (release func(), err error) {
	select {
	case engineSlot <- struct{}{}:
	case <-time.After(15 * time.Second):
		return nil, errors.New("предыдущее подключение ещё не остановлено: подождите несколько секунд и подключитесь снова")
	}
	f, err := os.OpenFile(lockFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		<-engineSlot
		return nil, fmt.Errorf("engine lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		<-engineSlot
		return nil, ErrOtherEngine
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			unix.Flock(int(f.Fd()), unix.LOCK_UN)
			f.Close()
			<-engineSlot
		})
	}, nil
}
