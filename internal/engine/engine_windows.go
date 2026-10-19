//go:build windows

package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/attrib"
	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/sysdns"
)

type Config struct {
	// DLLDir holds WinDivert.dll and WinDivert64.sys.
	DLLDir  string
	Options Options
	Tunnels Tunnels
	Log     *slog.Logger
	// OnFail is called once when the engine removes its filters after an
	// error (the kill switch closes the internet then).
	OnFail func()
	// groups
	// Groups resolves server group targets (Core.Groups).
	Groups *groups.Runtime
}

// Engine wires the platform-independent Core to the WinDivert handles:
//
//	H1 main NETWORK (inline)   -> Core.HandlePacket
//	H2 DNS sniff               -> Core.HandleDNS
//	H3 SOCKET sniff            -> Core.HandleSocketEvent
//	H4 FLOW sniff              -> Core.HandleFlowEvent
type Engine struct {
	*Core
	cfg Config
	log *slog.Logger

	driver        *divert.DriverInfo
	driverVersion string

	mainMu sync.Mutex // serializes hot swaps
	// swapMu pauses injection while a hot swap opens a main handle below
	// the receiving one (see reopenMain); inject holds it shared.
	swapMu    sync.RWMutex
	sendMu    sync.RWMutex
	send      *divert.Handle          // handle used for injection
	mains     map[*divert.Handle]bool // every open main handle; true = retired (no longer receives)
	mainPrio  int16                   // level of the receiving main handle
	serverIPs []netip.Addr            // excluded by the receiving main handle (see serverExclusions)
	// dns: dnsCapture: the main filter also captures DNS to private
	// destinations (FilterOptions.DNS); guarded by mainMu.
	dnsCapture bool

	sniffs []*divert.Handle // H2..H4

	loopMu sync.Mutex
	loops  map[*loopState]struct{} // running packet loops, for the watchdog

	failed  atomic.Bool
	stop    chan struct{}
	wg      sync.WaitGroup
	running atomic.Bool
}

const (
	batchSize = 64
	// maxPacket is WINDIVERT_MTU_MAX: an IPv6 header and a 64 KiB payload.
	maxPacket     = 40 + 0xFFFF
	watchdogTick  = 500 * time.Millisecond
	watchdogLimit = 2 * time.Second
	// maxStacks bounds the goroutine dump the watchdog logs.
	maxStacks = 64 << 10
	// stopWait bounds how long Stop waits for the engine's goroutines.
	stopWait = 5 * time.Second
	// maxServerIPs: the main filter's limit (see divert.MaxServerIPs).
	maxServerIPs = divert.MaxServerIPs
)

// machineLock names the object that marks a running engine. Wails' single
// instance lock is per Windows session, so HyRoute can run in two sessions
// at once (fast user switching, RDP). Two engines would open their main
// handles on the same levels and divert each other's traffic by their own
// rules, the other one's Hysteria included. A variable for tests.
var machineLock = `Global\HyRoute-engine-3f9b2c71`

// ErrOtherEngine: HyRoute is connected in another Windows session.
var ErrOtherEngine = errors.New("HyRoute уже подключён в другом сеансе Windows (другой пользователь или удалённый рабочий стол). Две копии перехватывали бы трафик друг друга: отключите HyRoute там и подключитесь снова")

// ErrStillStopping: this HyRoute's previous connection is still stopping.
var ErrStillStopping = errors.New("предыдущее подключение ещё не остановлено: подождите несколько секунд и подключитесь снова")

// engineSlot is the lock's in-process half. The named object cannot tell
// this process from another one, and a Connect may come while the previous
// session is still stopping (Disconnect forgets the session before it
// stops it; the tray and the window at once): that Connect waits for the
// Stop instead of blaming another Windows session.
var engineSlot = make(chan struct{}, 1)

// slotWait bounds that wait: a Stop takes up to stopWait for the engine,
// then stops the Hysteria processes. A variable for tests.
var slotWait = 15 * time.Second

// LockMachine claims the single engine a machine may run and returns the
// function that gives it back. Within the process a second claim waits
// for the first to be given back.
func LockMachine() (release func(), err error) {
	t := time.NewTimer(slotWait)
	defer t.Stop()
	select {
	case engineSlot <- struct{}{}:
	case <-t.C:
		return nil, ErrStillStopping
	}
	unlock, err := lockGlobal()
	if err != nil {
		<-engineSlot
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			unlock()
			<-engineSlot
		})
	}, nil
}

// lockSDDL secures the machine-wide object: owned by Administrators, which
// only an elevated process can set, and open to them and SYSTEM only.
const lockSDDL = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)"

// lockOwner reports whether sid, the owner of an existing object of that
// name, makes it another HyRoute's. Any process can create an object in
// Global\ (mutexes need no privilege), so a program without elevation
// could otherwise keep every Connect failing with ErrOtherEngine; it can
// not make Administrators or SYSTEM the owner. A variable for tests, which
// run without elevation.
var lockOwner = func(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid)
}

// lockGlobal creates the machine-wide object. Only its existence matters:
// it lives while a handle to it is open, so a crashed process gives it
// back too. An object of that name that no elevated process created, or
// one that is no mutex, is ignored: the engine runs without the
// machine-wide lock then.
func lockGlobal() (release func(), err error) {
	name, err := windows.UTF16PtrFromString(machineLock)
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString(lockSDDL)
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateMutex(sa, false, name)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		// Not elevated (tests): Administrators cannot be the owner.
		h, err = windows.CreateMutex(nil, false, name)
	}
	switch {
	case err == nil:
		return func() { windows.CloseHandle(h) }, nil
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		defer windows.CloseHandle(h)
		if engineLock(h) {
			return nil, ErrOtherEngine
		}
		return func() {}, nil
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		// An object we may not open fully, or no right to create global
		// objects (not elevated, WinDivert fails anyway); in the latter
		// case there is none to find. Another HyRoute's lock lets
		// Administrators read its owner, so one we cannot read is not.
		o, oerr := windows.OpenMutex(windows.READ_CONTROL, false, name)
		if oerr != nil {
			return func() {}, nil
		}
		defer windows.CloseHandle(o)
		if engineLock(o) {
			return nil, ErrOtherEngine
		}
		return func() {}, nil
	case errors.Is(err, windows.ERROR_INVALID_HANDLE):
		// An object of another type (event, semaphore, ...) has the name:
		// HyRoute creates only mutexes, so another program's.
		return func() {}, nil
	}
	return nil, fmt.Errorf("engine lock: %w", err)
}

// engineLock reports whether the existing object h is another HyRoute's
// lock (see lockOwner). An owner that cannot be read counts as one.
func engineLock(h windows.Handle) bool {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return true
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return true
	}
	return lockOwner(owner)
}

func New(cfg Config) *Engine {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	e := &Engine{cfg: cfg, log: cfg.Log, mains: make(map[*divert.Handle]bool), loops: make(map[*loopState]struct{})}
	e.Core = NewCore(cfg.Options, cfg.Tunnels, procinfo.NewCache(), e.inject)
	e.Core.Log = cfg.Log
	e.Core.SelfPID = uint32(os.Getpid())
	e.Core.SystemDNS = (&systemDNS{}).Has
	e.Core.IPv4Route = (&ipv4Route{}).Has
	e.Core.OwnerFallback = func(proto uint8, local, remote netip.AddrPort) (uint32, bool) {
		if proto == packet.ProtoTCP {
			return attrib.LookupTCPOwner(local, remote)
		}
		if pid, ok := attrib.LookupUDPOwner(local); ok || !local.Addr().Unmap().Is4() {
			return pid, ok
		}
		// A dual-stack socket ([::]:port) is only in the IPv6 table; the
		// strict lookup reads both and refuses to guess between owners.
		pid, err := attrib.LookupUDPOwnerStrict(local)
		return pid, err == nil
	}
	e.Core.TCPTable = attrib.ReadTCPTable
	e.Core.Groups = cfg.Groups
	e.Core.SysDNS = NewSysDNSView(sysdns.Snapshot, cfg.Log) // dns
	return e
}

// ServerIPRoom is how many more server IPs the exclusion filter can take
// (a group check's temporary Hysteria adds its servers to the union).
func (e *Engine) ServerIPRoom() int {
	e.mainMu.Lock()
	defer e.mainMu.Unlock()
	return maxServerIPs - len(e.serverIPs)
}

// DriverVersion is the loaded WinDivert driver version ("2.2").
func (e *Engine) DriverVersion() string { return e.driverVersion }

// Failed reports that the engine tore its filters down (fail-open).
func (e *Engine) Failed() bool { return e.failed.Load() }

// fail marks the engine failed and removes the filters (fail-open unless
// the kill switch is on) until Stop. The reflected connections are reset
// first, as on Stop: nothing reflects the relay's resets afterwards, so
// the applications would keep them open and send their segments direct.
// That happens while the kill switch still lets them through (its block
// could drop the resets). OnFail comes next, so with the kill switch the
// block is in place before diverting stops. Only the first call does all
// this: a second one (another loop failing at the same time) must not
// remove the filters while the first still resets or closes the kill
// switch.
func (e *Engine) fail() {
	if !e.failed.CompareAndSwap(false, true) {
		return
	}
	e.resetReflected()
	if e.cfg.OnFail != nil {
		e.cfg.OnFail()
	}
	e.closeMains()
}

// resetWait bounds how long resetting the reflected connections may hold
// up removing the filters. A variable for tests.
var resetWait = 500 * time.Millisecond

// resetReflected is Core.ResetReflected that never hangs its caller: a
// packet loop the watchdog gave up on may hold a lock the resets need (the
// NAT table's, or swapMu in a send that does not return). A hang there
// would keep the filters, and with them the black hole, in place; after
// resetWait the filters go without the remaining resets. The resets still
// running go nowhere once the main handles are closed.
func (e *Engine) resetReflected() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.ResetReflected()
	}()
	t := time.NewTimer(resetWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		e.log.Error("resetting reflected connections is stuck (a packet loop holds the engine's locks); removing filters without it", "waited", resetWait)
	}
}

// openError converts a WinDivertOpen failure into a user-facing error.
func (e *Engine) openError(err error) error {
	var oe *divert.OpenError
	if errors.As(err, &oe) {
		return fmt.Errorf("%s [код %d, слой %d]", divert.Explain(oe.Code, e.driver), oe.Code, oe.Layer)
	}
	return err
}

// openRetry is how long Start waits before it opens the first handle again
// when the driver is unloading. A variable for tests.
var openRetry = 2 * time.Second

// openFirst opens the first handle, which loads the driver. When another
// program that used WinDivert has just stopped, its driver may still be
// unloading (the service is marked for deletion): one more try a moment
// later loads it again.
func (e *Engine) openFirst(open func() (*divert.Handle, error)) (*divert.Handle, error) {
	h, err := open()
	var oe *divert.OpenError
	if errors.As(err, &oe) && oe.Unloading() {
		e.log.Info("WinDivert driver is unloading; opening again", "after", openRetry)
		time.Sleep(openRetry)
		h, err = open()
	}
	return h, err
}

// Start loads WinDivert and opens the handles.
func (e *Engine) Start() error {
	if err := divert.Load(e.cfg.DLLDir); err != nil {
		return err
	}
	sys := filepath.Join(e.cfg.DLLDir, "WinDivert64.sys")
	if d, err := divert.InspectDriver(sys); err == nil && d.Exists && !d.Ours && !d.Running {
		// A stopped service pointing elsewhere (an older HyRoute folder,
		// an uninstalled program) would load that .sys file, which may sit
		// in a user-writable folder. Remove the entry: WinDivert.dll then
		// installs the service for our verified copy. Programs that need
		// their own entry recreate it the same way when they start.
		if err := divert.DeleteStaleService(); err != nil {
			e.log.Warn("WinDivert service not replaced", "image", d.ImagePath, "err", err)
		} else {
			e.log.Info("WinDivert service pointed to another driver file; replaced by the verified copy", "old", d.ImagePath, "new", sys)
		}
	}
	if d, err := divert.InspectDriver(sys); err == nil {
		e.driver = d
		if d.Exists && !d.Ours {
			e.log.Warn("WinDivert driver service belongs to another program; its driver will be used",
				"image", d.ImagePath, "running", d.Running)
		}
		if len(d.Legacy) > 0 {
			e.log.Warn("WinDivert 1.x drivers are running; their order relative to HyRoute is undefined", "services", d.Legacy)
		}
	}
	if pid, err := procinfo.ServicePID("Dnscache"); err == nil && pid != 0 {
		e.DnscachePID.Store(pid)
	}

	sock, err := e.openFirst(func() (*divert.Handle, error) {
		return divert.Open(divert.SocketFilter, divert.LayerSocket, PrioSocket, divert.FlagSniff|divert.FlagRecvOnly)
	})
	if err != nil {
		return e.openError(err)
	}
	major, _ := sock.GetParam(divert.ParamVersionMajor)
	minor, _ := sock.GetParam(divert.ParamVersionMinor)
	if err := divert.CheckVersion(major, minor, e.driver); err != nil {
		sock.Close()
		return err
	}
	e.driverVersion = fmt.Sprintf("%d.%d", major, minor)
	e.log.Info("WinDivert driver", "version", e.driverVersion)
	e.stop = make(chan struct{})
	e.running.Store(true)
	e.sniffs = append(e.sniffs, sock)
	e.wg.Add(1)
	go e.eventLoop(sock, e.HandleSocketEvent)

	flow, err := divert.Open(divert.FlowFilter, divert.LayerFlow, PrioFlow, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.Stop()
		return e.openError(err)
	}
	e.sniffs = append(e.sniffs, flow)
	e.wg.Add(1)
	go e.eventLoop(flow, e.HandleFlowEvent)

	dns, err := divert.Open(divert.DNSFilter, divert.LayerNetwork, PrioDNS, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		e.Stop()
		return e.openError(err)
	}
	e.sniffs = append(e.sniffs, dns)
	e.wg.Add(1)
	go e.dnsLoop(dns)

	e.mainMu.Lock()
	err = e.reopenMain(e.serverIPs)
	e.mainMu.Unlock()
	if err != nil {
		e.Stop()
		return err
	}
	e.wg.Add(3)
	go e.maintainLoop()
	go e.watchdog()
	go func() { defer e.wg.Done(); e.Procs.Run(e.stop) }()
	return nil
}

// SetServerIPs updates the Hysteria server exclusion. While running it
// hot-swaps the main handle without dropping connections (NAT state lives
// in the engine, not in the handle). The list counts as applied only once
// a handle excluding it is open, so after a failed swap the next call with
// the same list tries again.
func (e *Engine) SetServerIPs(ips []netip.Addr) error {
	ips = serverExclusions(ips)
	if e.running.Load() && e.failed.Load() {
		// Not even mainMu: a swap stuck behind a send that never returns
		// may hold it, and Stop and the reconnect must not wait for it.
		return nil
	}
	e.mainMu.Lock()
	defer e.mainMu.Unlock()
	if !e.running.Load() {
		e.serverIPs = ips // the first main handle excludes them
		return nil
	}
	if e.failed.Load() || slices.Equal(e.serverIPs, ips) {
		// After a failure the filters stay removed until Stop: the status
		// says traffic goes direct, and no watchdog would watch a new loop.
		return nil
	}
	err := e.reopenMain(ips)
	if err != nil && e.failed.Load() {
		return nil // failed meanwhile: there is no filter to update
	}
	return err
}

// serverExclusions prepares server IPs for the main filter: sorted, without
// duplicates, without zones (the filter language has none, "fe80::1%12" is
// a bad token) and without addresses a fixed exclusion range covers.
func serverExclusions(ips []netip.Addr) []netip.Addr {
	fixed := slices.Concat(divert.ExcludedV4, divert.ExcludedV6)
	out := make([]netip.Addr, 0, len(ips))
next:
	for _, ip := range ips {
		ip = ip.Unmap().WithZone("")
		if !ip.IsValid() {
			continue
		}
		for _, p := range fixed {
			if p.Contains(ip) {
				continue next
			}
		}
		out = append(out, ip)
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

func (e *Engine) filter(serverIPs []netip.Addr) string {
	return divert.MainFilter(divert.FilterOptions{
		RelayPort: e.cfg.Options.RelayPort,
		ServerIPs: serverIPs,
		TCPOnly:   e.cfg.Options.TCPOnly,
		DNS:       e.dnsCapture, // dns
	})
}

// reopenMain opens a new main handle excluding serverIPs at the other
// priority level and retires every older one at once: retired handles stop
// receiving (their loops drain what is queued) and close a few seconds
// later. Only the newest handle receives, and injection goes through it,
// so no packet is diverted twice. Several swaps in a row (every profile
// reports its server IPs as it starts) must not leave an older handle
// receiving with an outdated exclusion list: it would divert Hysteria's
// own packets to a server added later.
//
// A packet a handle injects is seen by the handles below it. Every other
// swap opens the new handle below the receiving one, which keeps injecting
// until the switch: the new handle would divert those packets and drop the
// reflected ones as stray relay traffic. So injection pauses from before
// such a handle opens until it takes over.
//
// The caller holds mainMu.
func (e *Engine) reopenMain(serverIPs []netip.Addr) error {
	if len(serverIPs) > maxServerIPs {
		return fmt.Errorf("у работающих профилей слишком много адресов серверов (%d, фильтр WinDivert вмещает %d): уменьшите число профилей, которые работают одновременно", len(serverIPs), maxServerIPs)
	}
	if !e.running.Load() || e.failed.Load() {
		return errors.New("engine stopped")
	}
	prio := int16(PrioMain)
	if e.mainPrio == PrioMain {
		prio = PrioMainAlt
	}
	paused := e.mainPrio != 0 && prio < e.mainPrio
	if paused && !lockWithin(&e.swapMu, swapWait) {
		// A send that does not return holds swapMu (the watchdog fails
		// the engine); waiting for ever would keep mainMu with it.
		return errors.New("главный фильтр не заменён: отправка пакета не завершается")
	}
	resume := func() {
		if paused {
			paused = false
			e.swapMu.Unlock()
		}
	}
	defer resume()
	h, err := divert.Open(e.filter(serverIPs), divert.LayerNetwork, prio, 0)
	if err != nil {
		return e.openError(err)
	}
	h.SetParam(divert.ParamQueueLength, 8192)
	h.SetParam(divert.ParamQueueTime, 2000)
	h.SetParam(divert.ParamQueueSize, 8<<20)

	e.sendMu.Lock()
	if !e.running.Load() || e.failed.Load() {
		// Stop or fail closed every main handle; this one must not divert
		// again.
		e.sendMu.Unlock()
		h.Close()
		return errors.New("engine stopped")
	}
	// Older handles stop queueing new packets before injection moves to
	// the new one; their loops drain the queue and exit on ERROR_NO_DATA.
	var retire []*divert.Handle
	for m, retired := range e.mains {
		if !retired {
			m.Shutdown(divert.ShutdownRecv)
			e.mains[m] = true
			retire = append(retire, m)
		}
	}
	e.mains[h] = false
	e.send = h
	e.mainPrio = prio
	e.serverIPs = serverIPs
	e.sendMu.Unlock()
	resume()

	e.wg.Add(1)
	go e.packetLoop(h)

	for _, old := range retire {
		go func() {
			time.Sleep(3 * time.Second) // > QUEUE_TIME, queue is empty by now
			e.sendMu.Lock()
			_, open := e.mains[old]
			delete(e.mains, old)
			e.sendMu.Unlock()
			if open { // closeMains may have closed it already
				old.Close()
			}
		}()
	}
	e.log.Info("main filter active", "priority", prio, "serverIPs", serverIPs)
	return nil
}

// swapWait bounds how long a swap waits for the sends on their way.
const swapWait = 3 * time.Second

// lockWithin takes mu for writing, waiting at most d. A Lock that comes
// late (the send returned after all) is released at once.
func lockWithin(mu *sync.RWMutex, d time.Duration) bool {
	got := make(chan struct{})
	go func() { mu.Lock(); close(got) }()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-got:
		return true
	case <-t.C:
		go func() { <-got; mu.Unlock() }()
		return false
	}
}

// inject holds swapMu through the send: a hot swap that pauses injection
// waits for the packets already on their way. sendMu is not held through
// it, so fail-open never waits for a send.
func (e *Engine) inject(pkt []byte, addr *divert.Address) {
	e.swapMu.RLock()
	defer e.swapMu.RUnlock()
	e.sendMu.RLock()
	h := e.send
	e.sendMu.RUnlock()
	if h == nil {
		return
	}
	if err := h.Send(pkt, addr); err != nil {
		e.log.Debug("inject failed", "err", err)
	}
}

// ResetConnections resets the reflected connections now, while the
// filters reflect the resets (see Stop, which resets the ones since).
func (e *Engine) ResetConnections() {
	if e.running.Load() && !e.failed.Load() {
		e.resetReflected()
	}
}

// Stop removes all filters. Closing the main handles first makes the
// system fail open immediately. It does not wait long for a packet loop
// stuck in HandlePacket (what the watchdog catches): that loop may never
// return, and Disconnect, and the next Connect waiting for the machine
// lock, must not hang on it.
func (e *Engine) Stop() {
	if !e.running.Swap(false) {
		return
	}
	close(e.stop)
	// Applications must not keep reflected connections open past the
	// filters: they would later send them direct (Core.ResetReflected).
	e.resetReflected()
	e.closeMains()
	for _, h := range e.sniffs {
		h.Shutdown(divert.ShutdownBoth)
		h.Close()
	}
	e.Core.Close()
	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(stopWait):
		e.log.Error("engine goroutines still running after Stop (a packet loop is stuck); filters are removed", "waited", stopWait)
	}
}

func (e *Engine) isMain(h *divert.Handle) bool {
	e.sendMu.RLock()
	defer e.sendMu.RUnlock()
	_, ok := e.mains[h]
	return ok
}

// closeMains closes every main handle: the kernel stops diverting at once,
// so traffic flows directly (fail-open).
func (e *Engine) closeMains() {
	e.sendMu.Lock()
	hs := e.mains
	e.mains = make(map[*divert.Handle]bool)
	e.send = nil
	e.sendMu.Unlock()
	for h := range hs {
		h.Shutdown(divert.ShutdownBoth)
		h.Close()
	}
}

func (e *Engine) eventLoop(h *divert.Handle, handle func(divert.Event, divert.SocketData)) {
	defer e.wg.Done()
	var addr divert.Address
	for {
		if _, err := h.Recv(nil, &addr); err != nil {
			if e.running.Load() {
				e.log.Error("event layer recv failed", "err", err)
			}
			return
		}
		handle(addr.Event(), addr.Socket())
	}
}

func (e *Engine) dnsLoop(h *divert.Handle) {
	defer e.wg.Done()
	buf := make([]byte, maxPacket)
	var addr divert.Address
	for {
		n, err := h.Recv(buf, &addr)
		if err != nil {
			if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
				continue // one oversized packet (dequeued truncated) must not end sniffing
			}
			if e.running.Load() {
				e.log.Error("DNS sniff recv failed", "err", err)
			}
			return
		}
		e.HandleDNS(buf[:n], addr.Outbound())
	}
}

func (e *Engine) packetLoop(h *divert.Handle) {
	defer e.wg.Done()
	l := &loopState{}
	e.loopMu.Lock()
	e.loops[l] = struct{}{}
	e.loopMu.Unlock()
	defer func() {
		e.loopMu.Lock()
		delete(e.loops, l)
		e.loopMu.Unlock()
	}()
	defer func() {
		if r := recover(); r != nil {
			e.log.Error("packet loop panic: removing filters (fail-open)", "panic", r)
			e.fail()
		}
	}()
	buf := make([]byte, batchSize*65535)
	addrs := make([]divert.Address, batchSize)
	for {
		n, na, err := h.RecvEx(buf, addrs)
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_DATA) || !e.running.Load() || !e.isMain(h) {
				return // shut down and drained, or retired by a hot swap
			}
			if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
				continue
			}
			e.log.Error("main recv failed: removing filters (fail-open)", "err", err)
			e.fail()
			return
		}
		l.begin()
		pkts := divert.SplitBatch(buf[:n])
		for i := 0; i < len(pkts) && i < na; i++ {
			e.HandlePacket(pkts[i], &addrs[i])
		}
		l.end()
	}
}

// loopState is a packet loop's progress as the watchdog sees it. Each loop
// has its own: after a hot swap the retired loop drains its queue while
// the new one runs, and one loop finishing batches must not hide a hang of
// the other.
type loopState struct {
	// progress is twice the batches begun, plus one while a batch is being
	// processed. Only the loop writes it.
	progress atomic.Uint64

	// Watchdog only.
	seen  uint64
	ticks int
	since time.Time
}

func (l *loopState) begin() { l.progress.Add(3) }          // idle 2n -> busy 2(n+1)+1
func (l *loopState) end()   { l.progress.Add(^uint64(0)) } // busy 2n+1 -> idle 2n

// stuck runs on every watchdog tick. The loop is stuck once the same batch
// was in progress on watchdogLimit/watchdogTick ticks in a row. Counting
// ticks instead of comparing clock readings keeps a jump of the wall clock
// or a sleep of the PC in the middle of a batch from looking like a hang:
// the batch still has to stay unfinished over the following ticks.
func (l *loopState) stuck() bool {
	p := l.progress.Load()
	if p&1 == 0 || p != l.seen {
		l.seen, l.ticks, l.since = p, 0, time.Now()
		return false
	}
	l.ticks++
	return l.ticks >= int(watchdogLimit/watchdogTick)
}

// stuckLoop ticks every packet loop and returns one that is stuck, or nil.
func (e *Engine) stuckLoop() *loopState {
	e.loopMu.Lock()
	defer e.loopMu.Unlock()
	var stuck *loopState
	for l := range e.loops {
		if l.stuck() && stuck == nil {
			stuck = l
		}
	}
	return stuck
}

func (e *Engine) maintainLoop() {
	defer e.wg.Done()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case now := <-t.C:
			e.Maintain(now)
		}
	}
}

// watchdog closes the main handles if packet processing hangs: WinDivert
// drops packets that sit in the queue longer than QUEUE_TIME, so a stuck
// loop would black-hole all traffic. Closing the handles fails open; the
// engine stays failed until Stop (SetServerIPs does not divert again), and
// the controller restarts routing with a new engine (OnFail).
func (e *Engine) watchdog() {
	defer e.wg.Done()
	t := time.NewTicker(watchdogTick)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			l := e.stuckLoop()
			if l == nil {
				continue
			}
			e.log.Error("packet loop stuck: removing filters (fail-open)", "stuckFor", time.Since(l.since).Round(time.Millisecond))
			// Where the loop hangs, taken before fail: closing the handles
			// may release it.
			e.log.Error("packet loop stuck: goroutines", "stacks", allStacks())
			e.fail()
			return
		}
	}
}

// allStacks dumps every goroutine, cut at maxStacks.
func allStacks() string {
	buf := make([]byte, maxStacks)
	n := runtime.Stack(buf, true)
	if n == len(buf) {
		return string(buf) + "\n… (cut)"
	}
	return string(buf[:n])
}

// SetDNSCapture switches capturing DNS to private destinations on or off
// (dns). While running it hot-swaps the main handle like SetServerIPs; a
// failed swap leaves the capture as it was.
func (e *Engine) SetDNSCapture(on bool) error {
	if e.running.Load() && e.failed.Load() {
		return nil // as SetServerIPs: there is no filter to update
	}
	e.mainMu.Lock()
	defer e.mainMu.Unlock()
	if e.dnsCapture == on {
		return nil
	}
	prev := e.dnsCapture
	e.dnsCapture = on
	if !e.running.Load() || e.failed.Load() {
		return nil // the first main handle uses it
	}
	if err := e.reopenMain(e.serverIPs); err != nil {
		e.dnsCapture = prev
		if e.failed.Load() {
			return nil // failed meanwhile: there is no filter to update
		}
		return err
	}
	return nil
}
