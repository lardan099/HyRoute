//go:build windows

package engine

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/lardan099/hyroute/internal/divert"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/packet"
)

func testEngine() *Engine {
	return New(Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Options: Options{RelayPort: 50123}})
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func TestServerExclusions(t *testing.T) {
	in := append(addrs(
		"2001:db8::10%12", // zone: not in the filter language
		"203.0.113.10",
		"::ffff:203.0.113.9", // 4in6
		"203.0.113.10",       // duplicate
		"fe80::1%12",         // link-local: excluded by a fixed range
		"192.168.1.1",        // private: excluded by a fixed range
	), netip.Addr{})
	want := addrs("203.0.113.9", "203.0.113.10", "2001:db8::10")
	if got := serverExclusions(in); !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

// A swap that fails keeps the list the kernel still excludes, so the next
// call with the same list tries again instead of reporting success.
func TestSetServerIPsAppliedOnlyOnSuccess(t *testing.T) {
	e := testEngine()
	a, b := addrs("203.0.113.1")[0], addrs("203.0.113.2")[0]
	// Not running: the first main handle excludes them.
	if err := e.SetServerIPs([]netip.Addr{a}); err != nil {
		t.Fatal(err)
	}
	e.running.Store(true)
	// WinDivert.dll is not loaded in tests: every swap fails to open.
	for i := range 2 {
		if err := e.SetServerIPs([]netip.Addr{a, b}); err == nil {
			t.Fatalf("call %d: failed swap reported success", i)
		}
	}
	if !slices.Equal(e.serverIPs, []netip.Addr{a}) {
		t.Fatalf("applied %v after failed swaps", e.serverIPs)
	}
	if err := e.SetServerIPs([]netip.Addr{a}); err != nil {
		t.Fatalf("unchanged list: %v", err)
	}

	many := make([]netip.Addr, maxServerIPs+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)})
	}
	if err := e.SetServerIPs(many); err == nil || !strings.Contains(err.Error(), "слишком много") {
		t.Fatalf("too many server IPs: %v", err)
	}
}

// After fail the filters stay removed until Stop: a new server list must
// not open a main handle again.
func TestSetServerIPsAfterFail(t *testing.T) {
	e := testEngine()
	e.running.Store(true)
	e.failed.Store(true)
	if err := e.SetServerIPs(addrs("203.0.113.1")); err != nil {
		t.Fatal(err)
	}
	if len(e.serverIPs) != 0 || len(e.mains) != 0 {
		t.Fatalf("failed engine swapped: ips %v, mains %d", e.serverIPs, len(e.mains))
	}
	e.mainMu.Lock()
	err := e.reopenMain(nil)
	e.mainMu.Unlock()
	if err == nil {
		t.Fatal("reopenMain on a failed engine")
	}
}

func TestLoopStateStuck(t *testing.T) {
	limit := int(watchdogLimit / watchdogTick)
	var l loopState
	for range 2 * limit {
		if l.stuck() {
			t.Fatal("idle loop stuck")
		}
	}
	for range 2 * limit {
		l.begin()
		if l.stuck() {
			t.Fatal("loop finishing batches stuck")
		}
		l.end()
	}
	// A batch in progress is stuck once it stays unfinished for the limit;
	// one tick that sees it (a clock jump or sleep in the middle of it
	// included) is not enough.
	l.begin()
	for i := range limit {
		if l.stuck() {
			t.Fatalf("stuck after %d ticks", i)
		}
	}
	if !l.stuck() {
		t.Fatal("hung batch not detected")
	}
	l.end()
	if l.stuck() {
		t.Fatal("finished batch still stuck")
	}
}

// After a hot swap two loops run at once: the one finishing batches must
// not hide a hang of the other.
func TestWatchdogSeesEveryLoop(t *testing.T) {
	e := testEngine()
	hung, busy := &loopState{}, &loopState{}
	e.loops[hung], e.loops[busy] = struct{}{}, struct{}{}
	hung.begin()
	var stuck *loopState
	for range int(watchdogLimit/watchdogTick) + 1 {
		busy.begin()
		busy.end()
		stuck = e.stuckLoop()
	}
	if stuck != hung {
		t.Fatalf("stuck loop %p, want %p", stuck, hung)
	}
}

// The watchdog logs where every goroutine is (L40), within maxStacks.
func TestAllStacks(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	if s := allStacks(); !strings.Contains(s, "TestAllStacks") {
		t.Fatalf("this goroutine not in the dump: %.200s", s)
	}
	for range 2000 {
		go func() { <-block }()
	}
	if s := allStacks(); len(s) > maxStacks+20 || !strings.HasSuffix(s, "(cut)") {
		t.Fatalf("%d bytes, cut %v", len(s), strings.HasSuffix(s, "(cut)"))
	}
}

// currentUser is the SID of the user the tests run as.
func currentUser(t *testing.T) *windows.SID {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid
}

func TestLockMachine(t *testing.T) {
	defer func(name string, wait time.Duration, owner func(*windows.SID) bool) {
		machineLock, slotWait, lockOwner = name, wait, owner
	}(machineLock, slotWait, lockOwner)
	machineLock = fmt.Sprintf(`Local\HyRoute-engine-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	// Not elevated, the test's own lock belongs to its user.
	me, admins := currentUser(t), lockOwner
	lockOwner = func(sid *windows.SID) bool { return sid.Equals(me) || admins(sid) }
	release, err := LockMachine()
	if err != nil {
		t.Fatal(err)
	}
	// The named object is what a copy in another Windows session finds.
	if _, err := lockGlobal(); !errors.Is(err, ErrOtherEngine) {
		t.Fatalf("other session: %v", err)
	}
	// A claim from this process (Connect while the previous session is
	// still stopping) waits for the release instead of blaming another
	// session.
	slotWait = 50 * time.Millisecond
	if _, err := LockMachine(); !errors.Is(err, ErrStillStopping) {
		t.Fatalf("previous session still stopping: %v", err)
	}
	slotWait = 10 * time.Second
	go func() {
		time.Sleep(100 * time.Millisecond)
		release()
	}()
	next, err := LockMachine()
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	release() // idempotent: must not give back the new claim
	if _, err := lockGlobal(); !errors.Is(err, ErrOtherEngine) {
		t.Fatalf("old release freed the new claim: %v", err)
	}
	next()
	unlock, err := lockGlobal()
	if err != nil {
		t.Fatalf("after the last release: %v", err)
	}
	unlock()
}

// An object of the lock's name that no elevated process created (any
// program may create one in Global\), or one of another type, does not
// stop the engine.
func TestLockMachineIgnoresSquatter(t *testing.T) {
	defer func(name string) { machineLock = name }(machineLock)
	me := currentUser(t).String()
	mutex := func(sddl string) func(*uint16) (windows.Handle, error) {
		return func(name *uint16) (windows.Handle, error) {
			sd, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				return 0, err
			}
			sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
			return windows.CreateMutex(sa, false, name)
		}
	}
	for _, c := range []struct {
		what   string
		create func(*uint16) (windows.Handle, error)
	}{
		{"mutex open to everyone", mutex("O:" + me + "D:P(A;;GA;;;WD)")},
		{"mutex open to no one", mutex("O:" + me + "D:P")}, // but its owner's READ_CONTROL
		{"event", func(name *uint16) (windows.Handle, error) { return windows.CreateEvent(nil, 0, 0, name) }},
	} {
		machineLock = fmt.Sprintf(`Local\HyRoute-engine-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
		name, err := windows.UTF16PtrFromString(machineLock)
		if err != nil {
			t.Fatal(err)
		}
		squat, err := c.create(name)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		unlock, err := lockGlobal()
		windows.CloseHandle(squat)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		unlock()
	}
}

// The first handle is opened once more when the driver is unloading
// (ERROR_SERVICE_MARKED_FOR_DELETE), and only then.
func TestOpenFirstRetriesWhileUnloading(t *testing.T) {
	defer func(d time.Duration) { openRetry = d }(openRetry)
	openRetry = time.Millisecond
	e := testEngine()
	for _, c := range []struct {
		code  uint32
		calls int
	}{{1072, 2}, {5, 1}, {654, 1}} {
		calls := 0
		_, err := e.openFirst(func() (*divert.Handle, error) {
			calls++
			return nil, &divert.OpenError{Code: c.code}
		})
		if err == nil || calls != c.calls {
			t.Fatalf("code %d: %d calls, err %v", c.code, calls, err)
		}
	}
}

// Two failures at once (two packet loops after a hot swap, or the watchdog
// and a loop): the second must not remove the filters while the first is
// still closing the kill switch (OnFail), or traffic would go direct past
// it.
func TestSecondFailWaitsForKillSwitch(t *testing.T) {
	e := testEngine()
	e.send = &divert.Handle{} // stands for the open main handles
	entered, release := make(chan struct{}), make(chan struct{})
	e.cfg.OnFail = func() {
		close(entered)
		<-release
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.fail()
	}()
	<-entered
	e.fail()
	e.sendMu.RLock()
	open := e.send != nil
	e.sendMu.RUnlock()
	if !open {
		t.Fatal("second fail removed the filters before the kill switch closed")
	}
	close(release)
	<-done
	if e.send != nil {
		t.Fatal("filters not removed")
	}
}

// reflectedEntry registers the reflected flow L -> R after its handshake,
// as the packet loop would.
func reflectedEntry(t *testing.T, e *Engine) {
	t.Helper()
	now := time.Now()
	ent, err := e.NAT.Insert(&nat.Entry{Flow: flowKey(L, R), Mode: nat.NoSniff}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct {
		src, dst string
		flags    uint8
		seq, ack uint32
		app      bool
	}{
		{L, R, packet.FlagSYN, 1000, 0, true},
		{relaySide, relayPeer, packet.FlagSYN | packet.FlagACK, 5000, 1001, false},
		{L, R, packet.FlagACK, 1001, 5001, true},
	} {
		p, err := packet.Parse(packet.BuildTCP(netip.MustParseAddrPort(s.src), netip.MustParseAddrPort(s.dst), s.flags, s.seq, s.ack, nil))
		if err != nil {
			t.Fatal(err)
		}
		e.NAT.TouchPacket(ent, &p, s.app, outAddr(), now)
	}
}

// An engine failure resets the reflected connections before the filters
// go, as Stop does, and before OnFail (the kill switch block could drop
// the resets).
func TestFailResetsReflected(t *testing.T) {
	e := testEngine()
	reflectedEntry(t, e)
	var mu sync.Mutex
	var order []string
	e.cfg.OnFail = func() {
		mu.Lock()
		order = append(order, "onfail")
		mu.Unlock()
	}
	e.Core.Inject = func(b []byte, a *divert.Address) {
		p, err := packet.Parse(append([]byte(nil), b...))
		mu.Lock()
		defer mu.Unlock()
		if err != nil || a.Outbound() || p.TCPFlags()&packet.FlagRST == 0 || p.Dst() != netip.MustParseAddrPort(L) || p.Ack() != 1001 {
			order = append(order, "bad")
			return
		}
		order = append(order, "rst")
	}
	e.fail()
	e.fail() // a second failure resets nothing more
	mu.Lock()
	defer mu.Unlock()
	if !e.Failed() || strings.Join(order, ",") != "rst,onfail" {
		t.Fatalf("failed %v, order %v", e.Failed(), order)
	}
}

// A packet loop the watchdog gave up on may hold a lock the resets need
// (here swapMu, as a send that never returns would with a hot swap
// waiting): fail and Stop still remove the filters, without the resets.
func TestFailNeverWaitsForStuckLocks(t *testing.T) {
	defer func(w time.Duration) { resetWait = w }(resetWait)
	resetWait = 50 * time.Millisecond
	e := testEngine()
	reflectedEntry(t, e)
	e.swapMu.Lock()
	defer e.swapMu.Unlock()
	e.running.Store(true)
	e.stop = make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.fail()
		e.Stop()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("fail or Stop hangs on a lock held by a stuck packet loop")
	}
	if !e.Failed() || e.running.Load() {
		t.Fatalf("failed %v, running %v", e.Failed(), e.running.Load())
	}
}
