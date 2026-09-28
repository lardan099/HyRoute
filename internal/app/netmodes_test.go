package app

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/logx"
	"github.com/lardan099/hyroute/internal/netmode"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/session"
	"github.com/lardan099/hyroute/internal/store"
)

const (
	gHome   = "{5E1B9C0A-3C7D-4F0E-9A51-0D2B6B1C7E11}"
	gCafe   = "{11111111-2222-3333-4444-555555555555}"
	gOffice = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
)

// fakeNet is a scripted NetWatcher.
type fakeNet struct {
	mu       sync.Mutex
	snap     netmode.Snapshot
	ssid     string
	ssidErr  error
	watchErr error
	events   chan struct{}
	snaps    int
	watches  int
	ssids    int
	ssidFor  []string
	snapAt   []time.Time
	ctxs     []context.Context
	onSnap   func() // runs once, inside the next Snapshot (holding no lock)
}

func (f *fakeNet) set(n *netmode.Network) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snap = netmode.Snapshot{}
	if n != nil {
		c := *n
		f.snap.Active = &c
	}
}

func (f *fakeNet) Snapshot(wantSSID bool) (netmode.Snapshot, error) {
	f.mu.Lock()
	hook := f.onSnap
	f.onSnap = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.snaps++
	f.snapAt = append(f.snapAt, time.Now())
	s := f.snap.Clone()
	if wantSSID && s.Active != nil && s.Active.Adapter == netmode.WiFi {
		s.Active.SSID = f.ssid
	}
	return s, nil
}

func (f *fakeNet) Watch(ctx context.Context) (<-chan struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.watches++
	f.ctxs = append(f.ctxs, ctx)
	if f.watchErr != nil {
		return nil, f.watchErr
	}
	return f.events, nil
}

func (f *fakeNet) SSID(adapterID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ssids++
	f.ssidFor = append(f.ssidFor, adapterID)
	return f.ssid, f.ssidErr
}

func (f *fakeNet) counts() (snaps, watches, ssids int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.snaps, f.watches, f.ssids
}

func home() *netmode.Network {
	return &netmode.Network{ID: gHome, Identified: true, Name: "HomeNet", Category: netmode.Private, Adapter: netmode.WiFi,
		AdapterName: "Беспроводная сеть", AdapterID: "{AD-1}", GatewayIP: "192.168.77.1", GatewayMAC: "aa-aa-aa-aa-aa-aa"}
}

func cafe() *netmode.Network {
	return &netmode.Network{ID: gCafe, Identified: true, Name: "CafeNet", Category: netmode.Public, Adapter: netmode.WiFi,
		AdapterName: "Беспроводная сеть", AdapterID: "{AD-1}", GatewayIP: "10.9.8.1", GatewayMAC: "bb-bb-bb-bb-bb-bb"}
}

// unid is n before Windows identified it.
func unid(n *netmode.Network) *netmode.Network {
	n.Identified, n.Category = false, ""
	return n
}

// netCtl has one server, a fake watcher and a thread-safe session starter.
func netCtl(t *testing.T) (*Controller, *fakeNet, func() int) {
	t.Helper()
	c, _ := newCtl(t)
	var mu sync.Mutex
	n := 0
	c.Start = func(cfg session.Config) (Session, error) {
		mu.Lock()
		n++
		mu.Unlock()
		return &fakeSession{reg: flows.NewRegistry(10), cfg: cfg}, nil
	}
	if _, err := c.ImportURIs(link); err != nil {
		t.Fatal(err)
	}
	w := &fakeNet{events: make(chan struct{}, 1)}
	c.NetWatcher = w
	return c, w, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

func knownNet(ids ...string) netmode.Match {
	var m netmode.Match
	for _, id := range ids {
		m.Networks = append(m.Networks, netmode.Known{ID: id, Name: "сеть"})
	}
	return m
}

func netRule(name string, m netmode.Match, conn string) netmode.Rule {
	return netmode.Rule{Name: name, Match: m, Action: netmode.Action{Connect: conn}}
}

// netEnable saves cfg's rules and unknown and turns the feature on.
func netEnable(t *testing.T, c *Controller, cfg netmode.Config) {
	t.Helper()
	if _, err := c.SaveNetModes(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetNetModesEnabled(true); err != nil {
		t.Fatal(err)
	}
}

func netCfg(unknown string, rs ...netmode.Rule) netmode.Config {
	return netmode.Config{Version: 1, Rules: rs, Unknown: netmode.Action{Connect: unknown}}
}

func online(c *Controller) bool { return c.Status().State != "disconnected" }

func netNow(c *Controller) NetState {
	if n := c.Status().Net; n != nil {
		return *n
	}
	return NetState{}
}

// netBase takes n as the baseline (the first read after enabling).
func netBase(t *testing.T, c *Controller, w *fakeNet, n *netmode.Network, at time.Time) {
	t.Helper()
	w.set(n)
	c.netCheck(at)
	c.netMu.Lock()
	defer c.netMu.Unlock()
	if c.net.base.Empty() {
		t.Fatal("no baseline")
	}
}

func TestNetChangeConnectsAtOnce(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg("", netRule("Кафе", knownNet(gCafe), netmode.Connect)))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	if starts() != 0 {
		t.Fatal("the baseline acted")
	}
	w.set(cafe())
	c.netCheck(t0.Add(time.Second))
	if starts() != 1 || !online(c) {
		t.Fatal("not connected at the first read")
	}
	if st := netNow(c); !st.Pending || st.Rule != "Кафе" || !strings.Contains(st.Text, "Подключено правилом сети «Кафе»") {
		t.Fatalf("%+v", st)
	}
	c.netCheck(t0.Add(3 * time.Second))
	if st := netNow(c); st.Pending || starts() != 1 {
		t.Fatalf("%+v %d", st, starts())
	}
}

func TestNetChangeDisconnectSettles(t *testing.T) {
	c, w, _ := netCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	t0 := time.Now()
	netBase(t, c, w, cafe(), t0)
	w.set(home())
	c.netCheck(t0.Add(10 * time.Second))
	if !online(c) || !netNow(c).Pending {
		t.Fatal("disconnected before the confirming read")
	}
	c.netCheck(t0.Add(11 * time.Second))
	if !online(c) {
		t.Fatal("disconnected before netConfirm")
	}
	c.netCheck(t0.Add(12 * time.Second))
	if online(c) || ks.blocks {
		t.Fatalf("still connected: %v, block %v", online(c), ks.blocks)
	}
	if st := netNow(c); !st.Off || st.OffBy != "Дом" || st.Rule != "Дом" || st.Pending || st.Text != "Отключено правилом сети «Дом»" {
		t.Fatalf("%+v", st)
	}
}

func TestNetNoIDSettlesAfterMax(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Wi-Fi", netmode.Match{Adapters: []string{netmode.WiFi}}, netmode.Disconnect)))
	t0 := time.Now()
	e := cafe()
	e.Adapter, e.AdapterID, e.GatewayIP = netmode.Ethernet, "{AD-2}", "10.1.1.1"
	netBase(t, c, w, e, t0)
	w.set(unid(cafe()))
	c.netCheck(t0.Add(time.Second))
	if starts() != 1 {
		t.Fatal("unknown network not connected at once")
	}
	for _, d := range []time.Duration{3, 6, 10, 15} {
		c.netCheck(t0.Add(d * time.Second))
		if !online(c) {
			t.Fatalf("relaxed after %ds without an ID", d-1)
		}
	}
	c.netCheck(t0.Add(16 * time.Second)) // 15 s after the first read
	if online(c) {
		t.Fatal("not settled after netSettleMax")
	}
	c.netMu.Lock()
	idless := c.net.baseIdless
	c.netMu.Unlock()
	if !idless {
		t.Fatal("baseIdless not set")
	}
}

func TestNetBlipDoesNotAct(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	w.set(nil)
	c.netCheck(t0.Add(time.Second))
	if !netNow(c).NoNet {
		t.Fatal("NoNet")
	}
	w.set(home())
	c.netCheck(t0.Add(2 * time.Second))
	if starts() != 0 || !netNow(c).At.IsZero() {
		t.Fatalf("a blip acted: %+v", netNow(c))
	}
}

func TestNetUnclearAndRefined(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect))
	t0 := time.Now()
	h := home()
	h.GatewayMAC = ""
	netBase(t, c, w, h, t0)
	if err := c.Connect(); err != nil { // override
		t.Fatal(err)
	}
	hiccup := unid(home())
	hiccup.ID, hiccup.GatewayMAC = "", ""
	w.set(hiccup)
	for i := 1; i <= 20; i += 2 {
		c.netCheck(t0.Add(time.Duration(i) * time.Second))
		if !netNow(c).Override || starts() != 1 {
			t.Fatalf("read %d: %+v", i, netNow(c))
		}
	}
	c.netMu.Lock()
	quiet := c.net.quiet
	c.netMu.Unlock()
	if quiet.Empty() {
		t.Fatal("a timed-out unclear read that would not act is not quiet")
	}

	// A baseline without an ID taken by enabling gets the ID: no action.
	c2, w2, starts2 := netCtl(t)
	netEnable(t, c2, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	netBase(t, c2, w2, unid(home()), t0)
	w2.set(home())
	c2.netCheck(t0.Add(time.Second))
	c2.netCheck(t0.Add(5 * time.Second))
	c2.netMu.Lock()
	base, pend := c2.net.base, c2.net.pend
	c2.netMu.Unlock()
	if base.NetID != gHome || pend != nil || starts2() != 0 || !netNow(c2).At.IsZero() {
		t.Fatalf("%+v %+v %d", base, pend, starts2())
	}
}

func TestNetAttributeChangeNoAction(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Частная", netmode.Match{Categories: []string{netmode.Private}}, netmode.Disconnect)))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	h := home()
	h.Category, h.Name, h.SSID, h.SSIDDenied = netmode.Public, "Renamed", "x", true
	w.set(h)
	c.netCheck(t0.Add(time.Second))
	c.netCheck(t0.Add(5 * time.Second))
	if starts() != 0 || netNow(c).Pending || !netNow(c).At.IsZero() {
		t.Fatalf("%+v", netNow(c))
	}
}

func TestNetPendingReplaced(t *testing.T) {
	c, w, _ := netCtl(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	netEnable(t, c, netCfg("", netRule("B", knownNet(gCafe), netmode.Disconnect), netRule("C", knownNet(gOffice), netmode.Disconnect)))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	w.set(cafe())
	c.netCheck(t0.Add(time.Second))
	o := cafe()
	o.ID, o.GatewayMAC = gOffice, "cc-cc-cc-cc-cc-cc"
	w.set(o)
	c.netCheck(t0.Add(2 * time.Second)) // C replaces B: its first read counts again
	c.netCheck(t0.Add(3 * time.Second))
	if !online(c) {
		t.Fatal("C settled before netConfirm")
	}
	c.netCheck(t0.Add(4 * time.Second))
	if online(c) || netNow(c).Rule != "C" {
		t.Fatalf("%+v", netNow(c))
	}
	// Back to the baseline drops the pending change.
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	w.set(cafe())
	c.netCheck(t0.Add(10 * time.Second))
	w.set(o)
	c.netCheck(t0.Add(11 * time.Second))
	c.netCheck(t0.Add(20 * time.Second))
	if !online(c) || netNow(c).Pending {
		t.Fatalf("%+v", netNow(c))
	}
}

func TestNetManualWins(t *testing.T) {
	c, w, _ := netCtl(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	t0 := time.Now()
	netBase(t, c, w, cafe(), t0)
	w.set(home())
	c.netCheck(t0.Add(time.Second))
	c.netCheck(t0.Add(3 * time.Second))
	if online(c) {
		t.Fatal("not disconnected")
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	for i := 4; i < 40; i += 3 {
		c.netCheck(t0.Add(time.Duration(i) * time.Second))
	}
	if st := netNow(c); !online(c) || !st.Override || st.Off {
		t.Fatalf("the user's connect lost: %+v", st)
	}
	w.set(cafe())
	c.netCheck(t0.Add(50 * time.Second))
	if st := netNow(c); st.Override || !online(c) {
		t.Fatalf("%+v", st)
	}
}

func TestNetManualDuringPending(t *testing.T) {
	c, w, _ := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect), netRule("Кафе", knownNet(gCafe), netmode.Connect)))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	w.set(unid(cafe()))
	c.netCheck(t0.Add(time.Second))
	if !online(c) {
		t.Fatal("no protective connect")
	}
	c.Disconnect()
	w.set(cafe()) // now identified: the same pending network
	c.netCheck(t0.Add(4 * time.Second))
	c.netCheck(t0.Add(6 * time.Second)) // its confirming read
	if online(c) {
		t.Fatal("the settle overrode the user's disconnect")
	}
	c.netMu.Lock()
	base, pend := c.net.base, c.net.pend
	c.netMu.Unlock()
	if pend != nil || base.NetID != gCafe || !netNow(c).Override {
		t.Fatalf("%+v %+v", base, pend)
	}
}

func TestNetUserActsDuringApply(t *testing.T) {
	c, w, _ := netCtl(t)
	var wg sync.WaitGroup
	var once sync.Once
	c.Start = func(cfg session.Config) (Session, error) {
		once.Do(func() {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.Disconnect()
			}()
			time.Sleep(20 * time.Millisecond) // the click waits for the rule's connect
		})
		return &fakeSession{reg: flows.NewRegistry(10), cfg: cfg}, nil
	}
	netEnable(t, c, netCfg(netmode.Connect))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	w.set(cafe())
	c.netCheck(t0.Add(time.Second))
	wg.Wait()
	if online(c) {
		t.Fatal("the automatic connect won over the user's disconnect")
	}
	c.netCheck(t0.Add(3 * time.Second)) // the settle is dropped too
	if online(c) {
		t.Fatal("settle after the user's disconnect")
	}
}

func setAutoConnect(t *testing.T, c *Controller) {
	t.Helper()
	p := c.Prefs()
	p.AutoConnect = true
	if err := c.SavePrefs(p); err != nil {
		t.Fatal(err)
	}
}

func TestNetStartDecide(t *testing.T) {
	ctx := context.Background()
	start := func(t *testing.T, n *netmode.Network, rule netmode.Rule) (*Controller, *fakeNet) {
		c, w, _ := netCtl(t)
		setAutoConnect(t, c)
		netEnable(t, c, netCfg("", rule))
		c.netConfirm = 5 * time.Millisecond
		w.set(n)
		c.netStart(ctx, NetStartDecide)
		return c, w
	}
	if c, _ := start(t, home(), netRule("Дом", knownNet(gHome), netmode.Disconnect)); online(c) {
		t.Fatal("trusted network connected at start")
	}
	if c, _ := start(t, home(), netRule("Дом", knownNet(gHome), netmode.Keep)); !online(c) {
		t.Fatal("«не менять» + AutoConnect did not connect")
	}
	c, w := start(t, nil, netRule("Дом", knownNet(gHome), netmode.Disconnect))
	if !online(c) {
		t.Fatal("no network + AutoConnect did not connect")
	}
	t0 := time.Now()
	w.set(home())
	c.netCheck(t0)
	if !online(c) {
		t.Fatal("disconnected at the first read")
	}
	c.netCheck(t0.Add(3 * time.Second))
	if online(c) {
		t.Fatal("not disconnected after settling")
	}
}

func TestNetStartConfirmsRelaxing(t *testing.T) {
	type run struct {
		c       *Controller
		w       *fakeNet
		ks      *fakeKS
		decided chan bool // blocks at OnStartDecided
		starts  func() int
	}
	begin := func(t *testing.T, rule netmode.Rule) *run {
		c, w, starts := netCtl(t)
		ks := &fakeKS{blocks: true}
		c.KillSwitch = ks
		setKillSwitch(t, c, true)
		c.InitKillSwitch()
		netEnable(t, c, netCfg("", rule))
		c.netConfirm = 800 * time.Millisecond
		r := &run{c: c, w: w, ks: ks, decided: make(chan bool, 1), starts: starts}
		c.OnStartDecided = func() { r.decided <- ks.blocks }
		w.set(home())
		return r
	}
	waitSnaps := func(w *fakeNet, n int) {
		for end := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
			if s, _, _ := w.counts(); s >= n {
				return
			}
			if time.Now().After(end) {
				t.Fatalf("no read %d", n)
			}
		}
	}
	// A trusted network: the block goes only after the confirming read,
	// before the start gate is told.
	r := begin(t, netRule("Дом", knownNet(gHome), netmode.Disconnect))
	done := make(chan struct{})
	go func() { r.c.netStart(context.Background(), NetStartDecide); close(done) }()
	waitSnaps(r.w, 1)
	if st := r.c.Status(); st.KillSwitch != "blocking" {
		t.Fatal("released before the confirming read")
	}
	<-done
	if still := <-r.decided; still || r.ks.blocks {
		t.Fatal("block not released, or the gate told before the release")
	}
	// The second read shows another network: nothing released, no baseline.
	r = begin(t, netRule("Дом", knownNet(gHome), netmode.Disconnect))
	go func() {
		waitSnaps(r.w, 1)
		r.w.set(cafe())
	}()
	r.c.netStart(context.Background(), NetStartDecide)
	if !<-r.decided || !r.ks.blocks {
		t.Fatal("released on an unconfirmed read")
	}
	r.c.netMu.Lock()
	base := r.c.net.base
	r.c.netMu.Unlock()
	if !base.Empty() {
		t.Fatal("baseline from an unconfirmed read")
	}
	// «Подключить» connects before any second read.
	r = begin(t, netRule("Дом", knownNet(gHome), netmode.Connect))
	r.c.netStart(context.Background(), NetStartDecide)
	if s, _, _ := r.w.counts(); s != 1 || r.starts() != 1 {
		t.Fatalf("reads %d, starts %d", s, r.starts())
	}
	<-r.decided
}

func TestNetStartUserActedFirst(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	w.set(unid(cafe()))
	c.netStart(context.Background(), NetStartDecide)
	c.Disconnect()
	w.set(cafe())
	c.netCheck(time.Now())
	if st := netNow(c); starts() != 0 || !st.Override || st.Pending {
		t.Fatalf("%+v %d", st, starts())
	}
}

func TestNetStartRestore(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	decided := false
	c.OnStartDecided = func() { decided = true }
	c.netStart(context.Background(), NetStartRestore)
	if s, _, _ := w.counts(); s != 0 || decided {
		t.Fatal("restore read or told the gate")
	}
	w.set(home())
	c.netCheck(time.Now())
	if st := netNow(c); starts() != 0 || !st.Override || !st.Restored || st.Text != restoreText {
		t.Fatalf("%+v", st)
	}
}

func TestNetStartRestoreIdle(t *testing.T) {
	c, w, starts := netCtl(t)
	setAutoConnect(t, c)
	netEnable(t, c, netCfg(netmode.Connect))
	decided := make(chan struct{}, 1)
	c.OnStartDecided = func() { decided <- struct{}{} }
	c.netStart(context.Background(), NetStartRestoreIdle)
	<-decided
	if starts() != 0 {
		t.Fatal("connected after an update without --reconnect")
	}
	t0 := time.Now()
	w.set(home())
	c.netCheck(t0)
	if starts() != 0 || !netNow(c).Override {
		t.Fatal("the first identity acted")
	}
	w.set(cafe())
	c.netCheck(t0.Add(time.Second))
	if starts() != 1 {
		t.Fatal("a later change did not act")
	}
	// Feature off: as always, AutoConnect.
	c2, _, starts2 := netCtl(t)
	setAutoConnect(t, c2)
	c2.netStart(context.Background(), NetStartRestoreIdle)
	if starts2() != 1 {
		t.Fatal("AutoConnect with the feature off")
	}
}

// runNet runs the loop until the test ends.
func runNet(t *testing.T, c *Controller, mode NetStartMode) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.RunNetModes(ctx, mode)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !ok(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal(what)
		}
	}
}

func TestNetDisabledReadsNothing(t *testing.T) {
	c, w, starts := netCtl(t)
	setAutoConnect(t, c)
	c.netQuiet, c.netConfirm, c.netPoll = 5*time.Millisecond, 5*time.Millisecond, time.Hour
	w.set(home())
	runNet(t, c, NetStartDecide)
	eventually(t, "AutoConnect", func() bool { return starts() == 1 })
	c.Status()
	c.Diagnostics(nil, false)
	time.Sleep(20 * time.Millisecond)
	if s, wa, ss := w.counts(); s+wa+ss != 0 {
		t.Fatalf("disabled read %d/%d/%d", s, wa, ss)
	}
	if _, err := c.SetNetModesEnabled(true); err != nil {
		t.Fatal(err)
	}
	eventually(t, "baseline", func() bool {
		c.netMu.Lock()
		defer c.netMu.Unlock()
		return !c.net.base.Empty()
	})
	if netNow(c).Text != "" {
		t.Fatal("enabling acted")
	}
	c.Disconnect()
	if _, err := c.ApplyNetModes(""); err != nil {
		t.Fatal(err)
	}
	if !online(c) || !strings.Contains(netNow(c).Text, "Подключено") { // Default: «Неизвестная сеть: подключить»
		t.Fatalf("apply did not act: %+v", netNow(c))
	}
	if _, err := c.SetNetModesEnabled(false); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	ctx := w.ctxs[0]
	w.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("watching after disabling")
	}
	if c.Status().Net != nil {
		t.Fatal("status while disabled")
	}
}

func TestNetEnableOffline(t *testing.T) {
	for _, userActs := range []bool{false, true} {
		c, w, starts := netCtl(t)
		netEnable(t, c, netCfg(netmode.Connect))
		t0 := time.Now()
		w.set(nil)
		c.netCheck(t0)
		if userActs {
			c.Disconnect()
		}
		w.set(cafe())
		c.netCheck(t0.Add(time.Hour))
		if userActs != (starts() == 0) {
			t.Fatalf("user acts %v: starts %d", userActs, starts())
		}
		if userActs && !netNow(c).Override {
			t.Fatal("no override")
		}
	}
}

func TestNetUnknownDefaultConnects(t *testing.T) {
	c, w, _ := netCtl(t)
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	cfg := netmode.Default()
	cfg.Rules = []netmode.Rule{netRule("Дом", knownNet(gHome), netmode.Disconnect)}
	netEnable(t, c, cfg)
	t0 := time.Now()
	netBase(t, c, w, cafe(), t0)
	w.set(home())
	c.netCheck(t0.Add(time.Second))
	c.netCheck(t0.Add(3 * time.Second))
	if online(c) || ks.blocks {
		t.Fatal("home not disconnected")
	}
	w.set(unid(cafe()))
	c.netCheck(t0.Add(10 * time.Second))
	if !online(c) {
		t.Fatal("café without an ID not connected at the first read")
	}
	if st := netNow(c); st.Rule != netmode.UnknownName || st.Off {
		t.Fatalf("%+v", st)
	}
}

func TestNetOffCarriedOverKeep(t *testing.T) {
	c, w, _ := netCtl(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	netEnable(t, c, netCfg(netmode.Keep, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	t0 := time.Now()
	netBase(t, c, w, cafe(), t0)
	w.set(home())
	c.netCheck(t0.Add(time.Second))
	c.netCheck(t0.Add(3 * time.Second))
	w.set(cafe())
	c.netCheck(t0.Add(10 * time.Second))
	c.netCheck(t0.Add(12 * time.Second))
	st := netNow(c)
	if online(c) || !st.Off || st.OffBy != "Дом" || st.Rule != netmode.UnknownName {
		t.Fatalf("%+v", st)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	if st := netNow(c); st.Off || st.OffBy != "" {
		t.Fatalf("%+v", st)
	}
}

func TestNetSameGatewayNoMACNoID(t *testing.T) {
	sameGW := func() *netmode.Network {
		n := unid(cafe())
		n.ID, n.GatewayIP, n.GatewayMAC = "", home().GatewayIP, ""
		return n
	}
	// The café MAC shows up at the next read: a change, connect.
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	w.set(sameGW())
	c.netCheck(t0.Add(time.Second))
	if starts() != 0 {
		t.Fatal("an unclear read acted")
	}
	n := sameGW()
	n.GatewayMAC = "cc-cc-cc-cc-cc-cc"
	w.set(n)
	c.netCheck(t0.Add(3 * time.Second))
	if starts() != 1 {
		t.Fatal("not connected once the MAC showed another network")
	}
	// The MAC never shows while «Дом» disconnected: a change after netSettleMax.
	c, w, starts = netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	netBase(t, c, w, home(), t0)
	w.set(sameGW())
	for i := 1; i < 16; i += 2 {
		c.netCheck(t0.Add(time.Duration(i) * time.Second))
		if starts() != 0 {
			t.Fatalf("acted after %ds", i)
		}
	}
	c.netCheck(t0.Add(17 * time.Second))
	if starts() != 1 {
		t.Fatal("not taken as a change after netSettleMax")
	}
	// Unknown «не менять» and routing on: nothing would change: dropped and
	// quiet, identical reads not re-timed.
	c, w, starts = netCtl(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	netEnable(t, c, netCfg(netmode.Keep))
	netBase(t, c, w, home(), t0)
	w.set(sameGW())
	c.netCheck(t0.Add(time.Second))
	c.netCheck(t0.Add(17 * time.Second))
	c.netMu.Lock()
	quiet, pend := c.net.quiet, c.net.pend
	c.netMu.Unlock()
	if quiet.Empty() || pend != nil {
		t.Fatalf("%+v %+v", quiet, pend)
	}
	c.netCheck(t0.Add(19 * time.Second))
	if c.netPendingNow() || starts() != 1 {
		t.Fatal("a quiet read re-timed")
	}
}

func TestNetUnclearHiccupNoAction(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect))
	t0 := time.Now()
	h := home()
	h.GatewayMAC = ""
	netBase(t, c, w, h, t0)
	c.Disconnect() // override
	x := unid(home())
	x.ID, x.GatewayMAC = "", ""
	w.set(x)
	c.netCheck(t0.Add(time.Second))
	w.set(h)
	c.netCheck(t0.Add(3 * time.Second))
	if starts() != 0 || !netNow(c).Override || c.netPendingNow() {
		t.Fatalf("%+v", netNow(c))
	}
}

func TestNetNLMDownBaselineMACLearned(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect))
	t0 := time.Now()
	h := home()
	h.GatewayMAC = ""
	netBase(t, c, w, h, t0)
	w.set(home()) // the same ID, now with the MAC
	c.netCheck(t0.Add(time.Second))
	c.netMu.Lock()
	mac := c.net.base.GatewayMAC
	c.netMu.Unlock()
	if mac != home().GatewayMAC {
		t.Fatal("MAC not learned")
	}
	down := func(mac string) *netmode.Network {
		n := unid(home())
		n.ID, n.Name, n.GatewayMAC = "", "", mac
		return n
	}
	w.set(down(home().GatewayMAC))
	c.netCheck(t0.Add(2 * time.Second))
	if starts() != 0 || c.netPendingNow() {
		t.Fatal("home without NLM not Same")
	}
	w.set(down("dd-dd-dd-dd-dd-dd"))
	c.netCheck(t0.Add(3 * time.Second))
	if starts() != 1 {
		t.Fatal("another router not a change at once")
	}
}

func TestNetEventBurstFixedRead(t *testing.T) {
	c, w, starts := netCtl(t)
	c.netQuiet, c.netConfirm, c.netPoll = 150*time.Millisecond, 20*time.Millisecond, time.Hour
	netEnable(t, c, netCfg("", netRule("Кафе", knownNet(gCafe), netmode.Connect)))
	w.set(home())
	runNet(t, c, NetStartDecide)
	eventually(t, "baseline", func() bool { s, _, _ := w.counts(); return s >= 2 }) // the start and the loop's first read
	if starts() != 0 {
		t.Fatal("connected at home")
	}
	time.Sleep(20 * time.Millisecond)
	w.set(cafe())
	first := time.Now()
	for i := 0; i < 18; i++ { // 900 ms of events: a read after the burst would come at ≈ 1050 ms
		select {
		case w.events <- struct{}{}:
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	eventually(t, "connect", func() bool { return starts() == 1 })
	w.mu.Lock()
	var at time.Time
	for _, a := range w.snapAt {
		if a.After(first) {
			at = a
			break
		}
	}
	w.mu.Unlock()
	if d := at.Sub(first); d < 140*time.Millisecond || d > 700*time.Millisecond {
		t.Fatalf("first read %v after the first event", d)
	}
}

func TestNetIdlessSettleRedecided(t *testing.T) {
	setup := func(t *testing.T) (*Controller, *fakeNet, time.Time) {
		c, w, _ := netCtl(t)
		netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
		t0 := time.Now()
		netBase(t, c, w, cafe(), t0)
		w.set(unid(home())) // cold boot at home: NLM slower than 15 s
		c.netCheck(t0.Add(time.Second))
		c.netCheck(t0.Add(17 * time.Second))
		if !online(c) || c.netPendingNow() {
			t.Fatal("not settled as «Неизвестная сеть: подключить»")
		}
		return c, w, t0
	}
	c, w, t0 := setup(t)
	w.set(home())
	c.netCheck(t0.Add(20 * time.Second))
	if !online(c) {
		t.Fatal("re-decided before the confirming read")
	}
	c.netCheck(t0.Add(22 * time.Second))
	if st := netNow(c); online(c) || st.Rule != "Дом" {
		t.Fatalf("not re-decided: %+v", st)
	}
	// The user acted before the ID appeared: only the baseline takes it.
	c, w, t0 = setup(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	w.set(home())
	c.netCheck(t0.Add(20 * time.Second))
	c.netCheck(t0.Add(22 * time.Second))
	c.netMu.Lock()
	base := c.net.base
	c.netMu.Unlock()
	if !online(c) || base.NetID != gHome {
		t.Fatalf("%v %+v", online(c), base)
	}
	// A baseline decided with an ID never re-decides.
	c2, w2, starts := netCtl(t)
	netEnable(t, c2, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	netBase(t, c2, w2, home(), t0)
	x := unid(home())
	x.ID = ""
	w2.set(x)
	c2.netCheck(t0.Add(time.Second))
	w2.set(home())
	c2.netCheck(t0.Add(3 * time.Second))
	c2.netCheck(t0.Add(6 * time.Second))
	if starts() != 0 || c2.netPendingNow() {
		t.Fatal("re-decided a baseline decided with an ID")
	}
}

// rulesetsFor gives c two saved rule profiles «Прямо» (active) and «VPN».
func rulesetsFor(t *testing.T, c *Controller) (direct, vpn string) {
	t.Helper()
	res, err := c.CreateRuleset(RulesetInput{Name: "VPN", Config: &rules.Config{DefaultAction: rules.Tunnel}, FirstName: "Прямо"}, SourceUser)
	if err != nil {
		t.Fatal(err)
	}
	return rsID(t, c, "Прямо"), res.View.ID
}

func activeRS(c *Controller) (string, Source) { return c.rulesetActive() }

// netRev is the config revision now (netApply's rev).
func netRev(c *Controller) uint64 {
	c.netMu.Lock()
	defer c.netMu.Unlock()
	return c.net.rev
}

func TestNetProtectiveRuleset(t *testing.T) {
	c, w, _ := netCtl(t)
	direct, vpn := rulesetsFor(t, c)
	cfg := netCfg(netmode.Connect, netmode.Rule{Name: "Дом", Match: knownNet(gHome), Action: netmode.Action{Ruleset: direct}})
	cfg.Unknown.Ruleset = vpn
	netEnable(t, c, cfg)
	t0 := time.Now()
	netBase(t, c, w, cafe(), t0)
	if _, err := c.SwitchRuleset(vpn, SourceUser, SwitchOptions{}); err != nil {
		t.Fatal(err)
	}
	w.set(home())
	c.netCheck(t0.Add(time.Second))
	if id, _ := activeRS(c); id != vpn {
		t.Fatal("a matched rule's profile switched at the first read")
	}
	c.netCheck(t0.Add(3 * time.Second))
	if id, src := activeRS(c); id != direct || src != SourceNetwork {
		t.Fatalf("%s %s", id, src)
	}
	w.set(cafe())
	c.netCheck(t0.Add(10 * time.Second))
	if id, _ := activeRS(c); id != vpn {
		t.Fatal("the «Неизвестная сеть» profile not switched at once")
	}
	if !strings.Contains(netNow(c).Text, "Профиль правил «VPN» включён: сеть сменилась, правило «Неизвестная сеть»") {
		t.Fatal(netNow(c).Text)
	}
	// A profile the user chose is not touched at the first read.
	if _, err := c.SwitchRuleset(direct, SourceUser, SwitchOptions{}); err != nil {
		t.Fatal(err)
	}
	o := cafe()
	o.ID, o.GatewayMAC = gOffice, "cc-cc-cc-cc-cc-cc"
	w.set(o)
	c.netCheck(t0.Add(20 * time.Second))
	if id, _ := activeRS(c); id != direct {
		t.Fatal("the user's profile switched at the first read")
	}
	c.netCheck(t0.Add(22 * time.Second))
	if id, _ := activeRS(c); id != vpn {
		t.Fatal("the «Неизвестная сеть» profile not switched at the settle")
	}
	// A fresh process: the active profile a network rule selects counts as
	// set by a network rule.
	if err := c.ActivateRuleset(direct, SourceNetwork); err != nil {
		t.Fatal(err)
	}
	c2, _ := newCtlAt(t, c.Store)
	w2 := &fakeNet{events: make(chan struct{}, 1)}
	c2.NetWatcher = w2
	c2.netConfirm = time.Millisecond
	if id, src := activeRS(c2); id != direct || src != "" {
		t.Fatalf("%s %q", id, src)
	}
	w2.set(cafe())
	c2.netStart(context.Background(), NetStartDecide)
	if id, _ := activeRS(c2); id != vpn {
		t.Fatal("fresh process: not switched")
	}
}

func TestNetUnidentifiedNeverMatches(t *testing.T) {
	c, w, _ := netCtl(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	t0 := time.Now()
	netBase(t, c, w, cafe(), t0)
	w.set(unid(home()))
	for i := 1; i < 30; i += 2 {
		c.netCheck(t0.Add(time.Duration(i) * time.Second))
	}
	if !online(c) || netNow(c).Rule != netmode.UnknownName {
		t.Fatalf("an unidentified network matched: %+v", netNow(c))
	}
	// «Именно эта сеть» with the ID of an unidentified network is refused.
	o := unid(cafe())
	o.ID = gOffice
	w.set(o)
	c.NetModes(true)
	cfg := c.NetModes(false).Config
	cfg.Rules = append(cfg.Rules, netRule("Новая", knownNet(gOffice), netmode.Disconnect))
	if _, err := c.SaveNetModes(cfg); err == nil || !strings.Contains(err.Error(), "Windows ещё не опознала эту сеть") {
		t.Fatal(err)
	}
}

func TestNetSetEnabledKeepsEdits(t *testing.T) {
	c, _, _ := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			cfg := c.NetModes(false).Config
			cfg.Rules = append(cfg.Rules, netRule("r", netmode.Match{Adapters: []string{netmode.WiFi}}, netmode.Keep))
			if _, err := c.SaveNetModes(cfg); err != nil {
				t.Error(err)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			if _, err := c.SetNetModesEnabled(i%2 == 1); err != nil {
				t.Error(err)
			}
		}(i)
		wg.Wait()
	}
	disk, err := c.Store.LoadNetModes()
	if err != nil || len(disk.Rules) == 0 || !disk.Enabled {
		t.Fatalf("%d rules, enabled %v, %v", len(disk.Rules), disk.Enabled, err)
	}
	cfg := c.NetModes(false).Config
	cfg.Enabled = false
	if v, err := c.SaveNetModes(cfg); err != nil || !v.Config.Enabled {
		t.Fatal("SaveNetModes changed the flag")
	}
}

func TestNetApplyNoDeadlock(t *testing.T) {
	c, w, _ := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect))
	netBase(t, c, w, home(), time.Now())
	done := make(chan error, 1)
	go func() {
		_, err := c.ApplyNetModes("")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil || !online(c) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ApplyNetModes hangs")
	}
	c.Disconnect()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.ApplyNetModes("") }()
	go func() { defer wg.Done(); time.Sleep(time.Millisecond); c.Disconnect() }()
	wg.Wait()
	// Either order ends with the user's disconnect: it comes after or skips.
	if online(c) && netNow(c).Override {
		t.Fatal("the rule's connect came after the user's disconnect")
	}
}

func TestNetStopWakesLoop(t *testing.T) {
	c, w, _ := netCtl(t)
	c.netPoll = 10 * time.Millisecond
	netEnable(t, c, netCfg(netmode.Connect))
	w.set(home())
	runNet(t, c, NetStartDecide)
	eventually(t, "watch", func() bool { _, n, _ := w.counts(); return n == 1 })
	c.StopNetModes()
	w.mu.Lock()
	ctx := w.ctxs[0]
	w.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("watch not cancelled")
	}
	s1, _, _ := w.counts()
	time.Sleep(50 * time.Millisecond)
	if s2, _, _ := w.counts(); s2 != s1 {
		t.Fatal("read after StopNetModes")
	}
	c.ResumeNetModes()
	eventually(t, "watch again", func() bool { _, n, _ := w.counts(); return n == 2 })
}

func TestNetBrokenFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "networks.json"), []byte(`{"version":1,"enabled":true,"rules":[`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	c, started := newCtlAt2(t, st)
	if !strings.Contains(c.Status().LoadError, "networks.json") {
		t.Fatal(c.Status().LoadError)
	}
	w := &fakeNet{events: make(chan struct{}, 1)}
	c.NetWatcher = w
	if _, err := c.ImportURIs(link); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SaveNetModes(netmode.Default()); err == nil || !strings.Contains(err.Error(), "networks.json не загружен") {
		t.Fatal(err)
	}
	if _, err := c.SetNetModesEnabled(false); err == nil {
		t.Fatal("toggled a broken file")
	}
	setAutoConnect(t, c)
	w.set(home())
	c.netStart(context.Background(), NetStartDecide)
	if s, _, _ := w.counts(); s != 0 || len(*started) != 1 {
		t.Fatalf("reads %d, starts %d", s, len(*started))
	}
	if v := c.NetModes(false); v.LoadError == "" || c.Status().Net != nil {
		t.Fatal("broken file not shown")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "networks.json")); !strings.HasSuffix(string(b), `"rules":[`) {
		t.Fatal("broken file overwritten")
	}
}

func TestNetStopResume(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	c.StopNetModes()
	w.set(cafe())
	c.netCheck(t0.Add(time.Second))
	c.netApply(0, netRev(c), netmode.Decision{Name: "x", Action: netmode.Action{Connect: netmode.Connect}}, "test", false)
	if starts() != 0 {
		t.Fatal("acted after StopNetModes")
	}
	c.ResumeNetModes()
	c.netCheck(t0.Add(2 * time.Second))
	if starts() != 1 {
		t.Fatal("not acting after ResumeNetModes")
	}
}

func TestNetConnectOverFailedEngine(t *testing.T) {
	c, w, _ := netCtl(t)
	var mu sync.Mutex
	var sessions []*fakeSession
	c.Start = func(cfg session.Config) (Session, error) {
		f := &fakeSession{reg: flows.NewRegistry(10), cfg: cfg}
		mu.Lock()
		sessions = append(sessions, f)
		mu.Unlock()
		return f, nil
	}
	c.recoverDelay = time.Hour
	ks := &fakeKS{}
	c.KillSwitch = ks
	setKillSwitch(t, c, true)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	netEnable(t, c, netCfg(netmode.Connect))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	sessions[0].fail()
	c.recMu.Lock()
	pending := c.rec.timer != nil
	c.recMu.Unlock()
	if !pending || c.Status().KillSwitch != "blocking" {
		t.Fatal("no pending recovery")
	}
	ks.ops = nil
	w.set(cafe())
	c.netCheck(t0.Add(time.Second))
	mu.Lock()
	n := len(sessions)
	mu.Unlock()
	if n != 2 || c.Status().State != "connected" {
		t.Fatalf("sessions %d, %s", n, c.Status().State)
	}
	if strings.Contains(strings.Join(ks.ops, ","), "release") {
		t.Fatalf("block released in between: %v", ks.ops)
	}
	c.recMu.Lock()
	pending = c.rec.timer != nil
	c.recMu.Unlock()
	if pending {
		t.Fatal("the pending recovery not superseded")
	}
}

func TestNetConnectRefused(t *testing.T) {
	c, started := brokenSettingsCtl(t)
	w := &fakeNet{events: make(chan struct{}, 1)}
	c.NetWatcher = w
	if _, err := c.ImportURIs(link); err != nil {
		t.Fatal(err)
	}
	netEnable(t, c, netCfg(netmode.Connect))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	w.set(cafe())
	c.netCheck(t0.Add(time.Second))
	if st := netNow(c); *started != 0 || st.Error != "settings.json не загружен" {
		t.Fatalf("%+v", st)
	}
	// No servers.
	c2, w2, starts := netCtl(t)
	for _, p := range c2.Profiles() {
		if err := c2.DeleteProfile(p.ID); err != nil {
			t.Fatal(err)
		}
	}
	netEnable(t, c2, netCfg(netmode.Connect, netRule("Кафе", knownNet(gCafe), netmode.Connect)))
	netBase(t, c2, w2, home(), t0)
	w2.set(cafe())
	c2.netCheck(t0.Add(time.Second))
	if st := netNow(c2); starts() != 0 || st.Error != "нет серверов" {
		t.Fatalf("%+v", st)
	}
	// At start: no servers is not an error.
	c3, w3, _ := netCtl(t)
	for _, p := range c3.Profiles() {
		c3.DeleteProfile(p.ID)
	}
	netEnable(t, c3, netCfg("", netRule("Кафе", knownNet(gCafe), netmode.Connect)))
	w3.set(cafe())
	c3.netStart(context.Background(), NetStartDecide)
	if st := netNow(c3); st.Error != "" {
		t.Fatalf("%+v", st)
	}
}

func TestNetStatusEveryPath(t *testing.T) {
	c, gate, started := gatedCtl(t)
	c.NetWatcher = &fakeNet{events: make(chan struct{}, 1)}
	netEnable(t, c, netCfg(netmode.Connect))
	if c.Status().Net == nil {
		t.Fatal("disconnected")
	}
	go c.Connect()
	waitStarting(t, c)
	if c.Status().Net == nil {
		t.Fatal("starting")
	}
	close(gate)
	eventually(t, "connected", func() bool { return c.Status().State == "connected" })
	if c.Status().Net == nil {
		t.Fatal("connected")
	}
	started()[0].fail()
	if st := c.Status(); st.State != "error" || st.Net == nil {
		t.Fatalf("engine failed: %+v", st)
	}
	c.Disconnect()
}

func TestNetSaveRulesetRefs(t *testing.T) {
	c, _, _ := netCtl(t)
	// Rule profiles not saved: no profile exists.
	cfg := netCfg(netmode.Connect, netmode.Rule{Name: "Дом", Match: knownNet(gHome), Action: netmode.Action{Ruleset: "abcdef123456"}})
	if _, err := c.SaveNetModes(cfg); err == nil || !strings.Contains(err.Error(), "профиль правил не найден") {
		t.Fatal(err)
	}
	if v := c.NetModes(false); len(v.Rulesets) != 0 || !strings.Contains(v.RulesetsNote, "создайте второй профиль") {
		t.Fatalf("%+v", v)
	}
	direct, vpn := rulesetsFor(t, c)
	cfg.Rules[0].Ruleset = vpn
	v, err := c.SaveNetModes(cfg)
	if err != nil || len(v.Rulesets) != 2 {
		t.Fatalf("%+v %v", v, err)
	}
	if used := c.NetRulesUsing(vpn); strings.Join(used, ",") != "Дом" {
		t.Fatal(used)
	}
	if err := c.DeleteRuleset(vpn); err != nil {
		t.Fatal(err)
	}
	v = c.NetModes(false)
	id := v.Config.Rules[0].ID
	if v.RuleErrors[id] != "Профиль правил удалён — выберите другой" {
		t.Fatalf("%+v", v.RuleErrors)
	}
	// The stale reference stays saveable while another rule is edited.
	next := v.Config
	next.Rules = append(next.Rules, netRule("Ещё", netmode.Match{Adapters: []string{netmode.Ethernet}}, netmode.Connect))
	if _, err := c.SaveNetModes(next); err != nil {
		t.Fatal(err)
	}
	// A new missing reference is refused; the unknown one too.
	next = c.NetModes(false).Config
	next.Rules[1].Ruleset = vpn
	if _, err := c.SaveNetModes(next); err == nil || !strings.Contains(err.Error(), "«Ещё»: профиль правил не найден") {
		t.Fatal(err)
	}
	next = c.NetModes(false).Config
	next.Unknown.Ruleset = vpn
	if _, err := c.SaveNetModes(next); err == nil || !strings.Contains(err.Error(), "Неизвестная сеть: профиль правил не найден") {
		t.Fatal(err)
	}
	next.Unknown.Ruleset = direct
	if _, err := c.SaveNetModes(next); err != nil {
		t.Fatal(err)
	}
}

func TestNetRuleset(t *testing.T) {
	c, w, _ := netCtl(t)
	direct, vpn := rulesetsFor(t, c)
	var atConnect string
	c.Start = func(cfg session.Config) (Session, error) {
		atConnect, _ = c.rulesetActive()
		return &fakeSession{reg: flows.NewRegistry(10), cfg: cfg}, nil
	}
	cfg := netCfg("", netmode.Rule{Name: "Работа", Match: knownNet(gCafe), Action: netmode.Action{Connect: netmode.Connect, Ruleset: vpn}})
	cfg.Unknown.Ruleset = direct
	netEnable(t, c, cfg)
	if u := c.NetRulesUsing(direct); strings.Join(u, ",") != netmode.UnknownName {
		t.Fatal(u)
	}
	netBase(t, c, w, home(), time.Now())
	// One decision: the profile first, then the connect.
	c.netMu.Lock()
	g := c.net.gen
	c.netMu.Unlock()
	c.netApply(g, netRev(c), netmode.Decide(c.NetModes(false).Config, *cafe()), "network change", false)
	if atConnect != vpn {
		t.Fatalf("the profile %q at connect, want %q first", atConnect, vpn)
	}
	if st := netNow(c); !strings.Contains(st.Text, "Профиль правил «VPN» включён правилом сети «Работа»") {
		t.Fatal(st.Text)
	}
	// A missing profile: the error, the connect still runs.
	c.Disconnect()
	c.netMu.Lock()
	g = c.net.gen
	c.netMu.Unlock()
	c.netApply(g, netRev(c), netmode.Decision{Name: "Работа", Action: netmode.Action{Connect: netmode.Connect, Ruleset: "0badc0de0bad"}}, "network change", false)
	if st := netNow(c); !online(c) || !strings.Contains(st.Error, "профиль правил не найден") {
		t.Fatalf("%+v", st)
	}
	// The user's switch is a manual choice.
	if _, err := c.SwitchRuleset(direct, SourceUser, SwitchOptions{}); err != nil {
		t.Fatal(err)
	}
	if !netNow(c).Override {
		t.Fatal("no override after the user's switch")
	}
}

func TestNetInstallForBackup(t *testing.T) {
	c, w, starts := netCtl(t)
	cfg := netCfg(netmode.Connect)
	cfg.Enabled = true
	if err := c.Store.SaveNetModes(cfg); err != nil {
		t.Fatal(err)
	}
	c.saveMu.Lock()
	c.mu.Lock()
	c.netInstallLocked(cfg)
	c.mu.Unlock()
	c.saveMu.Unlock()
	w.set(cafe())
	c.netCheck(time.Now())
	if starts() != 0 {
		t.Fatal("a restore acted")
	}
	c.netMu.Lock()
	base := c.net.base
	c.netMu.Unlock()
	if base.Empty() {
		t.Fatal("no baseline")
	}
	exp, err := c.netExportLocked()
	if err != nil || !exp.Enabled {
		t.Fatal(err)
	}
	c.netInstallLoadedLocked(netmode.Default(), errors.New("networks.json: плохо"))
	o := cafe()
	o.ID, o.GatewayMAC = gOffice, "cc-cc-cc-cc-cc-cc"
	w.set(o)
	c.netCheck(time.Now())
	if starts() != 0 || c.NetModes(false).LoadError == "" || c.netOn() {
		t.Fatal("a broken install acts")
	}
}

func TestNetSSIDOnlyWhileSettling(t *testing.T) {
	c, w, _ := netCtl(t)
	w.ssid = "CafeSSID"
	netEnable(t, c, netCfg(netmode.Connect, netmode.Rule{Name: "Кафе", Match: netmode.Match{SSIDs: []string{"CafeSSID"}}, Action: netmode.Action{Connect: netmode.Disconnect}}))
	t0 := time.Now()
	e := home()
	e.Adapter = netmode.Ethernet
	netBase(t, c, w, e, t0)
	w.set(cafe())
	c.netCheck(t0.Add(time.Second))
	for i := 3; i < 60; i += 5 {
		c.netCheck(t0.Add(time.Duration(i) * time.Second))
	}
	_, _, n := w.counts()
	if n != 1 || w.ssidFor[0] != "{AD-1}" {
		t.Fatalf("SSID asked %d times: %v", n, w.ssidFor)
	}
	if netNow(c).Rule != "Кафе" {
		t.Fatalf("the SSID rule did not decide: %+v", netNow(c))
	}
	// Without SSID rules: never.
	c2, w2, _ := netCtl(t)
	netEnable(t, c2, netCfg(netmode.Connect))
	netBase(t, c2, w2, home(), t0)
	w2.set(cafe())
	c2.netCheck(t0.Add(time.Second))
	c2.netCheck(t0.Add(3 * time.Second))
	if _, _, n := w2.counts(); n != 0 {
		t.Fatal("SSID asked without SSID rules")
	}
	// «Текущее»: the active adapter; "" for Ethernet.
	if s, err := c2.CurrentSSID(); err != nil || w2.ssidFor[0] != "{AD-1}" || s != "" {
		t.Fatalf("%q %v %v", s, err, w2.ssidFor)
	}
	w2.set(e)
	if s, err := c2.CurrentSSID(); err != nil || s != "" {
		t.Fatal(s, err)
	}
	w2.ssidErr = netmode.ErrSSIDDenied
	w2.set(cafe())
	if _, err := c2.CurrentSSID(); err == nil || !strings.Contains(err.Error(), "Расположение") {
		t.Fatal(err)
	}
}

func TestNetViewPrivate(t *testing.T) {
	c, w, _ := netCtl(t)
	w.ssid = "MySecretWiFi"
	netEnable(t, c, netCfg(netmode.Connect, netmode.Rule{Name: "Квартира", Match: netmode.Match{SSIDs: []string{"MySecretWiFi"}, Names: []string{"HomeNet"}, Networks: []netmode.Known{{ID: gHome, Name: "HomeNet"}}}, Action: netmode.Action{Connect: netmode.Keep}}))
	netBase(t, c, w, cafe(), time.Now())
	w.set(home())
	c.NetModes(true)
	c.netMu.Lock()
	c.net.last = NetState{Rule: "Квартира", Text: "Сеть сменилась: правило «Квартира», ничего менять не нужно", Error: "не подключено: dial example.org 203.0.113.7: refused", OffBy: "Квартира", Off: true}
	c.netMu.Unlock()
	v := c.NetModes(false).Private()
	b := strings.Join([]string{v.Config.Rules[0].Name, v.Config.Rules[0].Match.SSIDs[0], v.Config.Rules[0].Match.Names[0], v.Config.Rules[0].Match.Networks[0].Name,
		v.Current.Active.Name, v.Current.Active.SSID, v.Current.Active.AdapterName, v.Match.Name, v.State.Rule, v.State.Text, v.State.Error, v.State.OffBy}, "|")
	for _, s := range []string{"Квартира", "MySecretWiFi", "HomeNet", "Беспроводная", "example.org", "203.0.113.7"} {
		if strings.Contains(b, s) {
			t.Fatalf("%s in %s", s, b)
		}
	}
	if !strings.Contains(v.State.Text, "правило «***»") {
		t.Fatal(v.State.Text)
	}
	ns := NetState{Rule: "Квартира", Text: "Отключено правилом сети «Квартира»", Error: "не подключено: example.org"}.Private()
	if strings.Contains(ns.Rule+ns.Text+ns.Error, "Квартира") || strings.Contains(ns.Error, "example.org") {
		t.Fatalf("%+v", ns)
	}
}

func TestNetNoSecretsInLogsOrDiag(t *testing.T) {
	c, w, _ := netCtl(t)
	c.Log = slog.New(logx.NewHandler(c.EngineLog, c.Redactor, slog.LevelDebug, nil))
	w.ssid = "MySecretWiFi"
	netEnable(t, c, netCfg(netmode.Connect, netmode.Rule{Name: "Кафе", Match: netmode.Match{SSIDs: []string{"MySecretWiFi"}}, Action: netmode.Action{Connect: netmode.Disconnect}}))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	w.set(cafe())
	c.netCheck(t0.Add(time.Second))
	c.netCheck(t0.Add(3 * time.Second))
	if netNow(c).Rule != "Кафе" {
		t.Fatalf("%+v", netNow(c))
	}
	var all strings.Builder
	for _, e := range c.EngineLog.Since(0, 0) {
		all.WriteString(e.Msg + "\n")
	}
	all.WriteString(c.Diagnostics(nil, false))
	out := all.String()
	if !strings.Contains(out, "сети: включены") {
		t.Fatal(out)
	}
	for _, s := range []string{"MySecretWiFi", "CafeNet", gCafe, "10.9.8.1", "bb-bb-bb", "{AD-1}"} {
		if strings.Contains(out, s) {
			t.Fatalf("%s in the log or diagnostics:\n%s", s, out)
		}
	}
	// «Скрыть данные»: the rule names (here the SSID itself) go too.
	next := netCfg(netmode.Connect, netmode.Rule{Name: "MySecretWiFi", Match: netmode.Match{SSIDs: []string{"MySecretWiFi"}}, Action: netmode.Action{Connect: netmode.Disconnect}})
	if _, err := c.SaveNetModes(next); err != nil {
		t.Fatal(err)
	}
	c.Connect()
	o := cafe()
	o.ID, o.GatewayMAC = gOffice, "cc-cc-cc-cc-cc-cc"
	w.set(o)
	c.netCheck(t0.Add(10 * time.Second))
	c.netCheck(t0.Add(13 * time.Second))
	if netNow(c).Rule != "MySecretWiFi" {
		t.Fatalf("%+v", netNow(c))
	}
	priv := c.Diagnostics(nil, true)
	if strings.Contains(priv, "MySecretWiFi") || !strings.Contains(priv, "правило «***»") {
		t.Fatalf("a rule name in the private report:\n%s", priv)
	}
}

func TestNetWatchErrorPolls(t *testing.T) {
	c, w, starts := netCtl(t)
	w.watchErr = errors.New("NotifyIpInterfaceChange: отказано")
	c.netPoll = 20 * time.Millisecond
	netEnable(t, c, netCfg(netmode.Connect))
	w.set(home())
	runNet(t, c, NetStartDecide)
	eventually(t, "baseline", func() bool { s, _, _ := w.counts(); return s >= 1 })
	w.set(cafe())
	eventually(t, "connect by polling", func() bool { return starts() == 1 })
	if v := c.NetModes(false); !strings.Contains(v.Unavailable, "задержкой до 30 с") {
		t.Fatal(v.Unavailable)
	}
}

func TestNetLockOrder(t *testing.T) {
	c, _, _ := netCtl(t)
	var calls atomic.Int32
	c.testNetManual = func() {
		calls.Add(1)
		for name, m := range map[string]*sync.Mutex{"saveMu": &c.saveMu, "lifeMu": &c.lifeMu, "mu": &c.mu} {
			if !free(m) {
				t.Errorf("netManual with %s held", name)
			}
		}
	}
	direct, vpn := rulesetsFor(t, c)
	c.Connect()
	c.Reconnect()
	c.Disconnect()
	c.KillSwitch = &fakeKS{}
	c.ReleaseKillSwitch()
	c.SwitchRuleset(vpn, SourceTray, SwitchOptions{})
	c.ActivateRuleset(direct, SourceNetwork) // not manual
	// rulesetsFor's CreateRuleset (without activating) was not manual either.
	if calls.Load() != 5 {
		t.Fatal(calls.Load())
	}
	if _, err := c.CreateRuleset(RulesetInput{Name: "Третий", From: "active"}, SourceUser); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 5 {
		t.Fatal("create without activating counted as manual")
	}
	if _, err := c.CreateRuleset(RulesetInput{Name: "Четвёртый", From: "active", Activate: true}, SourceUser); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 6 {
		t.Fatal("create and activate is not a manual action")
	}
}

// PLAN §7.1-6: a user who never enables «Сети» gets no file and no reads.
func TestNetUnusedCreatesNothing(t *testing.T) {
	c, w, _ := netCtl(t)
	c.NetModes(false)
	c.Status()
	c.Diagnostics(nil, false)
	c.netStart(context.Background(), NetStartDecide)
	if _, err := os.Stat(filepath.Join(c.Store.Dir, "networks.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("networks.json created")
	}
	if s, wa, ss := w.counts(); s+wa+ss != 0 {
		t.Fatal("read while unused")
	}
}

// A pending change first read without an NLM ID: its first identified
// read does not settle what relaxes; a confirming read with the ID does.
func TestNetRefinedPendingNeedsConfirm(t *testing.T) {
	c, w, _ := netCtl(t)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	t0 := time.Now()
	netBase(t, c, w, cafe(), t0)
	w.set(unid(home()))
	c.netCheck(t0.Add(time.Second)) // protective: stays connected
	w.set(home())
	c.netCheck(t0.Add(3 * time.Second)) // the first identified read
	if !online(c) || !netNow(c).Pending {
		t.Fatal("disconnected on the first identified read")
	}
	c.netCheck(t0.Add(4 * time.Second))
	if !online(c) {
		t.Fatal("disconnected before netConfirm from the identified read")
	}
	c.netCheck(t0.Add(5 * time.Second))
	if online(c) || netNow(c).Rule != "Дом" {
		t.Fatalf("not settled by the confirming read: %+v", netNow(c))
	}

	// The ID of the network just left, reported on the new link: not the
	// pending network with its ID (the baseline comparison decides).
	c, w, _ = netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	netBase(t, c, w, home(), t0)
	n := unid(cafe())
	n.ID = ""
	w.set(n)
	c.netCheck(t0.Add(time.Second))
	if !online(c) {
		t.Fatal("no protective connect")
	}
	stale := cafe()
	stale.ID = gHome
	w.set(stale)
	for i := 3; i <= 9; i += 2 {
		c.netCheck(t0.Add(time.Duration(i) * time.Second))
		if !online(c) {
			t.Fatalf("disconnected at %ds on the old network's ID", i)
		}
	}
}

// A read that may be another network never takes the cached Wi-Fi name:
// an Unclear read taken as a change asks for its own.
func TestNetSSIDNotReusedForUnclearChange(t *testing.T) {
	c, w, _ := netCtl(t)
	w.ssid = "HomeWiFi"
	netEnable(t, c, netCfg(netmode.Connect, netmode.Rule{Name: "Дом", Match: netmode.Match{SSIDs: []string{"HomeWiFi"}}, Action: netmode.Action{Connect: netmode.Disconnect}}))
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	e := cafe()
	e.Adapter, e.AdapterID = netmode.Ethernet, "{AD-2}"
	netBase(t, c, w, e, t0)
	w.set(home())
	c.netCheck(t0.Add(time.Second))
	c.netCheck(t0.Add(3 * time.Second))
	if online(c) || netNow(c).Rule != "Дом" {
		t.Fatalf("home not settled: %+v", netNow(c))
	}
	// Same adapter and gateway IP, no ID, no MAC: another Wi-Fi.
	n := unid(home())
	n.ID, n.GatewayMAC, n.Name = "", "", "SomeCafe"
	w.ssid = "SomeCafe"
	w.set(n)
	for i := 5; i <= 19; i += 2 {
		c.netCheck(t0.Add(time.Duration(i) * time.Second))
		if v := c.NetModes(false); v.Current.Active == nil || v.Current.Active.SSID == "HomeWiFi" {
			t.Fatalf("read %d shows the cached Wi-Fi name", i)
		}
	}
	c.netCheck(t0.Add(21 * time.Second))
	c.netCheck(t0.Add(23 * time.Second))
	if !online(c) {
		t.Fatalf("an unidentified network got the home rule: %+v", netNow(c))
	}
	if st := netNow(c); st.Rule != netmode.UnknownName || st.Pending {
		t.Fatalf("%+v", st)
	}
	if _, _, q := w.counts(); q != 2 {
		t.Fatalf("SSID asked %d times, want 2 (home, the new network)", q)
	}
	// A failed WLAN query is not cached: the settle asks again.
	c.netMu.Lock()
	c.netCacheSSIDLocked(netmode.Ident{}, "", false)
	c.netMu.Unlock()
	w.mu.Lock()
	w.ssidErr = errors.New("wlan down")
	w.mu.Unlock()
	w.set(cafe())
	c.netCheck(t0.Add(25 * time.Second))
	c.netMu.Lock()
	ok := c.net.ssidOK
	c.netMu.Unlock()
	if ok {
		t.Fatal("a failed WLAN query cached")
	}
	w.mu.Lock()
	w.ssidErr = nil
	w.mu.Unlock()
	c.netCheck(t0.Add(27 * time.Second))
	if _, _, q := w.counts(); q != 4 {
		t.Fatalf("the settle did not ask again: %d", q)
	}
}

// The user acts while the start reads the network: AutoConnect does not
// override them, nor start anything once HyRoute exits.
func TestNetStartAutoConnectAfterUser(t *testing.T) {
	for _, act := range []string{"disconnect", "stop"} {
		c, w, starts := netCtl(t)
		setAutoConnect(t, c)
		netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
		w.set(unid(home()))
		w.onSnap = func() {
			if act == "disconnect" {
				c.Disconnect()
			} else {
				c.StopNetModes()
			}
		}
		c.netStart(context.Background(), NetStartDecide)
		if starts() != 0 || online(c) {
			t.Fatalf("%s: AutoConnect connected", act)
		}
	}
	// Without an action: it connects.
	c, w, starts := netCtl(t)
	setAutoConnect(t, c)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	w.set(unid(home()))
	c.netStart(context.Background(), NetStartDecide)
	if starts() != 1 {
		t.Fatal("AutoConnect did not connect")
	}
}

// networks.json load errors name rules the view does not have.
func TestNetLoadErrorPrivate(t *testing.T) {
	v := NetModesView{LoadError: "networks.json: Правило сети «МойДом»: укажите хотя бы одно условие"}.Private()
	if strings.Contains(v.LoadError, "МойДом") || !strings.Contains(v.LoadError, "Правило сети «***»") {
		t.Fatal(v.LoadError)
	}
	if s := maskRuleNames("Правило сети «Неизвестная сеть»", nil); s != "Правило сети «Неизвестная сеть»" {
		t.Fatal(s)
	}
}

// «Применить сейчас» decides on a fresh read: a disconnect acts only when
// that rule is the one the user confirmed.
func TestNetApplyConfirmsDisconnect(t *testing.T) {
	c, w, _ := netCtl(t)
	netEnable(t, c, netCfg(netmode.Connect, netRule("Дом", knownNet(gHome), netmode.Disconnect)))
	netBase(t, c, w, cafe(), time.Now())
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	w.set(home()) // the page still shows the café
	for _, key := range []string{"", "unknown", "000000000000"} {
		v, err := c.ApplyNetModes(key)
		if err != nil || !v.Confirm || v.Match == nil || v.Match.Name != "Дом" || !online(c) {
			t.Fatalf("%q: %v %+v", key, err, v.Match)
		}
	}
	if !netNow(c).Override {
		t.Fatal("an unconfirmed apply cleared the user's override")
	}
	v, err := c.ApplyNetModes(NetRuleKey(c.NetModes(false).Match.RuleID, false))
	if err != nil || v.Confirm || online(c) || netNow(c).Rule != "Дом" {
		t.Fatalf("%v %+v", err, netNow(c))
	}
}

// A decision taken on a config that changed or went off is not applied.
func TestNetApplySkipsChangedConfig(t *testing.T) {
	c, w, starts := netCtl(t)
	cfg := netCfg(netmode.Connect)
	netEnable(t, c, cfg)
	netBase(t, c, w, home(), time.Now())
	d := netmode.Decision{Name: netmode.UnknownName, Unknown: true, Action: netmode.Action{Connect: netmode.Connect}}
	snapshot := func() (uint64, uint64) {
		c.netMu.Lock()
		defer c.netMu.Unlock()
		return c.net.gen, c.net.rev
	}
	g, rev := snapshot()
	if _, err := c.SetNetModesEnabled(false); err != nil {
		t.Fatal(err)
	}
	c.netApply(g, rev, d, "network change", false)
	if starts() != 0 {
		t.Fatal("applied after the feature went off")
	}
	if _, err := c.SetNetModesEnabled(true); err != nil {
		t.Fatal(err)
	}
	g, rev = snapshot()
	if _, err := c.SaveNetModes(cfg); err != nil {
		t.Fatal(err)
	}
	c.netApply(g, rev, d, "network change", false)
	if starts() != 0 {
		t.Fatal("applied a decision of the config before the save")
	}
	g, rev = snapshot()
	c.netApply(g, rev, d, "network change", false)
	if starts() != 1 {
		t.Fatal("a current decision not applied")
	}
}

// A change first read without an NLM ID: the identified read's «Подключить»
// is protective and runs at once, not after the confirming read.
func TestNetRefineConnectsAtOnce(t *testing.T) {
	c, w, starts := netCtl(t)
	netEnable(t, c, netCfg("", netRule("Кафе", knownNet(gCafe), netmode.Connect)))
	t0 := time.Now()
	netBase(t, c, w, home(), t0)
	w.set(unid(cafe()))
	c.netCheck(t0.Add(time.Second))
	if starts() != 0 {
		t.Fatal("«Неизвестная сеть: не менять» connected")
	}
	w.set(cafe())
	c.netCheck(t0.Add(2 * time.Second))
	if starts() != 1 || !strings.Contains(netNow(c).Text, "Подключено правилом сети «Кафе»") {
		t.Fatalf("not connected at the identified read: %d %+v", starts(), netNow(c))
	}
	// A disconnect still waits for the confirming read.
	c, w, _ = netCtl(t)
	netEnable(t, c, netCfg("", netRule("Кафе", knownNet(gCafe), netmode.Disconnect)))
	netBase(t, c, w, home(), t0)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	w.set(unid(cafe()))
	c.netCheck(t0.Add(time.Second))
	w.set(cafe())
	c.netCheck(t0.Add(2 * time.Second))
	if !online(c) {
		t.Fatal("disconnected at the first identified read")
	}
}

// Off and on again before the loop saw the off: the current network is
// the baseline at once, not whatever a poll finds later.
func TestNetQuickToggleTakesBaseline(t *testing.T) {
	c, w, _ := netCtl(t)
	c.netQuiet, c.netConfirm, c.netPoll = 5*time.Millisecond, 5*time.Millisecond, time.Hour
	netEnable(t, c, netCfg(netmode.Connect))
	w.set(home())
	runNet(t, c, NetStartDecide)
	baseIs := func(n *netmode.Network) func() bool {
		want := n.Ident()
		return func() bool {
			c.netMu.Lock()
			defer c.netMu.Unlock()
			return c.net.base == want
		}
	}
	eventually(t, "baseline", baseIs(home()))
	for i := 0; i < 10; i++ {
		n := cafe()
		if i%2 == 1 {
			n = home()
		}
		w.set(n)
		if _, err := c.SetNetModesEnabled(false); err != nil {
			t.Fatal(err)
		}
		if _, err := c.SetNetModesEnabled(true); err != nil {
			t.Fatal(err)
		}
		eventually(t, "baseline after a quick toggle", baseIs(n))
	}
}

// Load (v1.2.0's backup restore calls it) installs like any other change:
// hand-written rules keep their IDs, enabling takes a baseline.
func TestNetReloadInstalls(t *testing.T) {
	c, w, starts := netCtl(t)
	cfg := netCfg(netmode.Connect, netmode.Rule{Name: "Вручную", Match: netmode.Match{Adapters: []string{netmode.WiFi}}})
	if err := c.Store.SaveNetModes(cfg); err != nil {
		t.Fatal(err)
	}
	c.Load()
	id := c.NetModes(false).Config.Rules[0].ID
	if id == "" {
		t.Fatal("no ID")
	}
	cfg.Enabled = true
	if err := c.Store.SaveNetModes(cfg); err != nil {
		t.Fatal(err)
	}
	c.Load()
	if got := c.NetModes(false).Config.Rules[0].ID; got != id {
		t.Fatalf("ID %s → %s", id, got)
	}
	if !c.netOn() || !c.netBaselineDue() {
		t.Fatal("enabled by a reload without a baseline reset")
	}
	w.set(cafe())
	c.netCheck(time.Now())
	if starts() != 0 || c.netBaselineDue() {
		t.Fatal("a reload acted, or took no baseline")
	}
}

// At start the «Неизвестная сеть» profile in place of the one a rule
// selects is labelled as such until the confirming read.
func TestNetStartProtectiveRulesetText(t *testing.T) {
	c, w, _ := netCtl(t)
	direct, vpn := rulesetsFor(t, c)
	cfg := netCfg("", netmode.Rule{Name: "Дом", Match: knownNet(gHome), Action: netmode.Action{Ruleset: direct}})
	cfg.Unknown.Ruleset = vpn
	netEnable(t, c, cfg)
	if err := c.ActivateRuleset(direct, SourceNetwork); err != nil {
		t.Fatal(err)
	}
	c.netConfirm = time.Millisecond
	w.set(home())
	var between string
	var rsBetween string
	w.onSnap = func() { // the first read
		w.mu.Lock()
		w.onSnap = func() { // the confirming read
			between = netNow(c).Text
			rsBetween, _ = activeRS(c)
		}
		w.mu.Unlock()
	}
	c.netStart(context.Background(), NetStartDecide)
	if rsBetween != vpn || !strings.Contains(between, "Профиль правил «VPN» включён при запуске: правило «Неизвестная сеть», пока сеть не подтверждена") {
		t.Fatalf("%s %q", rsBetween, between)
	}
	if id, _ := activeRS(c); id != direct || !strings.Contains(netNow(c).Text, "правилом сети «Дом»") {
		t.Fatalf("%s %q", id, netNow(c).Text)
	}
}
