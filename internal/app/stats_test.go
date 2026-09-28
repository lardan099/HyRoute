package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/stats"
	"github.com/lardan099/hyroute/internal/store"
	"github.com/lardan099/hyroute/internal/tunnels"
)

// hookFiles are the store's statistics files with hooks around writes
// and listings (blocking them, or checking the locks).
type hookFiles struct {
	*store.StatsFiles
	mu    sync.Mutex
	write func(name string)
	list  func()
}

func (h *hookFiles) Write(name string, b []byte) error {
	h.mu.Lock()
	f := h.write
	h.mu.Unlock()
	if f != nil {
		f(name)
	}
	return h.StatsFiles.Write(name, b)
}

func (h *hookFiles) List() ([]string, error) {
	h.mu.Lock()
	f := h.list
	h.mu.Unlock()
	if f != nil {
		f()
	}
	return h.StatsFiles.List()
}

func (h *hookFiles) setWrite(f func(string)) { h.mu.Lock(); h.write = f; h.mu.Unlock() }
func (h *hookFiles) setList(f func())        { h.mu.Lock(); h.list = f; h.mu.Unlock() }

func hooked(c *Controller) *hookFiles {
	h := &hookFiles{StatsFiles: c.Store.StatsFiles()}
	c.stats.Configure(h)
	return h
}

// statsCtl is a controller with one server, connected.
func statsCtl(t *testing.T) (*Controller, *[]*fakeSession, string) {
	t.Helper()
	c, started := newCtl(t)
	res, err := c.ImportURIs(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	return c, started, res.Added[0].ID
}

func openFlow(reg *flows.Registry, path, route, profile, outcome string) *flows.Record {
	rec := reg.Open(&flows.Record{Proto: 6, Process: filepath.Base(strings.ReplaceAll(path, `\`, "/")), Path: path})
	rec.Set(func(f *flows.Fields) { f.Route, f.Profile, f.Outcome = route, profile, outcome })
	return rec
}

func today(t *testing.T, c *Controller) stats.Report {
	t.Helper()
	rep, err := c.Stats("today")
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func statsDay(t *testing.T, c *Controller) *stats.File {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.Store.Dir, "stats", "day-"+time.Now().Format("2006-01-02")+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var f stats.File
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out: %s", what)
}

// free reports that m can be taken within 200 ms: a lock the calling
// goroutine holds never can (another goroutine may hold it briefly).
func free(m *sync.Mutex) bool {
	for i := 0; i < 200; i++ {
		if m.TryLock() {
			m.Unlock()
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
	}
}

func TestStatsSession(t *testing.T) {
	c, started, de := statsCtl(t)
	f := (*started)[0]
	tun := openFlow(f.reg, `C:\Tools\curl.exe`, "tunnel", de, "relayed")
	tun.Set(func(x *flows.Fields) { x.Domain = "www.example.com" })
	tun.Sent.Add(100)
	tun.Recv.Add(1000)
	c.sampleStats(time.Now(), true)
	rep := today(t, c)
	if rep.Total.TC != 1 || rep.Total.TU != 100 || rep.Total.TD != 1000 {
		t.Fatalf("%+v", rep.Total)
	}
	if s := rep.Servers[0]; s.Key != de || s.Name != "DE one" || s.Gone {
		t.Fatalf("%+v", s)
	}
	f.reg.Close(tun, time.Now())
	if rep := today(t, c); rep.Total.TC != 1 || rep.Total.TU != 100 {
		t.Fatalf("closed: %+v", rep.Total)
	}
	// A direct flow the engine never closes: Disconnect samples it and
	// kicks RunStats, which writes it.
	dir := openFlow(f.reg, `C:\Tools\curl.exe`, "direct", "", "passed")
	dir.Sent.Add(50)
	c.Disconnect()
	if rep := today(t, c); rep.Total.DC != 1 || rep.Total.DU != 50 || len(c.statsFlush) != 1 {
		t.Fatalf("%+v kick %d", rep.Total, len(c.statsFlush))
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.RunStats(ctx)
	waitFor(t, "the day file", func() bool {
		_, err := os.Stat(filepath.Join(c.Store.Dir, "stats", "day-"+time.Now().Format("2006-01-02")+".json"))
		return err == nil
	})
	if d := statsDay(t, c); d.Total.DU != 50 || d.Total.TU != 100 {
		t.Fatalf("%+v", d.Total)
	}
}

// No lifecycle path waits for the statistics' disk work.
func TestDisconnectDoesNotWaitForStatsIO(t *testing.T) {
	c, started, de := statsCtl(t)
	h := hooked(c)
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	h.setWrite(func(string) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
	})
	rec := openFlow((*started)[0].reg, `C:\a.exe`, "tunnel", de, "relayed")
	rec.Sent.Add(10)
	c.sampleStats(time.Now(), false)
	flushed := make(chan struct{})
	go func() { c.stats.Flush(time.Now()); close(flushed) }()
	<-entered // the flush holds the disk lock in a write
	dir := openFlow((*started)[0].reg, `C:\b.exe`, "direct", "", "passed")
	dir.Sent.Add(7)
	within(t, time.Second, "Disconnect", c.Disconnect)
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	within(t, time.Second, "Reconnect", func() { c.Reconnect() })
	h.setWrite(nil)
	close(gate)
	<-flushed
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran := make(chan struct{})
	go func() { c.RunStats(ctx); close(ran) }()
	waitFor(t, "the Disconnect's deltas on disk", func() bool {
		b, _ := os.ReadFile(filepath.Join(c.Store.Dir, "stats", "day-"+time.Now().Format("2006-01-02")+".json"))
		return bytes.Contains(b, []byte(`"du":7`))
	})
	cancel()
	<-ran // its last flush is done before the next part and the TempDir cleanup

	// The same with the disk lock held by a slow «Без сайтов».
	gate2 := make(chan struct{})
	entered2 := make(chan struct{}, 1)
	h.setWrite(func(string) {
		select {
		case entered2 <- struct{}{}:
		default:
		}
		<-gate2
	})
	modeSet := make(chan struct{})
	go func() { c.SetStatsMode("no-sites"); close(modeSet) }()
	<-entered2
	within(t, time.Second, "Disconnect", c.Disconnect)
	h.setWrite(nil)
	close(gate2)
	// Its writes go on after the gate opens: wait, or the TempDir cleanup
	// races them («directory not empty»).
	<-modeSet
}

func TestEndSessionDoesNotWaitForMu(t *testing.T) {
	for _, withKS := range []bool{false, true} {
		c, started, de := statsCtl(t)
		if withKS {
			c.KillSwitch = &fakeKS{}
		}
		rec := openFlow((*started)[0].reg, `C:\a.exe`, "tunnel", de, "relayed")
		rec.Sent.Add(10)
		c.mu.Lock()
		within(t, 2*time.Second, "EndSession", c.EndSession)
		c.mu.Unlock()
		if d := statsDay(t, c); d.Total.TU != 10 {
			t.Fatalf("%+v", d.Total)
		}
		// The disk lock held by a report: EndSession waits about a second.
		h := hooked(c)
		gate := make(chan struct{})
		entered := make(chan struct{}, 1)
		h.setList(func() {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-gate
		})
		go c.Stats("today")
		<-entered
		start := time.Now()
		within(t, 3*time.Second, "EndSession", c.EndSession)
		if el := time.Since(start); el < statsEndWait-100*time.Millisecond {
			t.Fatalf("returned after %v", el)
		}
		h.setList(nil)
		close(gate)
	}
}

func TestShutdownFlushesWithoutSession(t *testing.T) {
	c, _ := newCtl(t)
	h := hooked(c)
	var lifeFree atomic.Int32
	h.setWrite(func(string) {
		if free(&c.lifeMu) {
			lifeFree.Store(1)
		} else {
			lifeFree.Store(-1)
		}
	})
	rec := c.proxyRecord(store.LocalProxy{ID: "Px1", Name: "Биржа"}, 6, socks5.Addr{Host: "a.example", Port: 443}, "de", "", false, "proxied")
	rec.Sent.Add(5)
	c.proxyFlows.Close(rec, time.Now())
	c.Shutdown()
	if d := statsDay(t, c); d.Total.TU != 5 || lifeFree.Load() != 1 {
		t.Fatalf("%+v lifeMu free %d", d.Total, lifeFree.Load())
	}
}

// Direct UDP flows met again after a reconnect count as new connections;
// their bytes are not counted twice.
func TestStatsReconnectUDP(t *testing.T) {
	c, started, _ := statsCtl(t)
	udp := func(reg *flows.Registry, sent int64) {
		rec := reg.Open(&flows.Record{Proto: 17, Process: "game.exe"})
		rec.Recv.Store(-1)
		rec.Set(func(f *flows.Fields) { f.Route, f.Outcome = "direct", "passed" })
		rec.Sent.Add(sent)
	}
	udp((*started)[0].reg, 100)
	c.sampleStats(time.Now(), false)
	if err := c.Reconnect(); err != nil {
		t.Fatal(err)
	}
	udp((*started)[1].reg, 30)
	c.Disconnect()
	if rep := today(t, c); rep.Total.DC != 2 || rep.Total.DU != 130 {
		t.Fatalf("%+v", rep.Total)
	}
}

func TestStatsProxies(t *testing.T) {
	stub := &socks5.Server{}
	if err := stub.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	c, _ := newCtl(t)
	m := &tunnels.Manager{Log: c.Log, New: func(hysteria.Profile, tunnels.Hooks) tunnels.Runner {
		return &stubRunner{c: socks5.Client{Server: stub.Addr()}}
	}}
	m.Sync([]hysteria.Profile{{ID: "p1", Name: "P"}})
	defer m.StopAll()
	p := store.LocalProxy{ID: "AbC", Name: "Биржа", Profile: "p1", Port: 1080}
	c.mu.Lock()
	c.sess = endpointSession{fakeSession: &fakeSession{}, ep: m.Get("p1")}
	c.proxies = []store.LocalProxy{p}
	c.mu.Unlock()
	dial := c.proxyDialer(p)
	conn, err := dial(t.Context(), socks5.AddrFromAddrPort(echo.Addr().(*net.TCPAddr).AddrPort()))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "hello")
	io.ReadFull(conn, make([]byte, 5))
	conn.Close()
	conn.Close()
	if n := len(c.proxyFlows.Closed()); n != 1 {
		t.Fatalf("%d closed records", n)
	}
	if _, err := dial(t.Context(), socks5.Addr{Host: "127.0.0.1", Port: 1}); err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	// A dial the proxy's stop cancels is not a refusal: not counted.
	stopped, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := dial(stopped, socks5.AddrFromAddrPort(echo.Addr().(*net.TCPAddr).AddrPort())); err == nil {
		t.Fatal("dial with a cancelled context succeeded")
	}
	c.sampleStats(time.Now(), false)
	rep := today(t, c)
	a := rep.Apps[0]
	if len(rep.Apps) != 1 || a.Key != "proxy:AbC" || a.Name != "Биржа" || a.Gone || a.TC != 1 || a.TU != 5 || a.TD != 5 || a.F != 1 {
		t.Fatalf("%+v", rep.Apps)
	}
	if s := rep.Servers[0]; s.Key != "p1" || s.TC != 1 || s.F != 1 {
		t.Fatalf("%+v", rep.Servers)
	}
	// Deleted since: gone.
	c.mu.Lock()
	c.proxies = nil
	c.mu.Unlock()
	if a := today(t, c).Apps[0]; !a.Gone {
		t.Fatalf("%+v", a)
	}
}

func TestSetStatsMode(t *testing.T) {
	c, _ := newCtl(t)
	prefs := filepath.Join(c.Store.Dir, "prefs.json")
	before, _ := os.ReadFile(prefs)
	if err := c.SetStatsMode("no-sites"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(prefs)
	if !bytes.Equal(before, after) {
		t.Fatal("prefs.json changed")
	}
	b, err := os.ReadFile(filepath.Join(c.Store.Dir, "stats", "mode.json"))
	if err != nil || !bytes.Contains(b, []byte(`"no-sites"`)) {
		t.Fatalf("%s %v", b, err)
	}
	if err := c.SetStatsMode("hourly"); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if rep := today(t, c); rep.Mode != "no-sites" {
		t.Fatal(rep.Mode)
	}
	// The mode survives a restart.
	c2, _ := newCtlAt(t, c.Store)
	if c2.stats.Mode() != stats.ModeNoSites {
		t.Fatal(c2.stats.Mode())
	}
}

// The backup functions run with no Controller lock held.
func TestStatsBackupUnlocked(t *testing.T) {
	c, started, de := statsCtl(t)
	var calls, locked atomic.Int32
	c.statsUnlocked = func() {
		calls.Add(1)
		for _, m := range []*sync.Mutex{&c.mu, &c.lifeMu, &c.saveMu, &c.proxyMu, &c.ksMu} {
			if !free(m) {
				locked.Add(1)
			}
		}
	}
	rec := openFlow((*started)[0].reg, `C:\a.exe`, "tunnel", de, "relayed")
	rec.Sent.Add(10)
	c.sampleStats(time.Now(), false)
	if _, empty := c.StatsBackupInfo(); empty {
		t.Fatal("empty with a delta")
	}
	raw, detail, err := c.ExportStats()
	if err != nil || !strings.Contains(detail, "сбор: всё") {
		t.Fatalf("%q %v", detail, err)
	}
	if _, err := c.CheckStatsImport(raw); err != nil {
		t.Fatal(err)
	}
	for len(c.statsFlush) > 0 {
		<-c.statsFlush
	}
	if err := c.ReplaceStats(raw); err != nil {
		t.Fatal(err)
	}
	if len(c.statsFlush) != 1 {
		t.Fatal("no kick")
	}
	if calls.Load() != 4 || locked.Load() != 0 {
		t.Fatalf("calls %d, locks held %d", calls.Load(), locked.Load())
	}
}

// Server and group names are the current ones; a deleted one is marked.
func TestStatsNames(t *testing.T) {
	c, started, de := statsCtl(t)
	reg := (*started)[0].reg
	for _, prof := range []string{de, "0123456789ab", "", "grp-000000000009"} {
		openFlow(reg, `C:\a.exe`, "tunnel", prof, "relayed").Sent.Add(1)
	}
	c.sampleStats(time.Now(), false)
	c.mu.Lock()
	p := *c.profiles.Find(de)
	c.mu.Unlock()
	p.Name = "Новое имя"
	if _, err := c.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	rep := today(t, c)
	for _, want := range []struct {
		key, name string
		gone      bool
	}{{de, "Новое имя", false}, {"0123456789ab", "", true}, {"", "", false}, {"grp-000000000009", "", true}} {
		var got *stats.Row
		for i := range rep.Servers {
			if rep.Servers[i].Key == want.key {
				got = &rep.Servers[i]
			}
		}
		if got == nil || got.Name != want.name || got.Gone != want.gone {
			t.Errorf("%q: %+v", want.key, got)
		}
	}
}

// RunStats: the first compaction a minute after the start, then on a day
// change; the end of its context flushes.
func TestRunStatsCompaction(t *testing.T) {
	c, _ := newCtl(t)
	clk := time.Now()
	var mu sync.Mutex
	c.stats.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clk }
	advance := func(d time.Duration) { mu.Lock(); clk = clk.Add(d); mu.Unlock() }
	c.statsTick = 5 * time.Millisecond
	f := c.Store.StatsFiles()
	old := "day-" + clk.AddDate(0, 0, -100).Format("2006-01-02")
	if err := f.Write(old, []byte(`{"v":1,"day":"`+old[4:]+`","total":{"tc":1}}`)); err != nil {
		t.Fatal(err)
	}
	exists := func(name string) bool {
		_, err := os.Stat(filepath.Join(c.Store.Dir, "stats", name+".json"))
		return err == nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.RunStats(ctx); close(done) }()
	time.Sleep(100 * time.Millisecond)
	if !exists(old) {
		t.Fatal("compacted at the start")
	}
	advance(statsCompactWait + time.Second)
	waitFor(t, "the first compaction", func() bool { return !exists(old) })
	mu.Lock()
	old2 := "day-" + clk.AddDate(0, 0, -99).Format("2006-01-02")
	mu.Unlock()
	if err := f.Write(old2, []byte(`{"v":1,"day":"`+old2[4:]+`","total":{"tc":1}}`)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if !exists(old2) {
		t.Fatal("compacted twice a day")
	}
	advance(24 * time.Hour)
	waitFor(t, "the compaction of the next day", func() bool { return !exists(old2) })
	// A delta, then the end of the context: flushed.
	rec := c.proxyRecord(store.LocalProxy{ID: "x"}, 6, socks5.Addr{}, "de", "", false, "proxied")
	rec.Sent.Add(9)
	c.proxyFlows.Close(rec, time.Now())
	cancel()
	<-done
	mu.Lock()
	day := "day-" + clk.Format("2006-01-02")
	mu.Unlock()
	if !exists(day) {
		t.Fatal("not flushed at the end")
	}
}

// failFiles are statistics files whose writes and listings fail, counted.
type failFiles struct {
	*store.StatsFiles
	writes, lists atomic.Int32
}

func (f *failFiles) Write(string, []byte) error {
	f.writes.Add(1)
	return &fs.PathError{Op: "write", Path: "x", Err: errors.New("disk full")}
}

func (f *failFiles) List() ([]string, error) {
	f.lists.Add(1)
	return nil, &fs.PathError{Op: "open", Path: "x", Err: errors.New("access denied")}
}

// RunStats retries a failing flush (after a day change) and a failing
// compaction at the flush pace, never at every sample.
func TestRunStatsFailingPace(t *testing.T) {
	c, _ := newCtl(t)
	clk := time.Now().Add(48 * time.Hour)
	var mu sync.Mutex
	c.stats.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clk }
	advance := func(d time.Duration) { mu.Lock(); clk = clk.Add(d); mu.Unlock() }
	c.statsTick = time.Millisecond
	ff := &failFiles{StatsFiles: c.Store.StatsFiles()}
	c.stats.Configure(ff)
	rec := c.proxyRecord(store.LocalProxy{ID: "x"}, 6, socks5.Addr{}, "de", "", false, "proxied")
	rec.Sent.Add(9)
	c.proxyFlows.Close(rec, time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.RunStats(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	steady := func(what string, writes, lists int32) {
		t.Helper()
		waitFor(t, what, func() bool { return ff.writes.Load() >= writes && ff.lists.Load() >= lists })
		time.Sleep(150 * time.Millisecond) // over a hundred samples
		if w, l := ff.writes.Load(), ff.lists.Load(); w != writes || l != lists {
			t.Fatalf("%s: %d flushes, %d compactions; want %d, %d", what, w, l, writes, lists)
		}
	}
	steady("the start", 1, 0)
	// A day change: one flush and (a minute after the start) one
	// compaction, both failing, then nothing until the flush pace.
	advance(24 * time.Hour)
	steady("the day change", 2, 1)
	advance(statsFlushEvery)
	steady("the flush pace", 3, 2)
}

// Unused, the statistics create nothing: no folder after Load, reports,
// the backup info, a sample and a RunStats start and stop.
func TestStatsCreateNothing(t *testing.T) {
	c, _ := newCtl(t)
	c.Stats("today")
	c.Stats("30d")
	c.StatsBackupInfo()
	c.sampleStats(time.Now(), true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.RunStats(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	c.Shutdown()
	if _, err := os.Lstat(filepath.Join(c.Store.Dir, "stats")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("stats folder: %v", err)
	}
}

// The statistics of HyRoute 1.2.0 are imported once and left in place.
func TestStatsImportsV12(t *testing.T) {
	c, _ := newCtl(t)
	d := time.Now().Format("2006-01-02")
	old := []byte(`{"version":1,"days":{"` + d + `":{"servers":{"p1":{"sent":10,"recv":20}},"apps":{"chrome.exe":{"sent":10,"recv":20}}}},"hours":{},"names":{"p1":"DE"}}`)
	path := filepath.Join(c.Store.Dir, "traffic.json")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	rep := today(t, c)
	if rep.Total.TU != 10 || rep.Total.TD != 20 || rep.Apps[0].Key != "chrome.exe" {
		t.Fatalf("%+v %+v", rep.Total, rep.Apps)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, old) {
		t.Fatal("traffic.json changed")
	}
	// A local proxy of 1.2.0 is found by its name then.
	c.mu.Lock()
	c.proxies = []store.LocalProxy{{ID: "AbC", Name: "Биржа", Port: 1080}, {ID: "x", Port: 1081}, {ID: "y", Name: "Два", Port: 1082}, {ID: "z", Name: "Два", Port: 1083}}
	c.mu.Unlock()
	for name, want := range map[string]string{"Локальный прокси «Биржа»": "proxy:AbC", "Локальный прокси :1081": "proxy:x", "Локальный прокси «Два»": "", "Локальный прокси :1080": ""} {
		if key, _, ok := c.statsLegacyProxy(name); key != want || ok != (want != "") {
			t.Errorf("%s: %q %v", name, key, ok)
		}
	}
	// Not again after a restart.
	c2, _ := newCtlAt(t, c.Store)
	if err := c2.ResetStats(); err != nil {
		t.Fatal(err)
	}
	if rep := today(t, c2); rep.Total.TU != 0 {
		t.Fatalf("imported again: %+v", rep.Total)
	}
}

// Diagnostics: the mode and file names, never sites or programs.
func TestStatsDiag(t *testing.T) {
	c, started, de := statsCtl(t)
	rec := openFlow((*started)[0].reg, `C:\secret-app.exe`, "tunnel", de, "relayed")
	rec.Set(func(f *flows.Fields) { f.Domain = "private.example.org" })
	rec.Sent.Add(1)
	c.sampleStats(time.Now(), false)
	os.MkdirAll(filepath.Join(c.Store.Dir, "stats"), 0o700)
	bad := "day-" + time.Now().AddDate(0, 0, -1).Format("2006-01-02")
	os.WriteFile(filepath.Join(c.Store.Dir, "stats", bad+".json"), []byte("{"), 0o600)
	c.Stats("7d")
	diag := c.Diagnostics(nil, false)
	if !strings.Contains(diag, "   статистика: сбор всё; файлы: файл "+bad+".json повреждён, пропущен") {
		t.Fatalf("%s", diag)
	}
	if strings.Contains(diag, "private.example") || strings.Contains(diag, "secret-app") {
		t.Fatal("a site or program in the diagnostics")
	}
}
