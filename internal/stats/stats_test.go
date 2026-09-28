package stats

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
)

// A flow counts once, at its first settled observation; bytes are deltas;
// stale samples and samples of a closed flow add nothing while its
// tombstone lives (one to two generations).
func TestObserveSettledOnce(t *testing.T) {
	r := newRig(t)
	rec := r.open(`C:\Tools\curl.exe`, func(f *flows.Fields) { f.Route = "pending" })
	rec.Sent.Add(100)
	r.sample()
	if got := r.today(t); got != (Counters{}) {
		t.Fatalf("unsettled counted: %+v", got)
	}
	rec.Set(tunnel("de", "relayed"))
	rec.Sent.Add(50)
	r.sample()
	if got := r.today(t); got.TC != 1 || got.TU != 150 {
		t.Fatalf("%+v", got)
	}
	rec.Sent.Add(10)
	rec.Recv.Add(7)
	r.sample()
	if got := r.today(t); got.TC != 1 || got.TU != 160 || got.TD != 7 {
		t.Fatalf("%+v", got)
	}
	// A stale sample (smaller counters) adds nothing.
	r.c.mu.Lock()
	r.src.applyLocked(r.clk.now(), &obs{id: rec.ID, sent: 20, recv: 1})
	r.c.mu.Unlock()
	if got := r.today(t); got.TU != 160 || got.TD != 7 {
		t.Fatalf("stale sample: %+v", got)
	}
	rec.Sent.Add(1)
	r.close(rec)
	if got := r.today(t); got.TC != 1 || got.TU != 161 {
		t.Fatalf("close: %+v", got)
	}
	// A sample taken before the close, applied after it.
	late := func() {
		r.c.mu.Lock()
		o := obs{id: rec.ID, full: true, settled: true, f: Flow{App: "x", Route: Tunnel}, sent: 500}
		r.src.applyLocked(r.clk.now(), &o)
		r.c.mu.Unlock()
	}
	late()
	r.clk.add(61 * time.Second) // one rotation: still a tombstone
	late()
	if got := r.today(t); got.TC != 1 || got.TU != 161 {
		t.Fatalf("tombstone: %+v", got)
	}
	r.clk.add(61 * time.Second) // two: gone
	late()
	if got := r.today(t); got.TC != 2 {
		t.Fatalf("tombstone outlived two generations: %+v", got)
	}
}

// Tombstones hold at most two minutes of closes, whatever the close rate.
func TestTombstonesHighCloseRate(t *testing.T) {
	r := newRig(t)
	var at []time.Time
	closeOne := func(id uint64) {
		r.src.Closed(flows.View{ID: id, Process: "a.exe", Fields: flows.Fields{Route: "tunnel", Profile: "de", Outcome: "relayed"}, Sent: 1})
		at = append(at, r.clk.now())
	}
	check := func() {
		now := r.clk.now()
		recent := 0
		for i := len(at) - 1; i >= 0 && now.Sub(at[i]) < 2*time.Minute+time.Second; i-- {
			recent++
		}
		r.c.mu.Lock()
		held := len(r.src.tomb[0]) + len(r.src.tomb[1])
		r.c.mu.Unlock()
		if held > recent {
			t.Fatalf("%d tombstones, %d closes in two minutes", held, recent)
		}
	}
	id := uint64(0)
	// 200 000 closes over 10 minutes (~333/s), 1 ms apart in 100-close steps.
	for i := 0; i < 2000; i++ {
		for j := 0; j < 100; j++ {
			id++
			closeOne(id)
		}
		r.clk.add(300 * time.Millisecond)
		if i%100 == 0 {
			check()
		}
	}
	// A burst of 50 000 in one second.
	for j := 0; j < 50000; j++ {
		id++
		closeOne(id)
		if j%10000 == 0 {
			r.clk.add(200 * time.Millisecond)
		}
	}
	check()
	r.clk.set(t0) // the report's day
	r.c.Now = func() time.Time { return t0 }
	if got := r.today(t); got.TC != int64(id) || got.TU != int64(id) {
		t.Fatalf("totals %+v, want %d", got, id)
	}
}

// Sample reads ticks: unchanged flows cost nothing, counters-only changes
// build no View, a Set builds one; observations are applied in chunks.
func TestSampleTicks(t *testing.T) {
	r := newRig(t)
	var holds, views atomic.Int64
	r.c.testHold = func() { holds.Add(1) }
	r.c.testView = func() { views.Add(1) }
	rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	rec.Sent.Add(10)
	r.sample()
	if views.Load() != 1 || holds.Load() != 1 {
		t.Fatalf("views %d holds %d", views.Load(), holds.Load())
	}
	r.sample() // nothing changed
	if views.Load() != 1 || holds.Load() != 1 {
		t.Fatalf("unchanged: views %d holds %d", views.Load(), holds.Load())
	}
	rec.Sent.Add(5)
	r.sample() // counters only
	if views.Load() != 1 || holds.Load() != 2 {
		t.Fatalf("counters: views %d holds %d", views.Load(), holds.Load())
	}
	rec.Set(func(f *flows.Fields) { f.Domain = "x.example" })
	r.sample()
	if views.Load() != 2 {
		t.Fatalf("Set: views %d", views.Load())
	}
	if got := r.today(t); got.TC != 1 || got.TU != 15 {
		t.Fatalf("%+v", got)
	}
	// 1000 new records: at least four holds.
	before := holds.Load()
	for i := 0; i < 1000; i++ {
		r.open(fmt.Sprintf(`C:\p%d.exe`, i), tunnel("de", "relayed")).Sent.Add(1)
	}
	r.sample()
	if n := holds.Load() - before; n < 4 {
		t.Fatalf("1000 observations in %d holds", n)
	}
	// A flow that settles after several unsettled samples counts its whole
	// bytes once.
	late := r.open(`C:\late.exe`, func(f *flows.Fields) { f.Route, f.Outcome = "pending", "reflected: sniff" })
	late.Sent.Add(100)
	r.sample()
	late.Sent.Add(100)
	r.sample()
	late.Set(tunnel("de", "relayed"))
	r.sample()
	r.sample()
	app := rowOf(r.report(t, "today").Apps, `c:\late.exe`)
	if app.TC != 1 || app.TU != 200 {
		t.Fatalf("%+v", app)
	}
}

func TestRoutes(t *testing.T) {
	r := newRig(t)
	mk := func(path string, set func(f *flows.Fields), sent, recv int64) {
		rec := r.open(path, set)
		rec.Sent.Add(sent)
		rec.Recv.Store(recv)
		r.close(rec)
	}
	mk(`C:\t.exe`, func(f *flows.Fields) {
		f.Route, f.Profile, f.Group, f.Outcome, f.Domain = "tunnel", "de", "grp-1", "relayed", "www.youtube.com"
	}, 10, 20)
	mk(`C:\d.exe`, func(f *flows.Fields) { f.Route, f.Outcome = "direct", "passed" }, 5, 99)
	mk(`C:\d2.exe`, func(f *flows.Fields) { f.Route, f.Outcome = "direct", "passed" }, 5, -1)
	mk(`C:\b.exe`, func(f *flows.Fields) { f.Route, f.Outcome = "block", "rst: blocked" }, 7, 0)
	mk(`C:\f.exe`, tunnel("de", "rst: socks5 connect failed"), 517, 0) // a sniffed head
	mk(`C:\fo.exe`, func(f *flows.Fields) { f.Route, f.Profile, f.Failover, f.Outcome = "tunnel", "nl", true, "relayed" }, 1, 1)
	mk(`C:\fof.exe`, func(f *flows.Fields) {
		f.Route, f.Profile, f.Failover, f.Outcome = "tunnel", "nl", true, "rst: tunnel unavailable"
	}, 0, 0)
	mk(`C:\bfo.exe`, func(f *flows.Fields) { f.Route, f.Failover, f.Outcome = "block", true, "rst: IPv6 blocked for tunnel" }, 0, 0)
	mk(`C:\dfo.exe`, func(f *flows.Fields) { f.Route, f.Failover, f.Outcome = "direct", true, "passed" }, 1, -1)
	mk(`C:\none.exe`, tunnel("", "rst: tunnel unavailable"), 0, 0)
	rep := r.report(t, "today")
	want := Counters{TC: 2, TU: 11, TD: 21, DC: 3, DU: 11, BC: 2, F: 3, FO: 2}
	if rep.Total != want {
		t.Fatalf("total %+v, want %+v", rep.Total, want)
	}
	if s := rowOf(rep.Servers, "de"); s.TC != 1 || s.TU != 10 || s.TD != 20 || s.F != 1 {
		t.Fatalf("server de %+v", s)
	}
	if s := rowOf(rep.Servers, "nl"); s.TC != 1 || s.F != 1 || s.FO != 2 {
		t.Fatalf("server nl %+v", s)
	}
	if s := rowOf(rep.Servers, ""); s.F != 1 {
		t.Fatalf("no server %+v", s)
	}
	if g := rowOf(rep.Groups, "grp-1"); g.TC != 1 || g.TU != 10 || len(rep.Groups) != 1 {
		t.Fatalf("groups %+v", rep.Groups)
	}
	if s := rowOf(rep.Sites, "youtube.com"); s.TC != 1 || s.TU != 10 {
		t.Fatalf("site %+v", rep.Sites)
	}
	if a := rowOf(rep.Apps, `c:\f.exe`); a.F != 1 || a.TU != 0 {
		t.Fatalf("failed flow's head counted: %+v", a)
	}
	if a := rowOf(rep.Apps, `c:\d.exe`); a.DC != 1 || a.DU != 5 || a.TD != 0 {
		t.Fatalf("direct ↓ counted: %+v", a)
	}
	if a := rowOf(rep.Apps, `c:\bfo.exe`); a.FO != 0 || a.BC != 1 {
		t.Fatalf("failover on block: %+v", a)
	}
	if a := rowOf(rep.Apps, `c:\dfo.exe`); a.FO != 0 {
		t.Fatalf("failover on direct: %+v", a)
	}
}

// NL6: a UDP flow first refused while the tunnel was down keeps its one
// failure; its bytes count once it carries.
func TestFailedThenCarrying(t *testing.T) {
	r := newRig(t)
	rec := r.open(`C:\game.exe`, tunnel("de", "dropped: tunnel unavailable"))
	rec.Sent.Add(100)
	r.sample()
	if got := r.today(t); got.F != 1 || got.TU != 0 || got.TC != 0 {
		t.Fatalf("%+v", got)
	}
	rec.Set(func(f *flows.Fields) { f.Outcome = "tunneled" })
	rec.Sent.Add(200)
	r.sample()
	if got := r.today(t); got.F != 1 || got.TU != 200 || got.TC != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestNotSettledOutcomes(t *testing.T) {
	r := newRig(t)
	for _, o := range []string{"reflected", "reflected: sniff", "aborted: stopping"} {
		rec := r.open(`C:\x.exe`, tunnel("de", o))
		rec.Sent.Add(517)
		r.sample()
		r.close(rec)
	}
	pend := r.open(`C:\x.exe`, func(f *flows.Fields) { f.Route = "pending" })
	r.close(pend)
	if got := r.today(t); got != (Counters{}) {
		t.Fatalf("%+v", got)
	}
}

// Collection off adds nothing and builds no View, but offsets move: a flow
// counted before adds only the bytes after collection is on again; a flow
// first seen while off never counts.
func TestModeOff(t *testing.T) {
	r := newRig(t)
	var views atomic.Int64
	r.c.testView = func() { views.Add(1) }
	old := r.open(`C:\old.exe`, tunnel("de", "relayed"))
	old.Sent.Add(10)
	r.sample()
	if err := r.c.SetMode(r.clk.now(), ModeOff); err != nil {
		t.Fatal(err)
	}
	v0 := views.Load()
	old.Sent.Add(1000)
	fresh := r.open(`C:\new.exe`, tunnel("de", "relayed"))
	fresh.Sent.Add(50)
	old.Set(func(f *flows.Fields) { f.Domain = "a.example" })
	r.sample()
	r.c.EngineFailed(r.clk.now())
	if views.Load() != v0 {
		t.Fatal("a View built while off")
	}
	if got := r.today(t); got.TC != 1 || got.TU != 10 {
		t.Fatalf("off: %+v", got)
	}
	if err := r.c.SetMode(r.clk.now(), ModeAll); err != nil {
		t.Fatal(err)
	}
	old.Sent.Add(5)
	fresh.Sent.Add(5)
	r.sample()
	r.close(old)
	r.close(fresh)
	if got := r.report(t, "today"); got.Total.TC != 1 || got.Total.TU != 15 || got.Events.EngineFails != 0 {
		t.Fatalf("on again: %+v", got.Total)
	}
	// The mode is written.
	if b := r.files.get("mode"); !strings.Contains(string(b), `"mode":""`) {
		t.Fatalf("%s", b)
	}
}

// «Без сайтов» keeps no site rows and strips sites from every file; a
// corrupt file (which may hold sites) is removed.
func TestModeNoSites(t *testing.T) {
	r := newRig(t)
	rec := r.open(`C:\a.exe`, func(f *flows.Fields) {
		f.Route, f.Profile, f.Outcome, f.Domain = "tunnel", "de", "relayed", "a.example.com"
	})
	rec.Sent.Add(1)
	r.sample()
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	past := "day-" + addDays(dayOf(t0), -3)
	r.files.put(past, mustJSON(t, File{V: 1, Day: past[4:], Sites: []Row{{Key: "b.com", Counters: Counters{TC: 1}}}}))
	r.files.put("day-"+addDays(dayOf(t0), -4), []byte("{garbage"))
	rec.Sent.Add(1)
	r.sample() // an unflushed site row
	if err := r.c.SetMode(r.clk.now(), ModeNoSites); err != nil {
		t.Fatal(err)
	}
	if f := r.files.file(t, "day-"+dayOf(t0)); len(f.Sites) != 0 {
		t.Fatalf("today: %+v", f.Sites)
	}
	if f := r.files.file(t, past); len(f.Sites) != 0 {
		t.Fatalf("past: %+v", f.Sites)
	}
	if r.files.has("day-" + addDays(dayOf(t0), -4)) {
		t.Fatal("corrupt file kept")
	}
	other := r.open(`C:\b.exe`, func(f *flows.Fields) { f.Route, f.Outcome, f.Domain = "direct", "passed", "c.example.org" })
	other.Sent.Add(3)
	r.close(other)
	rep := r.report(t, "7d")
	if len(rep.Sites) != 0 || rep.Mode != "no-sites" {
		t.Fatalf("%+v", rep.Sites)
	}
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if f := r.files.file(t, "day-"+dayOf(t0)); len(f.Sites) != 0 || f.Total.DU != 3 {
		t.Fatalf("%+v", f)
	}
}

func TestDayAttribution(t *testing.T) {
	r := newRig(t)
	r.clk.set(time.Date(2026, 9, 28, 23, 59, 58, 0, time.Local))
	rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	rec.Sent.Add(100)
	r.sample()
	r.clk.add(4 * time.Second) // 00:00:02
	rec.Sent.Add(30)
	r.sample()
	d1, d2 := r.c.delta["2026-09-28"], r.c.delta["2026-09-29"]
	if d1 == nil || d2 == nil || d1.total.TU != 100 || d1.total.TC != 1 || d2.total.TU != 30 || d2.total.TC != 0 {
		t.Fatalf("%+v %+v", d1, d2)
	}
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	// The clock goes back a day: new bytes go to the earlier day.
	r.clk.add(-24 * time.Hour)
	rec.Sent.Add(7)
	r.sample()
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if f := r.files.file(t, "day-2026-09-28"); f.Total.TU != 107 {
		t.Fatalf("%+v", f.Total)
	}
	if f := r.files.file(t, "day-2026-09-29"); f.Total.TU != 30 {
		t.Fatalf("later file changed: %+v", f.Total)
	}
}

func TestMemoryCapsOverflow(t *testing.T) {
	r := newRig(t)
	for i := 0; i < memCaps[listApps]+1; i++ {
		rec := r.reg.Open(&flows.Record{Proto: 6, Process: fmt.Sprintf("p%d.exe", i)})
		rec.Set(tunnel("de", "relayed"))
		rec.Sent.Add(1)
		r.close(rec)
	}
	d := r.c.delta[dayOf(t0)]
	if len(d.lists[listApps]) != memCaps[listApps]+1 || d.lists[listApps][Others].TC != 1 || d.total.TC != int64(memCaps[listApps]+1) {
		t.Fatalf("apps %d, * %+v, total %+v", len(d.lists[listApps]), d.lists[listApps][Others], d.total)
	}
	// Seven unflushed days (the disk refuses); an eighth drops the oldest.
	r.files.onWrite = func(string) error { return fmt.Errorf("disk full") }
	for i := 0; i < 8; i++ {
		r.clk.add(24 * time.Hour)
		rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
		rec.Sent.Add(1)
		r.close(rec)
		r.c.Flush(r.clk.now())
	}
	if len(r.c.delta) != maxDeltaDays {
		t.Fatalf("%d days in memory", len(r.c.delta))
	}
	if e := r.c.StoreError(); !strings.Contains(e, "не удалось записать") {
		t.Fatalf("storeError %q", e)
	}
	r.files.onWrite = nil
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if e := r.c.StoreError(); e != "" {
		t.Fatalf("after a good flush: %q", e)
	}
}

func TestDrops(t *testing.T) {
	r := newRig(t)
	st := time.Unix(100, 0)
	feed := func(connected bool, restarts int, started time.Time) {
		r.c.ServerStates(r.clk.now(), []ServerState{{ID: "de", Name: "DE", Started: started, Connected: connected, Restarts: restarts}})
	}
	feed(true, 0, st)
	feed(false, 0, st) // connected → connecting
	feed(true, 0, st)
	feed(true, 1, st) // restarted while connected
	feed(true, 0, st.Add(time.Hour))
	feed(false, 0, st.Add(2*time.Hour)) // a new endpoint: no drop
	r.c.ServerStates(r.clk.now(), nil)  // gone
	rep := r.report(t, "today")
	if rep.Events.Drops != 2 || rowOf(rep.Servers, "de").Drops != 2 || rowOf(rep.Servers, "de").Name != "DE" {
		t.Fatalf("%+v %+v", rep.Events, rep.Servers)
	}
	// A drop while collection is off is not counted once it is back on:
	// the states are kept up to date in mode off too.
	feed(true, 0, st)
	r.c.SetMode(r.clk.now(), ModeOff)
	feed(false, 0, st)
	r.c.SetMode(r.clk.now(), ModeAll)
	feed(false, 0, st)
	feed(true, 0, st)
	r.c.SetMode(r.clk.now(), ModeOff)
	feed(true, 1, st)
	r.c.SetMode(r.clk.now(), ModeAll)
	feed(true, 1, st)
	if rep := r.report(t, "today"); rep.Events.Drops != 2 {
		t.Fatalf("counted while off: %+v", rep.Events)
	}
}

// Everything at once under -race.
func TestConcurrent(t *testing.T) {
	r := newRig(t)
	export := func() []byte {
		raw, _, err := r.c.Export(r.clk.now())
		if err != nil {
			t.Error(err)
		}
		return raw
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					f()
				}
			}
		}()
	}
	var n atomic.Int64
	run(func() {
		rec := r.open(fmt.Sprintf(`C:\p%d.exe`, n.Add(1)%50), func(f *flows.Fields) {
			f.Route, f.Profile, f.Outcome, f.Domain = "tunnel", "de", "relayed", "a.example.com"
		})
		rec.Sent.Add(10)
		if n.Load()%3 == 0 {
			r.close(rec)
		}
	})
	run(r.sample)
	run(func() { r.c.Flush(r.clk.now()) })
	run(func() { r.c.Compact(r.clk.now()) })
	run(func() { r.c.Report(r.clk.now(), "7d") })
	raw := export()
	run(func() { r.c.Replace(r.clk.now(), raw) })
	run(func() {
		r.c.SetMode(r.clk.now(), ModeNoSites)
		r.c.SetMode(r.clk.now(), ModeAll)
	})
	run(func() { r.c.Reset(r.clk.now()) })
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// DNS rows (dns: Stage "dns", queries HyRoute answered) and normal flows
// go through one sampler and one OnClose: only the flows count, live or
// closed, whatever the rows' counters say.
func TestDNSRowsAndFlowsOneSampler(t *testing.T) {
	r := newRig(t)
	dnsRow := func(f *flows.Fields) {
		f.Route, f.Profile, f.Outcome, f.Stage, f.Count = "tunnel", "de", "tunneled", flows.StageDNS, 3
	}
	rows := make([]*flows.Record, 0, 3)
	for range 3 {
		rec := r.open(`C:\Windows\System32\svchost.exe`, dnsRow)
		rec.Sent.Add(40)
		rec.Recv.Add(80)
		rows = append(rows, rec)
	}
	flow := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	flow.Sent.Add(10)
	flow.Recv.Add(20)
	r.sample()
	rows[0].Sent.Add(40)
	flow.Sent.Add(5)
	r.sample()
	r.close(rows[1])
	r.close(flow)
	r.sample()
	r.close(rows[0])
	r.close(rows[2])
	rep := r.report(t, "today")
	if got := rep.Total; got.TC != 1 || got.TU != 15 || got.TD != 20 {
		t.Fatalf("total %+v, want one flow 15/20", got)
	}
	if len(rep.Apps) != 1 || rep.Apps[0].Key != `c:\a.exe` {
		t.Fatalf("apps %+v", rep.Apps)
	}
}
