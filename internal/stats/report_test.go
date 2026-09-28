package stats

import (
	"errors"
	"io/fs"
	"slices"
	"sync"
	"testing"
	"time"
	_ "time/tzdata" // America/Santiago on any machine

	"github.com/lardan099/hyroute/internal/flows"
)

func TestReportPeriods(t *testing.T) {
	r := newRig(t)
	today := dayOf(t0)
	for i := 0; i < 40; i++ {
		d := addDays(today, -i)
		r.files.put("day-"+d, validFile(t, "day-"+d, Counters{TC: int64(i + 1)}))
	}
	rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	r.close(rec) // today's delta: +1
	for _, c := range []struct {
		period   string
		from, to string
		tc       int64
		days     int
	}{
		{"today", today, today, 1 + 1, 1},
		{"yesterday", addDays(today, -1), addDays(today, -1), 2, 1},
		{"7d", addDays(today, -6), today, 28 + 1, 7},
		{"30d", addDays(today, -29), today, 465 + 1, 30},
		{"2026-09", "2026-09-01", today, 406 + 1, 28}, // the 28 days of September so far
	} {
		rep := r.report(t, c.period)
		if rep.From != c.from || rep.To != c.to || rep.Total.TC != c.tc || len(rep.Days) != c.days {
			t.Errorf("%s: %s..%s tc %d days %d", c.period, rep.From, rep.To, rep.Total.TC, len(rep.Days))
		}
	}
	for _, bad := range []string{"", "week", "2026-13", "2099-01", "2026-9"} {
		if _, err := r.c.Report(r.clk.now(), bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	rep := r.report(t, "7d")
	if rep.Days[6].Day != today || rep.Days[6].TC != 2 || rep.Since != addDays(today, -39) {
		t.Fatalf("%+v since %s", rep.Days[6], rep.Since)
	}
	if !slices.Equal(rep.Months, []string{"2026-09", "2026-08"}) {
		t.Fatalf("%v", rep.Months)
	}

	// An old month: its month file, the days it does not hold, and the
	// crash case (a day the month holds whose day file and delta are still
	// there) counted once, from the month file.
	r2 := newRig(t)
	m := &File{V: 1, Month: "2026-05", Days: []string{"2026-05-01", "2026-05-02"}, Total: Counters{TC: 100}}
	b, _ := m.marshal()
	r2.files.put("month-2026-05", b)
	r2.files.put("day-2026-05-02", validFile(t, "day-2026-05-02", Counters{TC: 1000}))
	r2.files.put("day-2026-05-20", validFile(t, "day-2026-05-20", Counters{TC: 5}))
	r2.c.mu.Lock()
	r2.c.deltaLocked("2026-05-02").total.TC = 10000
	r2.c.deltaLocked("2026-05-21").total.TC = 7
	r2.c.mu.Unlock()
	rep = r2.report(t, "2026-05")
	if rep.Total.TC != 112 || len(rep.Days) != 29 || rep.From != "2026-05-01" || rep.To != "2026-05-31" {
		t.Fatalf("%+v days %d", rep.Total, len(rep.Days))
	}
	if rep.Since != "2026-05-01" || !slices.Contains(rep.Months, "2026-05") || rep.Months[0] != "2026-09" {
		t.Fatalf("since %s months %v", rep.Since, rep.Months)
	}
	// Only a month file: no bars.
	r3 := newRig(t)
	full := &File{V: 1, Month: "2026-04", Total: Counters{TC: 3}}
	for d := "2026-04-01"; d <= "2026-04-30"; d = addDays(d, 1) {
		full.Days = append(full.Days, d)
	}
	b, _ = full.marshal()
	r3.files.put("month-2026-04", b)
	if rep := r3.report(t, "2026-04"); len(rep.Days) != 0 || rep.Total.TC != 3 {
		t.Fatalf("%+v", rep)
	}
	// Empty: lists are [] (never null for the UI).
	r4 := newRig(t)
	rep = r4.report(t, "today")
	if rep.Apps == nil || rep.Sites == nil || rep.Servers == nil || rep.Groups == nil || rep.Days == nil || len(rep.Months) != 1 {
		t.Fatalf("%+v", rep)
	}
}

// A large delta is reported while observations go on; each hold copies
// one day.
func TestReportWhileObserving(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 13000; i++ {
		r.src.Closed(flows.View{ID: uint64(i + 1), Process: "p" + itoa(i%1500) + ".exe", Fields: flows.Fields{
			Route: "direct", Outcome: "passed", Domain: "s" + itoa(i) + ".example" + itoa(i%9000) + ".com"}, Sent: 1})
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		id := uint64(100000)
		for {
			select {
			case <-stop:
				return
			default:
			}
			id++
			r.src.Closed(flows.View{ID: id, Process: "x.exe", Fields: flows.Fields{Route: "direct", Outcome: "passed"}, Sent: 1})
		}
	}()
	for i := 0; i < 5; i++ {
		rep, err := r.c.Report(r.clk.now(), "7d")
		if err != nil || rep.Total.DC < 13000 || len(rep.Sites) != reportCaps[listSites] {
			t.Errorf("%v %+v %d", err, rep.Total, len(rep.Sites))
		}
	}
	close(stop)
	wg.Wait()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// Where daylight saving starts at midnight (Chile: 2026-09-06 00:00 does
// not exist), days still advance: every period ends and "yesterday" is
// the day before.
func TestReportMidnightDST(t *testing.T) {
	loc, err := time.LoadLocation("America/Santiago")
	if err != nil {
		t.Skip(err)
	}
	defer func(l *time.Location) { time.Local = l }(time.Local)
	time.Local = loc
	if d := addDays("2026-09-05", 1); d != "2026-09-06" {
		t.Fatalf("2026-09-05 + 1 = %s", d)
	}
	if d := addDays("2026-09-06", -1); d != "2026-09-05" {
		t.Fatalf("2026-09-06 - 1 = %s", d)
	}
	r := newRig(t)
	r.clk.set(time.Date(2026, 9, 10, 12, 0, 0, 0, loc))
	for _, c := range []struct {
		period string
		from   string
		days   int
	}{{"7d", "2026-09-04", 7}, {"30d", "2026-08-12", 30}, {"2026-09", "2026-09-01", 10}} {
		done := make(chan Report, 1)
		go func() {
			rep, _ := r.c.Report(r.clk.now(), c.period)
			done <- rep
		}()
		select {
		case rep := <-done:
			if rep.From != c.from || rep.To != "2026-09-10" || len(rep.Days) != c.days {
				t.Errorf("%s: %s..%s, %d days", c.period, rep.From, rep.To, len(rep.Days))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the report does not end", c.period)
		}
	}
	r.clk.set(time.Date(2026, 9, 6, 12, 0, 0, 0, loc))
	if rep := r.report(t, "yesterday"); rep.From != "2026-09-05" {
		t.Fatalf("yesterday of 2026-09-06: %s", rep.From)
	}
}

// A file or the folder that cannot be read now makes the period
// incomplete: the report says so (and the diagnostics, through
// StoreError) until a report reads everything again.
func TestReportReadError(t *testing.T) {
	r := newRig(t)
	today := dayOf(t0)
	r.files.put("day-"+today, validFile(t, "day-"+today, Counters{TC: 1}))
	r.files.readErr["day-"+today] = &fs.PathError{Op: "open", Path: `C:\secret\day.json`, Err: errors.New("sharing violation")}
	if rep := r.report(t, "today"); rep.StoreError != "не удалось прочитать day-"+today+".json: sharing violation" {
		t.Fatalf("%q", rep.StoreError)
	}
	if e := r.c.StoreError(); e == "" {
		t.Fatal("not kept for the diagnostics")
	}
	delete(r.files.readErr, "day-"+today)
	r.files.listErr = errors.New("access denied")
	if rep := r.report(t, "today"); rep.StoreError != "не удалось прочитать папку stats: access denied" {
		t.Fatalf("%q", rep.StoreError)
	}
	r.files.listErr = nil
	if rep := r.report(t, "today"); rep.StoreError != "" || rep.Total.TC != 1 {
		t.Fatalf("%q %+v", rep.StoreError, rep.Total)
	}
}

// A program known only by its file name (days of HyRoute 1.2.0) joins the
// row of its path when exactly one path has that name.
func TestFoldExeRows(t *testing.T) {
	l := []Row{
		{Key: `c:\apps\chrome.exe`, Name: "chrome.exe", Counters: Counters{TU: 5}},
		{Key: "chrome.exe", Name: "Chrome.exe", Counters: Counters{TU: 3, TC: 1}},
		{Key: `c:\x\a.exe`, Counters: Counters{TU: 1}},
		{Key: `c:\y\a.exe`, Counters: Counters{TU: 1}},
		{Key: "a.exe", Counters: Counters{TU: 1}},
		{Key: "proxy:b.exe", Counters: Counters{TU: 1}},
		{Key: "b.exe", Counters: Counters{TU: 1}},
		{Key: "", Counters: Counters{TU: 1}},
		{Key: Others, Counters: Counters{TU: 1}},
	}
	foldExeRows(&l)
	if len(l) != 8 {
		t.Fatalf("%+v", l)
	}
	if c := rowOf(l, `c:\apps\chrome.exe`); c.TU != 8 || c.TC != 1 || c.Name != "chrome.exe" || rowOf(l, "chrome.exe").Key != "<none>" {
		t.Fatalf("%+v", l)
	}
	for _, k := range []string{"a.exe", "b.exe", "proxy:b.exe", "", Others} {
		if rowOf(l, k).TU != 1 {
			t.Errorf("%q folded", k)
		}
	}
}
