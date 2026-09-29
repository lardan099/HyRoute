package stats

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/flows"
)

func TestModeFile(t *testing.T) {
	for _, c := range []struct {
		name  string
		body  []byte
		read  error
		want  Mode
		store bool
	}{
		{"absent", nil, nil, ModeOn, false},
		{"valid", []byte(`{"v":1,"mode":"no-sites"}`), nil, ModeOn, false},
		{"valid all", []byte(`{"v":1,"mode":""}`), nil, ModeOn, false},
		{"newer, known mode", []byte(`{"v":2,"mode":"off","x":1}`), nil, ModeOff, false},
		{"newer, known all", []byte(`{"v":2,"mode":""}`), nil, ModeOn, false},
		{"newer, unknown mode", []byte(`{"v":2,"mode":"hourly"}`), nil, ModeOff, true},
		{"corrupt", []byte(`{"v":1,`), nil, ModeOff, true},
		{"link", nil, ErrCorrupt, ModeOff, true},
		{"folder refused", nil, errors.New("folder is a link"), ModeOff, true},
		{"too large", bytes.Repeat([]byte(" "), maxModeBytes+1), nil, ModeOff, true},
	} {
		f := newFiles()
		if c.body != nil {
			f.put("mode", c.body)
		}
		if c.read != nil {
			f.readErr["mode"] = c.read
		}
		col := New(nil)
		col.Configure(f)
		if col.Mode() != c.want || (col.StoreError() != "") != c.store {
			t.Errorf("%s: mode %q storeError %q", c.name, col.Mode(), col.StoreError())
		}
	}
	// SetMode applies in memory even when the file is not written.
	f := newFiles()
	f.onWrite = func(string) error { return errors.New("access denied") }
	col := New(nil)
	col.Configure(f)
	if err := col.SetMode(t0, ModeOff); err == nil || !strings.Contains(err.Error(), "не сохранён") || col.Mode() != ModeOff {
		t.Fatalf("%v %q", err, col.Mode())
	}
	// Reset keeps the mode file.
	r := newRig(t)
	r.c.SetMode(t0, ModeOn)
	r.c.Reset(t0)
	if !r.files.has("mode") || r.c.Mode() != ModeOn {
		t.Fatal("reset removed the mode")
	}
}

// Future files are ignored by reports, flush, compaction and export and
// removed only by Reset.
func TestFutureFiles(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 30; i++ {
		d := addDays(dayOf(t0), -i)
		r.files.put("day-"+d, validFile(t, "day-"+d, Counters{TC: 1}))
	}
	old := "day-" + addDays(dayOf(t0), -120)
	r.files.put(old, validFile(t, old, Counters{TC: 1}))
	fd, fm := validFile(t, "day-2031-01-01", Counters{TC: 1000}), validFile(t, "month-2031-01", Counters{TC: 1000})
	r.files.put("day-2031-01-01", fd)
	r.files.put("month-2031-01", fm)
	near := "day-" + addDays(dayOf(t0), 2) // today+2 is not the future yet
	r.files.put(near, validFile(t, near, Counters{TC: 1}))
	rep := r.report(t, "30d")
	if rep.Total.TC != 30 {
		t.Fatalf("%+v", rep.Total)
	}
	for _, m := range rep.Months {
		if m == "2031-01" {
			t.Fatalf("future month listed: %v", rep.Months)
		}
	}
	if _, err := r.c.Report(r.clk.now(), "2031-01"); err == nil {
		t.Fatal("a future month reported")
	}
	rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	r.close(rec)
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if err := r.c.Compact(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	raw, _, _, err := r.c.Export(r.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "2031") || !strings.Contains(string(raw), near) {
		t.Fatal("export and the future")
	}
	if err := r.c.Replace(r.clk.now(), raw); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.files.get("day-2031-01-01"), fd) || !bytes.Equal(r.files.get("month-2031-01"), fm) {
		t.Fatal("future files touched")
	}
	if r.files.has(old) || !r.files.has("month-"+addDays(dayOf(t0), -120)[:7]) {
		t.Fatal("retention did not run")
	}
	if err := r.c.Reset(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if r.files.has("day-2031-01-01") || r.files.has("month-2031-01") {
		t.Fatal("Reset kept the future files")
	}
}

// Flush merges into the file, trims to the caps with «Остальные», keeps
// the sums, the latest name, and saturates.
func TestFlushMergeTrim(t *testing.T) {
	r := newRig(t)
	name := "day-" + dayOf(t0)
	f := &File{V: 1, Day: dayOf(t0), Total: Counters{TU: maxCount - 5, TC: 1},
		Apps: []Row{{Key: "old.exe", Name: "Old", Counters: Counters{TU: maxCount - 5, TC: 1}}}}
	b, _ := f.marshal()
	r.files.put(name, b)
	for i := 0; i < 300; i++ {
		rec := r.reg.Open(&flows.Record{Proto: 6, Process: fmt.Sprintf("p%03d.exe", i)})
		rec.Set(func(fl *flows.Fields) {
			fl.Route, fl.Profile, fl.Outcome, fl.Domain = "tunnel", "de", "relayed", fmt.Sprintf("s%d.example.com", i)
		})
		rec.Sent.Add(int64(i + 1))
		r.close(rec)
	}
	rec := r.reg.Open(&flows.Record{Proto: 6, Process: "OLD.exe"})
	rec.Set(tunnel("de", "relayed"))
	rec.Sent.Add(100)
	r.close(rec)
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	got := r.files.file(t, name)
	if len(got.Apps) != dayCaps[listApps] || got.Apps[len(got.Apps)-1].Key != Others {
		t.Fatalf("%d apps, last %q", len(got.Apps), got.Apps[len(got.Apps)-1].Key)
	}
	if got.Total.TU != maxCount || got.Total.TC != 302 {
		t.Fatalf("total %+v", got.Total)
	}
	// Every row (with «Остальные») sums to the total; the old file had no
	// server row, nothing went through a group, and sites are never kept.
	for i, want := range [nLists]int64{302, 0, 301, 0} {
		var sum Counters
		for _, row := range *got.list(i) {
			sum.add(row.Counters)
		}
		if sum.TC != want {
			t.Fatalf("list %d: sum %+v, want tc %d", i, sum, want)
		}
	}
	if a := rowOf(got.Apps, "old.exe"); a.Name != "OLD.exe" || a.TU != maxCount {
		t.Fatalf("%+v", a)
	}
}

func TestFlushNeverCompacts(t *testing.T) {
	r := newRig(t)
	old := "day-" + addDays(dayOf(t0), -100)
	r.files.put(old, validFile(t, old, Counters{TC: 3}))
	rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	r.close(rec)
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if !r.files.has(old) {
		t.Fatal("flush compacted")
	}
	if !r.c.CompactDue(r.clk.now()) {
		t.Fatal("not due")
	}
	if err := r.c.Compact(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	m := r.files.file(t, "month-"+old[4:11])
	if r.files.has(old) || m.Total.TC != 3 || len(m.Days) != 1 || r.c.CompactDue(r.clk.now()) {
		t.Fatalf("%+v", m)
	}
}

func TestFlushWriteErrorKeepsDelta(t *testing.T) {
	r := newRig(t)
	r.files.onWrite = func(string) error { return errors.New("disk full") }
	rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	rec.Sent.Add(10)
	r.close(rec)
	if err := r.c.Flush(r.clk.now()); err == nil {
		t.Fatal("no error")
	}
	if e := r.c.StoreError(); !strings.Contains(e, "day-"+dayOf(t0)+".json") || strings.Contains(e, `\`) {
		t.Fatalf("%q", e)
	}
	if got := r.today(t); got.TU != 10 {
		t.Fatalf("delta lost: %+v", got)
	}
	r.files.onWrite = nil
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if r.c.StoreError() != "" || r.files.file(t, "day-"+dayOf(t0)).Total.TU != 10 {
		t.Fatal("second flush")
	}
}

func TestFlushCorruptPastDay(t *testing.T) {
	r := newRig(t)
	d := addDays(dayOf(t0), -3)
	r.files.put("day-"+d, []byte("not json"))
	r.clk.set(t0.AddDate(0, 0, -3))
	rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	rec.Sent.Add(10)
	r.close(rec)
	r.clk.set(t0)
	if rep := r.report(t, "7d"); !strings.Contains(rep.StoreError, "повреждён") {
		t.Fatalf("%q", rep.StoreError)
	}
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if f := r.files.file(t, "day-"+d); f.Total.TU != 10 || r.c.StoreError() != "" {
		t.Fatalf("%+v %q", f.Total, r.c.StoreError())
	}
	// A transient read error keeps the delta and retries.
	rec = r.open(`C:\a.exe`, tunnel("de", "relayed"))
	rec.Sent.Add(5)
	r.close(rec)
	r.c.cache.init()
	r.files.readErr["day-"+dayOf(t0)] = errors.New("sharing violation")
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if r.files.has("day-"+dayOf(t0)) || r.c.StoreError() == "" {
		t.Fatal("written over an unreadable file")
	}
	delete(r.files.readErr, "day-"+dayOf(t0))
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if r.files.file(t, "day-"+dayOf(t0)).Total.TU != 5 || r.c.StoreError() != "" {
		t.Fatal("retry")
	}
}

func TestFlushLateDelta(t *testing.T) {
	r := newRig(t)
	late := addDays(dayOf(t0), -95)
	r.c.mu.Lock()
	r.c.deltaLocked(late).total.TC = 4
	r.c.mu.Unlock()
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	m := r.files.file(t, "month-"+late[:7])
	if m.Total.TC != 4 || len(m.Days) != 1 || m.Days[0] != late || r.files.has("day-"+late) {
		t.Fatalf("%+v", m)
	}
}

// A file of a newer version is never touched by this version.
func TestNewerVersionUntouched(t *testing.T) {
	r := newRig(t)
	name := "day-" + dayOf(t0)
	v2 := []byte(`{"v":2,"day":"` + dayOf(t0) + `","total":{"tc":9},"future":{"x":1}}`)
	r.files.put(name, v2)
	rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	rec.Sent.Add(10)
	r.close(rec)
	for i := 0; i < 2; i++ {
		if err := r.c.Flush(r.clk.now()); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(r.files.get(name), v2) {
		t.Fatal("newer file overwritten")
	}
	rep := r.report(t, "today")
	if rep.Total.TC != 0 || !strings.Contains(rep.StoreError, "более новой версией") {
		t.Fatalf("%+v %q", rep.Total, rep.StoreError)
	}
	// A newer month file keeps its old day unfolded; both go at 24 months.
	old := addDays(dayOf(t0), -100)
	r.files.put("day-"+old, validFile(t, "day-"+old, Counters{TC: 1}))
	r.files.put("month-"+old[:7], []byte(`{"v":2,"month":"`+old[:7]+`"}`))
	if err := r.c.Compact(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if !r.files.has("day-" + old) {
		t.Fatal("folded into a newer month")
	}
	r.clk.set(t0.AddDate(2, 1, 0))
	if err := r.c.Compact(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if r.files.has("day-"+old) || r.files.has("month-"+old[:7]) || r.files.has(name) {
		t.Fatal("date retention kept newer files")
	}
}

func TestCompactIdempotent(t *testing.T) {
	r := newRig(t)
	d1, d2 := addDays(dayOf(t0), -100), addDays(dayOf(t0), -101)
	r.files.put("day-"+d1, validFile(t, "day-"+d1, Counters{TC: 1}))
	r.files.put("day-"+d2, validFile(t, "day-"+d2, Counters{TC: 2}))
	// A crash after the month was written: the day is still there.
	m := &File{V: 1, Month: d1[:7], Days: []string{d1}, Total: Counters{TC: 1}}
	if d1[:7] != d2[:7] {
		t.Skip("the two days straddle a month")
	}
	b, _ := m.marshal()
	r.files.put("month-"+d1[:7], b)
	bad := addDays(dayOf(t0), -102)
	r.files.put("day-"+bad, []byte("{"))
	ancient := "month-" + addMonths(dayOf(t0)[:7], -30)
	r.files.put(ancient, validFile(t, ancient, Counters{TC: 1}))
	r.files.tmp[".tmp-old"] = t0.Add(-2 * time.Hour)
	r.files.tmp[".tmp-new"] = t0.Add(-time.Minute)
	for i := 0; i < 2; i++ {
		r.c.mu.Lock()
		r.c.compactAt = ""
		r.c.mu.Unlock()
		if err := r.c.Compact(r.clk.now()); err != nil {
			t.Fatal(err)
		}
	}
	got := r.files.file(t, "month-"+d1[:7])
	if got.Total.TC != 3 || len(got.Days) != 2 {
		t.Fatalf("%+v", got)
	}
	if r.files.has("day-"+d1) || r.files.has("day-"+d2) || r.files.has("day-"+bad) || r.files.has(ancient) {
		t.Fatal("left over")
	}
	if _, ok := r.files.tmp[".tmp-old"]; ok {
		t.Fatal("old temp file kept")
	}
	if _, ok := r.files.tmp[".tmp-new"]; !ok {
		t.Fatal("fresh temp file removed")
	}
}

// The parse cache is bounded by bytes: large files are not kept.
func TestCacheBytes(t *testing.T) {
	r := newRig(t)
	big := func(name string, rows, keyLen int) {
		kind, date, _ := parseName(name)
		f := &File{V: 1}
		if kind == kindDay {
			f.Day = date
		}
		for i := 0; i < rows; i++ {
			f.Apps = append(f.Apps, Row{Key: fmt.Sprintf("%06d%s", i, strings.Repeat("k", keyLen)), Counters: Counters{TC: 1}})
		}
		b, _ := f.marshal()
		r.files.put(name, b)
	}
	for i := 1; i <= 10; i++ {
		big("day-"+addDays(dayOf(t0), -i), 3000, 1000) // ~3 MiB
	}
	r.report(t, "30d")
	if r.c.cache.bytes != 0 {
		t.Fatalf("large files cached: %d bytes", r.c.cache.bytes)
	}
	r2 := newRig(t)
	r = r2
	for i := 1; i <= 29; i++ {
		big("day-"+addDays(dayOf(t0), -i), 600, 1000) // ~600 KiB
	}
	r.report(t, "30d")
	if r.c.cache.bytes > cacheBytes || r.c.cache.bytes == 0 {
		t.Fatalf("cached %d bytes", r.c.cache.bytes)
	}
}

func TestParseDefensive(t *testing.T) {
	day := dayOf(t0)
	name := "day-" + day
	rows := make([]Row, maxRows+1)
	for i := range rows {
		rows[i].Key = fmt.Sprint(i)
	}
	for _, c := range []struct {
		name string
		body string
		ok   bool
	}{
		{name, `garbage`, false},
		{name, `{"v":1,"day":"` + day + `","total":{"tc":-5,"tu":9007199254740993}}`, true},
		{name, `{"v":1,"day":"2020-01-01"}`, false},
		{name, `{"v":0,"day":"` + day + `"}`, false},
		{name, `{"v":1,"day":"` + day + `","apps":[null,{"k":"a"}]}`, true},
		{name, `{"v":1,"day":"` + day + `","apps":[{"k":"` + strings.Repeat("x", maxKey+1) + `"}]}`, false},
		{name, `{"v":1,"day":"` + day + `","apps":[{"k":"a","n":"` + strings.Repeat("x", maxName+1) + `"}]}`, false},
		{"month-2026-09", `{"v":1,"month":"2026-09","days":["2026-08-31"]}`, false},
		{"month-2026-09", `{"v":1,"month":"2026-09","days":["2026-09-01","2026-09-01"]}`, false},
		{"month-2026-09", `{"v":1,"month":"2026-09","days":["2026-09-02","2026-09-01"]}`, true},
		{"../x", `{"v":1}`, false},
		{"day-2026-13-01", `{"v":1,"day":"2026-13-01"}`, false},
		{"day-2026-09-28.json.tmp", `{"v":1}`, false},
		{"Mode", `{"v":1}`, false},
		{"mode", `{"v":1}`, false},
	} {
		f, err := parseFile(c.name, []byte(c.body))
		if (err == nil) != c.ok {
			t.Errorf("%s %.60s: %v", c.name, c.body, err)
		}
		if err == nil && (f.Total.TC < 0 || f.Total.TU > maxCount) {
			t.Errorf("not clamped: %+v", f.Total)
		}
	}
	b := mustJSON(t, File{V: 1, Day: day, Apps: rows})
	if _, err := parseFile(name, b); err == nil {
		t.Error("20001 rows accepted")
	}
	// A null day in a report or a flush does no harm.
	r := newRig(t)
	r.files.put(name, []byte(`{"v":1,"day":"`+day+`","apps":null,"sites":[null],"servers":[{"k":"x","drops":-1}]}`))
	rec := r.open(`C:\a.exe`, tunnel("de", "relayed"))
	r.close(rec)
	r.report(t, "today")
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
}

func TestFlushWithinBusy(t *testing.T) {
	r := newRig(t)
	r.c.ioMu.Lock()
	start := time.Now()
	err := r.c.FlushWithin(r.clk.now(), 50*time.Millisecond)
	el := time.Since(start)
	r.c.ioMu.Unlock()
	if !errors.Is(err, ErrBusy) || el > time.Second {
		t.Fatalf("%v after %v", err, el)
	}
	if err := r.c.FlushWithin(r.clk.now(), 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
}
