package stats

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"time"
)

// reopen is a new collector over the same files (the next start).
func (r *rig) reopen() {
	r.c = New(nil)
	r.c.Now = r.clk.now
	r.c.Configure(r.files)
	r.src = r.c.NewSource()
	r.reg.OnClose = r.src.Closed
}

func imported(f *memFiles) bool { return bytes.Contains(f.get("mode"), []byte(`"imported":true`)) }

// The statistics of HyRoute 1.2.0 (traffic.json) are imported once;
// entries that make no sense (the nulls 1.2.0 crashed on) are skipped;
// the old file is only read.
func TestLegacyImport(t *testing.T) {
	today := dayOf(t0)
	y := addDays(today, -1)
	old := addDays(today, -120)
	legacy := []byte(`{"version":1,"days":{
		"` + today + `":{"servers":{"p1":{"sent":10,"recv":100},"p2":{"sent":1,"recv":2}},"apps":{"chrome.exe":{"sent":10,"recv":100},"?":{"sent":1,"recv":2}}},
		"` + y + `":{},
		"` + old + `":{"servers":{"p1":{"sent":5,"recv":50}}},
		"2020-01-01":{"servers":{"p1":{"sent":5,"recv":50}}},
		"2031-01-01":{"servers":{"p1":{"sent":5,"recv":50}}},
		"garbage":{"servers":{"p1":{"sent":5,"recv":50}}},
		"2026-01-01":null,
		"` + addDays(today, -2) + `":{"servers":{"x":null,"p1":{"sent":-5,"recv":3}},"apps":{"a.exe":null}}
	},"hours":{"x":null},"names":{"p1":"Германия"}}`)
	r := newRig(t)
	r.files.legacy = legacy
	rep := r.report(t, "today")
	if rep.Total.TU != 11 || rep.Total.TD != 102 || rep.Total.TC != 0 {
		t.Fatalf("%+v", rep.Total)
	}
	if s := rowOf(rep.Servers, "p1"); s.Name != "Германия" || s.TD != 100 {
		t.Fatalf("%+v", rep.Servers)
	}
	if a := rowOf(rep.Apps, "chrome.exe"); a.TU != 10 || a.Name != "chrome.exe" {
		t.Fatalf("%+v", rep.Apps)
	}
	if a := rowOf(rep.Apps, ""); a.TU != 1 {
		t.Fatalf("unknown program: %+v", rep.Apps)
	}
	// No site is known: the list still sums to the total.
	if len(rep.Sites) != 1 || rep.Sites[0].Key != "" || rep.Sites[0].Counters != rep.Total {
		t.Fatalf("%+v", rep.Sites)
	}
	d2 := r.files.file(t, "day-"+addDays(today, -2))
	if d2.Total.TU != 0 || d2.Total.TD != 3 || rowOf(d2.Apps, Others).TD != 3 || !d2.Imported {
		t.Fatalf("%+v", d2)
	}
	m := r.files.file(t, "month-"+old[:7])
	if len(m.Days) != 1 || m.Days[0] != old || m.Total.TU != 5 || rowOf(m.Apps, Others).TU != 5 {
		t.Fatalf("%+v", m)
	}
	if r.files.has("day-2031-01-01") || r.files.has("day-2020-01-01") || r.files.has("day-"+y) || r.files.has("month-2020-01") {
		t.Fatal("nonsense imported")
	}
	if !imported(r.files) {
		t.Fatalf("mode.json: %s", r.files.get("mode"))
	}
	// Once: the next start does not read it again (not even after Reset).
	if err := r.c.Reset(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	r.reopen()
	if rep := r.report(t, "today"); rep.Total != (Counters{}) {
		t.Fatalf("imported twice: %+v", rep.Total)
	}

	// Not the 1.2.0 format, not JSON, a link: nothing imported, and not
	// tried again.
	for _, bad := range []string{`{"version":2,"days":{}}`, `{garbage`, `{"days":{"` + today + `":{"servers":{"p":{"sent":1}}}}}`, "link"} {
		r := newRig(t)
		if bad == "link" {
			r.files.legacyErr = fmt.Errorf("%w: traffic.json", ErrCorrupt)
		} else {
			r.files.legacy = []byte(bad)
		}
		r.report(t, "today")
		if r.files.writes != 1 || !imported(r.files) {
			t.Fatalf("%s: %d writes, mode %s", bad, r.files.writes, r.files.get("mode"))
		}
		r.files.legacy, r.files.legacyErr = legacy, nil
		r.reopen()
		if r.report(t, "today").Total != (Counters{}) {
			t.Fatalf("%s: tried again", bad)
		}
	}
	// No traffic.json: nothing is written (the folder is not created).
	r3 := newRig(t)
	r3.report(t, "today")
	if r3.files.writes != 0 {
		t.Fatal("wrote without traffic.json")
	}
	// mode.json unreadable: whether it was imported is unknown, so not
	// in this run.
	r4 := newRig(t)
	r4.files.put("mode", []byte("{"))
	r4.files.legacy = legacy
	r4.reopen()
	if r4.report(t, "today").Total != (Counters{}) || r4.files.writes != 0 {
		t.Fatal("imported with an unreadable mode.json")
	}
}

// A transient failure (traffic.json busy, a failed write) is retried later
// in the run, also after this version created the folder, and a repeated
// import never counts a day twice (PITFALLS #14).
func TestLegacyImportRetry(t *testing.T) {
	today := dayOf(t0)
	y := addDays(today, -1)
	legacy := []byte(`{"version":1,"days":{
		"` + today + `":{"servers":{"p1":{"sent":10,"recv":100}}},
		"` + y + `":{"servers":{"p1":{"sent":1,"recv":2}}}
	}}`)
	r := newRig(t)
	r.files.legacy = legacy
	r.files.legacyErr = &fs.PathError{Op: "open", Path: "traffic.json", Err: errors.New("sharing violation")}
	if rep := r.report(t, "today"); rep.Total != (Counters{}) {
		t.Fatalf("%+v", rep.Total)
	}
	// This version writes today's file meanwhile.
	rec := r.open(`C:\a.exe`, tunnel("p1", "relayed"))
	rec.Sent.Add(1000)
	r.close(rec)
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	r.files.mu.Lock()
	r.files.legacyErr = nil
	r.files.mu.Unlock()
	// Not before the retry time.
	if rep := r.report(t, "today"); rep.Total.TU != 1000 {
		t.Fatalf("%+v", rep.Total)
	}
	// A write fails in the middle: yesterday is written, today not.
	r.clk.add(legacyRetryMin)
	r.files.onWrite = func(name string) error {
		if name == "day-"+today {
			return errors.New("disk full")
		}
		return nil
	}
	r.report(t, "today")
	if !r.files.has("day-"+y) || imported(r.files) {
		t.Fatal("the first half not written, or marked done")
	}
	r.files.onWrite = nil
	// The next start completes it without counting yesterday twice.
	r.reopen()
	if rep := r.report(t, "today"); rep.Total.TU != 1010 || rep.Total.TC != 1 {
		t.Fatalf("today: %+v", rep.Total)
	}
	if rep := r.report(t, "yesterday"); rep.Total.TU != 1 || rep.Total.TD != 2 {
		t.Fatalf("yesterday: %+v", rep.Total)
	}
	if !imported(r.files) {
		t.Fatal("not marked done")
	}
	// A lost mark (mode.json written by an older build): a repeated
	// import skips the files that hold it.
	r.files.put("mode", []byte(`{"v":1,"mode":""}`))
	r.reopen()
	if rep := r.report(t, "7d"); rep.Total.TU != 1011 || rep.Total.TD != 102 {
		t.Fatalf("repeated: %+v", rep.Total)
	}
	// The flags survive this version's flushes of the same day.
	rec = r.open(`C:\a.exe`, tunnel("p1", "relayed"))
	rec.Sent.Add(1)
	r.close(rec)
	r.c.Flush(r.clk.now())
	if f := r.files.file(t, "day-"+today); !f.Imported || f.Total.TU != 1011 {
		t.Fatalf("%+v", f)
	}
	// Retries back off: at most once a minute, then less often.
	r2 := newRig(t)
	r2.files.legacyErr = errors.New("busy")
	reads := 0
	for i := 0; i < 10; i++ {
		before := r2.c.legacyRetry
		r2.report(t, "today")
		if r2.c.legacyRetry != before {
			reads++
		}
		r2.clk.add(30 * time.Second)
	}
	if reads != 3 { // at 0, 60 s (wait 1 min) and 180 s (wait 2 min)
		t.Fatalf("%d attempts in 5 minutes", reads)
	}
}

// v1.2.0's program rows: a local proxy maps to that proxy's rows when it
// is found; «Без сайтов» imports no site row.
func TestLegacyImportMapping(t *testing.T) {
	today := dayOf(t0)
	legacy := []byte(`{"version":1,"days":{"` + today + `":{"servers":{"p1":{"sent":10,"recv":100}},
		"apps":{"Локальный прокси «Биржа»":{"sent":4,"recv":40},"Локальный прокси :1081":{"sent":6,"recv":60}}}}}`)
	r := newRig(t)
	r.c.LegacyProxy = func(name string) (string, string, bool) {
		if name == "Локальный прокси «Биржа»" {
			return "proxy:AbC", "Биржа", true
		}
		return "", "", false
	}
	if err := r.c.SetMode(t0, ModeNoSites); err != nil {
		t.Fatal(err)
	}
	r.files.legacy = legacy
	r.c.legacyDone = false // SetMode ran the import attempt before traffic.json appeared
	rep := r.report(t, "today")
	if a := rowOf(rep.Apps, "proxy:AbC"); a.Name != "Биржа" || a.TU != 4 {
		t.Fatalf("%+v", rep.Apps)
	}
	if a := rowOf(rep.Apps, "локальный прокси :1081"); a.TU != 6 || a.Name != "Локальный прокси :1081" {
		t.Fatalf("%+v", rep.Apps)
	}
	if len(rep.Sites) != 0 {
		t.Fatalf("%+v", rep.Sites)
	}
	if !bytes.Contains(r.files.get("mode"), []byte(`"no-sites"`)) {
		t.Fatalf("mode lost: %s", r.files.get("mode"))
	}
}

// legacyOne is traffic.json with one day of 7 bytes up, 70 down.
func legacyOne(day string) []byte {
	return []byte(`{"version":1,"days":{"` + day + `":{"servers":{"p1":{"sent":7,"recv":70}},"apps":{"a.exe":{"sent":7,"recv":70}}}}}`)
}

// A day imported and then folded into its month by the compaction keeps
// the mark in the month; an unreadable mode.json is taken as imported. The
// v1.2.0 history is never counted twice.
func TestLegacyImportCompacted(t *testing.T) {
	d := addDays(dayOf(t0), -89)
	r := newRig(t)
	r.files.legacy = legacyOne(d)
	if rep := r.report(t, d[:7]); rep.Total.TU != 7 || !imported(r.files) {
		t.Fatalf("%+v", rep.Total)
	}
	r.clk.add(48 * time.Hour)
	if err := r.c.Compact(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if r.files.has("day-"+d) || !r.files.file(t, "month-"+d[:7]).Imported {
		t.Fatal("not folded, or the month lost the mark")
	}
	check := func(what string) {
		t.Helper()
		if rep := r.report(t, d[:7]); rep.Total.TU != 7 || rep.Total.TD != 70 {
			t.Fatalf("%s: %+v", what, rep.Total)
		}
	}
	// A damaged mode.json, then the user picks a mode again.
	r.files.put("mode", []byte("{"))
	r.reopen()
	if err := r.c.SetMode(r.clk.now(), ModeAll); err != nil {
		t.Fatal(err)
	}
	if !imported(r.files) {
		t.Fatalf("mark lost: %s", r.files.get("mode"))
	}
	r.reopen()
	check("after a damaged mode.json")
	// The mark lost anyway: the month holds the import.
	r.files.put("mode", []byte(`{"v":1,"mode":""}`))
	r.reopen()
	check("after a lost mark")
}

// While the import is still pending, the compaction does not fold an
// imported day into a month the import has yet to write.
func TestLegacyImportPendingCompaction(t *testing.T) {
	today := dayOf(t0)
	d, old := addDays(today, -89), addDays(today, -120)
	r := newRig(t)
	r.files.legacy = []byte(`{"version":1,"days":{
		"` + d + `":{"servers":{"p1":{"sent":7,"recv":70}}},
		"` + old + `":{"servers":{"p1":{"sent":5,"recv":50}}}}}`)
	r.files.onWrite = func(name string) error {
		if name == "month-"+old[:7] {
			return errors.New("disk full")
		}
		return nil
	}
	r.report(t, "today")
	if !r.files.has("day-"+d) || imported(r.files) {
		t.Fatal("setup")
	}
	r.clk.add(48 * time.Hour)
	if err := r.c.Compact(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if !r.files.has("day-"+d) || r.files.has("month-"+d[:7]) {
		t.Fatal("folded while the import is pending")
	}
	r.files.mu.Lock()
	r.files.onWrite = nil
	r.files.mu.Unlock()
	r.clk.add(legacyRetryMax)
	if err := r.c.Compact(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	if !imported(r.files) || r.files.has("day-"+d) || !r.files.file(t, "month-"+d[:7]).Imported {
		t.Fatal("import or compaction not completed")
	}
	if m := r.files.file(t, "month-"+old[:7]); m.Total.TU != 5 {
		t.Fatalf("%+v", m.Total)
	}
	if rep := r.report(t, d[:7]); rep.Total.TU != 7 {
		t.Fatalf("%+v", rep.Total)
	}
}

// «Сбросить статистику» and a restore end a pending import: what the user
// deleted or replaced does not come back, neither later in the run nor at
// the next start.
func TestLegacyImportDroppedByReset(t *testing.T) {
	today := dayOf(t0)
	busy := &fs.PathError{Op: "open", Path: "traffic.json", Err: errors.New("sharing violation")}
	for _, how := range []string{"reset", "replace"} {
		r := newRig(t)
		r.files.legacy = legacyOne(today)
		r.files.legacyErr = busy
		r.report(t, "today")
		switch how {
		case "reset":
			if err := r.c.Reset(r.clk.now()); err != nil {
				t.Fatal(err)
			}
		case "replace":
			raw, _, err := newRig(t).c.Export(t0)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.c.Replace(r.clk.now(), raw); err != nil {
				t.Fatal(err)
			}
		}
		if !imported(r.files) {
			t.Fatalf("%s: not marked: %s", how, r.files.get("mode"))
		}
		r.files.mu.Lock()
		r.files.legacyErr = nil
		r.files.mu.Unlock()
		r.clk.add(legacyRetryMax)
		if rep := r.report(t, "today"); rep.Total != (Counters{}) {
			t.Fatalf("%s: came back in the run: %+v", how, rep.Total)
		}
		r.reopen()
		if rep := r.report(t, "today"); rep.Total != (Counters{}) {
			t.Fatalf("%s: came back at the next start: %+v", how, rep.Total)
		}
	}
	// Imported, deleted, then a damaged mode.json and a new choice of the
	// mode: the mark stays, the deleted history does not come back.
	r := newRig(t)
	r.files.legacy = legacyOne(today)
	r.report(t, "today")
	if err := r.c.Reset(r.clk.now()); err != nil {
		t.Fatal(err)
	}
	r.files.put("mode", []byte("{"))
	r.reopen()
	if err := r.c.SetMode(r.clk.now(), ModeNoSites); err != nil {
		t.Fatal(err)
	}
	r.reopen()
	if rep := r.report(t, "today"); rep.Total != (Counters{}) {
		t.Fatalf("came back after a damaged mode.json: %+v", rep.Total)
	}
	// No import pending (no traffic.json): Reset writes nothing.
	r = newRig(t)
	r.report(t, "today")
	if err := r.c.Reset(r.clk.now()); err != nil || r.files.writes != 0 {
		t.Fatalf("%v, %d writes", err, r.files.writes)
	}
}

// 1.2.0 promised to keep no sites: an upgraded user starts with «Без
// сайтов»; a new user, or one who picked a mode, keeps «Всё».
func TestLegacyNoSitesDefault(t *testing.T) {
	today := dayOf(t0)
	r := newRig(t)
	if r.c.Mode() != ModeAll {
		t.Fatalf("new user: %v", r.c.Mode())
	}
	r.files.legacy = legacyOne(today)
	r.reopen()
	if r.c.Mode() != ModeNoSites {
		t.Fatalf("upgraded user: %v", r.c.Mode())
	}
	rep := r.report(t, "today")
	if rep.Total.TU != 7 || len(rep.Sites) != 0 || rep.Mode != string(ModeNoSites) {
		t.Fatalf("%+v %+v", rep.Total, rep.Sites)
	}
	if b := r.files.get("mode"); !bytes.Contains(b, []byte(`"no-sites"`)) || !imported(r.files) {
		t.Fatalf("mode.json: %s", b)
	}
	// The user's choice holds over the default.
	if err := r.c.SetMode(r.clk.now(), ModeAll); err != nil {
		t.Fatal(err)
	}
	r.reopen()
	if r.c.Mode() != ModeAll {
		t.Fatalf("choice lost: %v", r.c.Mode())
	}
	// A link or a busy file at the place of traffic.json counts too.
	r2 := newRig(t)
	r2.files.legacyErr = fmt.Errorf("%w: traffic.json", ErrCorrupt)
	r2.reopen()
	if r2.c.Mode() != ModeNoSites {
		t.Fatalf("link: %v", r2.c.Mode())
	}
}

// An upgrade without traffic.json (1.2.0 wrote it only after VPN traffic,
// and «Очистить» deleted it; or 1.0/1.1) also starts with «Без сайтов».
// The default is written with the first statistics file, so a later start
// does not decide again.
func TestUpgradedNoSitesDefault(t *testing.T) {
	traffic := func(r *rig) {
		rec := r.open(`C:\a.exe`, tunnel("de", "ok"))
		rec.Sent.Add(10)
		r.close(rec)
		if err := r.c.Flush(r.clk.now()); err != nil {
			t.Fatal(err)
		}
	}
	r := newRig(t)
	r.files.earlier = true
	r.reopen()
	if r.c.Mode() != ModeNoSites {
		t.Fatalf("upgraded user: %v", r.c.Mode())
	}
	if r.files.has("mode") {
		t.Fatal("mode.json written before any statistics")
	}
	traffic(r)
	if b := r.files.get("mode"); !bytes.Contains(b, []byte(`"no-sites"`)) {
		t.Fatalf("mode.json: %s", b)
	}
	// A new user: «Всё», kept after the servers and settings appear.
	r2 := newRig(t)
	if r2.c.Mode() != ModeAll {
		t.Fatalf("new user: %v", r2.c.Mode())
	}
	traffic(r2)
	if b := r2.files.get("mode"); b == nil || bytes.Contains(b, []byte(`"no-sites"`)) {
		t.Fatalf("mode.json: %s", b)
	}
	r2.files.earlier = true
	r2.reopen()
	if r2.c.Mode() != ModeAll {
		t.Fatalf("decided again: %v", r2.c.Mode())
	}
	// A failed mode write is retried with the next file.
	r3 := newRig(t)
	r3.files.onWrite = func(name string) error {
		if name == "mode" {
			return errors.New("access denied")
		}
		return nil
	}
	traffic(r3)
	if r3.files.has("mode") {
		t.Fatal("mode.json written")
	}
	r3.files.onWrite = nil
	traffic(r3)
	if !r3.files.has("mode") {
		t.Fatal("mode.json not retried")
	}
}

// The conversion is linear in the size of traffic.json (it is written by
// the user's programs), and a file over the bounds is not imported and
// not retried.
func TestLegacyImportLarge(t *testing.T) {
	today := dayOf(t0)
	big := func(apps, days int) []byte {
		var b bytes.Buffer
		b.WriteString(`{"version":1,"days":{`)
		for i := 0; i < days; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%d":{}`, i)
		}
		if days > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"%s":{"servers":{"p1":{"sent":%d,"recv":1}},"apps":{`, today, apps)
		for i := 0; i < apps; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"app%d.exe":{"sent":1,"recv":0}`, i)
		}
		b.WriteString(`}}}}`)
		return b.Bytes()
	}
	start := time.Now()
	files, n, err := legacyFiles(t0, big(maxLegacyRows, 0), ModeAll, nil)
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("%d programs took %v", maxLegacyRows, took)
	}
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	f := files["day-"+today]
	if len(f.Apps) != dayCaps[listApps] || f.Total.TU != maxLegacyRows {
		t.Fatalf("%d rows, %+v", len(f.Apps), f.Total)
	}
	if o := rowOf(f.Apps, Others); o.TU != int64(maxLegacyRows-dayCaps[listApps]+1) {
		t.Fatalf("others: %+v", o)
	}
	for _, b := range [][]byte{big(maxLegacyRows+1, 0), big(1, maxLegacyDays)} {
		if _, _, err := legacyFiles(t0, b, ModeAll, nil); !errors.Is(err, errLegacyFormat) {
			t.Fatalf("over the bounds: %v", err)
		}
	}
	// Refused for good: marked done, not retried.
	r := newRig(t)
	r.files.legacy = big(maxLegacyRows+1, 0)
	if rep := r.report(t, "today"); rep.Total != (Counters{}) || !imported(r.files) {
		t.Fatalf("%+v %s", rep.Total, r.files.get("mode"))
	}
}
