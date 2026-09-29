package stats

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/flows"
)

// history fills a rig: flows today, day files, an old month file.
func history(t *testing.T, r *rig) {
	t.Helper()
	for i, path := range []string{`C:\a.exe`, `C:\b.exe`, `C:\c.exe`} {
		rec := r.open(path, func(f *flows.Fields) {
			f.Route, f.Profile, f.Outcome, f.Domain = "tunnel", "de", "relayed", "www.example"+itoa(i)+".com"
		})
		rec.Sent.Add(int64(100 * (i + 1)))
		rec.Recv.Add(7)
		r.close(rec)
	}
	for i := 1; i <= 5; i++ {
		d := addDays(dayOf(t0), -i)
		r.files.put("day-"+d, validFile(t, "day-"+d, Counters{TC: int64(i), TU: 10}))
	}
	m := &File{V: 1, Month: "2026-03", Days: []string{"2026-03-05"}, Total: Counters{TC: 50}, Sites: []Row{{Key: "old.com", Counters: Counters{TC: 50}}}}
	b, _ := m.marshal()
	r.files.put("month-2026-03", b)
	if err := r.c.Flush(r.clk.now()); err != nil {
		t.Fatal(err)
	}
}

func reports(t *testing.T, r *rig) []Report {
	t.Helper()
	var out []Report
	for _, p := range []string{"today", "30d", "2026-03"} {
		rep := r.report(t, p)
		rep.StoreError = ""
		out = append(out, rep)
	}
	return out
}

func TestExportImport(t *testing.T) {
	src := newRig(t)
	history(t, src)
	raw, detail, _, err := src.c.Export(src.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "с 05.03.2026") || !strings.Contains(detail, "7 дней") || !strings.Contains(detail, "сбор: всё") {
		t.Fatalf("detail %q", detail)
	}
	// Into an empty collector: the same reports.
	dst := newRig(t)
	if d, err := dst.c.CheckImport(dst.clk.now(), raw); err != nil || !strings.Contains(d, "сбор: всё") {
		t.Fatalf("%q %v", d, err)
	}
	if err := dst.c.Replace(dst.clk.now(), raw); err != nil {
		t.Fatal(err)
	}
	if a, b := reports(t, src), reports(t, dst); !reflect.DeepEqual(a, b) {
		t.Fatalf("reports differ:\n%+v\n%+v", a, b)
	}

	// The backup's mode is named; the stricter one wins.
	var env envelope
	json.Unmarshal(raw, &env)
	env.Mode = "no-sites"
	noSites := mustJSON(t, env)
	if d, _ := dst.c.CheckImport(dst.clk.now(), noSites); !strings.Contains(d, "сбор: без сайтов") {
		t.Fatalf("%q", d)
	}
	off := newRig(t)
	off.c.SetMode(t0, ModeOff)
	if d, _ := off.c.CheckImport(off.clk.now(), raw); !strings.Contains(d, "(останется «выключен»)") {
		t.Fatalf("%q", d)
	}
	if err := off.c.Replace(off.clk.now(), raw); err != nil || off.c.Mode() != ModeOff {
		t.Fatalf("%v %q", err, off.c.Mode())
	}
	ns := newRig(t)
	if err := ns.c.Replace(ns.clk.now(), noSites); err != nil || ns.c.Mode() != ModeNoSites {
		t.Fatalf("%v %q", err, ns.c.Mode())
	}
	if f := ns.files.file(t, "month-2026-03"); len(f.Sites) != 0 {
		t.Fatal("sites restored in «без сайтов»")
	}
	if !strings.Contains(string(ns.files.get("mode")), "no-sites") {
		t.Fatal("mode not written")
	}

	// Replace over existing files: v1 and corrupt ones not in the backup
	// go; newer and future ones stay; a backup file over a newer one is
	// skipped; unflushed deltas are kept.
	cur := newRig(t)
	stray := "day-" + addDays(dayOf(t0), -20)
	cur.files.put(stray, validFile(t, stray, Counters{TC: 1}))
	broken := "day-" + addDays(dayOf(t0), -21)
	cur.files.put(broken, []byte("{"))
	newer := []byte(`{"v":2,"day":"` + addDays(dayOf(t0), -22) + `"}`)
	cur.files.put("day-"+addDays(dayOf(t0), -22), newer)
	newerToday := []byte(`{"v":2,"day":"` + addDays(dayOf(t0), -1) + `"}`)
	cur.files.put("day-"+addDays(dayOf(t0), -1), newerToday)
	fut := validFile(t, "day-2031-01-01", Counters{TC: 1})
	cur.files.put("day-2031-01-01", fut)
	rec := cur.open(`C:\z.exe`, tunnel("de", "relayed"))
	rec.Sent.Add(3)
	cur.close(rec)
	if err := cur.c.Replace(cur.clk.now(), raw); err != nil {
		t.Fatal(err)
	}
	if cur.files.has(stray) || cur.files.has(broken) {
		t.Fatal("old files kept")
	}
	if !bytes.Equal(cur.files.get("day-"+addDays(dayOf(t0), -22)), newer) || !bytes.Equal(cur.files.get("day-"+addDays(dayOf(t0), -1)), newerToday) ||
		!bytes.Equal(cur.files.get("day-2031-01-01"), fut) {
		t.Fatal("newer or future files touched")
	}
	if err := cur.c.Flush(cur.clk.now()); err != nil {
		t.Fatal(err)
	}
	if f := cur.files.file(t, "day-"+dayOf(t0)); f.Total.TU != 600+3 {
		t.Fatalf("delta not merged into the restored day: %+v", f.Total)
	}

	// Refusals: nothing is written.
	bad := newRig(t)
	var e2 envelope
	json.Unmarshal(raw, &e2)
	e2.Files["day-"+dayOf(t0)] = json.RawMessage(`{"v":1,"day":"2020-01-01"}`)
	for name, payload := range map[string][]byte{
		"invalid file": mustJSON(t, e2),
		"v2":           []byte(`{"v":2,"mode":"","files":{}}`),
		"unknown key":  []byte(`{"v":1,"mode":"","files":{},"x":1}`),
		"bad mode":     []byte(`{"v":1,"mode":"all","files":{}}`),
		"bad name":     []byte(`{"v":1,"mode":"","files":{"mode":{}}}`),
		"too large":    bytes.Repeat([]byte(" "), MaxExport+1),
	} {
		if _, err := bad.c.CheckImport(bad.clk.now(), payload); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := bad.c.Replace(bad.clk.now(), payload); err == nil {
			t.Errorf("%s: replaced", name)
		}
	}
	if bad.files.writes != 0 {
		t.Fatalf("%d writes", bad.files.writes)
	}
	// Future files in a backup are dropped, and said.
	var e3 envelope
	json.Unmarshal(raw, &e3)
	e3.Files["day-2031-01-01"] = json.RawMessage(fut)
	if d, err := bad.c.CheckImport(bad.clk.now(), mustJSON(t, e3)); err != nil || !strings.Contains(d, "1 файл с датой в будущем пропущено") {
		t.Fatalf("%q %v", d, err)
	}

	// A huge history: the oldest days are left out, and said.
	exportLimit = len(raw) - 100
	defer func() { exportLimit = MaxExport }()
	raw2, d2, _, err := src.c.Export(src.clk.now())
	oldest := "без дней до " + ruDate(addDays(dayOf(t0), -5))
	if err != nil || len(raw2) > exportLimit || !strings.Contains(d2, oldest+": слишком много данных") {
		t.Fatalf("%d %q %v", len(raw2), d2, err)
	}
	exportLimit = MaxExport

	// A write failure in the middle: an error naming it.
	fail := newRig(t)
	n := 0
	fail.files.onWrite = func(string) error {
		if n++; n == 2 {
			return errors.New("disk full")
		}
		return nil
	}
	if err := fail.c.Replace(fail.clk.now(), raw); err == nil || !strings.Contains(err.Error(), "не записана") || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("%v", err)
	}
}

func TestSummary(t *testing.T) {
	r := newRig(t)
	if d, empty := r.c.Summary(t0); !empty || d != "сбор: всё" {
		t.Fatalf("%q %v", d, empty)
	}
	history(t, r)
	if d, empty := r.c.Summary(t0); empty || !strings.HasPrefix(d, "с 05.03.2026 · 7 дней") {
		t.Fatalf("%q %v", d, empty)
	}
}
