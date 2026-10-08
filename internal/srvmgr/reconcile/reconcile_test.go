package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// A server as HyRoute recorded it: everything compared, nothing found,
// nothing written, the state left alone.
func TestRoundClean(t *testing.T) {
	w := newWorld(t)
	w.r.Round(context.Background())
	d := w.drift(w.a)
	want := []string{"config", "unit", "binary", "geo", model.DriftKey(model.DriftLink, w.chain, 0)}
	if d.Error != "" || len(d.Items) != 0 || !slices.Equal(d.Checked, want) || len(d.Skipped) != 0 {
		t.Fatalf("%+v", d)
	}
	readsOnly(t, w.m, 0)
	if w.state(w.a) != model.StateHealthy {
		t.Fatalf("state %s", w.state(w.a))
	}
	if ds, _ := w.ev.get(); len(ds) != 0 {
		t.Fatalf("events %q", ds)
	}
	// b has no trusted key: never connected.
	if w.conn.count(w.b) != 0 {
		t.Fatal("connected to a server without a trusted key")
	}
}

// changeAll changes every thing HyRoute recorded on the machine.
func changeAll(w *world) {
	m := w.m
	m.SetFile(cfgPath, []byte(strings.Replace(revisionCfg, "listen: :443", "listen: :8443", 1)+"sniff:\n  enable: true\n"))
	m.SetFile(dropIn, []byte("[Service]\nUser=root\n"))
	m.unit(unitName, unitPath, dropIn)
	m.SetFile(binPath, []byte("#!another build"))
	m.DeleteFile(geo.ServerDir + "/" + geo.GeoSite)
	m.SetFile(w.linkAt, []byte("server: 203.0.113.9:443\n"))
	m.SetFile("/etc/systemd/system/"+w.linkU, []byte(linkUnit+"# edited\n"))
}

// Every kind of difference is found by reading only; the server needs
// attention and each difference is reported once.
func TestRoundFindsEveryDifference(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	changeAll(w)
	w.r.Round(ctx)
	d := w.drift(w.a)
	link := model.DriftKey(model.DriftLink, w.chain, 0)
	if d.Error != "" || !slices.Equal(keys(d.Items), []string{"config", "unit", "binary", "geo", link}) {
		t.Fatalf("%+v", d)
	}
	readsOnly(t, w.m, 0)
	if w.state(w.a) != model.StateNeedsAttention || d.AttentionAt.IsZero() {
		t.Fatalf("state %s, attention %v", w.state(w.a), d.AttentionAt)
	}
	cfg, _ := d.Item("config")
	if cfg.Revision != 1 || cfg.Files[0].Got == "" || !strings.Contains(cfg.Summary, "Изменены разделы: listen, sniff") || d.Config == nil {
		t.Fatalf("config %+v", cfg)
	}
	unit, _ := d.Item("unit")
	if !slices.Equal(unit.Units, []string{unitPath, dropIn}) || !strings.Contains(unit.Summary, "drop-in") {
		t.Fatalf("unit %+v", unit)
	}
	gi, _ := d.Item("geo")
	if len(gi.Files) != 1 || gi.Files[0].Got != "" || !strings.Contains(gi.Summary, "geosite.dat удалён") {
		t.Fatalf("geo %+v", gi)
	}
	li, _ := d.Item(link)
	if li.Chain != w.chain || len(li.Files) != 2 || !strings.Contains(li.Summary, "«Через Хельсинки»") {
		t.Fatalf("link %+v", li)
	}
	// One event for the server, naming every difference.
	want := "Frankfurt: Отличаются от записанного HyRoute: конфиг Hysteria " + cfgPath + ", служба " + unitName + ", бинарник Hysteria " + binPath +
		", базы geo " + geo.ServerDir + ", связь каскада «Через Хельсинки»."
	if ds, _ := w.ev.get(); !slices.Equal(ds, []string{want}) {
		t.Fatalf("events %q", ds)
	}

	// The next round finds the same: no new events, the times stay.
	since := cfg.Since
	w.r.Round(ctx)
	if ds, _ := w.ev.get(); len(ds) != 1 {
		t.Fatalf("events again %q", ds)
	}
	if c, _ := w.drift(w.a).Item("config"); !c.Since.Equal(since) {
		t.Fatalf("since %v → %v", since, c.Since)
	}
	// The config changed back by hand: the event says what is left.
	w.m.SetFile(cfgPath, []byte(revisionCfg))
	w.r.Round(ctx)
	if _, ok := w.drift(w.a).Item("config"); ok {
		t.Fatal("the config is as recorded again")
	}
	if ds, gone := w.ev.get(); len(ds) != 2 || strings.Contains(ds[1], "конфиг") || len(gone) != 0 {
		t.Fatalf("events %q, gone %q", ds, gone)
	}
	// Everything back: the event closes, the server is healthy again.
	in, _ := w.db.Installation(ctx, w.a)
	in.BinarySHA256, in.UnitSHA256 = "", ""
	w.db.SetInstallation(ctx, in)
	w.db.SetServerGeo(ctx, model.ServerGeo{ServerID: w.a, Release: "r"})
	w.m.SetFile(w.linkAt, linkCfg)
	w.m.SetFile("/etc/systemd/system/"+w.linkU, []byte(linkUnit))
	w.r.Round(ctx)
	if _, gone := w.ev.get(); !slices.Equal(gone, []string{"Frankfurt"}) || w.state(w.a) != model.StateHealthy {
		t.Fatalf("gone %q, state %s", gone, w.state(w.a))
	}
}

// A server with an unfinished job waits for the next round; offline ones
// are not touched.
func TestRoundSkipsBusyAndOffline(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	changeAll(w)
	j := model.Job{Kind: "tuning", ServerID: w.a, State: model.JobQueued, Params: []byte("{}"), CreatedAt: time.Now()}
	if err := w.db.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "check"}}, nil); err != nil {
		t.Fatal(err)
	}
	w.r.Round(ctx)
	if w.conn.count(w.a) != 0 {
		t.Fatal("a busy server was checked")
	}
	if _, err := w.db.Drift(ctx, w.a); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("result of a busy server: %v", err)
	}
	if _, err := w.r.Check(ctx, w.a); !errors.Is(err, store.ErrBusy) {
		t.Fatalf("check now of a busy server: %v", err)
	}
	j.State, j.FinishedAt = model.JobCompleted, time.Now()
	if err := w.db.UpdateJob(ctx, j); err != nil {
		t.Fatal(err)
	}
	// Offline: left to the monitor.
	w.db.SetServerState(ctx, w.a, model.StateOffline, time.Now())
	w.r.Round(ctx)
	if w.conn.count(w.a) != 0 {
		t.Fatal("an offline server was checked")
	}
	w.db.SetServerState(ctx, w.a, model.StateHealthy, time.Now())
	w.r.Round(ctx)
	if w.conn.count(w.a) != 1 || len(w.drift(w.a).Items) != 5 {
		t.Fatalf("next round: %d connections, %+v", w.conn.count(w.a), w.drift(w.a))
	}
}

// Nothing recorded (an installation or a link from before P4-06): not
// compared, and said so.
func TestNothingRecordedNotCompared(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	in, _ := w.db.Installation(ctx, w.a)
	in.BinarySHA256, in.UnitSHA256 = "", ""
	w.db.SetInstallation(ctx, in)
	c, _ := w.db.ChainByID(ctx, w.chain)
	l := c.Links[0]
	l.UnitSHA256 = ""
	w.db.UpdateLink(ctx, l)
	changeAll(w)
	w.m.SetFile(w.linkAt, linkCfg) // only the unit of the link differs
	w.r.Round(ctx)
	d := w.drift(w.a)
	if !slices.Equal(d.Skipped, []string{"unit", "binary"}) || !slices.Equal(keys(d.Items), []string{"config", "geo"}) {
		t.Fatalf("%+v", d)
	}
}

// A server that does not answer keeps what was found before, with the
// error; its state is the monitor's business.
func TestUnreachableKeepsResult(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	changeAll(w)
	w.r.Round(ctx)
	delete(w.conn.machines, w.a)
	w.r.Round(ctx)
	d := w.drift(w.a)
	if !strings.HasPrefix(d.Error, "Сервер не проверен") || len(d.Items) != 5 || w.state(w.a) != model.StateNeedsAttention {
		t.Fatalf("%+v %s", d, w.state(w.a))
	}
}

// Neither the stored result nor a summary, an event or the diff holds a
// secret of either config.
func TestNoSecretsShown(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	edited := strings.Replace(revisionCfg, canaryAuth, canaryNew, 1) + "# password=" + canaryNew + "\n"
	w.m.SetFile(cfgPath, []byte(edited))
	w.r.Round(ctx)
	d := w.drift(w.a)
	lines, secrets, err := w.r.ConfigDiff(ctx, w.a)
	if err != nil || len(lines) == 0 || !slices.Contains(secrets, "auth.password") {
		t.Fatalf("diff %v %q %v", lines, secrets, err)
	}
	stored, _ := json.Marshal(d.Items)
	ds, _ := w.ev.get()
	text, _ := json.Marshal(lines)
	all := string(stored) + strings.Join(ds, "\n") + string(text) + d.Error
	for _, c := range []string{canaryAuth, canaryObfs, canaryStats, canaryProxy, canaryNew} {
		if strings.Contains(all, c) {
			t.Fatalf("%s shown:\n%s", c, all)
		}
	}
	if !strings.Contains(string(text), "[REDACTED]") {
		t.Fatalf("diff without masks: %s", text)
	}
	// The found config is sealed.
	if strings.Contains(string(d.Config), canaryNew) {
		t.Fatal("the found config is stored in the clear")
	}
	// Not YAML: no diff at all.
	w.m.SetFile(cfgPath, []byte("listen: [:443\n"+canaryNew))
	w.r.Round(ctx)
	if _, _, err := w.r.ConfigDiff(ctx, w.a); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("diff of a broken config: %v", err)
	}
}

// Run checks after First, then each Interval; with Interval 0 never.
func TestRunSchedule(t *testing.T) {
	w := newWorld(t)
	changeAll(w)
	r := &Reconciler{Store: w.db, Conn: w.conn, Keys: w.keys, Interval: 30 * time.Millisecond, First: 10 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	for i := 0; i < 300 && w.conn.count(w.a) < 2; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if n := w.conn.count(w.a); n < 2 {
		t.Fatalf("%d rounds", n)
	}
	if d := w.drift(w.a); len(d.Items) != 5 {
		t.Fatalf("%+v", d)
	}

	off := &Reconciler{Store: w.db, Conn: w.conn, Keys: w.keys, First: time.Millisecond}
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() { off.Run(ctx); close(done) }()
	n := w.conn.count(w.a)
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if w.conn.count(w.a) != n {
		t.Fatal("a round with the interval 0")
	}
}
