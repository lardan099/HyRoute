package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// «Принять как новую ревизию»: the config on the server becomes a
// revision with source external, read again and checked first; the
// server needs no attention once nothing differs.
func TestAcceptConfig(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	edited := strings.Replace(revisionCfg, "listen: :443", "listen: :8443", 1)
	w.m.SetFile(cfgPath, []byte(edited))
	w.r.Round(ctx)
	from := len(w.m.Calls())

	// Changed again after the check: refused, nothing stored.
	w.m.SetFile(cfgPath, []byte(edited+"# again\n"))
	if _, err := w.r.Accept(ctx, w.a, "config", 0); !errors.Is(err, ErrChanged) {
		t.Fatalf("accept of a config changed again: %v", err)
	}
	w.m.SetFile(cfgPath, []byte(edited))
	d, err := w.r.Accept(ctx, w.a, "config", 0)
	if err != nil {
		t.Fatal(err)
	}
	readsOnly(t, w.m, from)
	if len(d.Items) != 0 || d.Config != nil || w.state(w.a) != model.StateHealthy {
		t.Fatalf("%+v, state %s", d, w.state(w.a))
	}
	cur, _ := w.db.CurrentConfig(ctx, w.a)
	b, _ := w.keys.Open(cur.Sealed, model.ConfigContext(w.a, cur.Revision))
	if cur.Revision != 2 || cur.Source != model.ConfigExternal || cur.SHA256 != hexSHA([]byte(edited)) || string(b) != edited || cur.Meta.Ports != "8443" || cur.JobID != 0 {
		t.Fatalf("revision %+v", cur)
	}
	if es, _ := w.db.ListAudit(ctx, 1); len(es) != 1 || es[0].Action != "drift_accepted" || es[0].Target != "server/1" || es[0].Details != "what=config revision=2" {
		t.Fatalf("audit %+v", es)
	}
	if _, res := w.ev.get(); !slices.Equal(res, []string{"1 config"}) {
		t.Fatalf("resolved %q", res)
	}
	if _, err := w.r.Accept(ctx, w.a, "config", 0); !errors.Is(err, ErrGone) {
		t.Fatalf("accepted twice: %v", err)
	}
	w.r.Round(ctx)
	if d := w.drift(w.a); len(d.Items) != 0 {
		t.Fatalf("after accepting: %+v", d)
	}

	// A config gone from the server or not one Hysteria reads cannot be
	// a revision.
	var fe *model.FieldError
	for _, cfg := range []string{"", "listen: [:443\n"} {
		if cfg == "" {
			w.m.DeleteFile(cfgPath)
		} else {
			w.m.SetFile(cfgPath, []byte(cfg))
		}
		w.r.Round(ctx)
		if _, err := w.r.Accept(ctx, w.a, "config", 0); !errors.As(err, &fe) {
			t.Fatalf("accept of %q: %v", cfg, err)
		}
	}
}

// Accepting the unit, the binary, the geo databases and a link records
// their hashes as found; the next round finds nothing.
func TestAcceptRecordsHashes(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	changeAll(w)
	w.r.Round(ctx)
	link := model.DriftKey(model.DriftLink, w.chain, 0)
	for _, k := range []string{"unit", "binary", "geo", link} {
		d, err := w.r.Accept(ctx, w.a, k, 0)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if _, ok := d.Item(k); ok {
			t.Fatalf("%s still there", k)
		}
	}
	if w.state(w.a) != model.StateNeedsAttention {
		t.Fatalf("state %s while the config still differs", w.state(w.a))
	}
	in, _ := w.db.Installation(ctx, w.a)
	if in.BinarySHA256 != hexSHA([]byte("#!another build")) || in.Version != "v2.12.3" || in.UnitSHA256 == hexSHA([]byte(unitText)) || in.UnitSHA256 == "" {
		t.Fatalf("installation %+v", in)
	}
	if g, _ := w.db.ServerGeo(ctx, w.a); g.GeoSite != "" || g.GeoIP != hexSHA(geoIPData) {
		t.Fatalf("geo %+v", g)
	}
	c, _ := w.db.ChainByID(ctx, w.chain)
	if l := c.Links[0]; l.ConfigSHA256 != hexSHA([]byte("server: 203.0.113.9:443\n")) || l.UnitSHA256 != hexSHA([]byte(linkUnit+"# edited\n")) {
		t.Fatalf("link %+v", l)
	}
	if _, err := w.r.Accept(ctx, w.a, "config", 0); err != nil {
		t.Fatal(err)
	}
	if w.state(w.a) != model.StateHealthy {
		t.Fatalf("state %s", w.state(w.a))
	}
	w.r.Round(ctx)
	if d := w.drift(w.a); len(d.Items) != 0 || !slices.Contains(d.Checked, "geo") {
		t.Fatalf("after accepting all: %+v", d)
	}
}

// Nothing is accepted or reverted while a job runs on the server.
func TestActionsWaitForJobs(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	changeAll(w)
	w.r.Round(ctx)
	j := model.Job{Kind: "tuning", ServerID: w.a, State: model.JobQueued, Params: []byte("{}"), CreatedAt: time.Now()}
	w.db.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "check"}}, nil)
	if _, err := w.r.Accept(ctx, w.a, "binary", 0); !errors.Is(err, store.ErrBusy) {
		t.Fatalf("accept: %v", err)
	}
	if _, err := w.r.Accept(ctx, w.a, "nothing", 0); !errors.Is(err, store.ErrBusy) && !errors.Is(err, ErrGone) {
		t.Fatalf("accept of nothing: %v", err)
	}
}

// A job (not a revert) ran since the round made the server need
// attention: the state is that job's, and accepting leaves it.
func TestReleaseLeavesOtherJobsState(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.m.SetFile(cfgPath, []byte(revisionCfg+"# by hand\n"))
	w.r.Round(ctx)
	j := model.Job{Kind: "import", ServerID: w.a, State: model.JobCompleted, Params: []byte("{}"), CreatedAt: time.Now().Add(time.Second), FinishedAt: time.Now()}
	w.db.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "connect"}}, nil)
	if _, err := w.r.Accept(ctx, w.a, "config", 0); err != nil {
		t.Fatal(err)
	}
	if w.state(w.a) != model.StateNeedsAttention {
		t.Fatalf("state %s: the import's findings would be hidden", w.state(w.a))
	}
}

// controller is a job engine with the kinds the reverts queue, not
// running unless started.
type controller struct {
	eng  *jobs.Engine
	jobs Jobs
}

func newController(w *world) *controller {
	eng := jobs.New(w.db, w.keys, redact.New(), w.conn, nil)
	eng.Poll = 10 * time.Millisecond
	app := apply.New(apply.Deps{Store: w.db, Keys: w.keys, Jobs: eng, VerifyTimeout: 300 * time.Millisecond, Poll: 10 * time.Millisecond})
	eng.Register(app.Kind())
	eng.Register(deploy.Maintenance(deploy.Deps{Store: w.db, Keys: w.keys}))
	files := &geo.Store{Dir: w.t.TempDir()}
	info, _ := json.Marshal(geo.Info{Release: "202610020000", Files: []geo.File{
		{Name: geo.GeoIP, SHA256: hexSHA([]byte("geoip v2")), Size: 8, URL: "https://example.com/geoip.dat"},
		{Name: geo.GeoSite, SHA256: hexSHA([]byte("geosite v2")), Size: 10, URL: "https://example.com/geosite.dat"}}, At: time.Now()})
	os.WriteFile(filepath.Join(files.Dir, "info.json"), info, 0o600)
	gi := geo.New(geo.Deps{DB: w.db, Keys: w.keys, Files: files, Jobs: eng})
	eng.Register(gi.Kind())
	lk := cascade.New(cascade.Deps{Store: w.db, Keys: w.keys, Jobs: eng})
	eng.Register(lk.Kind())
	return &controller{eng: eng, jobs: Jobs{Apply: app, Deploy: &deploy.Submitter{Store: w.db, Keys: w.keys, Jobs: eng}, Geo: gi, Links: lk}}
}

func (c *controller) start(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.eng.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// «Вернуть версию HyRoute» queues the job that writes each thing; nothing
// runs on the server until the job does.
func TestRevertQueuesJobs(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	c := newController(w)
	w.r.Jobs = c.jobs
	changeAll(w)
	w.r.Round(ctx)
	before := len(w.m.Calls())
	link := model.DriftKey(model.DriftLink, w.chain, 0)
	cfg, _ := w.drift(w.a).Item("config")
	for _, x := range []struct {
		key, kind, params string
		servers           []int64
	}{
		{"config", apply.JobKind, `"drift":"` + cfg.Files[0].Got + `"`, nil},
		{"unit", deploy.MaintainKind, `"op":"reinstall"`, nil},
		{"binary", deploy.MaintainKind, `"op":"reinstall"`, nil},
		{"geo", geo.JobKind, `"release":"202610020000"`, nil},
		{link, cascade.JobLink, `"chain":1`, []int64{w.b}},
	} {
		j, err := w.r.Revert(ctx, w.a, x.key, 0)
		if err != nil {
			t.Fatalf("%s: %v", x.key, err)
		}
		if j.Kind != x.kind || j.ServerID != w.a || !slices.Equal(j.Servers, x.servers) || !strings.Contains(string(j.Params), x.params) {
			t.Fatalf("%s: %s %d %v %s", x.key, j.Kind, j.ServerID, j.Servers, j.Params)
		}
		d := w.drift(w.a)
		if it, _ := d.Item(x.key); it.Job != j.ID || !slices.Contains(d.Reverts, j.ID) {
			t.Fatalf("%s: %+v", x.key, d)
		}
		// One job a server: this one ends before the next.
		j.State, j.FinishedAt = model.JobFailed, time.Now()
		w.db.UpdateJob(ctx, j)
	}
	if len(w.m.Calls()) != before {
		t.Fatalf("the server was touched: %v", w.m.Calls()[before:])
	}
	// An installation HyRoute did not make: its unit is accepted only, its
	// binary goes back as the release of the recorded version.
	in, _ := w.db.Installation(ctx, w.a)
	in.Managed = false
	w.db.SetInstallation(ctx, in)
	var cr *CannotRevertError
	if _, err := w.r.Revert(ctx, w.a, "unit", 0); !errors.As(err, &cr) {
		t.Fatalf("revert of a foreign unit: %v", err)
	}
	j, err := w.r.Revert(ctx, w.a, "binary", 0)
	if err != nil || !strings.Contains(string(j.Params), `"op":"upgrade","version":"v2.12.3"`) {
		t.Fatalf("binary of a foreign installation: %s %v", j.Params, err)
	}
	if _, err := w.r.Revert(ctx, w.a, "nothing", 0); !errors.Is(err, ErrGone) {
		t.Fatalf("revert of nothing: %v", err)
	}
}

// The apply job of a revert runs with its checks and rollback; once it
// completes the server is checked again and the difference is gone.
func TestRevertConfigEndToEnd(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	c := newController(w)
	c.start(t)
	w.r.Jobs = c.jobs
	edited := strings.Replace(revisionCfg, "listen: :443", "listen: :8443", 1)
	w.m.SetFile(cfgPath, []byte(edited))
	w.m.start()
	w.r.Round(ctx)

	// Hysteria does not start with the revision: the config changed by
	// hand comes back, and the difference stays with its job.
	w.m.mu.Lock()
	w.m.bad = "listen: :443\n"
	w.m.mu.Unlock()
	j, err := w.r.Revert(ctx, w.a, "config", 0)
	if err != nil {
		t.Fatal(err)
	}
	j = waitJob(t, w, j.ID)
	if j.State != model.JobFailed {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if b, _ := w.m.File(cfgPath); string(b) != edited {
		t.Fatalf("not rolled back:\n%s", b)
	}
	if it, ok := w.drift(w.a).Item("config"); !ok || it.Job != j.ID || w.state(w.a) != model.StateNeedsAttention {
		t.Fatalf("%+v %v %s", it, ok, w.state(w.a))
	}

	w.m.mu.Lock()
	w.m.bad = ""
	w.m.mu.Unlock()
	if j, err = w.r.Revert(ctx, w.a, "config", 0); err != nil {
		t.Fatal(err)
	}
	if j = waitJob(t, w, j.ID); j.State != model.JobCompleted {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	for i := 0; i < 300; i++ {
		if _, ok := w.drift(w.a).Item("config"); !ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d := w.drift(w.a); len(d.Items) != 0 || w.state(w.a) != model.StateHealthy {
		t.Fatalf("after the revert: %+v %s", d, w.state(w.a))
	}
	if b, _ := w.m.File(cfgPath); string(b) != revisionCfg {
		t.Fatalf("config:\n%s", b)
	}
	if cs, _ := w.db.ListConfigs(ctx, w.a); len(cs) != 1 {
		t.Fatalf("%d revisions", len(cs))
	}
}

func waitJob(t *testing.T, w *world, id int64) model.Job {
	t.Helper()
	for i := 0; i < 500; i++ {
		j, _ := w.db.JobByID(context.Background(), id)
		if j.State.Terminal() {
			time.Sleep(20 * time.Millisecond) // the Finished hook
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job stuck")
	return model.Job{}
}
