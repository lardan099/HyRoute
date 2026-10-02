package geo

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// addServer is another server with config cfg, an installation and, when
// release is not "", HyRoute's databases of that release.
func (h *harness) addServer(name, cfg, release string) int64 {
	h.t.Helper()
	ctx := context.Background()
	srv := model.Server{Name: name, Host: name + ".example.com", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	if err := h.db.CreateServer(ctx, &srv, nil); err != nil {
		h.t.Fatal(err)
	}
	h.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: cfgPath, Unit: "hysteria-server.service", At: time.Now()})
	c := model.ServerConfig{ServerID: srv.ID, SHA256: sha([]byte(cfg)), Source: model.ConfigDeploy, At: time.Now()}
	h.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return h.keys.Seal([]byte(cfg), model.ConfigContext(srv.ID, rev)) })
	if release != "" {
		h.db.SetServerGeo(ctx, model.ServerGeo{ServerID: srv.ID, Release: release, At: time.Now()})
	}
	return srv.ID
}

const paths = "  geoip: /etc/hysteria/geo/geoip.dat\n  geosite: /etc/hysteria/geo/geosite.dat\n"

func TestScheduleDue(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.files.Base = "http://127.0.0.1:1/releases" // never the network
	h.put("R1", testDB(t, "one"))
	if j := h.run(SourceAuto, 0); j.State != model.JobCompleted {
		t.Fatal(j.ErrorMessage)
	}
	noRules := h.addServer("norules", strings.Replace(config, "    - reject(geoip:private)\n    - direct(geosite:google)\n", "    - direct(all)\n", 1)+paths, "R0")
	never := h.addServer("never", config+paths, "")
	ownPaths := h.addServer("ownpaths", config+"  geoip: /var/lib/geoip.dat\n  geosite: /var/lib/geosite.dat\n", "R0")
	file := h.addServer("file", strings.Replace(config, "  inline:\n    - reject(geoip:private)\n    - direct(geosite:google)\n", "  file: /etc/hysteria/acl.txt\n", 1)+paths, "R0")
	_ = []int64{noRules, never, ownPaths}

	s := &Scheduler{Files: h.files, Jobs: h.inst, DB: h.db, Keys: h.keys, Interval: time.Hour}
	h.put("R2", testDB(t, "two"))
	due, err := s.Due(ctx, "R2")
	slices.Sort(due)
	if err != nil || !slices.Equal(due, []int64{h.server, file}) {
		t.Fatalf("%v %v", due, err)
	}
	if due, _ := s.Due(ctx, "R1"); !slices.Equal(due, []int64{file}) {
		t.Fatalf("R1: %v", due)
	}
}

func TestScheduleRound(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	r := &releases{latest: "R1", files: map[string]map[string][]byte{"R1": testDB(t, "one")}, sums: map[string]string{}}
	srv := r.serve(t)
	h.files.Base, h.files.HTTP = srv.URL+"/releases", srv.Client()
	now := time.Now()
	clock := func() time.Time { return now }
	h.files.Now = clock
	s := &Scheduler{Files: h.files, Jobs: h.inst, DB: h.db, Keys: h.keys, Interval: 24 * time.Hour, Now: clock}

	// Nothing downloaded yet: the schedule does not start it.
	if q := s.Round(ctx); q != nil || len(r.gets) != 0 {
		t.Fatalf("%v %v", q, r.gets)
	}
	h.put("R1", r.files["R1"])
	if j := h.run(SourceAuto, 0); j.State != model.JobCompleted {
		t.Fatal(j.ErrorMessage)
	}

	// A newer release after the interval: downloaded, the server gets it.
	r.latest, r.files["R2"] = "R2", testDB(t, "two")
	now = now.Add(25 * time.Hour)
	h.v.github = false // the server cannot download: the controller uploads
	if q := s.Round(ctx); !slices.Equal(q, []int64{h.server}) {
		t.Fatalf("%v", q)
	}
	h.wait()
	if !h.hasFiles(r.files["R2"]) {
		t.Fatal("R2 not installed")
	}
	if g, _ := h.db.ServerGeo(ctx, h.server); g.Release != "R2" {
		t.Fatalf("%+v", g)
	}
	// Up to date: nothing to do, no download before the interval.
	r.gets = nil
	if q := s.Round(ctx); q != nil || len(r.gets) != 0 {
		t.Fatalf("%v %v", q, r.gets)
	}

	// A release the server cannot run: one try, the files stay.
	three := testDB(t, "three")
	h.v.bad = func(f map[string][]byte) bool { return string(f[ServerDir+"/"+GeoSite]) == string(three[GeoSite]) }
	r.latest, r.files["R3"] = "R3", three
	now = now.Add(25 * time.Hour)
	if q := s.Round(ctx); !slices.Equal(q, []int64{h.server}) {
		t.Fatalf("%v", q)
	}
	h.wait()
	if !h.hasFiles(r.files["R2"]) {
		t.Fatal("R2 not kept")
	}
	if q := s.Round(ctx); q != nil {
		t.Fatalf("tried again: %v", q)
	}
}

// wait waits for the server's jobs to end.
func (h *harness) wait() {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		js, _ := h.db.ListJobs(context.Background(), model.JobFilter{ServerID: h.server, Limit: 1})
		if len(js) > 0 && js[0].State.Terminal() {
			time.Sleep(20 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("job stuck")
}

func (h *harness) hasFiles(files map[string][]byte) bool {
	for _, name := range Names {
		if b, _ := h.v.file(ServerDir + "/" + name); string(b) != string(files[name]) {
			return false
		}
	}
	return true
}
