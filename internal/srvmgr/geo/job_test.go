package geo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

const cfgPath = "/etc/hysteria/config.yaml"

const config = `listen: :443
acme:
  domains:
    - vpn.example.com
auth:
  type: password
  password: fake-geo-auth
masquerade:
  type: proxy
  proxy:
    url: https://www.example.com
acl:
  inline:
    - reject(geoip:private)
    - direct(geosite:google)
`

type harness struct {
	t      *testing.T
	db     *sqlite.DB
	keys   *secrets.Keyring
	files  *Store
	v      *vps
	node   *vps
	server int64
	nodeID int64
	inst   *Installer
	db2    map[string]map[string][]byte // release → files put
	mu     sync.Mutex
}

func (h *harness) Connect(_ context.Context, id int64) (remote.Executor, error) {
	if id == h.nodeID {
		return h.node, nil
	}
	return h.v, nil
}

func newHarness(t *testing.T) *harness {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{6}, 32)})
	h := &harness{t: t, db: db, keys: keys, v: newVPS(), node: newVPS(), files: &Store{Dir: filepath.Join(t.TempDir(), "geo")}, db2: map[string]map[string][]byte{}}
	for i, name := range []string{"geo-test", "node"} {
		srv := model.Server{Name: name, Host: "192.0.2." + itoa(70+i), SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
		if err := db.CreateServer(ctx, &srv, nil); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			h.server = srv.ID
		} else {
			h.nodeID = srv.ID
		}
	}
	db.SetInstallation(ctx, model.Installation{ServerID: h.server, Binary: "/usr/local/bin/hysteria", Config: cfgPath, Unit: "hysteria-server.service", User: "hysteria", Version: "v2.12.3", Managed: true, At: time.Now()})
	c := model.ServerConfig{ServerID: h.server, SHA256: sha([]byte(config)), Source: model.ConfigDeploy, At: time.Now()}
	db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return keys.Seal([]byte(config), model.ConfigContext(h.server, rev)) })
	h.v.files[cfgPath] = []byte(config)

	eng := jobs.New(db, keys, redact.New(), h, nil)
	eng.Poll = 10 * time.Millisecond
	h.inst = New(Deps{DB: db, Keys: keys, Files: h.files, Jobs: eng, Nodes: h.Connect, VerifyTimeout: 200 * time.Millisecond, Poll: 10 * time.Millisecond})
	eng.Register(h.inst.Kind())
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { eng.Run(runCtx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return h
}

// put makes release the controller's: its files, as servers can download
// them too.
func (h *harness) put(release string, files map[string][]byte) {
	h.t.Helper()
	os.MkdirAll(filepath.Join(h.files.Dir, release), 0o700)
	i := Info{Release: release, At: time.Now()}
	for _, name := range Names {
		b := files[name]
		os.WriteFile(filepath.Join(h.files.Dir, release, name), b, 0o600)
		url := "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/" + release + "/" + name
		i.Files = append(i.Files, File{Name: name, SHA256: sha(b), Size: int64(len(b)), URL: url})
		h.v.mu.Lock()
		h.v.downloads[url] = b
		h.v.mu.Unlock()
	}
	b, _ := json.Marshal(i)
	os.WriteFile(filepath.Join(h.files.Dir, "info.json"), b, 0o600)
	h.db2[release] = files
}

func (h *harness) run(source string, via int64) model.Job {
	h.t.Helper()
	j, err := h.inst.Submit(context.Background(), h.server, source, via, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		j, _ = h.db.JobByID(context.Background(), j.ID)
		if j.State.Terminal() {
			time.Sleep(20 * time.Millisecond) // the Finished hook
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("job %d stuck in %s", j.ID, j.State)
	return j
}

func (h *harness) log(id int64) string {
	ls, _ := h.db.JobLogs(context.Background(), id, 0, 0)
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Message + "\n")
	}
	return b.String()
}

// has: the server has the files of release.
func (h *harness) has(release string) bool {
	for _, name := range Names {
		if b, _ := h.v.file(ServerDir + "/" + name); !bytes.Equal(b, h.db2[release][name]) {
			return false
		}
	}
	return true
}

func TestInstall(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.put("R1", testDB(t, "one"))
	j := h.run(SourceAuto, 0)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if !h.has("R1") || h.v.modes[ServerDir+"/"+GeoIP] != "644 root root" || h.v.dirs[ServerDir] != "0755 root root" {
		t.Fatalf("files %v dirs %v", h.v.modes, h.v.dirs)
	}
	c, _ := hyconfig.ParseServer(h.v.files[cfgPath])
	if c.ACL.GeoIP != "/etc/hysteria/geo/geoip.dat" || c.ACL.GeoSite != "/etc/hysteria/geo/geosite.dat" || len(c.ACL.Inline) != 2 {
		t.Fatalf("acl %+v", c.ACL)
	}
	cur, _ := h.db.CurrentConfig(ctx, h.server)
	if cur.Revision != 2 || cur.Source != model.ConfigGeo || cur.SHA256 != sha(h.v.files[cfgPath]) || cur.JobID != j.ID {
		t.Fatalf("revision %+v", cur)
	}
	if g, err := h.db.ServerGeo(ctx, h.server); err != nil || g.Release != "R1" || g.GeoIP != sha(h.db2["R1"][GeoIP]) || g.JobID != j.ID {
		t.Fatalf("%v %+v", err, g)
	}
	if !h.v.ran("systemctl restart") || h.v.ran("cp -p -- /etc/hysteria/geo") || strings.Contains(h.log(j.ID), "не скачал") {
		t.Fatalf("%q\n%s", h.v.cmds, h.log(j.ID))
	}
	for _, p := range []string{cfgPath + Backup, ServerDir + "/" + GeoIP + Backup} {
		if _, found := h.v.file(p); found {
			t.Fatalf("%s left", p)
		}
	}

	// Again with the same release: nothing changes on the server.
	h.v.reset()
	j = h.run(SourceAuto, 0)
	if j.State != model.JobCompleted || h.v.ran("systemctl restart") || h.v.ran("install -m") || h.v.ran("curl") || len(h.v.writes) != 0 {
		t.Fatalf("%s %q %q", j.State, h.v.cmds, h.v.writes)
	}
	if cur, _ := h.db.CurrentConfig(ctx, h.server); cur.Revision != 2 {
		t.Fatalf("revision %d", cur.Revision)
	}
}

// A file that does not match the release hash changes nothing.
func TestInstallChecksum(t *testing.T) {
	h := newHarness(t)
	h.put("R1", testDB(t, "one"))
	if j := h.run(SourceAuto, 0); j.State != model.JobCompleted {
		t.Fatal(j.ErrorMessage)
	}
	cfg := h.v.files[cfgPath]
	h.put("R2", testDB(t, "two"))
	h.v.downloads["https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/R2/geosite.dat"] = []byte("tampered")
	h.v.reset()
	j := h.run(SourceAuto, 0)
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "не совпадает с хешем") {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if !h.has("R1") || !bytes.Equal(h.v.files[cfgPath], cfg) || h.v.ran("systemctl restart") {
		t.Fatalf("changed: %q", h.v.cmds)
	}
	if g, _ := h.db.ServerGeo(context.Background(), h.server); g.Release != "R1" {
		t.Fatalf("%+v", g)
	}
}

// Hysteria does not start with the new files: the old ones and the old
// config come back and the service runs with them.
func TestInstallRollback(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	two := testDB(t, "two")
	h.v.bad = func(f map[string][]byte) bool { return bytes.Equal(f[ServerDir+"/"+GeoSite], two[GeoSite]) }

	// The first install: the files go away again, the config is the old.
	h.put("R2", two)
	j := h.run(SourceAuto, 0)
	if j.State != model.JobFailed || j.CurrentStep != "verify" || !strings.Contains(h.log(j.ID), "failed to load geo database") {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, h.log(j.ID))
	}
	if _, found := h.v.file(ServerDir + "/" + GeoSite); found || string(h.v.files[cfgPath]) != config || h.v.state != "active" {
		t.Fatalf("not rolled back: %s %q", h.v.state, h.v.files[cfgPath])
	}
	if cur, _ := h.db.CurrentConfig(ctx, h.server); cur.Revision != 1 {
		t.Fatalf("revision %d", cur.Revision)
	}
	if _, err := h.db.ServerGeo(ctx, h.server); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}

	// Over a release that works: it comes back.
	h.put("R1", testDB(t, "one"))
	if j := h.run(SourceAuto, 0); j.State != model.JobCompleted {
		t.Fatal(j.ErrorMessage)
	}
	h.put("R2", two)
	if j = h.run(SourceAuto, 0); j.State != model.JobFailed || !h.has("R1") || h.v.state != "active" {
		t.Fatalf("%s %v %s", j.State, h.has("R1"), h.v.state)
	}
	if s, _ := h.db.ServerByID(ctx, h.server); s.State == model.StateNeedsAttention {
		t.Fatal("needs attention after a clean rollback")
	}
}

// The server cannot reach GitHub: the controller uploads its files.
func TestInstallRelay(t *testing.T) {
	h := newHarness(t)
	h.put("R1", testDB(t, "one"))
	h.v.github = false
	j := h.run(SourceAuto, 0)
	if j.State != model.JobCompleted || !h.has("R1") || !strings.Contains(h.log(j.ID), "через controller") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}

	h2 := newHarness(t)
	h2.put("R1", testDB(t, "one"))
	if j := h2.run(SourceRelay, 0); j.State != model.JobCompleted || h2.v.ran("curl") || !h2.has("R1") {
		t.Fatalf("%s %q", j.State, h2.v.cmds)
	}
}

// Another managed server gives the files it has.
func TestInstallNode(t *testing.T) {
	h := newHarness(t)
	one := testDB(t, "one")
	h.put("R1", one)
	h.v.github = false
	h.node.files[ServerDir+"/"+GeoIP] = one[GeoIP]
	h.node.files[ServerDir+"/"+GeoSite] = one[GeoSite]
	j := h.run(SourceNode, h.nodeID)
	if j.State != model.JobCompleted || !h.has("R1") || h.v.ran("curl") || h.node.ran("curl") || !strings.Contains(h.log(j.ID), "через другой сервер") {
		t.Fatalf("%s: %s\n%s\n%q", j.State, j.ErrorMessage, h.log(j.ID), h.node.cmds)
	}
}

// A stopped service is not started; the files wait for it.
func TestInstallStopped(t *testing.T) {
	h := newHarness(t)
	h.put("R1", testDB(t, "one"))
	h.v.state = "inactive"
	j := h.run(SourceAuto, 0)
	if j.State != model.JobCompleted || h.v.ran("systemctl restart") || h.v.state != "inactive" || !h.has("R1") {
		t.Fatalf("%s %q", j.State, h.v.cmds)
	}
}

// A config changed on the server outside HyRoute is not overwritten.
func TestInstallConfigChanged(t *testing.T) {
	h := newHarness(t)
	h.put("R1", testDB(t, "one"))
	h.v.files[cfgPath] = []byte(config + "speedTest: true\n")
	j := h.run(SourceAuto, 0)
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "изменён не через HyRoute") || len(h.v.writes) != 0 || h.has("R1") {
		t.Fatalf("%s: %s %q", j.State, j.ErrorMessage, h.v.writes)
	}
}

func TestSubmitRefused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	if _, err := h.inst.Submit(ctx, h.server, SourceAuto, 0, 0); !errors.Is(err, ErrNone) {
		t.Fatalf("no files: %v", err)
	}
	h.put("R1", testDB(t, "one"))
	var fe *model.FieldError
	for _, c := range []struct {
		source string
		via    int64
	}{{"ftp", 0}, {SourceNode, 0}, {SourceNode, h.server}, {SourceNode, 999}} {
		if _, err := h.inst.Submit(ctx, h.server, c.source, c.via, 0); !errors.As(err, &fe) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	if _, err := h.inst.Submit(ctx, h.nodeID, SourceAuto, 0, 0); !errors.Is(err, ErrNoInstallation) {
		t.Fatalf("no installation: %v", err)
	}
}
