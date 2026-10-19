package deploy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// testVersion is not pinned: its hashes come from the fake release.
const testVersion = "v2.99.0"

var fakeBinary = []byte("#!fake hysteria " + testVersion)

type harness struct {
	t      *testing.T
	db     *sqlite.DB
	keys   *secrets.Keyring
	eng    *jobs.Engine
	sim    *sim
	server int64
	rel    *httptest.Server
	res    *hyrelease.Resolver
	stop   context.CancelFunc
	done   chan struct{}

	mu   sync.Mutex
	bins map[string][]byte // the fake releases: version → binary
	// noBinary: the release server gives hashes.txt but not the binary
	// (the controller cannot download it).
	noBinary bool
	// fetched counts the binaries the release server gave.
	fetched int
	// store replaces db as the jobs' store (startEngine).
	store Store
	// nodes are the other managed servers (source node): ID → simulator.
	nodes map[int64]*sim
}

// release publishes a fake release of version with binary b: its
// hashes.txt and binary on the release server, the binary downloadable
// on the server too.
func (h *harness) release(version string, b []byte) {
	h.mu.Lock()
	h.bins[version] = b
	h.mu.Unlock()
	h.sim.AddDownload(h.res.URL(version, "hysteria-linux-amd64"), b)
}

type conn struct{ s *sim }

func (c conn) Connect(context.Context, int64) (remote.Executor, error) { return c.s, nil }

// node adds another managed server with a trusted SSH key, simulated by
// n (source node).
func (h *harness) node(name string, n *sim) int64 {
	h.t.Helper()
	srv := model.Server{Name: name, Host: "192.0.2.11", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	if err := h.db.CreateServer(context.Background(), &srv, nil); err != nil {
		h.t.Fatal(err)
	}
	if err := h.db.SetHostKey(context.Background(), model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake-host-key"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()}); err != nil {
		h.t.Fatal(err)
	}
	h.mu.Lock()
	h.nodes[srv.ID] = n
	h.mu.Unlock()
	return srv.ID
}

// connectNode connects to a node (Deps.Nodes); a server without a
// simulator does not answer.
func (h *harness) connectNode(_ context.Context, id int64) (remote.Executor, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n := h.nodes[id]; n != nil {
		return n, nil
	}
	return nil, errors.New("dial tcp 192.0.2.12:22: i/o timeout")
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newHarness(t *testing.T, s *sim) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)})
	srv := model.Server{Name: "test", Host: "192.0.2.10", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	if err := db.CreateServer(ctx, &srv, nil); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, db: db, keys: keys, sim: s, server: srv.ID, bins: map[string][]byte{}, nodes: map[int64]*sim{}}
	h.rel = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /app/<version>/<file>
		f := strings.Split(r.URL.Path, "/")
		h.mu.Lock()
		b, found := h.bins[f[len(f)-2]]
		noBinary := h.noBinary
		binary := found && f[len(f)-1] == "hysteria-linux-amd64" && !noBinary
		if binary {
			h.fetched++
		}
		h.mu.Unlock()
		switch {
		case !found:
			http.NotFound(w, r)
		case f[len(f)-1] == "hashes.txt":
			w.Write([]byte(sum(b) + "  build/hysteria-linux-amd64\n"))
		case binary:
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(h.rel.Close)
	h.res = &hyrelease.Resolver{Base: h.rel.URL, HTTP: h.rel.Client()}
	h.release(testVersion, fakeBinary)
	h.startEngine()
	t.Cleanup(h.kill)
	return h
}

// startEngine starts a controller process on the harness's database.
func (h *harness) startEngine() {
	h.eng = jobs.New(h.db, h.keys, redact.New(), conn{h.sim}, nil)
	h.eng.Poll = 10 * time.Millisecond
	var st Store = h.db
	if h.store != nil {
		st = h.store
	}
	// One relay for both kinds, as in the controller.
	d := Deps{Store: st, Keys: h.keys, Resolver: h.res, Relay: hyrelease.NewRelay(h.res), Nodes: h.connectNode, VerifyTimeout: 200 * time.Millisecond, Poll: 10 * time.Millisecond}
	h.eng.Register(Kind(d))
	h.eng.Register(Maintenance(d))
	ctx, cancel := context.WithCancel(context.Background())
	h.stop, h.done = cancel, make(chan struct{})
	go func() { h.eng.Run(ctx); close(h.done) }()
}

// kill stops the controller process wherever it is.
func (h *harness) kill() {
	if h.stop != nil {
		h.stop()
		<-h.done
		h.stop = nil
	}
}

func params() Params {
	return Params{Version: testVersion, TLS: TLSSelfSigned, Masquerade: "https://www.example.com"}
}

func (h *harness) deploy(p Params, sec map[string]string) model.Job {
	h.t.Helper()
	if sec == nil {
		var err error
		if sec, err = NewSecrets(p, "192.0.2.10", nil, Input{}); err != nil {
			h.t.Fatal(err)
		}
	}
	j, err := h.eng.Submit(context.Background(), JobKind, h.server, p, sec, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.wait(j.ID)
}

func (h *harness) wait(id int64) model.Job {
	h.t.Helper()
	j := model.Job{ID: id}
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

func (h *harness) steps(id int64) map[string]model.StepState {
	rows, _ := h.db.JobSteps(context.Background(), id)
	out := map[string]model.StepState{}
	for _, r := range rows {
		out[r.Name] = r.State
	}
	return out
}

func (h *harness) log(id int64) string {
	ls, _ := h.db.JobLogs(context.Background(), id, 0, 0)
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Message + "\n")
	}
	return b.String()
}

func (h *harness) state() model.ServerState {
	s, _ := h.db.ServerByID(context.Background(), h.server)
	return s.State
}

func (h *harness) revisions() []model.ServerConfig {
	cs, _ := h.db.ListConfigs(context.Background(), h.server)
	return cs
}

func TestFreshDeploy(t *testing.T) {
	s := newSim()
	s.ufw = true
	h := newHarness(t, s)
	p := params()
	p.Obfs = true
	p.HopPorts = "20000-50000"
	sec, _ := NewSecrets(p, "192.0.2.10", nil, Input{})
	j := h.deploy(p, sec)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s %s\n%s", j.State, j.ErrorMessage, j.ErrorDetails, h.log(j.ID))
	}
	// Binary, user, TLS, config and unit in the places of the official
	// installer.
	if b, _ := s.file(BinaryPath); !bytes.Equal(b, fakeBinary) {
		t.Fatalf("binary %q", b)
	}
	cfgYAML, _ := s.file(ConfigPath)
	c, err := hyconfig.ParseServer(cfgYAML)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":443,20000-50000" || c.Auth.Password != sec[SecretAuth] || c.Obfs.Salamander.Password != sec[SecretObfs] || c.TLS.Cert != CertPath || c.Masquerade.Proxy.URL != "https://www.example.com" {
		t.Fatalf("config %+v", c)
	}
	if u, _ := s.file(UnitPath); string(u) != UnitText || !s.enabled || s.state != "active" || !s.users[User] {
		t.Fatalf("unit/state: enabled=%v state=%s user=%v", s.enabled, s.state, s.users[User])
	}
	// Secret files are not world-readable.
	for _, w := range []string{ConfigPath + " 0640 root:hysteria", KeyPath + " 0640 root:hysteria", CertPath + " 0644 root:root", UnitPath + " 0644 root:root"} {
		if !slices.Contains(s.writes, w) {
			t.Errorf("no write %q in %q", w, s.writes)
		}
	}
	if !s.ran("ufw allow 443/udp") || !s.ran("ufw allow 20000:50000/udp") {
		t.Errorf("firewall: %q", s.cmds)
	}
	// Downloaded by the server itself and checked; the temp dir is gone.
	if !s.ran("curl -fsSL") || !s.ran("sha256sum -- /tmp/hyroute.abcdefghij/hysteria") || s.dirs["/tmp/hyroute.abcdefghij"] {
		t.Errorf("download: %q", s.cmds)
	}
	// The controller keeps the revision (sealed) and what clients need.
	revs := h.revisions()
	if len(revs) != 1 || revs[0].Revision != 1 || revs[0].SHA256 != sum(cfgYAML) || revs[0].Source != model.ConfigDeploy {
		t.Fatalf("revisions %+v", revs)
	}
	pin, _ := Pin([]byte(sec[SecretCert]))
	want := model.ConfigMeta{Version: testVersion, Listen: ":443,20000-50000", Ports: "443,20000-50000", TLS: TLSSelfSigned, PinSHA256: pin, SNI: "www.example.com", Obfs: "salamander", Auth: "password"}
	if revs[0].Meta != want {
		t.Fatalf("meta %+v", revs[0].Meta)
	}
	open, err := h.keys.Open(revs[0].Sealed, model.ConfigContext(h.server, 1))
	if err != nil || !bytes.Equal(open, cfgYAML) || bytes.Contains(revs[0].Sealed, []byte(sec[SecretAuth])) {
		t.Fatal("revision not sealed")
	}
	if h.state() != model.StateHealthy {
		t.Fatalf("server state %s", h.state())
	}
	// No password in the job log or data.
	jj, _ := h.db.JobByID(context.Background(), j.ID)
	for _, secret := range []string{sec[SecretAuth], sec[SecretObfs], sec[SecretKey]} {
		if strings.Contains(h.log(j.ID), secret) || strings.Contains(dataJSON(jj.Data), secret) {
			t.Fatal("secret leaked into the job")
		}
	}
}

func dataJSON(m map[string]string) string {
	var b strings.Builder
	for k, v := range m {
		b.WriteString(k + "=" + v + "\n")
	}
	return b.String()
}

func TestInstallFails(t *testing.T) {
	s := newSim()
	s.failOn["install -m 0755"] = true
	h := newHarness(t, s)
	j := h.deploy(params(), nil)
	if j.State != model.JobFailed || j.CurrentStep != "binary" || !strings.Contains(j.ErrorMessage, "установить Hysteria") {
		t.Fatalf("%s at %s: %s", j.State, j.CurrentStep, j.ErrorMessage)
	}
	// Nothing was installed or started, the temp dir is gone.
	for _, p := range []string{BinaryPath, ConfigPath, UnitPath, CertPath} {
		if _, found := s.file(p); found {
			t.Errorf("%s exists", p)
		}
	}
	if s.ran("systemctl restart") || s.dirs["/tmp/hyroute.abcdefghij"] {
		t.Fatalf("%q", s.cmds)
	}
	if h.state() != model.StateNew || len(h.revisions()) != 0 {
		t.Fatalf("state %s, revisions %d", h.state(), len(h.revisions()))
	}
}

func TestChecksumMismatch(t *testing.T) {
	s := newSim()
	h := newHarness(t, s)
	for u := range s.downloads {
		s.downloads[u] = []byte("tampered")
	}
	j := h.deploy(params(), nil)
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "не совпадает с хешем") {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if _, found := s.file(BinaryPath); found {
		t.Fatal("tampered binary installed")
	}
}

func TestStartFailsRollsBackFreshInstall(t *testing.T) {
	s := newSim()
	s.badConfig = func([]byte) bool { return true }
	h := newHarness(t, s)
	j := h.deploy(params(), nil)
	if j.State != model.JobFailed || j.CurrentStep != "verify" {
		t.Fatalf("%s at %s: %s", j.State, j.CurrentStep, j.ErrorMessage)
	}
	st := h.steps(j.ID)
	for _, n := range []string{"binary", "tls", "config", "unit", "start"} {
		if st[n] != model.StepRolledBack {
			t.Errorf("%s: %s", n, st[n])
		}
	}
	// Back to a machine without Hysteria (the user stays, harmless).
	for _, p := range []string{BinaryPath, ConfigPath, UnitPath, CertPath, KeyPath} {
		if _, found := s.file(p); found {
			t.Errorf("%s left behind", p)
		}
	}
	if s.state == "active" || s.enabled {
		t.Fatalf("service %s enabled=%v", s.state, s.enabled)
	}
	// The service's own words are in the log for the admin.
	if !strings.Contains(h.log(j.ID), "simulated crash") || !strings.Contains(h.log(j.ID), "Откат") {
		t.Fatal(h.log(j.ID))
	}
	if h.state() != model.StateNeedsAttention || len(h.revisions()) != 0 {
		t.Fatalf("state %s", h.state())
	}
}

// Without ss the port cannot be looked at: the log says the ports were
// not checked, the deploy waits until the running process says it
// serves, and a service that stays "active" without saying so (a
// certificate never issued) is rolled back.
func TestVerifyWithoutSS(t *testing.T) {
	s := newSim()
	s.noSS = true
	h := newHarness(t, s)
	p := params()
	p.HopPorts = "20000-50000"
	j := h.deploy(p, nil)
	if j.State != model.JobCompleted || !strings.Contains(h.log(j.ID), "server up and running") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	for _, w := range []string{"Не удалось проверить, свободен ли порт UDP 443", "Не проверено, свободны ли порты 20000-50000"} {
		if !strings.Contains(h.log(j.ID), w) {
			t.Errorf("no %q in the log:\n%s", w, h.log(j.ID))
		}
	}

	s = newSim()
	s.noSS = true
	s.silent = true
	h = newHarness(t, s)
	j = h.deploy(params(), nil)
	if j.State != model.JobFailed || j.CurrentStep != "verify" || h.steps(j.ID)["start"] != model.StepRolledBack {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, h.log(j.ID))
	}
	if h.state() == model.StateHealthy || len(h.revisions()) != 0 {
		t.Fatalf("state %s, %d revisions", h.state(), len(h.revisions()))
	}
}

// Another Hysteria on the port (its own unit, a container) is not the
// deploy's: preflight stops before any change and offers the import, and
// verify does not take its socket for the new service's.
func TestForeignHysteriaOnPort(t *testing.T) {
	s := newSim()
	s.squatter = 777
	h := newHarness(t, s)
	j := h.deploy(params(), nil)
	if j.State != model.JobFailed || j.CurrentStep != "preflight" || j.Data["foreign"] != "1" || !strings.Contains(j.ErrorMessage, "другой Hysteria") {
		t.Fatalf("%s at %s: %s %v", j.State, j.CurrentStep, j.ErrorMessage, j.Data)
	}
	if _, found := s.file(BinaryPath); found {
		t.Fatal("installed next to the other Hysteria")
	}

	s = newSim()
	s.squatter, s.squatsLate = 777, true
	h = newHarness(t, s)
	j = h.deploy(params(), nil)
	if j.State != model.JobFailed || j.CurrentStep != "verify" || h.state() == model.StateHealthy {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, h.log(j.ID))
	}
}

func TestFailedUpgradeRestoresPrevious(t *testing.T) {
	s := newSim()
	h := newHarness(t, s)
	p := params()
	sec, _ := NewSecrets(p, "192.0.2.10", nil, Input{})
	if j := h.deploy(p, sec); j.State != model.JobCompleted {
		t.Fatalf("first: %s %s", j.ErrorMessage, h.log(j.ID))
	}
	old, _ := s.file(ConfigPath)
	oldCert, _ := s.file(CertPath)

	// The new config (with obfs) kills the service.
	s.badConfig = func(cfg []byte) bool { return bytes.Contains(cfg, []byte("salamander")) }
	p2 := p
	p2.Obfs = true
	sec2, _ := NewSecrets(p2, "192.0.2.10", map[string]string{SecretAuth: sec[SecretAuth]}, Input{})
	j := h.deploy(p2, sec2)
	if j.State != model.JobFailed {
		t.Fatalf("%s", j.State)
	}
	now, _ := s.file(ConfigPath)
	cert, _ := s.file(CertPath)
	if !bytes.Equal(now, old) || !bytes.Equal(cert, oldCert) {
		t.Fatal("previous config not restored")
	}
	// The previous version runs again with its config.
	if s.state != "active" || !bytes.Equal(s.running, old) {
		t.Fatalf("service %s", s.state)
	}
	if !strings.Contains(h.log(j.ID), "Прежняя версия Hysteria запущена снова") {
		t.Fatal(h.log(j.ID))
	}
	if len(h.revisions()) != 1 {
		t.Fatalf("revisions %d", len(h.revisions()))
	}
}

func TestRedeployChangesNothing(t *testing.T) {
	s := newSim()
	s.ufw = true
	h := newHarness(t, s)
	p := params()
	sec, _ := NewSecrets(p, "192.0.2.10", nil, Input{})
	if j := h.deploy(p, sec); j.State != model.JobCompleted {
		t.Fatal(j.ErrorMessage)
	}
	before := s.fileList()
	cfg, _ := s.file(ConfigPath)
	s.reset()

	// A second deploy with the same choices and passwords (a new
	// certificate is generated, but the one in place is kept).
	sec2, _ := NewSecrets(p, "192.0.2.10", map[string]string{SecretAuth: sec[SecretAuth]}, Input{})
	j := h.deploy(p, sec2)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if len(s.writes) != 0 {
		t.Fatalf("wrote %q", s.writes)
	}
	for _, c := range []string{"systemctl restart", "systemctl stop", "install -m", "mv ", "useradd", "curl -fsSL"} {
		if s.ran(c) {
			t.Errorf("ran %q", c)
		}
	}
	if now, _ := s.file(ConfigPath); !bytes.Equal(now, cfg) || !slices.Equal(s.fileList(), before) || s.state != "active" {
		t.Fatal("server changed")
	}
	st := h.steps(j.ID)
	for _, n := range []string{"binary", "user", "tls", "config", "unit", "start", "commit"} {
		if st[n] != model.StepSkipped {
			t.Errorf("%s: %s", n, st[n])
		}
	}
	if len(h.revisions()) != 1 || h.state() != model.StateHealthy {
		t.Fatalf("revisions %d state %s", len(h.revisions()), h.state())
	}
}

func TestRelayDownload(t *testing.T) {
	s := newSim()
	s.github = false // the server cannot reach GitHub
	h := newHarness(t, s)
	j := h.deploy(params(), nil)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s %s\n%s", j.State, j.ErrorMessage, j.ErrorDetails, h.log(j.ID))
	}
	if !slices.Contains(s.writes, "/tmp/hyroute.abcdefghij/hysteria 0600 root:root") || s.ran("curl -fsSL") {
		t.Fatalf("writes %q", s.writes)
	}
	if b, _ := s.file(BinaryPath); !bytes.Equal(b, fakeBinary) {
		t.Fatal("binary")
	}
	if !strings.Contains(h.log(j.ID), "через controller") {
		t.Fatal(h.log(j.ID))
	}

	// The maintenance jobs share the relay: a reinstall of the same build
	// takes the file the controller downloaded for the deploy.
	s.mu.Lock()
	s.files[BinaryPath] = []byte("garbage")
	s.mu.Unlock()
	j = h.maintain(MaintainParams{Op: OpReinstall})
	if b, _ := s.file(BinaryPath); j.State != model.JobCompleted || !bytes.Equal(b, fakeBinary) {
		t.Fatalf("reinstall: %s %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fetched != 1 {
		t.Fatalf("the controller downloaded the binary %d times", h.fetched)
	}
}

// The controller cannot download the release: the error says who could,
// the server itself or only another server.
func TestRelayDownloadFails(t *testing.T) {
	s := newSim()
	h := newHarness(t, s)
	h.mu.Lock()
	h.noBinary = true
	h.mu.Unlock()
	p := params()
	p.Source = SourceRelay
	j := h.deploy(p, nil)
	if j.State != model.JobFailed || !strings.HasPrefix(j.ErrorMessage, "Controller не скачал Hysteria") || !strings.Contains(j.ErrorMessage, "самим сервером") {
		t.Fatalf("relay chosen: %s: %s", j.State, j.ErrorMessage)
	}
	s.github = false
	j = h.deploy(params(), nil)
	if j.State != model.JobFailed || !strings.HasPrefix(j.ErrorMessage, "С сервера GitHub недоступен") || !strings.Contains(j.ErrorMessage, "через другой сервер") {
		t.Fatalf("no GitHub anywhere: %s: %s", j.State, j.ErrorMessage)
	}
}

func TestForeignInstallation(t *testing.T) {
	s := newSim()
	foreign := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-foreign-password\n")
	s.files[BinaryPath] = []byte("someone else's hysteria")
	s.files[ConfigPath] = foreign
	h := newHarness(t, s)
	j := h.deploy(params(), nil)
	if j.State != model.JobFailed || j.CurrentStep != "preflight" || !strings.Contains(j.ErrorMessage, "Импортируйте") || j.Data["foreign"] != "1" {
		t.Fatalf("%s at %s: %s", j.State, j.CurrentStep, j.ErrorMessage)
	}
	if len(s.writes) != 0 || h.state() != model.StateNew {
		t.Fatalf("writes %q", s.writes)
	}
	// With replace the old files are kept aside.
	p := params()
	p.Replace = true
	if j := h.deploy(p, nil); j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, h.log(j.ID))
	}
	if b, _ := s.file(ConfigPath + Backup); !bytes.Equal(b, foreign) {
		t.Fatal("foreign config not kept")
	}
	if b, _ := s.file(BinaryPath + Backup); string(b) != "someone else's hysteria" {
		t.Fatal("foreign binary not kept")
	}
	// The next change of HyRoute's files reuses .hyroute-prev; the copies
	// of the replaced installation stay.
	p = params()
	p.Port = 8443
	if j := h.deploy(p, nil); j.State != model.JobCompleted {
		t.Fatalf("%s\n%s", j.ErrorMessage, h.log(j.ID))
	}
	if b, _ := s.file(ConfigPath + Backup); bytes.Equal(b, foreign) {
		t.Fatal("the second deploy kept no copy of its own config")
	}
	if b, _ := s.file(ConfigPath + Original); !bytes.Equal(b, foreign) {
		t.Fatal("foreign config lost")
	}
	if b, _ := s.file(BinaryPath + Original); string(b) != "someone else's hysteria" {
		t.Fatal("foreign binary lost")
	}
}

func TestParams(t *testing.T) {
	good := []Params{
		{TLS: TLSSelfSigned},
		{TLS: TLSSelfSigned, Port: 8443, HopPorts: "20000-50000", SNI: "www.example.com", Obfs: true},
		{TLS: TLSACME, Domain: "VPN.Example.com", Email: "admin@example.com", Challenge: "tls"},
		// International zones: punycode as is, Unicode converted.
		{TLS: TLSACME, Domain: "vpn.xn--80ak6aa92e.xn--p1ai"},
		{TLS: TLSACME, Domain: "VPN.Пример.РФ"},
		{TLS: TLSSelfSigned, SNI: "cdn.пример.москва"},
		// An email domain in capitals, as a config or an import may have it.
		{TLS: TLSACME, Domain: "vpn.example.com", Email: "Admin@Example.COM"},
	}
	for i := range good {
		if err := good[i].Normalize(); err != nil {
			t.Errorf("%+v: %v", good[i], err)
		}
	}
	if p := good[2]; p.Domain != "vpn.example.com" || p.TCPPorts()[0] != 443 {
		t.Errorf("%+v", p)
	}
	if good[3].Domain != "vpn.xn--80ak6aa92e.xn--p1ai" || good[4].Domain != "vpn.xn--e1afmkfd.xn--p1ai" || good[5].SNI != "cdn.xn--e1afmkfd.xn--80adxhks" {
		t.Errorf("punycode: %q %q %q", good[3].Domain, good[4].Domain, good[5].SNI)
	}
	if p := good[0]; p.Version != hyrelease.DefaultVersion || p.Port != 443 || p.Source != SourceAuto || p.Listen() != ":443" {
		t.Errorf("defaults %+v", p)
	}
	for _, p := range []Params{
		{},
		{TLS: "none"},
		{TLS: TLSSelfSigned, Port: 70000},
		{TLS: TLSSelfSigned, HopPorts: "50000-20000"},
		{TLS: TLSSelfSigned, HopPorts: "a-b"},
		{TLS: TLSSelfSigned, SNI: "not a name"},
		{TLS: TLSACME},
		{TLS: TLSACME, Domain: "192.0.2.10"},
		{TLS: TLSACME, Domain: "vpn.example.com", Challenge: "dns"},
		{TLS: TLSSelfSigned, Masquerade: "http://www.example.com"},
		{TLS: TLSSelfSigned, Masquerade: "https://user:pass@www.example.com"},
		{TLS: TLSSelfSigned, Version: "latest"},
		{TLS: TLSSelfSigned, Source: "ftp"},
	} {
		if err := p.Normalize(); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}

func TestSelfSigned(t *testing.T) {
	cert, key, err := SelfSigned("www.example.com", "192.0.2.10", time.Now())
	if err != nil || !bytes.Contains(key, []byte("PRIVATE KEY")) {
		t.Fatal(err)
	}
	pin, err := Pin(cert)
	if err != nil || len(pin) != 64 {
		t.Fatalf("%q %v", pin, err)
	}
	if _, err := Pin(key); err == nil {
		t.Fatal("key taken for a certificate")
	}
	// A config built from these parses and validates.
	p := params()
	p.Normalize()
	sec, _ := NewSecrets(p, "192.0.2.10", nil, Input{})
	c, err := BuildConfig(p, sec)
	if err != nil || hyconfig.HasErrors(c.Validate()) {
		t.Fatal(err)
	}
	if len(sec[SecretAuth]) != 32 || strings.ContainsAny(sec[SecretAuth], "+/=:@") {
		t.Fatalf("password %q", sec[SecretAuth])
	}
}

// The controller dies right after restarting the service; the next
// process checks the server and finishes the deploy.
func TestControllerRestartMidDeploy(t *testing.T) {
	s := newSim()
	h := newHarness(t, s)
	killed := make(chan struct{})
	var once sync.Once
	stop, done := h.stop, h.done
	s.before = func(line string) {
		if strings.HasPrefix(line, "systemctl restart") {
			// The controller dies while the restart runs: its context is
			// gone before the job can go further.
			once.Do(func() {
				stop()
				go func() { <-done; close(killed) }()
			})
		}
	}
	p := params()
	sec, _ := NewSecrets(p, "192.0.2.10", nil, Input{})
	j, err := h.eng.Submit(context.Background(), JobKind, h.server, p, sec, 0)
	if err != nil {
		t.Fatal(err)
	}
	<-killed
	h.stop = nil
	if cur, _ := h.db.JobByID(context.Background(), j.ID); cur.State.Terminal() {
		t.Fatalf("job already %s", cur.State)
	}
	s.before = nil
	h.startEngine()
	j = h.wait(j.ID)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if !strings.Contains(h.log(j.ID), "перезапущен") || len(h.revisions()) != 1 || s.state != "active" || h.state() != model.StateHealthy {
		t.Fatalf("revisions %d, service %s, server %s\n%s", len(h.revisions()), s.state, h.state(), h.log(j.ID))
	}
}

// fullDisk is the controller's database refusing to record installations
// while full is set.
type fullDisk struct {
	*sqlite.DB
	full atomic.Bool
}

func (d *fullDisk) SetInstallation(ctx context.Context, in model.Installation) error {
	if d.full.Load() {
		return errors.New("database or disk is full")
	}
	return d.DB.SetInstallation(ctx, in)
}

// The database fails right after the commit stored the revision: the
// server keeps the config clients now get instead of going back to the
// previous one, and a retry records the installation without touching
// the server.
func TestCommitFailsAfterRevision(t *testing.T) {
	ctx := context.Background()
	s := newSim()
	h := newHarness(t, s)
	db := &fullDisk{DB: h.db}
	db.full.Store(true)
	h.kill()
	h.store = db
	h.startEngine()
	j := h.deploy(params(), nil)
	if j.State != model.JobFailed || j.CurrentStep != "commit" || !strings.Contains(j.ErrorMessage, "Повторите задание") {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, h.log(j.ID))
	}
	cfg, _ := s.file(ConfigPath)
	revs := h.revisions()
	if len(revs) != 1 || revs[0].JobID != j.ID || revs[0].SHA256 != sum(cfg) || s.state != "active" {
		t.Fatalf("server and controller parted: %d revisions, service %s\n%s", len(revs), s.state, h.log(j.ID))
	}
	if h.state() != model.StateNeedsAttention {
		t.Fatalf("state %s", h.state())
	}

	db.full.Store(false)
	s.reset()
	if _, err := h.eng.Retry(ctx, j.ID, 0); err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("retry: %s %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if in, err := h.db.Installation(ctx, h.server); err != nil || !in.Managed || len(h.revisions()) != 1 || len(s.writes) != 0 || s.ran("systemctl restart") {
		t.Fatalf("installation %+v %v, %d revisions, writes %q", in, err, len(h.revisions()), s.writes)
	}
	if h.state() != model.StateHealthy {
		t.Fatalf("state %s", h.state())
	}
}

// The controller dies right after the new config is written, inside the
// step: what the step recorded for the rollback must survive, so the
// failed start after the restart brings the previous config back instead
// of deleting the file.
func TestRestartMidStepKeepsRollbackRecord(t *testing.T) {
	s := newSim()
	h := newHarness(t, s)
	p := params()
	sec, _ := NewSecrets(p, "192.0.2.10", nil, Input{})
	if j := h.deploy(p, sec); j.State != model.JobCompleted {
		t.Fatalf("first: %s %s", j.ErrorMessage, h.log(j.ID))
	}
	old, _ := s.file(ConfigPath)

	s.badConfig = func(cfg []byte) bool { return bytes.Contains(cfg, []byte("salamander")) }
	killed := make(chan struct{})
	var once sync.Once
	stop, done := h.stop, h.done
	s.written = func(path string) {
		if path == ConfigPath {
			once.Do(func() {
				stop()
				go func() { <-done; close(killed) }()
			})
		}
	}
	p2 := p
	p2.Obfs = true
	sec2, _ := NewSecrets(p2, "192.0.2.10", map[string]string{SecretAuth: sec[SecretAuth]}, Input{})
	j, err := h.eng.Submit(context.Background(), JobKind, h.server, p2, sec2, 0)
	if err != nil {
		t.Fatal(err)
	}
	<-killed
	h.stop = nil
	s.written = nil
	h.startEngine()
	j = h.wait(j.ID)
	if j.State != model.JobFailed {
		t.Fatalf("%s\n%s", j.State, h.log(j.ID))
	}
	now, found := s.file(ConfigPath)
	if !found || !bytes.Equal(now, old) {
		t.Fatalf("previous config not restored (found %v)\n%s", found, h.log(j.ID))
	}
	if s.state != "active" || !bytes.Equal(s.running, old) {
		t.Fatalf("service %s", s.state)
	}
}

// ACME: the certificate comes from Let's Encrypt at start; a failed
// start must not delete certificate files the deploy never wrote.
func TestACMERollbackKeepsForeignCert(t *testing.T) {
	s := newSim()
	s.files[CertPath] = []byte("someone's certificate")
	s.badConfig = func([]byte) bool { return true }
	h := newHarness(t, s)
	p := Params{Version: testVersion, TLS: TLSACME, Domain: "vpn.example.com"}
	j := h.deploy(p, nil)
	if j.State != model.JobFailed {
		t.Fatal(j.State)
	}
	if b, found := s.file(CertPath); !found || string(b) != "someone's certificate" {
		t.Fatal("foreign certificate removed")
	}
	cfg := string(h.sim.files[ConfigPath])
	if cfg != "" {
		t.Fatalf("config left: %s", cfg)
	}
	// ACME needs TCP 80 free: preflight asked for it.
	if !s.ran("ss -Hlntup") {
		t.Fatal("ports not checked")
	}
}

func TestSubmitterKeepsPasswords(t *testing.T) {
	s := newSim()
	h := newHarness(t, s)
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	ctx := context.Background()

	_, err := sub.Submit(ctx, h.server, Params{TLS: "none"}, Input{}, 0)
	var fe *model.FieldError
	if !errors.As(err, &fe) || !strings.HasPrefix(fe.Msg, "Неизвестный режим TLS") || !strings.HasSuffix(fe.Msg, ".") {
		t.Fatalf("bad params: %v", err)
	}
	if _, err := sub.Submit(ctx, 999, params(), Input{}, 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing server: %v", err)
	}

	j, err := sub.Submit(ctx, h.server, params(), Input{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("first deploy: %s %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	first, _ := s.file(ConfigPath)
	cert, _ := s.file(CertPath)

	// The same deploy again: same passwords and certificate, nothing written.
	s.reset()
	j, _ = sub.Submit(ctx, h.server, params(), Input{}, 0)
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("redeploy: %s %s", j.State, j.ErrorMessage)
	}
	if again, _ := s.file(ConfigPath); !bytes.Equal(again, first) || len(s.writes) != 0 {
		t.Fatalf("redeploy changed the config: %v", s.writes)
	}

	// Obfuscation added: the auth password and the pin stay.
	p := params()
	p.Obfs = true
	j, _ = sub.Submit(ctx, h.server, p, Input{}, 0)
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("obfs deploy: %s %s", j.State, j.ErrorMessage)
	}
	before, _ := hyconfig.ParseServer(first)
	b, _ := s.file(ConfigPath)
	after, err := hyconfig.ParseServer(b)
	if err != nil || after.Auth.Password != before.Auth.Password || after.Obfs.Salamander.Password == "" {
		t.Fatalf("passwords after adding obfs: %v", err)
	}
	if c, _ := s.file(CertPath); !bytes.Equal(c, cert) {
		t.Fatal("the certificate changed")
	}
	sec, err := CurrentSecrets(ctx, h.db, h.keys, h.server)
	if err != nil || sec[SecretAuth] != before.Auth.Password || sec[SecretObfs] != after.Obfs.Salamander.Password {
		t.Fatalf("current secrets: %v", err)
	}
	if revs := h.revisions(); len(revs) != 2 || revs[0].Meta.Obfs != "salamander" || revs[0].Meta.PinSHA256 != revs[1].Meta.PinSHA256 {
		t.Fatalf("revisions (newest first): %d", len(revs))
	}
}

func TestInstallationRecorded(t *testing.T) {
	s := newSim()
	h := newHarness(t, s)
	if j := h.deploy(params(), nil); j.State != model.JobCompleted {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	in, err := h.db.Installation(context.Background(), h.server)
	if err != nil || !in.Managed || in.Unit != Unit || in.Config != ConfigPath || in.Binary != BinaryPath || in.User != User || in.Version != testVersion {
		t.Fatalf("%+v %v", in, err)
	}
	// What the reconciliation compares (P4-06): the release binary and
	// the unit the job wrote.
	if in.BinarySHA256 != sum(fakeBinary) || in.UnitSHA256 != sum([]byte(UnitText)) {
		t.Fatalf("hashes: %+v", in)
	}
	// A redeploy that finds the binary in place records it too.
	if j := h.deploy(params(), nil); j.State != model.JobCompleted {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if in, _ := h.db.Installation(context.Background(), h.server); in.BinarySHA256 != sum(fakeBinary) {
		t.Fatalf("after a redeploy: %+v", in)
	}
}

func TestDeployOverImport(t *testing.T) {
	ctx := context.Background()
	imported := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-imported-password\n")

	// Imported elsewhere: deploy would install a second Hysteria.
	s := newSim()
	h := newHarness(t, s)
	h.db.SetInstallation(ctx, model.Installation{ServerID: h.server, Binary: "/opt/hy/hysteria", Config: "/opt/hy/server.yaml", Unit: "hy2.service", At: time.Now()})
	p := params()
	p.Replace = true
	if j := h.deploy(p, nil); j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "hy2.service") || len(s.writes) != 0 {
		t.Fatalf("%s: %s (writes %q)", j.State, j.ErrorMessage, s.writes)
	}

	// Imported in the standard places: its own message; replace works and
	// the installation becomes HyRoute's.
	s = newSim()
	s.files[BinaryPath] = []byte("imported hysteria")
	s.files[ConfigPath] = imported
	s.files[UnitPath] = []byte("[Service]\n")
	s.unitLoaded = "[Service]\n"
	h = newHarness(t, s)
	h.db.SetInstallation(ctx, model.Installation{ServerID: h.server, Binary: BinaryPath, Config: ConfigPath, Unit: Unit, At: time.Now()})
	h.db.AddConfig(ctx, &model.ServerConfig{ServerID: h.server, SHA256: sum(imported), Source: model.ConfigImport, At: time.Now()}, func(rev int) ([]byte, error) {
		return h.keys.Seal(imported, model.ConfigContext(h.server, rev))
	})
	j := h.deploy(params(), nil)
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "импортирована") || len(s.writes) != 0 {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	// The imported config is replaced by the form's only when confirmed.
	if _, err := sub.Submit(ctx, h.server, p, Input{}, 0); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("replace without overwrite: %v", err)
	}
	p.Overwrite = true
	j, err := sub.Submit(ctx, h.server, p, Input{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("replace: %s %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	b, _ := s.file(ConfigPath)
	c, _ := hyconfig.ParseServer(b)
	if c.Auth.Password != "fake-imported-password" {
		t.Fatal("the imported password did not carry over: client links would break")
	}
	if in, _ := h.db.Installation(ctx, h.server); !in.Managed {
		t.Fatal("installation not HyRoute's after replace")
	}
}

// A redeploy over a config changed in the editor is refused without the
// confirmation; with it, the config is the form's again, and the userpass
// users keep their passwords.
func TestRedeployOverEditedConfig(t *testing.T) {
	s := newSim()
	h := newHarness(t, s)
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	ctx := context.Background()
	j, err := sub.Submit(ctx, h.server, params(), Input{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("first deploy: %s %s", j.State, j.ErrorMessage)
	}

	// The editor: a user per client and bandwidth limits.
	b, _ := s.file(ConfigPath)
	c, _ := hyconfig.ParseServer(b)
	users := map[string]string{"alice": "fake-alice-password", "bob": "fake-bob-password"}
	c.Auth = hyconfig.Auth{Type: "userpass", UserPass: users}
	c.Bandwidth = hyconfig.Bandwidth{Up: "100 mbps", Down: "100 mbps"}
	edited, _ := c.Marshal()
	s.mu.Lock()
	s.files[ConfigPath] = edited
	s.mu.Unlock()
	meta := h.revisions()[0].Meta
	meta.Auth = "userpass"
	err = h.db.AddConfig(ctx, &model.ServerConfig{ServerID: h.server, SHA256: sum(edited), Meta: meta, Source: model.ConfigEdit, At: time.Now()}, func(rev int) ([]byte, error) {
		return h.keys.Seal(edited, model.ConfigContext(h.server, rev))
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sub.Submit(ctx, h.server, params(), Input{}, 0); !errors.Is(err, ErrConfigChanged) {
		t.Fatalf("redeploy over the edit without confirmation: %v", err)
	}
	if js, _ := h.db.ListJobs(ctx, model.JobFilter{ServerID: h.server}); len(js) != 1 {
		t.Fatalf("a refused deploy queued a job: %d jobs", len(js))
	}

	p := params()
	p.Overwrite = true
	j, err = sub.Submit(ctx, h.server, p, Input{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("confirmed redeploy: %s %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	check := func(when string) {
		t.Helper()
		b, _ := s.file(ConfigPath)
		after, err := hyconfig.ParseServer(b)
		if err != nil || after.Auth.Type != "userpass" || !maps.Equal(after.Auth.UserPass, users) || after.Auth.Password != "" {
			t.Fatalf("%s: auth %+v (%v): client links would break", when, after.Auth, err)
		}
		if after.Bandwidth.Up != "" {
			t.Fatalf("%s: the config is not the form's: %s", when, b)
		}
		if rev := h.revisions()[0]; rev.Source != model.ConfigDeploy || rev.Meta.Auth != "userpass" || rev.Meta.PinSHA256 != meta.PinSHA256 {
			t.Fatalf("%s: revision %+v", when, rev)
		}
		for _, pw := range users {
			if strings.Contains(h.log(j.ID), pw) {
				t.Fatalf("%s: a password in the job log", when)
			}
		}
	}
	check("confirmed redeploy")

	// The current config is a deploy's again: no question, same users.
	j, err = sub.Submit(ctx, h.server, params(), Input{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobCompleted {
		t.Fatalf("redeploy: %s %s", j.State, j.ErrorMessage)
	}
	check("redeploy")
}

// Every auth type comes through a redeploy as it was; with nothing to
// keep, the deploy makes a password.
func TestAuthSecretsKept(t *testing.T) {
	p := params()
	if err := p.Normalize(); err != nil {
		t.Fatal(err)
	}
	for _, a := range []hyconfig.Auth{
		{Type: "password", Password: "fake-password-1"},
		{Type: "userpass", UserPass: map[string]string{"alice": "fake-alice-pass", "Bob Smith": "fake-bob-pass"}},
		{Type: "http", HTTP: hyconfig.AuthHTTP{URL: "https://auth.example.com/check", Insecure: true}},
		{Type: "http", HTTP: hyconfig.AuthHTTP{URL: "http://127.0.0.1:8080/auth"}},
		{Type: "command", Command: "/etc/hysteria/auth.sh"},
	} {
		sec, err := NewSecrets(p, "192.0.2.10", AuthSecrets(a), Input{})
		if err != nil {
			t.Fatal(err)
		}
		c, err := BuildConfig(p, sec)
		if err != nil || !reflect.DeepEqual(c.Auth, a) {
			t.Fatalf("%s: %+v (%v)", a.Type, c, err)
		}
	}
	for _, a := range []hyconfig.Auth{{}, {Type: "password"}, {Type: "userpass"}, {Type: "http"}} {
		if s := AuthSecrets(a); len(s) != 0 {
			t.Fatalf("%+v: %v", a, s)
		}
		sec, _ := NewSecrets(p, "192.0.2.10", AuthSecrets(a), Input{})
		if c, err := BuildConfig(p, sec); err != nil || c.Auth.Type != "password" || len(c.Auth.Password) != 32 {
			t.Fatalf("%+v: %+v (%v)", a, c, err)
		}
	}
	// The job keeps each password as a secret of its own (masked in the
	// job log one by one).
	s := AuthSecrets(hyconfig.Auth{Type: "userpass", UserPass: map[string]string{"alice": "fake-alice-pass"}})
	if s[SecretUserPrefix+"alice"] != "fake-alice-pass" {
		t.Fatalf("%v", s)
	}
}
