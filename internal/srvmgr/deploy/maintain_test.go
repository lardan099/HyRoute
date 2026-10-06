package deploy

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

const newVersion = "v2.99.1"

var newBinary = []byte("#!fake hysteria " + newVersion)

// deployed is a harness with a completed deploy of testVersion.
func deployed(t *testing.T, s *sim) *harness {
	t.Helper()
	h := newHarness(t, s)
	if j := h.deploy(params(), nil); j.State != model.JobCompleted {
		t.Fatalf("deploy: %s %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	h.release(newVersion, newBinary)
	s.reset()
	return h
}

func (h *harness) maintain(p MaintainParams) model.Job {
	h.t.Helper()
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	j, err := sub.Maintain(context.Background(), h.server, p, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.wait(j.ID)
}

func (h *harness) installation() model.Installation {
	in, _ := h.db.Installation(context.Background(), h.server)
	return in
}

func TestUpgrade(t *testing.T) {
	s := newSim()
	h := deployed(t, s)
	cfg, _ := s.file(ConfigPath)
	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion})
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if b, _ := s.file(BinaryPath); !bytes.Equal(b, newBinary) {
		t.Fatalf("binary %q", b)
	}
	// The previous binary is kept; the config is not touched.
	if b, _ := s.file(BinaryPath + Backup); !bytes.Equal(b, fakeBinary) {
		t.Fatalf("backup %q", b)
	}
	if b, _ := s.file(ConfigPath); !bytes.Equal(b, cfg) {
		t.Fatal("config changed")
	}
	if s.state != "active" || !s.ran("systemctl restart") {
		t.Fatalf("service %s", s.state)
	}
	if in := h.installation(); in.Version != newVersion || !in.Managed {
		t.Fatalf("installation %+v", in)
	}
	if h.state() != model.StateHealthy {
		t.Fatalf("state %s", h.state())
	}
	if l := h.log(j.ID); !strings.Contains(l, testVersion+" → "+newVersion) || !strings.Contains(l, "SHA-256 совпал") {
		t.Fatalf("log:\n%s", l)
	}

	// Back to the earlier version: the same job.
	j = h.maintain(MaintainParams{Op: OpUpgrade, Version: testVersion})
	if b, _ := s.file(BinaryPath); j.State != model.JobCompleted || !bytes.Equal(b, fakeBinary) || h.installation().Version != testVersion {
		t.Fatalf("downgrade: %s %s %q", j.State, j.ErrorMessage, b)
	}
}

// A redeploy that names no version after an upgrade keeps the upgraded
// one; an older one named is installed, and the log says so.
func TestRedeployAfterUpgrade(t *testing.T) {
	ctx := context.Background()
	s := newSim()
	h := deployed(t, s)
	if j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion}); j.State != model.JobCompleted {
		t.Fatalf("upgrade: %s %s", j.State, j.ErrorMessage)
	}
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	p := params()
	p.Version = ""
	p.Obfs = true
	j, err := sub.Submit(ctx, h.server, p, Input{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(j.Params), `"version":"`+newVersion+`"`) {
		t.Fatalf("params: %s", j.Params)
	}
	j = h.wait(j.ID)
	if b, _ := s.file(BinaryPath); j.State != model.JobCompleted || !bytes.Equal(b, newBinary) || h.installation().Version != newVersion {
		t.Fatalf("redeploy: %s %s %q", j.State, j.ErrorMessage, b)
	}

	p.Version = testVersion
	j, err = sub.Submit(ctx, h.server, p, Input{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobCompleted || h.installation().Version != testVersion {
		t.Fatalf("older version: %s %s", j.State, j.ErrorMessage)
	}
	if l := h.log(j.ID); !strings.Contains(l, newVersion+" → "+testVersion) {
		t.Fatalf("log:\n%s", l)
	}
}

// A version that does not start: the previous binary comes back and the
// service runs with it again.
func TestUpgradeRollback(t *testing.T) {
	s := newSim()
	s.badBinary = func(b []byte) bool { return bytes.Equal(b, newBinary) }
	h := deployed(t, s)
	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion})
	if j.State != model.JobFailed || j.CurrentStep != "verify" {
		t.Fatalf("%s at %s: %s", j.State, j.CurrentStep, j.ErrorMessage)
	}
	st := h.steps(j.ID)
	if st["binary"] != model.StepRolledBack || st["prepare"] != model.StepRolledBack {
		t.Fatalf("steps %v", st)
	}
	if b, _ := s.file(BinaryPath); !bytes.Equal(b, fakeBinary) {
		t.Fatalf("binary not restored: %q", b)
	}
	if s.state != "active" {
		t.Fatalf("service %s after rollback", s.state)
	}
	if in := h.installation(); in.Version != testVersion {
		t.Fatalf("version recorded %s", in.Version)
	}
	if h.state() != model.StateHealthy {
		t.Fatalf("state %s", h.state())
	}
	if l := h.log(j.ID); !strings.Contains(l, "simulated crash") || !strings.Contains(l, "Прежняя установка возвращена") {
		t.Fatalf("log:\n%s", l)
	}
}

// The service was stopped before: after a failed upgrade it stays
// stopped, with the previous binary.
func TestUpgradeRollbackStopped(t *testing.T) {
	s := newSim()
	s.badBinary = func(b []byte) bool { return bytes.Equal(b, newBinary) }
	h := deployed(t, s)
	s.state, s.running = "inactive", nil
	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion})
	if j.State != model.JobFailed {
		t.Fatalf("%s", j.State)
	}
	if b, _ := s.file(BinaryPath); !bytes.Equal(b, fakeBinary) || s.state != "inactive" {
		t.Fatalf("binary %q, service %s", b, s.state)
	}
}

// The installed version again: nothing is downloaded or restarted.
func TestUpgradeSameVersion(t *testing.T) {
	s := newSim()
	h := deployed(t, s)
	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: testVersion})
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if st := h.steps(j.ID); st["binary"] != model.StepSkipped || st["restart"] != model.StepSkipped {
		t.Fatalf("steps %v", st)
	}
	if s.ran("curl -fsSL") || s.ran("systemctl restart") || len(s.writes) != 0 {
		t.Fatalf("changed the server: %q", s.cmds)
	}
}

// A tampered download changes nothing on the server.
func TestUpgradeChecksum(t *testing.T) {
	s := newSim()
	h := deployed(t, s)
	s.AddDownload(h.res.URL(newVersion, "hysteria-linux-amd64"), []byte("tampered"))
	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion})
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "не совпадает с хешем") {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if b, _ := s.file(BinaryPath); !bytes.Equal(b, fakeBinary) || s.ran("systemctl restart") {
		t.Fatalf("binary %q", b)
	}
	if h.state() != model.StateHealthy {
		t.Fatalf("state %s", h.state())
	}
}

// The controller downloads when the server cannot reach GitHub.
func TestUpgradeRelay(t *testing.T) {
	s := newSim()
	h := deployed(t, s)
	s.github = false
	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion})
	if b, _ := s.file(BinaryPath); j.State != model.JobCompleted || !bytes.Equal(b, newBinary) {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if !strings.Contains(h.log(j.ID), "через controller") {
		t.Fatal(h.log(j.ID))
	}
}

// Neither the server nor the controller reach GitHub: another managed
// server downloads the release (its own Hysteria is another build), the
// controller carries the file over, the server checks it again.
func TestUpgradeNode(t *testing.T) {
	ctx := context.Background()
	s := newSim()
	h := deployed(t, s)
	s.github = false
	n := newSim()
	n.files[BinaryPath] = fakeBinary
	n.AddDownload(h.res.URL(newVersion, "hysteria-linux-amd64"), newBinary)
	via := h.node("nl-1", n)
	h.db.SetInstallation(ctx, model.Installation{ServerID: via, Binary: BinaryPath, Config: ConfigPath, Unit: Unit, Version: testVersion, Managed: true, At: time.Now()})
	h.mu.Lock()
	h.noBinary = true
	h.mu.Unlock()

	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion, Source: SourceNode, Via: via})
	if b, _ := s.file(BinaryPath); j.State != model.JobCompleted || !bytes.Equal(b, newBinary) {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if l := h.log(j.ID); !strings.Contains(l, "через сервер «nl-1»") || !strings.Contains(l, "SHA-256 совпал") {
		t.Fatalf("log:\n%s", l)
	}
	if !n.ran("curl -fsSL") || !n.ran("sha256sum") || !s.ran("sha256sum") {
		t.Fatalf("node %q\nserver %q", n.cmds, s.cmds)
	}
	// The node is as it was: its binary, no temporary directory left.
	if b, _ := n.file(BinaryPath); !bytes.Equal(b, fakeBinary) || !n.ran("rm -rf") {
		t.Fatalf("node binary %q, commands %q", b, n.cmds)
	}
}

// The node runs this very build: its binary is copied, nothing is
// downloaded anywhere.
func TestUpgradeNodeInstalled(t *testing.T) {
	ctx := context.Background()
	s := newSim()
	h := deployed(t, s)
	s.github = false
	n := newSim()
	n.github = false
	n.files["/opt/hy/hysteria"] = newBinary
	via := h.node("nl-1", n)
	h.db.SetInstallation(ctx, model.Installation{ServerID: via, Binary: "/opt/hy/hysteria", Config: ConfigPath, Unit: Unit, Version: newVersion, At: time.Now()})

	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion, Source: SourceNode, Via: via})
	if b, _ := s.file(BinaryPath); j.State != model.JobCompleted || !bytes.Equal(b, newBinary) {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if n.ran("curl") || n.ran("mktemp") || len(n.writes) != 0 {
		t.Fatalf("node %q, writes %q", n.cmds, n.writes)
	}
}

// The node's SSH user has no sudo: the node downloads as that user,
// which needs no root.
func TestUpgradeNodeWithoutSudo(t *testing.T) {
	s := newSim()
	h := deployed(t, s)
	s.github = false
	n := newSim()
	n.nonRoot = true
	n.AddDownload(h.res.URL(newVersion, "hysteria-linux-amd64"), newBinary)
	via := h.node("nl-1", n)
	h.mu.Lock()
	h.noBinary = true
	h.mu.Unlock()

	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion, Source: SourceNode, Via: via})
	if b, _ := s.file(BinaryPath); j.State != model.JobCompleted || !bytes.Equal(b, newBinary) {
		t.Fatalf("%s: %s %s\n%s", j.State, j.ErrorMessage, j.ErrorDetails, h.log(j.ID))
	}
	if !n.ran("curl -fsSL") || !n.ran("rm -rf") {
		t.Fatalf("node %q", n.cmds)
	}
}

// What the node downloads does not match the release hash, or the node
// does not answer: the server is not changed, the error says why.
func TestUpgradeNodeFails(t *testing.T) {
	s := newSim()
	h := deployed(t, s)
	n := newSim()
	n.AddDownload(h.res.URL(newVersion, "hysteria-linux-amd64"), []byte("tampered"))
	bad := h.node("nl-1", n)
	gone := h.node("nl-2", nil)
	for _, c := range []struct {
		via  int64
		want string
	}{
		{bad, "не совпадает с хешем"},
		{gone, "нет подключения к серверу «nl-2»"},
	} {
		s.reset()
		j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion, Source: SourceNode, Via: c.via})
		if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage+h.log(j.ID), c.want) {
			t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
		}
		if b, _ := s.file(BinaryPath); !bytes.Equal(b, fakeBinary) || s.ran("systemctl restart") || len(s.writes) != 0 {
			t.Fatalf("server changed: %q %q", b, s.writes)
		}
		if h.state() != model.StateHealthy {
			t.Fatalf("state %s", h.state())
		}
	}
}

// Automatic choice, and neither the server nor the controller can
// download: the error offers another server.
func TestUpgradeNoGitHub(t *testing.T) {
	s := newSim()
	h := deployed(t, s)
	s.github = false
	h.mu.Lock()
	h.noBinary = true
	h.mu.Unlock()
	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion})
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "через другой сервер") {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
}

func TestReinstall(t *testing.T) {
	s := newSim()
	h := deployed(t, s)
	cfg, _ := s.file(ConfigPath)
	cert, _ := s.file(CertPath)
	// Damage: a broken binary, an edited unit, rights too wide.
	s.files[BinaryPath] = []byte("garbage")
	s.files[UnitPath] = []byte("[Service]\nExecStart=/bin/false\n")
	s.modes[ConfigPath] = "644 root root"
	s.modes[KeyPath] = "644 hysteria hysteria"
	s.state, s.running = "failed", nil

	// The version is the recorded one, whatever the request says.
	j := h.maintain(MaintainParams{Op: OpReinstall, Version: newVersion})
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if b, _ := s.file(BinaryPath); !bytes.Equal(b, fakeBinary) {
		t.Fatalf("binary %q", b)
	}
	if u, _ := s.file(UnitPath); string(u) != UnitText || s.unitLoaded != UnitText || !s.enabled {
		t.Fatalf("unit %q", u)
	}
	if s.modes[ConfigPath] != "640 root hysteria" || s.modes[KeyPath] != "640 root hysteria" || s.modeOf(CertPath) != "644 root root" {
		t.Fatalf("rights %v", s.modes)
	}
	if b, _ := s.file(ConfigPath); !bytes.Equal(b, cfg) {
		t.Fatal("config changed")
	}
	if b, _ := s.file(CertPath); !bytes.Equal(b, cert) {
		t.Fatal("certificate changed")
	}
	if s.state != "active" || h.installation().Version != testVersion || h.state() != model.StateHealthy {
		t.Fatalf("service %s, %+v, %s", s.state, h.installation(), h.state())
	}

	// A sound installation: nothing to do.
	s.reset()
	j = h.maintain(MaintainParams{Op: OpReinstall})
	if j.State != model.JobCompleted || len(s.writes) != 0 || s.ran("systemctl restart") || s.ran("chmod") {
		t.Fatalf("%s: writes %q", j.State, s.writes)
	}
}

// A reinstall whose new unit does not start puts the previous files back.
func TestReinstallRollback(t *testing.T) {
	s := newSim()
	h := deployed(t, s)
	edited := []byte("[Service]\nExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml\n")
	s.files[UnitPath] = edited
	s.unitLoaded = string(edited)
	s.failOn["systemctl restart"] = true
	j := h.maintain(MaintainParams{Op: OpReinstall})
	if j.State != model.JobFailed || j.CurrentStep != "restart" {
		t.Fatalf("%s at %s", j.State, j.CurrentStep)
	}
	if u, _ := s.file(UnitPath); !bytes.Equal(u, edited) || s.unitLoaded != string(edited) {
		t.Fatalf("unit not restored: %q", u)
	}
	if h.state() != model.StateNeedsAttention {
		// the restart of the previous unit failed too
		t.Fatalf("state %s", h.state())
	}
}

func TestMaintainRefused(t *testing.T) {
	ctx := context.Background()
	s := newSim()
	h := newHarness(t, s)
	sub := &Submitter{Store: h.db, Keys: h.keys, Jobs: h.eng}
	if _, err := sub.Maintain(ctx, h.server, MaintainParams{Op: OpUpgrade}, 0); !errors.Is(err, ErrNoInstallation) {
		t.Fatalf("no installation: %v", err)
	}
	h.db.SetInstallation(ctx, model.Installation{ServerID: h.server, Binary: BinaryPath, Config: ConfigPath, Unit: Unit, Version: testVersion, At: time.Now()})
	if _, err := sub.Maintain(ctx, h.server, MaintainParams{Op: OpReinstall}, 0); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("imported: %v", err)
	}
	var fe *model.FieldError
	unchecked := model.Server{Name: "nl-new", Host: "192.0.2.12", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateNew}
	if err := h.db.CreateServer(ctx, &unchecked, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []MaintainParams{
		{Op: "rm"}, {Op: OpUpgrade, Version: "latest"}, {Op: OpUpgrade, Source: "ftp"},
		// Through another server: which one, not itself, a known one, one
		// whose SSH key is trusted.
		{Op: OpUpgrade, Source: SourceNode}, {Op: OpUpgrade, Source: SourceNode, Via: h.server}, {Op: OpUpgrade, Source: SourceNode, Via: 999},
		{Op: OpUpgrade, Source: SourceNode, Via: unchecked.ID},
	} {
		if _, err := sub.Maintain(ctx, h.server, p, 0); !errors.As(err, &fe) {
			t.Errorf("%+v: %v", p, err)
		}
	}
	if !strings.Contains(fe.Msg, "«nl-new» ещё не проверен") || fe.Field != "via" {
		t.Errorf("untrusted node: %+v", fe)
	}

	// A service that runs another program (docker, env): it is not
	// replaced, by Submit or by a job queued before the import changed.
	h.db.SetInstallation(ctx, model.Installation{ServerID: h.server, Binary: "/usr/bin/docker", Config: ConfigPath, Unit: "hysteria.service", At: time.Now()})
	if _, err := sub.Maintain(ctx, h.server, MaintainParams{Op: OpUpgrade}, 0); !errors.Is(err, ErrNotHysteria) {
		t.Fatalf("docker: %v", err)
	}
	j, err := h.eng.Submit(ctx, MaintainKind, h.server, MaintainParams{Op: OpUpgrade, Version: testVersion, Source: SourceAuto}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j = h.wait(j.ID); j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "/usr/bin/docker") {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if s.ran("/usr/bin/docker") || s.ran("install") || s.ran("cp") {
		t.Fatalf("touched the program: %q", s.cmds)
	}
}

// An imported installation is upgraded where it is.
func TestUpgradeImported(t *testing.T) {
	ctx := context.Background()
	s := newSim()
	h := deployed(t, s)
	in := h.installation()
	in.Managed = false
	h.db.SetInstallation(ctx, in)
	j := h.maintain(MaintainParams{Op: OpUpgrade, Version: newVersion})
	if b, _ := s.file(BinaryPath); j.State != model.JobCompleted || !bytes.Equal(b, newBinary) {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if in := h.installation(); in.Managed || in.Version != newVersion {
		t.Fatalf("%+v", in)
	}
}
