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
	for _, p := range []MaintainParams{{Op: "rm"}, {Op: OpUpgrade, Version: "latest"}, {Op: OpUpgrade, Source: "ftp"}} {
		if _, err := sub.Maintain(ctx, h.server, p, 0); !errors.As(err, &fe) {
			t.Errorf("%+v: %v", p, err)
		}
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
