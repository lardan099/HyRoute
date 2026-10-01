package deploy

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func (h *harness) firewall() model.Firewall {
	h.t.Helper()
	in, err := h.db.Installation(context.Background(), h.server)
	if err != nil {
		h.t.Fatal(err)
	}
	return in.Firewall
}

// A failed deploy closes the ports it opened and leaves the rules that
// were there before.
func TestFirewallRollbackKeepsExistingRules(t *testing.T) {
	s := newSim()
	s.ufw = true
	s.ufwRules["443/udp"] = true
	s.badConfig = func([]byte) bool { return true }
	h := newHarness(t, s)
	p := params()
	p.HopPorts = "20000-50000"
	j := h.deploy(p, nil)
	if j.State != model.JobFailed {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	if !s.ran("ufw allow 20000:50000/udp") || s.ran("ufw allow 443/udp") {
		t.Fatalf("firewall: %q", s.cmds)
	}
	if r := s.rules(); !slices.Equal(r, []string{"443/udp"}) {
		t.Fatalf("rules after the rollback: %q\n%s", r, h.log(j.ID))
	}
	if st := h.steps(j.ID); st["firewall"] != model.StepRolledBack {
		t.Fatalf("firewall step %s", st["firewall"])
	}
}

// HyRoute records the rules it opened; a port change closes those that
// the new config no longer needs, after it works, and never the admin's.
func TestFirewallPortChange(t *testing.T) {
	s := newSim()
	s.ufw = true
	s.ufwRules["443/udp"] = true // the admin's
	h := newHarness(t, s)
	p := params()
	p.HopPorts = "20000-50000"
	sec, _ := NewSecrets(p, "192.0.2.10", nil, Input{})
	if j := h.deploy(p, sec); j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if fw := h.firewall(); fw != (model.Firewall{Tool: "ufw", Ports: "20000-50000/udp"}) {
		t.Fatalf("recorded %+v", fw)
	}

	p2 := p
	p2.Port, p2.HopPorts = 8443, ""
	sec2, _ := NewSecrets(p2, "192.0.2.10", map[string]string{SecretAuth: sec[SecretAuth]}, Input{})
	j := h.deploy(p2, sec2)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if r := s.rules(); !slices.Equal(r, []string{"443/udp", "8443/udp"}) {
		t.Fatalf("rules %q\n%s", r, h.log(j.ID))
	}
	if fw := h.firewall(); fw != (model.Firewall{Tool: "ufw", Ports: "8443/udp"}) {
		t.Fatalf("recorded %+v", fw)
	}
	if !strings.Contains(h.log(j.ID), "20000-50000/udp") {
		t.Fatal(h.log(j.ID))
	}

	// "Leave the firewall alone": nothing opened or closed, the record
	// stays for later.
	p3 := p2
	p3.Port, p3.KeepFirewall = 9443, true
	sec3, _ := NewSecrets(p3, "192.0.2.10", map[string]string{SecretAuth: sec[SecretAuth]}, Input{})
	if j := h.deploy(p3, sec3); j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, h.log(j.ID))
	}
	if r := s.rules(); !slices.Equal(r, []string{"443/udp", "8443/udp"}) {
		t.Fatalf("rules %q", r)
	}
	if fw := h.firewall(); fw != (model.Firewall{Tool: "ufw", Ports: "8443/udp", Keep: true}) {
		t.Fatalf("recorded %+v", fw)
	}
}

// The controller stops right after opening a port: the job's record of it
// survives, and the rollback after the restart closes it.
func TestRestartMidFirewallClosesOpenedPort(t *testing.T) {
	s := newSim()
	s.ufw = true
	s.badConfig = func([]byte) bool { return true }
	h := newHarness(t, s)
	killed := make(chan struct{})
	var once sync.Once
	stop, done := h.stop, h.done
	s.before = func(line string) {
		if strings.HasPrefix(line, "ufw allow") {
			once.Do(func() {
				stop()
				go func() { <-done; close(killed) }()
			})
		}
	}
	sec, _ := NewSecrets(params(), "192.0.2.10", nil, Input{})
	j, err := h.eng.Submit(context.Background(), JobKind, h.server, params(), sec, 0)
	if err != nil {
		t.Fatal(err)
	}
	<-killed
	h.stop = nil
	s.before = nil
	if r := s.rules(); !slices.Equal(r, []string{"443/udp"}) {
		t.Fatalf("rules before the restart %q", r)
	}
	h.startEngine()
	j = h.wait(j.ID)
	if j.State != model.JobFailed {
		t.Fatalf("%s\n%s", j.State, h.log(j.ID))
	}
	if r := s.rules(); len(r) != 0 {
		t.Fatalf("rules after the rollback %q\n%s", r, h.log(j.ID))
	}
}
