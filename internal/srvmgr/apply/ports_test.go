package apply

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/hopping"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func (h *harness) listen() string {
	h.t.Helper()
	c, err := hyconfig.ParseServer([]byte(h.v.file()))
	if err != nil {
		h.t.Fatal(err)
	}
	return c.Listen
}

// New ports go through the apply job: the config listens on them (only
// listen changes), the firewall opens them, and the revision has them.
func TestSetPorts(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.v.mu.Lock()
	h.v.ufw = map[string]bool{}
	h.v.mu.Unlock()
	j, err := h.app.SetPorts(ctx, h.server, 1, hopping.Spec{Ports: []string{"20000-50000", "443"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	if l := h.listen(); l != ":443,20000-50000" {
		t.Fatalf("listen %q", l)
	}
	if !strings.Contains(h.v.file(), "fake-apply-auth-pass") || !strings.Contains(h.v.file(), "vpn.example.com") {
		t.Fatalf("config lost settings:\n%s", h.v.file())
	}
	if !slices.Contains(h.v.rules(), "20000:50000/udp") {
		t.Fatalf("rules %q\n%s", h.v.rules(), log)
	}
	if !strings.Contains(log, "перенаправлять на него остальные (443,20000-50000, всего 30002)") {
		t.Fatal(log)
	}
	cur, _ := h.db.CurrentConfig(ctx, h.server)
	if cur.Revision != 2 || cur.Meta.Ports != "443,20000-50000" || cur.Source != model.ConfigEdit {
		t.Fatalf("%+v", cur)
	}

	// Back to one port, IPv4 only.
	j, err = h.app.SetPorts(ctx, h.server, 2, hopping.Spec{Ports: []string{"8443"}, Host: "0.0.0.0"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j, log = h.wait(j); j.State != model.JobCompleted || h.listen() != "0.0.0.0:8443" {
		t.Fatalf("%s %q\n%s", j.State, h.listen(), log)
	}
	if slices.Contains(h.v.rules(), "20000:50000/udp") {
		t.Fatalf("old range still open: %q", h.v.rules())
	}
}

// Ports another program listens on are refused before anything changes
// on the server.
func TestSetPortsBusy(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.v.mu.Lock()
	h.v.others = "udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:* users:((\"wg-quick\",pid=900,fd=3))\n"
	h.v.mu.Unlock()
	j, err := h.app.SetPorts(ctx, h.server, 1, hopping.Spec{Ports: []string{"443", "50000-60000"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobFailed || j.CurrentStep != "validate" || !strings.Contains(j.ErrorMessage, "UDP 51820 — wg-quick") {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if h.v.file() != deployed {
		t.Fatal("config changed")
	}
	// The same check for an edit in the editor.
	j, err = h.app.Submit(ctx, h.server, 1, h.edit(func(s string) string { return strings.Replace(s, "listen: :443", "listen: :51820", 1) }), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if j, _ = h.wait(j); j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "51820") {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
}

// Hopping without a redirect tool for the address family is refused.
func TestSetPortsNoTool(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.v.mu.Lock()
	h.v.tools = map[string]bool{"/usr/sbin/iptables": true}
	h.v.mu.Unlock()
	j, _ := h.app.SetPorts(ctx, h.server, 1, hopping.Spec{Ports: []string{"443", "20000-50000"}}, 0)
	if j, _ = h.wait(j); j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "ip6tables") {
		t.Fatalf("%s: %s", j.State, j.ErrorMessage)
	}
	// IPv4 only needs iptables alone.
	j, _ = h.app.SetPorts(ctx, h.server, 1, hopping.Spec{Ports: []string{"443", "20000-50000"}, Host: "0.0.0.0"}, 0)
	if j, log := h.wait(j); j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
}

func TestSetPortsRefused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	var fe *model.FieldError
	if _, err := h.app.SetPorts(ctx, h.server, 1, hopping.Spec{Ports: []string{"443", "400-500"}}, 0); !errors.As(err, &fe) || !strings.Contains(fe.Msg, "пересекаются") {
		t.Fatalf("overlap: %v", err)
	}
	if _, err := h.app.SetPorts(ctx, h.server, 1, hopping.Spec{Ports: []string{" 443 "}}, 0); !errors.Is(err, ErrSamePorts) {
		t.Fatalf("same: %v", err)
	}
	var stale *StaleError
	if _, err := h.app.SetPorts(ctx, h.server, 7, hopping.Spec{Ports: []string{"8443"}}, 0); !errors.As(err, &stale) {
		t.Fatalf("stale: %v", err)
	}
}
