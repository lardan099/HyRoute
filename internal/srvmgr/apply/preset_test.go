package apply

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preset"
)

// A preset of another server: speed, ACL and its ports.
func fastPreset(t *testing.T) model.Preset {
	t.Helper()
	src, err := hyconfig.ParseServer([]byte("listen: 198.51.100.9:443,20000-50000\nauth:\n  type: password\n  password: fake-other-pass\nbandwidth:\n  up: 900 mbps\n  down: 400 mbps\nignoreClientBandwidth: false\nacl:\n  inline:\n    - reject(geoip:private)\n    - direct(all)\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := preset.Extract(src)
	b, _ := p.Marshal()
	return model.Preset{ID: 1, Name: "Быстрый", Config: string(b), CreatedAt: time.Now(), UpdatedAt: time.Now()}
}

// The diff shows the section; the job changes only it on the server.
func TestApplyPresetSection(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	e := &Editor{Store: h.db, Keys: h.keys}
	p := fastPreset(t)
	ch, err := e.PresetPreview(ctx, h.server, 1, p, []string{preset.Speed})
	if err != nil {
		t.Fatal(err)
	}
	var added []string
	for _, l := range ch.Diff {
		if l.Op != " " {
			added = append(added, l.Op+l.Text)
		}
	}
	if d := strings.Join(added, "\n"); !strings.Contains(d, "900 mbps") || strings.Contains(d, "acl") || strings.Contains(d, "listen") || len(ch.Secrets) != 0 || !ch.OK {
		t.Fatalf("diff:\n%s\n%v", d, ch.Secrets)
	}

	j, err := h.app.ApplyPreset(ctx, h.server, 1, p, []string{preset.Speed}, 0)
	if err != nil {
		t.Fatal(err)
	}
	j, log := h.wait(j)
	if j.State != model.JobCompleted || !strings.Contains(log, "Разделы пресета «Быстрый» (speed) применены") {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	after, _ := hyconfig.ParseServer([]byte(h.v.file()))
	before, _ := hyconfig.ParseServer([]byte(deployed))
	if after.Bandwidth.Up != "900 mbps" || after.Bandwidth.Down != "400 mbps" {
		t.Fatalf("%+v", after.Bandwidth)
	}
	after.Bandwidth = before.Bandwidth
	a, _ := after.Marshal()
	b, _ := before.Marshal()
	if string(a) != string(b) {
		t.Fatalf("other sections changed:\n%s\n---\n%s", a, b)
	}

	// The same again: nothing to change.
	var fe *model.FieldError
	if _, err := h.app.ApplyPreset(ctx, h.server, 2, p, []string{preset.Speed}, 0); !errors.As(err, &fe) || !strings.Contains(fe.Msg, "Изменений нет") {
		t.Fatalf("same: %v", err)
	}
	// Ports keep this server's address.
	if ch, err = e.PresetPreview(ctx, h.server, 2, p, []string{preset.Ports, preset.ACL}); err != nil || strings.Contains(ch.YAML, "198.51.100.9") || !strings.Contains(ch.YAML, "listen: :443,20000-50000") || !strings.Contains(ch.YAML, "geoip:private") {
		t.Fatalf("%v\n%s", err, ch.YAML)
	}
}

func TestApplyPresetRefused(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	p := fastPreset(t)
	var fe *model.FieldError
	for _, sections := range [][]string{nil, {preset.Sniff}, {"tls"}} {
		if _, err := h.app.ApplyPreset(ctx, h.server, 1, p, sections, 0); !errors.As(err, &fe) {
			t.Errorf("%v: %v", sections, err)
		}
	}
	var stale *StaleError
	if _, err := h.app.ApplyPreset(ctx, h.server, 5, p, []string{preset.Speed}, 0); !errors.As(err, &stale) {
		t.Fatalf("stale: %v", err)
	}
}
