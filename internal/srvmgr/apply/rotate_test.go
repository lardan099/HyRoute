package apply

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

const (
	certPath = "/etc/hysteria/server.crt"
	keyPath  = "/etc/hysteria/server.key"
)

// selfSignedCfg: userpass, Salamander and a self-signed certificate.
const selfSignedCfg = `listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: userpass
  userpass:
    alice: fake-alice-pass-0001
    bob: fake-bob-pass-0002
obfs:
  type: salamander
  salamander:
    password: fake-obfs-pass-0003
`

// selfSigned makes revision 2 of the harness a config with a
// self-signed certificate on the server; it returns the certificate.
func selfSigned(t *testing.T, h *harness) []byte {
	t.Helper()
	ctx := context.Background()
	cert, key, err := deploy.SelfSigned("vpn.example.com", "192.0.2.50", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := deploy.Pin(cert)
	h.v.mu.Lock()
	h.v.files[cfgPath] = []byte(selfSignedCfg)
	h.v.files[certPath], h.v.modes[certPath] = cert, "644 root root"
	h.v.files[keyPath], h.v.modes[keyPath] = key, "640 root hysteria"
	h.v.start()
	h.v.mu.Unlock()
	c := model.ServerConfig{ServerID: h.server, SHA256: sha([]byte(selfSignedCfg)), Source: model.ConfigEdit, At: time.Now(),
		Meta: model.ConfigMeta{Listen: ":443", TLS: "self-signed", SNI: "vpn.example.com", PinSHA256: pin, Auth: "userpass", Obfs: "salamander"}}
	if err := h.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) {
		return h.keys.Seal([]byte(selfSignedCfg), model.ConfigContext(h.server, rev))
	}); err != nil {
		t.Fatal(err)
	}
	return cert
}

func (h *harness) rotate(base int, r Rotation) (model.Job, string) {
	h.t.Helper()
	j, err := h.app.Rotate(context.Background(), h.server, base, r, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	return h.wait(j)
}

func TestRotatePassword(t *testing.T) {
	h := newHarness(t)
	j, log := h.rotate(1, Rotation{Auth: true})
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	c, _ := hyconfig.ParseServer([]byte(h.v.file()))
	if c.Auth.Password == "fake-apply-auth-pass" || len(c.Auth.Password) < 32 || c.Listen != ":443" || c.ACME == nil {
		t.Fatalf("config:\n%s", h.v.file())
	}
	// The new password is nowhere but in the config.
	if strings.Contains(string(j.Params), c.Auth.Password) || strings.Contains(log, c.Auth.Password) {
		t.Fatal("new password in the params or the log")
	}
	cur, _ := h.db.CurrentConfig(context.Background(), h.server)
	if cur.Revision != 2 || cur.Source != model.ConfigRotate || !strings.Contains(log, "Старые ссылки") {
		t.Fatalf("%+v\n%s", cur, log)
	}
	if st, port := h.v.service(); st != "active" || port != 443 {
		t.Fatalf("service %s %d", st, port)
	}
}

func TestRotateUsersAndObfs(t *testing.T) {
	h := newHarness(t)
	cert := selfSigned(t, h)
	j, log := h.rotate(2, Rotation{Auth: true, Users: []string{"alice"}, Obfs: true})
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	c, _ := hyconfig.ParseServer([]byte(h.v.file()))
	if c.Auth.UserPass["alice"] == "fake-alice-pass-0001" || c.Auth.UserPass["bob"] != "fake-bob-pass-0002" || c.Obfs.Salamander.Password == "fake-obfs-pass-0003" {
		t.Fatalf("config:\n%s", h.v.file())
	}
	if !strings.Contains(string(j.Params), `"rotated":["user:alice","obfs"]`) {
		t.Fatalf("params %s", j.Params)
	}
	// The certificate stays.
	if b, _ := h.v.ReadFile(context.Background(), certPath, false); !bytes.Equal(b, cert) {
		t.Fatal("certificate changed")
	}

	// All users at once.
	j, _ = h.rotate(3, Rotation{Auth: true})
	c2, _ := hyconfig.ParseServer([]byte(h.v.file()))
	if j.State != model.JobCompleted || c2.Auth.UserPass["alice"] == c.Auth.UserPass["alice"] || c2.Auth.UserPass["bob"] == "fake-bob-pass-0002" {
		t.Fatalf("%s:\n%s", j.State, h.v.file())
	}
}

func TestRotateCert(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	old := selfSigned(t, h)
	oldKey, _ := h.v.ReadFile(ctx, keyPath, false)
	before, _ := h.db.CurrentConfig(ctx, h.server)
	h.v.cmds = nil
	j, log := h.rotate(2, Rotation{Cert: true})
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	cert, _ := h.v.ReadFile(ctx, certPath, false)
	key, _ := h.v.ReadFile(ctx, keyPath, false)
	pin, err := deploy.Pin(cert)
	if err != nil || bytes.Equal(cert, old) || bytes.Equal(key, oldKey) {
		t.Fatalf("certificate not replaced: %v", err)
	}
	// The config is the same; the revision has the new pin.
	cur, _ := h.db.CurrentConfig(ctx, h.server)
	if h.v.file() != selfSignedCfg || cur.SHA256 != before.SHA256 || cur.Revision != 3 || cur.Meta.PinSHA256 != pin || cur.Meta.PinSHA256 == before.Meta.PinSHA256 || cur.Source != model.ConfigRotate {
		t.Fatalf("%+v", cur)
	}
	// The key keeps its rights; the old one is not left behind; the
	// service runs with the new certificate.
	if h.v.modes[keyPath] != "640 root hysteria" || h.v.has(keyPath+Backup) || h.v.has(certPath+Backup) {
		t.Fatalf("modes %v", h.v.modes)
	}
	if !slices.ContainsFunc(h.v.cmds, func(c string) bool { return strings.HasPrefix(c, "systemctl restart") }) {
		t.Fatal("not restarted")
	}
	if strings.Contains(log, "PRIVATE KEY") || strings.Contains(string(j.Params), "PRIVATE KEY") {
		t.Fatal("key in the log or the params")
	}
	if !strings.Contains(log, pin) {
		t.Fatalf("log:\n%s", log)
	}
}

// Hysteria does not start with the new certificate: the old one and its
// key come back, and the controller keeps the old revision.
func TestRotateCertRollback(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	old := selfSigned(t, h)
	oldKey, _ := h.v.ReadFile(ctx, keyPath, false)
	h.v.crash = func(files map[string][]byte) bool { return !bytes.Equal(files[certPath], old) }
	j, log := h.rotate(2, Rotation{Cert: true, Obfs: true})
	if j.State != model.JobFailed || j.CurrentStep != "verify" {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	cert, _ := h.v.ReadFile(ctx, certPath, false)
	key, _ := h.v.ReadFile(ctx, keyPath, false)
	if !bytes.Equal(cert, old) || !bytes.Equal(key, oldKey) || h.v.file() != selfSignedCfg {
		t.Fatal("not rolled back")
	}
	if st, _ := h.v.service(); st != "active" || h.state() != model.StateHealthy {
		t.Fatalf("service %s, state %s", st, h.state())
	}
	if cur, _ := h.db.CurrentConfig(ctx, h.server); cur.Revision != 2 {
		t.Fatalf("revision %d", cur.Revision)
	}
	if h.v.has(keyPath+Backup) || h.v.has(certPath+Backup) {
		t.Fatal("copies left after the rollback")
	}
}

func TestRotateRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var fe *model.FieldError
	for name, r := range map[string]Rotation{
		"nothing":   {},
		"no obfs":   {Obfs: true},
		"acme cert": {Cert: true},
	} {
		if _, err := h.app.Rotate(ctx, h.server, 1, r, 0); !errors.As(err, &fe) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Password auth has one password: users are ignored.
	if j, _ := h.rotate(1, Rotation{Auth: true, Users: []string{"alice"}}); j.State != model.JobCompleted {
		t.Fatalf("users of password auth: %s %s", j.State, j.ErrorMessage)
	}
	h2 := newHarness(t)
	selfSigned(t, h2)
	if _, err := h2.app.Rotate(ctx, h2.server, 2, Rotation{Auth: true, Users: []string{"mallory"}}, 0); !errors.As(err, &fe) || !strings.Contains(fe.Msg, "mallory") {
		t.Fatalf("unknown user: %v", err)
	}
	var stale *StaleError
	if _, err := h2.app.Rotate(ctx, h2.server, 1, Rotation{Obfs: true}, 0); !errors.As(err, &stale) {
		t.Fatalf("stale: %v", err)
	}
	for _, auth := range []string{"auth:\n  type: http\n  http:\n    url: https://auth.example.com/check\n", "auth:\n  type: command\n  command: /usr/local/bin/fake-check\n"} {
		if err := rotateAuthOf(t, auth); !errors.As(err, &fe) {
			t.Errorf("%q: %v", auth, err)
		}
	}
}

func rotateAuthOf(t *testing.T, auth string) error {
	c, err := hyconfig.ParseServer([]byte("listen: :443\n" + auth))
	if err != nil {
		t.Fatal(err)
	}
	_, err = rotateAuth(c, nil)
	return err
}
