package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

const (
	driftCanary    = "fake-drift-api-auth-31d7"
	driftCanaryNew = "fake-drift-api-new-a0c4"
)

var driftRevision = "listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: " + driftCanary + "\n"

type driftConn struct{ m *fake.Executor }

func (c driftConn) Connect(context.Context, int64) (remote.Executor, error) {
	return keepOpen{c.m}, nil
}

type keepOpen struct{ *fake.Executor }

func (keepOpen) Close() error { return nil }

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// driftServer is a server with a trusted key, an installation and a
// revision, read over a fake machine.
func (e *testEnv) driftServer() (int64, *fake.Executor) {
	e.t.Helper()
	ctx := context.Background()
	s := model.Server{Name: "Amsterdam", Host: "192.0.2.40", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	if err := e.db.CreateServer(ctx, &s, nil); err != nil {
		e.t.Fatal(err)
	}
	e.db.SetHostKey(ctx, model.HostKey{ServerID: s.ID, Type: "ssh-ed25519", Key: []byte{1}, Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	e.db.SetInstallation(ctx, model.Installation{ServerID: s.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service",
		User: "hysteria", Version: "v2.12.3", Managed: true, At: time.Now()})
	c := model.ServerConfig{ServerID: s.ID, SHA256: hexSum([]byte(driftRevision)), Source: model.ConfigDeploy, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) {
		return e.keys.Seal([]byte(driftRevision), model.ConfigContext(s.ID, rev))
	})
	m := fake.New()
	m.On("id", "-un").Reply("root\n", 0)
	m.On("id", "-u").Reply("0\n", 0)
	m.On("uname").Reply("x\n", 0)
	m.On("stat").Reply("640 root hysteria 100\n", 0)
	m.SetFile("/etc/hysteria/config.yaml", []byte(strings.Replace(driftRevision, driftCanary, driftCanaryNew, 1)))
	e.reconcile.Conn = driftConn{m}
	return s.ID, m
}

// The reconciliation over the API: everyone sees the differences, only
// those who may write see the masked diff, check, accept and revert.
func TestReconcileAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	_, op, ro, _ := e.staff(owner)
	id, m := e.driftServer()
	base := "/api/v1/servers/" + strconv.FormatInt(id, 10) + "/reconcile"
	var d driftJSON

	rec := ro.do("GET", base, nil, nil)
	if json.Unmarshal(rec.Body.Bytes(), &d); rec.Code != 200 || d.At != nil || len(d.Items) != 0 || d.Interval != 3600 {
		t.Fatalf("never checked: %d %s", rec.Code, rec.Body)
	}
	code(t, ro.do("POST", base+"/check", nil, nil), http.StatusForbidden, "forbidden")
	rec = op.do("POST", base+"/check", nil, nil)
	if json.Unmarshal(rec.Body.Bytes(), &d); rec.Code != 200 || len(d.Items) != 1 || d.Items[0].Key != "config" || len(d.Items[0].Diff) == 0 || !d.Items[0].CanRevert {
		t.Fatalf("check: %d %s", rec.Code, rec.Body)
	}
	if len(d.Items[0].Secrets) != 1 || d.Items[0].Secrets[0] != "auth.password" || len(d.Skipped) != 2 {
		t.Fatalf("check: %s", rec.Body)
	}
	for _, c := range []*client{op, ro} {
		body := c.do("GET", base, nil, nil).Body.String()
		if strings.Contains(body, driftCanary) || strings.Contains(body, driftCanaryNew) {
			t.Fatalf("a secret in %s", body)
		}
		if diff := strings.Contains(body, `"diff":`); diff != (c == op) {
			t.Fatalf("diff shown %v to %s", diff, body)
		}
	}
	if s, _ := e.db.ServerByID(context.Background(), id); s.State != model.StateNeedsAttention {
		t.Fatalf("state %s", s.State)
	}

	// Revert queues the apply job; while it waits nothing is accepted.
	code(t, ro.do("POST", base+"/revert", map[string]string{"key": "config"}, nil), http.StatusForbidden, "forbidden")
	rec = op.do("POST", base+"/revert", map[string]string{"key": "config"}, nil)
	var j jobJSON
	if json.Unmarshal(rec.Body.Bytes(), &j); rec.Code != http.StatusAccepted || j.Kind != "apply" || !strings.Contains(string(j.Params), `"drift":`) {
		t.Fatalf("revert: %d %s", rec.Code, rec.Body)
	}
	code(t, op.do("POST", base+"/accept", map[string]string{"key": "config"}, nil), http.StatusConflict, "server_busy")
	code(t, op.do("POST", base+"/check", nil, nil), http.StatusConflict, "server_busy")
	rec = op.do("GET", base, nil, nil)
	if json.Unmarshal(rec.Body.Bytes(), &d); d.Items[0].Job == nil || d.Items[0].Job.ID != j.ID {
		t.Fatalf("the revert job: %s", rec.Body)
	}
	jm, _ := e.db.JobByID(context.Background(), j.ID)
	jm.State, jm.FinishedAt = model.JobFailed, time.Now()
	e.db.UpdateJob(context.Background(), jm)

	// Accept: a revision from outside HyRoute; nothing written there.
	code(t, ro.do("POST", base+"/accept", map[string]string{"key": "config"}, nil), http.StatusForbidden, "forbidden")
	rec = op.do("POST", base+"/accept", map[string]string{"key": "config"}, nil)
	if json.Unmarshal(rec.Body.Bytes(), &d); rec.Code != 200 || len(d.Items) != 0 {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body)
	}
	if len(m.Writes()) != 0 {
		t.Fatalf("written: %v", m.Writes())
	}
	rec = op.do("GET", "/api/v1/servers/"+strconv.FormatInt(id, 10)+"/config/revisions", nil, nil)
	if !strings.Contains(rec.Body.String(), `"source":"external"`) {
		t.Fatalf("revisions: %s", rec.Body)
	}
	code(t, op.do("POST", base+"/accept", map[string]string{"key": "config"}, nil), http.StatusConflict, "drift_gone")
	code(t, op.do("POST", base+"/revert", map[string]string{"key": "binary"}, nil), http.StatusConflict, "drift_gone")
	code(t, op.do("GET", "/api/v1/servers/999/reconcile", nil, nil), http.StatusNotFound, "not_found")
}
