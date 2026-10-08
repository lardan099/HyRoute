package batch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/routing"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
	"github.com/lardan099/hyroute/internal/srvmgr/tuning"
)

// acmeCfg: password auth, a certificate from ACME, no obfuscation.
const acmeCfg = `listen: :443
acme:
  domains:
    - vpn.example.com
  email: admin@example.com
auth:
  type: password
  password: fake-batch-pass-0001
acl:
  inline:
    - direct(all)
`

type actionsEnv struct {
	t   *testing.T
	db  *sqlite.DB
	a   *Actions
	ctx context.Context
}

// newActions is the actions over a database with a deployed config per
// server; the jobs are queued, never run.
func newActions(t *testing.T) *actionsEnv {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{6}, 32)})
	eng := jobs.New(db, keys, redact.New(), nil, nil)
	app := apply.New(apply.Deps{Store: db, Keys: keys, Jobs: eng})
	eng.Register(app.Kind())
	eng.Register(tuning.Kind())
	dd := deploy.Deps{Store: db, Keys: keys, Resolver: &hyrelease.Resolver{}}
	eng.Register(deploy.Maintenance(dd))
	ed := &apply.Editor{Store: db, Keys: keys}
	a := &Actions{Store: db, Jobs: eng, Deploy: &deploy.Submitter{Store: db, Keys: keys, Jobs: eng}, Apply: app, Editor: ed,
		Routing: &routing.Service{Editor: ed, Applier: app, Chains: db}}
	return &actionsEnv{t: t, db: db, a: a, ctx: ctx}
}

// server is a deployed server with cfg as its config.
func (e *actionsEnv) server(name, cfg string) int64 {
	e.t.Helper()
	srv := model.Server{Name: name, Host: "192.0.2.60", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, State: model.StateHealthy}
	if err := e.db.CreateServer(e.ctx, &srv, nil); err != nil {
		e.t.Fatal(err)
	}
	e.db.SetInstallation(e.ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", Version: "v2.6.0", Managed: true, At: time.Now()})
	s := sha256.Sum256([]byte(cfg))
	c := model.ServerConfig{ServerID: srv.ID, SHA256: hex.EncodeToString(s[:]), Source: model.ConfigDeploy, At: time.Now(), Meta: model.ConfigMeta{TLS: "acme"}}
	if err := e.db.AddConfig(e.ctx, &c, func(rev int) ([]byte, error) {
		return e.a.Editor.Keys.Seal([]byte(cfg), model.ConfigContext(srv.ID, rev))
	}); err != nil {
		e.t.Fatal(err)
	}
	return srv.ID
}

func (e *actionsEnv) preset(name, cfg string) int64 {
	e.t.Helper()
	p := model.Preset{Name: name, Config: cfg, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := e.db.CreatePreset(e.ctx, &p); err != nil {
		e.t.Fatal(err)
	}
	return p.ID
}

func (e *actionsEnv) queue(action model.BatchAction, params string, server int64) (model.Job, string, error) {
	e.t.Helper()
	raw, err := e.a.Check(e.ctx, action, json.RawMessage(params))
	if err != nil {
		e.t.Fatalf("%s %s: %v", action, params, err)
	}
	return e.a.Queue(e.ctx, model.Batch{Action: action, Params: raw}, server, 0)
}

// Check refuses what a batch cannot do and keeps the params normalized.
func TestCheck(t *testing.T) {
	e := newActions(t)
	acl := e.preset("acl", "acl:\n  inline:\n    - reject(all)\n")
	for _, c := range []struct {
		action model.BatchAction
		params string
		field  string
	}{
		{"nope", `{}`, "action"},
		{model.BatchMaintain, `{"version":"latest"}`, "version"},
		{model.BatchMaintain, `{"source":"node"}`, "source"},
		{model.BatchGeo, `{"source":"node"}`, "via"},
		{model.BatchGeo, `{"source":"ftp"}`, "source"},
		{model.BatchPreset, `{"preset":999,"sections":["acl"]}`, "preset"},
		{model.BatchPreset, `{"preset":` + strconv.FormatInt(acl, 10) + `}`, "sections"},
		{model.BatchPreset, `{"preset":` + strconv.FormatInt(acl, 10) + `,"sections":["nope"]}`, "sections"},
		{model.BatchRouting, `{"template":"builtin:nope"}`, "template"},
		{model.BatchRouting, `{"template":"builtin:local","place":"middle"}`, "place"},
		{model.BatchTuning, `{"keys":[]}`, "keys"},
		{model.BatchTuning, `{"keys":["kernel.panic"]}`, "keys"},
		{model.BatchRotate, `{}`, "rotate"},
	} {
		_, err := e.a.Check(e.ctx, c.action, json.RawMessage(c.params))
		var fe *model.FieldError
		if !errors.As(err, &fe) || fe.Field != c.field || fe.Msg == "" {
			t.Errorf("%s %s: %v", c.action, c.params, err)
		}
	}
	for action, want := range map[model.BatchAction]string{
		model.BatchMaintain: `{"version":"` + hyrelease.DefaultVersion + `","source":"auto"}`,
		model.BatchGeo:      `{"source":"auto"}`,
		model.BatchRouting:  `{"template":"builtin:ads","place":"top"}`,
	} {
		in := map[model.BatchAction]string{model.BatchMaintain: `{"via":4}`, model.BatchGeo: `{"via":4}`, model.BatchRouting: `{"template":"builtin:ads","servers":[1]}`}[action]
		got, err := e.a.Check(e.ctx, action, json.RawMessage(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: %s %v", action, got, err)
		}
	}
	if got := Via(model.Batch{Params: json.RawMessage(`{"source":"node","via":7}`)}); got != 7 {
		t.Errorf("via %d", got)
	}
}

// Each action queues the job its single-server route would, on the
// current revision; a server that already is so, or has nothing the
// action changes, gets no job.
func TestQueue(t *testing.T) {
	e := newActions(t)
	same := e.preset("same", "acl:\n  inline:\n    - direct(all)\n")
	other := e.preset("other", "acl:\n  inline:\n    - reject(geoip:private)\n    - direct(all)\n")

	a := e.server("a", acmeCfg)
	if _, _, err := e.queue(model.BatchPreset, `{"preset":`+strconv.FormatInt(same, 10)+`,"sections":["acl"]}`, a); !isUnchanged(err) {
		t.Fatalf("same preset: %v", err)
	}
	j, _, err := e.queue(model.BatchPreset, `{"preset":`+strconv.FormatInt(other, 10)+`,"sections":["acl"]}`, a)
	if err != nil || j.Kind != apply.JobKind || !strings.Contains(string(j.Params), `"preset":"other"`) || !strings.Contains(string(j.Params), `"base":1`) {
		t.Fatalf("preset: %+v %v", j, err)
	}
	if _, _, err := e.queue(model.BatchTuning, `{"keys":["net.core.rmem_max"]}`, a); !errors.Is(err, jobs.ErrBusy) {
		t.Fatalf("busy: %v", err)
	}

	b := e.server("b", acmeCfg)
	tpl := `{"template":"preset:` + strconv.FormatInt(same, 10) + `","place":"replace"}`
	if _, _, err := e.queue(model.BatchRouting, tpl, b); !isUnchanged(err) {
		t.Fatalf("same rules: %v", err)
	}
	if j, _, err := e.queue(model.BatchRouting, `{"template":"builtin:local","place":"top"}`, b); err != nil || !strings.Contains(string(j.Params), `"change":"routing"`) {
		t.Fatalf("routing: %+v %v", j, err)
	}

	// Rotation: what the server has of what the batch asks.
	c := e.server("c", acmeCfg)
	if _, _, err := e.queue(model.BatchRotate, `{"obfs":true,"cert":true}`, c); !isUnchanged(err) || !strings.Contains(err.Error(), "Salamander") || !strings.Contains(err.Error(), "сертификат") {
		t.Fatalf("nothing to rotate: %v", err)
	}
	j, note, err := e.queue(model.BatchRotate, `{"auth":true,"obfs":true}`, c)
	var p apply.Params
	json.Unmarshal(j.Params, &p)
	if err != nil || !slices.Equal(p.Rotated, []string{"auth"}) || !strings.Contains(note, "Salamander") {
		t.Fatalf("rotate: %+v %q %v", p, note, err)
	}

	d := e.server("d", acmeCfg)
	if j, _, err := e.queue(model.BatchMaintain, `{"version":"v2.12.3"}`, d); err != nil || j.Kind != deploy.MaintainKind || !strings.Contains(string(j.Params), `"op":"upgrade"`) {
		t.Fatalf("maintain: %+v %v", j, err)
	}
	if _, _, err := e.queue(model.BatchMaintain, `{"version":"v2.12.3"}`, 999); Message(err) == "" || !errors.Is(err, deploy.ErrNoInstallation) {
		t.Fatalf("no installation: %v %q", err, Message(err))
	}
	if Message(errors.New("disk full")) == "disk full" {
		t.Fatal("an internal error shown as is")
	}
}

func isUnchanged(err error) bool {
	var un *Unchanged
	return errors.As(err, &un) && un.Msg != ""
}
