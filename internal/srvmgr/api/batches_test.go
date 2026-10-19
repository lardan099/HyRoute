package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
)

// ready gives a server an installation of version and a trusted SSH key,
// as a batch needs.
func (e *testEnv) ready(id int64, version string) {
	e.t.Helper()
	ctx := context.Background()
	e.db.SetInstallation(ctx, model.Installation{ServerID: id, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", Version: version, Managed: true, At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: id, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
}

func (e *testEnv) addServer(name string, tags ...string) int64 {
	e.t.Helper()
	pw := fakeSSHPass
	in, err := e.servers.Create(context.Background(), 1, servers.Input{Name: name, Tags: tags, Host: "127.0.0.1", SSHPort: 1, SSHUser: "root", AuthType: model.AuthPassword, Password: &pw})
	if err != nil {
		e.t.Fatal(err)
	}
	return in.ID
}

func decodeBatch(t *testing.T, b []byte) batchJSON {
	t.Helper()
	var out batchJSON
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return out
}

const tuningKeys = `["net.core.rmem_max"]`

// A batch is created over servers that can take its jobs, shown with its
// items, stopped (what has not started is skipped) and retried once.
func TestBatchAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	a, b := e.addServer("a"), e.addServer("b")
	body := map[string]any{"servers": []int64{a, b, a}, "keys": json.RawMessage(tuningKeys)}

	rec := owner.do("POST", "/api/v1/batches/tuning", body, nil)
	code(t, rec, http.StatusConflict, "no_installation")
	if e := decodeError(t, rec); !strings.Contains(e.Message, "«a»") {
		t.Fatalf("%+v", e)
	}
	e.ready(a, "v2.6.0")
	e.db.SetInstallation(context.Background(), model.Installation{ServerID: b, Binary: "/usr/local/bin/hysteria", At: time.Now()})
	code(t, owner.do("POST", "/api/v1/batches/tuning", body, nil), http.StatusConflict, "host_key_required")
	e.ready(b, "v2.6.0")
	code(t, owner.do("POST", "/api/v1/batches/tuning", map[string]any{"keys": json.RawMessage(tuningKeys)}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/batches/tuning", map[string]any{"servers": []int64{a}, "keys": []string{}}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/batches/tuning", map[string]any{"servers": []int64{a}, "parallel": 11, "keys": json.RawMessage(tuningKeys)}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/batches/geo", map[string]any{"servers": []int64{a, b}, "source": "node", "via": b}, nil), http.StatusBadRequest, "invalid")
	code(t, owner.do("POST", "/api/v1/batches/geo", map[string]any{"servers": []int64{a}}, nil), http.StatusConflict, "no_geo")
	code(t, owner.do("POST", "/api/v1/batches/tuning", map[string]any{"servers": []int64{a, 999999}, "keys": json.RawMessage(tuningKeys)}, nil), http.StatusNotFound, "not_found")

	rec = owner.do("POST", "/api/v1/batches/tuning", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	got := decodeBatch(t, rec.Body.Bytes())
	if got.Action != model.BatchTuning || got.Parallel != 3 || got.State != model.BatchRunning || got.CreatedBy != "owner" || len(got.Items) != 2 ||
		got.Items[0].ServerID != a || got.Items[1].ServerID != b || got.Items[0].State != model.ItemPending || !got.MayStop || got.MayRetry ||
		string(got.Params) != `{"keys":["net.core.rmem_max"]}` {
		t.Fatalf("%s", rec.Body)
	}
	id := strconvID(got.ID)
	rec = owner.do("GET", "/api/v1/batches", nil, nil)
	var list []batchJSON
	json.Unmarshal(rec.Body.Bytes(), &list)
	if rec.Code != 200 || len(list) != 1 || list[0].ID != got.ID {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}

	// Nothing ran (the runner is not started): stopping skips everything
	// and ends the batch.
	rec = owner.do("POST", "/api/v1/batches/"+id+"/stop", nil, nil)
	got = decodeBatch(t, rec.Body.Bytes())
	if rec.Code != 200 || got.State != model.BatchStopped || got.Stop != model.StopUser || got.StoppedBy != "owner" || got.Items[1].State != model.ItemSkipped || got.MayStop || !got.MayRetry {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/batches/"+id+"/stop", nil, nil), http.StatusConflict, "batch_not_running")

	rec = owner.do("POST", "/api/v1/batches/"+id+"/retry", nil, nil)
	again := decodeBatch(t, rec.Body.Bytes())
	if rec.Code != http.StatusCreated || again.RetryOf != got.ID || len(again.Items) != 2 || again.State != model.BatchRunning {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, owner.do("POST", "/api/v1/batches/"+id+"/retry", nil, nil), http.StatusConflict, "batch_retried")
	code(t, owner.do("POST", "/api/v1/batches/"+strconvID(again.ID)+"/retry", nil, nil), http.StatusConflict, "batch_running")

	// The runner fails both jobs at the connection (a closed port): the
	// canary's failure skips the other server, and the item tells why.
	e.jobs.OnEnd = e.batches.JobEnded
	e.runJobs()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.batches.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	for i := 0; i < 500; i++ {
		if b, _ := e.db.BatchByID(context.Background(), again.ID); b.State.Terminal() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	rec = owner.do("GET", "/api/v1/batches/"+strconvID(again.ID), nil, nil)
	got = decodeBatch(t, rec.Body.Bytes())
	if got.State != model.BatchFailed || got.Items[0].State != model.ItemFailed || got.Items[0].Job == nil || got.Items[0].Job.State != model.JobFailed ||
		!got.Items[0].Canary || got.Items[1].State != model.ItemSkipped || got.Items[0].Message == "" {
		t.Fatalf("%s", rec.Body)
	}

	audit := owner.do("GET", "/api/v1/audit?action=batch_created,batch_stopped,batch_retried", nil, nil).Body.String()
	for _, a := range []string{"batch_created", "batch_stopped", "batch_retried"} {
		if !strings.Contains(audit, a) {
			t.Fatalf("no %s in %s", a, audit)
		}
	}
}

func strconvID(id int64) string { b, _ := json.Marshal(id); return string(b) }

// A server out of the user's scope cannot be put into a batch: the
// batch is refused as if the server did not exist (not left out
// silently), and batches with such a server are not shown, stopped or
// retried.
func TestBatchScope(t *testing.T) {
	s := newScoped(t)
	for _, id := range []int64{s.a, s.b, s.c} {
		s.ready(id, "v2.6.0")
	}
	missing := s.op.do("GET", "/api/v1/servers/999999", nil, nil).Body.String()
	notFound := func(method, path string, body any) {
		t.Helper()
		rec := s.op.do(method, path, body, nil)
		if rec.Code != http.StatusNotFound || rec.Body.String() != missing {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body)
		}
	}
	notFound("POST", "/api/v1/batches/tuning", map[string]any{"servers": []int64{s.a, s.b}, "keys": json.RawMessage(tuningKeys)})
	notFound("POST", "/api/v1/batches/maintain", map[string]any{"servers": []int64{s.a}, "source": "node", "via": s.b})
	if n, _ := s.db.ListBatches(context.Background(), model.BatchFilter{}); len(n) != 0 {
		t.Fatalf("a batch was made: %+v", n)
	}

	rec := s.owner.do("POST", "/api/v1/batches/tuning", map[string]any{"servers": []int64{s.a, s.b}, "keys": json.RawMessage(tuningKeys)}, nil)
	theirs := decodeBatch(t, rec.Body.Bytes())
	rec = s.op.do("POST", "/api/v1/batches/tuning", map[string]any{"servers": []int64{s.c, s.a}, "keys": json.RawMessage(tuningKeys)}, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	mine := decodeBatch(t, rec.Body.Bytes())

	notFound("GET", "/api/v1/batches/"+strconvID(theirs.ID), nil)
	notFound("POST", "/api/v1/batches/"+strconvID(theirs.ID)+"/stop", nil)
	notFound("POST", "/api/v1/batches/"+strconvID(theirs.ID)+"/retry", nil)
	var list []batchJSON
	json.Unmarshal(s.op.do("GET", "/api/v1/batches", nil, nil).Body.Bytes(), &list)
	if len(list) != 1 || list[0].ID != mine.ID {
		t.Fatalf("%+v", list)
	}
	json.Unmarshal(s.owner.do("GET", "/api/v1/batches", nil, nil).Body.Bytes(), &list)
	if len(list) != 2 {
		t.Fatalf("owner: %+v", list)
	}

	// A role without the action's permission sees the batch but may not
	// stop it.
	if rec := s.owner.do("POST", "/api/v1/users", map[string]any{"username": "viewer", "password": pass, "role": "readonly"}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	viewer := s.login("viewer")
	rec = viewer.do("GET", "/api/v1/batches/"+strconvID(mine.ID), nil, nil)
	if got := decodeBatch(t, rec.Body.Bytes()); rec.Code != 200 || got.MayStop || got.CreatedBy != "de" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, viewer.do("POST", "/api/v1/batches/"+strconvID(mine.ID)+"/stop", nil, nil), http.StatusForbidden, "forbidden")
	if rec := s.op.do("POST", "/api/v1/batches/"+strconvID(mine.ID)+"/stop", nil, nil); rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Updating Hysteria is deploy's: a role with config only cannot.
	if rec := s.owner.do("POST", "/api/v1/users", map[string]any{"username": "cm", "password": pass, "role": "clients"}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	code(t, s.login("cm").do("POST", "/api/v1/batches/maintain", map[string]any{"servers": []int64{s.a}}, nil), http.StatusForbidden, "forbidden")
}

// The release notice: the newest release the watch found, and the
// servers of the caller's scope with an older Hysteria.
func TestReleaseNotice(t *testing.T) {
	s := newScoped(t)
	s.ready(s.a, "v2.6.0")
	s.ready(s.b, "v2.6.0")
	s.ready(s.c, "v9.0.0")
	// Hysteria run through docker: HyRoute does not update it.
	d := s.addServer("d", "de")
	s.ready(d, "v2.6.0")
	s.db.SetInstallation(context.Background(), model.Installation{ServerID: d, Binary: "/usr/bin/docker", Version: "v2.6.0", At: time.Now()})
	get := func(c *client) releaseJSON {
		t.Helper()
		rec := c.do("GET", "/api/v1/hysteria/release", nil, nil)
		var out releaseJSON
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		return out
	}
	r := get(s.op)
	if !r.Check || r.Latest != "" || r.Target != "v2.12.3" || len(r.Outdated) != 1 || r.Outdated[0].ID != s.a || r.Outdated[0].Version != "v2.6.0" {
		t.Fatalf("%+v", r)
	}
	s.releases.Find = func(context.Context) (string, error) { return "v9.1.0", nil }
	s.releases.Check(context.Background())
	r = get(s.op)
	var ids []int64
	for _, o := range r.Outdated {
		ids = append(ids, o.ID)
	}
	if r.Latest != "v9.1.0" || r.Target != "v9.1.0" || r.CheckedAt == nil || !slices.Equal(ids, []int64{s.a, s.c}) {
		t.Fatalf("%+v", r)
	}
	if r := get(s.owner); len(r.Outdated) != 3 {
		t.Fatalf("owner: %+v", r)
	}
}
