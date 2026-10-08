package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// clientsServer is a userpass server with a cascade link into it, an
// installation and a trusted host key.
func clientsServer(t *testing.T, e *testEnv, owner *client) (id int64, link string) {
	ctx := context.Background()
	ids := map[string]int64{}
	for _, name := range []string{"entry", "exit"} {
		rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": name, "host": name + ".example.com", "authType": "password", "password": fakeSSHPass}, nil)
		var srv serverJSON
		json.Unmarshal(rec.Body.Bytes(), &srv)
		ids[name] = srv.ID
	}
	ch := model.Chain{Name: "c", Nodes: []int64{ids["entry"], ids["exit"]}, Links: []model.ChainLink{{}}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := e.db.CreateChain(ctx, &ch, nil); err != nil {
		t.Fatal(err)
	}
	link = "link-" + strconv.FormatInt(ch.ID, 10) + "-0"
	id = ids["exit"]
	cfg := []byte("# kept\nlisten: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: userpass\n  userpass:\n    phone: fake-phone-pass\n    " + link + ": fake-link-pass\nobfs:\n  type: salamander\n  salamander:\n    password: fake-obfs-pass\nacl:\n  inline:\n    - reject(geoip:cn)\n")
	c := model.ServerConfig{ServerID: id, SHA256: "x", Source: model.ConfigCascade, Meta: model.ConfigMeta{TLS: "acme", Ports: "443"}, At: time.Now()}
	if err := e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(id, rev)) }); err != nil {
		t.Fatal(err)
	}
	e.db.SetInstallation(ctx, model.Installation{ServerID: id, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: id, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	return id, link
}

// candidateOf is the config a queued apply job installs.
func candidateOf(t *testing.T, e *testEnv, jobID int64) *hyconfig.Server {
	t.Helper()
	sealed, err := e.db.JobSecret(context.Background(), jobID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.keys.Open(sealed, model.JobSecretContext(jobID))
	if err != nil {
		t.Fatal(err)
	}
	var sec map[string]string
	json.Unmarshal(b, &sec)
	c, err := hyconfig.ParseServer([]byte(sec[apply.SecretConfig]))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The client manager adds, removes and re-keys client users of its servers
// and nothing else: each change is an apply job whose candidate is the
// current config with only those users changed.
func TestClientManagerAPI(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	id, link := clientsServer(t, e, owner)
	if rec := owner.do("POST", "/api/v1/users", map[string]any{"username": "helper", "password": pass, "role": "clients"}, nil); rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	cm := e.login("helper")
	ctx := context.Background()
	srv := "/api/v1/servers/" + strconv.FormatInt(id, 10)
	finish := func(jobID int64) {
		t.Helper()
		// As the job would: the candidate becomes the next revision.
		c := candidateOf(t, e, jobID)
		b, _ := c.Marshal()
		rev := model.ServerConfig{ServerID: id, SHA256: "y", Source: model.ConfigEdit, At: time.Now()}
		if err := e.db.AddConfig(ctx, &rev, func(r int) ([]byte, error) { return e.keys.Seal(b, model.ConfigContext(id, r)) }); err != nil {
			t.Fatal(err)
		}
		j, _ := e.db.JobByID(ctx, jobID)
		j.State, j.FinishedAt = model.JobCompleted, time.Now()
		e.db.UpdateJob(ctx, j)
	}

	// The session says what the role may do.
	rec := cm.do("GET", "/api/v1/session", nil, nil)
	var sess sessionJSON
	json.Unmarshal(rec.Body.Bytes(), &sess)
	if strings.Join(permStrings(sess.Permissions), ",") != "view,clients.reveal,clients.manage" || sess.User.Scope == nil || !sess.User.Scope.All {
		t.Fatalf("%s", rec.Body)
	}

	// Add: a generated password, shown once, and nothing but the user in
	// the candidate.
	rec = cm.do("POST", srv+"/clients", map[string]any{"base": 1, "user": " мама "}, nil)
	var res clientsJSON
	res = clientsJSON{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != http.StatusAccepted || res.User != "мама" || len(res.Password) < 20 || !strings.Contains(string(res.Job.Params), `"change":"clients"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	cand := candidateOf(t, e, res.Job.ID)
	if cand.Auth.UserPass["мама"] != res.Password || cand.Auth.UserPass["phone"] != "fake-phone-pass" || cand.Auth.UserPass[link] != "fake-link-pass" ||
		cand.Obfs.Salamander.Password != "fake-obfs-pass" || len(cand.ACL.Inline) != 1 {
		t.Fatalf("candidate %+v", cand)
	}
	audit, _ := e.db.ListAudit(ctx, 5)
	for _, a := range audit {
		if strings.Contains(a.Details, res.Password) {
			t.Fatalf("password in the audit: %+v", a)
		}
	}
	if audit[0].Action != "client.add" || !strings.Contains(audit[0].Details, "user=мама") {
		t.Fatalf("%+v", audit[0])
	}
	// One job at a time, as every apply.
	code(t, cm.do("POST", srv+"/clients", map[string]any{"base": 1, "user": "papa"}, nil), http.StatusConflict, "server_busy")
	finish(res.Job.ID)

	// Nothing else can be asked for: unknown fields, names that are not
	// names, the cascade's user, an old revision.
	code(t, cm.do("POST", srv+"/clients", map[string]any{"base": 2, "user": "x", "yaml": "obfs: {}"}, nil), http.StatusBadRequest, "bad_request")
	for _, name := range []string{"a:b", "a b", "x\nobfs:\n  type: none", "", strings.Repeat("я", 65), "Link-9-0", "МАМА", "phone"} {
		code(t, cm.do("POST", srv+"/clients", map[string]any{"base": 2, "user": name}, nil), http.StatusBadRequest, "invalid")
	}
	for _, p := range []string{"/clients/remove", "/clients/password"} {
		code(t, cm.do("POST", srv+p, map[string]any{"base": 2, "user": link}, nil), http.StatusConflict, "link_user")
		code(t, cm.do("POST", srv+p, map[string]any{"base": 2, "user": "nobody"}, nil), http.StatusBadRequest, "invalid")
	}
	code(t, cm.do("POST", srv+"/clients", map[string]any{"base": 1, "user": "papa"}, nil), http.StatusConflict, "config_changed")

	// A new password for one user: the others keep theirs.
	rec = cm.do("POST", srv+"/clients/password", map[string]any{"base": 2, "user": "PHONE"}, nil)
	res = clientsJSON{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != http.StatusAccepted || res.Password == "" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	cand = candidateOf(t, e, res.Job.ID)
	if cand.Auth.UserPass["phone"] != res.Password || cand.Auth.UserPass[link] != "fake-link-pass" || cand.Auth.UserPass["мама"] == "" {
		t.Fatalf("%+v", cand.Auth.UserPass)
	}
	finish(res.Job.ID)
	// Remove.
	rec = cm.do("POST", srv+"/clients/remove", map[string]any{"base": 3, "user": "мама"}, nil)
	res = clientsJSON{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if rec.Code != http.StatusAccepted || res.Password != "" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if cand = candidateOf(t, e, res.Job.ID); len(cand.Auth.UserPass) != 2 || cand.Auth.UserPass["мама"] != "" {
		t.Fatalf("%+v", cand.Auth.UserPass)
	}
	// The job of the client manager is retried by the client manager; a
	// config change of an operator is not.
	j, _ := e.db.JobByID(ctx, res.Job.ID)
	j.State = model.JobFailed
	e.db.UpdateJob(ctx, j)
	if rec := cm.do("POST", "/api/v1/jobs/"+strconv.FormatInt(j.ID, 10)+"/retry", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
	j.State = model.JobCompleted
	e.db.UpdateJob(ctx, j)
	other := e.failedJob(apply.JobKind, id, apply.Params{Base: 3})
	code(t, cm.do("POST", "/api/v1/jobs/"+strconv.FormatInt(other, 10)+"/retry", nil, nil), http.StatusForbidden, "forbidden")

	// The links are the client manager's to give out; the config is not.
	if rec := cm.do("POST", srv+"/client/reveal", map[string]any{"user": "phone"}, nil); rec.Code != http.StatusOK {
		t.Fatalf("reveal: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"/config/rotate", "/config/apply", "/ports", "/service/restart"} {
		code(t, cm.do("POST", srv+p, map[string]any{}, nil), http.StatusForbidden, "forbidden")
	}
	code(t, cm.do("GET", srv+"/config/edit", nil, nil), http.StatusForbidden, "forbidden")
	// Readonly users manage no clients.
	if rec := owner.do("POST", "/api/v1/users", map[string]any{"username": "viewer", "password": pass, "role": "readonly"}, nil); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	code(t, e.login("viewer").do("POST", srv+"/clients", map[string]any{"base": 3, "user": "x"}, nil), http.StatusForbidden, "forbidden")
}

// A server whose clients share one password has no users to manage.
func TestClientManagerPasswordAuth(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	ctx := context.Background()
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "s", "host": "s.example.com", "authType": "password", "password": fakeSSHPass}, nil)
	var srv serverJSON
	json.Unmarshal(rec.Body.Bytes(), &srv)
	cfg := []byte("listen: :443\nacme:\n  domains: [vpn.example.com]\nauth:\n  type: password\n  password: fake-shared-pass\n")
	c := model.ServerConfig{ServerID: srv.ID, SHA256: "x", Source: model.ConfigImport, At: time.Now()}
	e.db.AddConfig(ctx, &c, func(rev int) ([]byte, error) { return e.keys.Seal(cfg, model.ConfigContext(srv.ID, rev)) })
	e.db.SetInstallation(ctx, model.Installation{ServerID: srv.ID, Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service", At: time.Now()})
	e.db.SetHostKey(ctx, model.HostKey{ServerID: srv.ID, Type: "ssh-ed25519", Key: []byte("fake"), Fingerprint: "SHA256:fake", TrustedAt: time.Now()})
	code(t, owner.do("POST", "/api/v1/servers/"+strconv.FormatInt(srv.ID, 10)+"/clients", map[string]any{"base": 1, "user": "x"}, nil), http.StatusConflict, "not_userpass")
}

func permStrings(ps []model.Permission) []string {
	var out []string
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}
