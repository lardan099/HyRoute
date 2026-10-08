package api

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
)

// Every route declares who may call it, and the declaration fits the
// path; nothing is registered on the mux but through routes.
func TestRoutesDeclared(t *testing.T) {
	seen := map[string]bool{}
	for _, rt := range (&server{}).routes() {
		rl := rt.rule
		method, path, _ := strings.Cut(rt.pattern, " ")
		if seen[rt.pattern] {
			t.Errorf("%s: twice", rt.pattern)
		}
		seen[rt.pattern] = true
		if rt.h == nil {
			t.Errorf("%s: no handler", rt.pattern)
		}
		switch rl.kind {
		case rulePublic, ruleSignedIn:
			continue
		case rulePerm:
		default:
			t.Errorf("%s: no declaration", rt.pattern)
			continue
		}
		if !rl.byJob && !rl.perm.Valid() {
			t.Errorf("%s: unknown permission %q", rt.pattern, rl.perm)
		}
		if len(rl.find) == 0 {
			t.Errorf("%s: say how the servers are found (global if none)", rt.pattern)
		}
		// A write is never for every reader.
		if mutating(method) && !rl.byJob && rl.perm == model.PermView {
			t.Errorf("%s: a write for view", rt.pattern)
		}
		var names []string
		for _, f := range rl.find {
			names = append(names, f.name)
		}
		for prefix, want := range map[string]string{"/api/v1/servers/{id}": "server", "/api/v1/chains/{id}": "chain", "/api/v1/jobs/{id}": "job"} {
			if strings.HasPrefix(path, prefix) && !slices.Contains(names, want) {
				t.Errorf("%s: the {id} of the path is not checked (finders %v)", rt.pattern, names)
			}
		}
		if slices.Contains(names, "global") && len(names) > 1 {
			t.Errorf("%s: global with other finders", rt.pattern)
		}
	}

	// The sources of the package register nothing on a mux but in New:
	// the routes loop, the JSON 404 of /api/ and the UI.
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"rt.pattern": true, `"/api/"`: true, `"/"`: true}
	found := 0
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") || len(call.Args) == 0 {
					return true
				}
				arg := string(src[fset.Position(call.Args[0].Pos()).Offset:fset.Position(call.Args[0].End()).Offset])
				if fn.Name.Name != "New" || !allowed[arg] {
					t.Errorf("%s: %s(%s) in %s: register routes in routes() with a rule", fset.Position(call.Pos()), sel.Sel.Name, arg, fn.Name.Name)
				}
				found++
				return true
			})
		}
	}
	if found != len(allowed) {
		t.Errorf("%d registrations found, want %d", found, len(allowed))
	}
}

// matrixEnv is a controller with one user of every role (all servers) and
// something of each kind a route names.
type matrixEnv struct {
	*testEnv
	clients map[model.Role]*client
	vars    map[string]string
	job     model.Job
}

func newMatrix(t *testing.T) *matrixEnv {
	e := newEnv(t)
	ctx := context.Background()
	m := &matrixEnv{testEnv: e, clients: map[model.Role]*client{}}
	m.clients[model.RoleOwner] = e.setupOwner()
	owner := m.clients[model.RoleOwner]
	for _, r := range model.Roles[1:] {
		rec := owner.do("POST", "/api/v1/users", map[string]any{"username": string(r), "password": pass, "role": r}, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s: %d %s", r, rec.Code, rec.Body)
		}
		m.clients[r] = e.login(string(r))
	}
	// A blocked user the user routes act on: handing it the owner role is
	// refused, so the owner stays the owner.
	rec := owner.do("POST", "/api/v1/users", map[string]any{"username": "victim", "password": pass, "role": "readonly"}, nil)
	var victim userJSON
	json.Unmarshal(rec.Body.Bytes(), &victim)
	if rec := owner.do("PATCH", userPath(victim.ID, ""), map[string]any{"disabled": true}, nil); rec.Code != 200 {
		t.Fatalf("block: %d %s", rec.Code, rec.Body)
	}
	// Servers on a closed loopback port: a request that connects fails at
	// once. They are in a cascade, so they are not deleted.
	var ids []int64
	for _, name := range []string{"a", "b"} {
		pw := fakeSSHPass
		in, err := e.servers.Create(ctx, 1, servers.Input{Name: name, Host: "127.0.0.1", SSHPort: 1, SSHUser: "root", AuthType: model.AuthPassword, Password: &pw})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, in.ID)
	}
	chain := model.Chain{Name: "c", Nodes: ids, Links: []model.ChainLink{{}}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := e.db.CreateChain(ctx, &chain, nil); err != nil {
		t.Fatal(err)
	}
	preset := model.Preset{Name: "p", Config: "{}", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := e.db.CreatePreset(ctx, &preset); err != nil {
		t.Fatal(err)
	}
	// A failed service job: it may be retried by the holders of service.
	j, err := e.jobs.Submit(ctx, service.JobKind, ids[0], service.Params{Action: "restart"}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	j.State, j.FinishedAt = model.JobFailed, time.Now()
	if err := e.db.UpdateJob(ctx, j); err != nil {
		t.Fatal(err)
	}
	m.job = j
	m.vars = map[string]string{
		"{rev}":    "1",
		"{action}": "restart",
		"{name}":   "nope.db",
	}
	m.vars["server"] = strconv.FormatInt(ids[0], 10)
	m.vars["chain"] = strconv.FormatInt(chain.ID, 10)
	m.vars["job"] = strconv.FormatInt(j.ID, 10)
	m.vars["preset"] = strconv.FormatInt(preset.ID, 10)
	m.vars["user"] = strconv.FormatInt(victim.ID, 10)
	return m
}

// path is the pattern's path with its variables filled in.
func (m *matrixEnv) path(pattern string) (method, path string) {
	method, path, _ = strings.Cut(pattern, " ")
	id := "999999" // sessions: a missing one (revoking one's own would log out)
	for prefix, v := range map[string]string{"/api/v1/servers/": "server", "/api/v1/chains/": "chain", "/api/v1/jobs/": "job", "/api/v1/presets/": "preset", "/api/v1/users/": "user"} {
		if strings.HasPrefix(path, prefix) {
			id = m.vars[v]
		}
	}
	path = strings.ReplaceAll(path, "{id}", id)
	for k, v := range m.vars {
		if strings.HasPrefix(k, "{") {
			path = strings.ReplaceAll(path, k, v)
		}
	}
	return method, path
}

// call sends one request as c with an empty JSON object for a write; a
// stream ends with its context.
func (m *matrixEnv) call(c *client, role model.Role, method, path string) *httptest.ResponseRecorder {
	if c.cookie == nil {
		// A logout or a password change ended the session.
		*c = *m.login(string(role))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var body *bytes.Reader
	if mutating(method) {
		body = bytes.NewReader([]byte("{}"))
	} else {
		body = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, body).WithContext(ctx)
	r.RemoteAddr = c.ip + ":50000"
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(c.cookie)
	r.Header.Set("X-CSRF-Token", c.csrf)
	rec := httptest.NewRecorder()
	m.h.ServeHTTP(rec, r)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == cookieName {
			if ck.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = ck
			}
		}
	}
	return rec
}

// expect is what the declaration of a route says about role.
func expect(rl rule, role model.Role, job model.Job) bool {
	switch rl.kind {
	case rulePublic, ruleSignedIn:
		return true
	}
	if rl.owner && role != model.RoleOwner {
		return false
	}
	if rl.byJob {
		p, ok := jobPerm(job)
		return ok && role.Can(p)
	}
	return role.Can(rl.perm)
}

// Every route for every role: refused with 403 exactly when the role lacks
// what the route declares. The narrow roles are pinned by name too: a
// declaration that changes for them fails here.
func TestRoleRouteMatrix(t *testing.T) {
	m := newMatrix(t)
	writes := map[model.Role][]string{}
	for _, rt := range (&server{}).routes() {
		method, path := m.path(rt.pattern)
		for _, role := range model.Roles {
			rec := m.call(m.clients[role], role, method, path)
			allowed := expect(rt.rule, role, m.job)
			if allowed && rec.Code == http.StatusForbidden || !allowed && rec.Code != http.StatusForbidden {
				t.Errorf("%s as %s: %d %s (allowed: %v)", rt.pattern, role, rec.Code, strings.TrimSpace(rec.Body.String()), allowed)
			}
			if !allowed && rec.Code == http.StatusForbidden && decodeError(t, rec).Code != "forbidden" {
				t.Errorf("%s as %s: %s", rt.pattern, role, rec.Body)
			}
			if allowed && mutating(method) && rt.rule.kind == rulePerm {
				writes[role] = append(writes[role], rt.pattern)
			}
		}
	}
	if len(writes[model.RoleReadOnly]) != 0 {
		t.Errorf("readonly writes: %v", writes[model.RoleReadOnly])
	}
	want := []string{"POST /api/v1/servers/{id}/client/reveal"}
	if !slices.Equal(writes[model.RoleClients], want) {
		t.Errorf("clients writes:\n%s", strings.Join(writes[model.RoleClients], "\n"))
	}
	for _, p := range writes[model.RoleOperator] {
		if strings.Contains(p, "/users") || strings.Contains(p, "/backups") || strings.Contains(p, "master-key") {
			t.Errorf("operator: %s", p)
		}
	}
}

// scoped is a controller with servers tagged de and us and an operator
// whose scope is de.
type scoped struct {
	*testEnv
	owner, op *client
	a, b, c   int64 // a and c: de; b: us
	ab, ac    int64 // cascades
}

func newScoped(t *testing.T) *scoped {
	e := newEnv(t)
	ctx := context.Background()
	s := &scoped{testEnv: e, owner: e.setupOwner()}
	rec := s.owner.do("POST", "/api/v1/users", map[string]any{"username": "de", "password": pass, "role": "operator", "scope": map[string]any{"tags": []string{"de"}}}, nil)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"scope":{"tags":["de"]}`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	s.op = e.login("de")
	for _, x := range []struct {
		id   *int64
		name string
		tag  string
	}{{&s.a, "a", "de"}, {&s.b, "b", "us"}, {&s.c, "c", "DE"}} {
		pw := fakeSSHPass
		in, err := e.servers.Create(ctx, 1, servers.Input{Name: x.name, Tags: []string{x.tag}, Host: "127.0.0.1", SSHPort: 1, SSHUser: "root", AuthType: model.AuthPassword, Password: &pw})
		if err != nil {
			t.Fatal(err)
		}
		*x.id = in.ID
	}
	for _, x := range []struct {
		id    *int64
		name  string
		nodes []int64
	}{{&s.ab, "ab", []int64{s.a, s.b}}, {&s.ac, "ca", []int64{s.c, s.a}}} {
		ch := model.Chain{Name: x.name, Nodes: x.nodes, Links: []model.ChainLink{{}}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
		if err := e.db.CreateChain(ctx, &ch, nil); err != nil {
			t.Fatal(err)
		}
		*x.id = ch.ID
	}
	return s
}

// failedJob is a failed job of kind on server with params.
func (e *testEnv) failedJob(kind string, server int64, params any) int64 {
	e.t.Helper()
	j, err := e.jobs.Submit(context.Background(), kind, server, params, nil, 1)
	if err != nil {
		e.t.Fatal(err)
	}
	j.State, j.FinishedAt = model.JobFailed, time.Now()
	if err := e.db.UpdateJob(context.Background(), j); err != nil {
		e.t.Fatal(err)
	}
	return j.ID
}

func id(n int64) string { return strconv.FormatInt(n, 10) }

// A user scoped by a tag does not reach other servers through any path:
// the server, its cascades, its jobs, or a server named in a body. Those
// answer as if they did not exist.
func TestScopeEnforced(t *testing.T) {
	s := newScoped(t)
	op := s.op
	missing := op.do("GET", "/api/v1/servers/999999", nil, nil)
	code(t, missing, http.StatusNotFound, "not_found")
	notFound := func(method, path string, body any) {
		t.Helper()
		rec := op.do(method, path, body, nil)
		if rec.Code != http.StatusNotFound || rec.Body.String() != missing.Body.String() {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body)
		}
	}
	reached := func(method, path string, body any) {
		t.Helper()
		if rec := op.do(method, path, body, nil); rec.Code == http.StatusNotFound && decodeError(t, rec).Code == "not_found" || rec.Code == http.StatusForbidden {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body)
		}
	}
	srv := "/api/v1/servers/"
	for _, p := range []string{"", "/config", "/client", "/metrics", "/health", "/traffic", "/config/revisions", "/status", "/journal", "/tuning", "/geo", "/config/edit", "/routing"} {
		notFound("GET", srv+id(s.b)+p, nil)
		reached("GET", srv+id(s.a)+p, nil)
	}
	for _, p := range []string{"/service/restart", "/preflight", "/import", "/check", "/config/rollback", "/tuning"} {
		notFound("POST", srv+id(s.b)+p, map[string]any{})
	}
	notFound("DELETE", srv+id(s.b), nil)
	reached("POST", srv+id(s.a)+"/service/restart", nil)

	// Cascades: on every server of theirs.
	notFound("GET", "/api/v1/chains/"+id(s.ab), nil)
	notFound("POST", "/api/v1/chains/"+id(s.ab)+"/unlink", map[string]any{})
	notFound("GET", "/api/v1/chains/"+id(s.ab)+"/checks?idx=0", nil)
	reached("GET", "/api/v1/chains/"+id(s.ac), nil)

	// Jobs: of any server out of scope, the node they download through
	// included.
	onB := s.failedJob(service.JobKind, s.b, service.Params{Action: "restart"})
	viaB := s.failedJob(service.JobKind, s.a, map[string]any{"action": "restart", "via": s.b})
	for _, j := range []int64{onB, viaB} {
		for _, p := range []string{"", "/logs", "/events"} {
			notFound("GET", "/api/v1/jobs/"+id(j)+p, nil)
		}
		notFound("POST", "/api/v1/jobs/"+id(j)+"/retry", nil)
	}
	reached("GET", "/api/v1/jobs/"+id(s.failedJob(service.JobKind, s.c, service.Params{Action: "restart"})), nil)

	// Servers named in a body.
	notFound("POST", "/api/v1/chains", map[string]any{"name": "x", "nodes": []int64{s.a, s.b}})
	notFound("POST", "/api/v1/presets", map[string]any{"name": "x", "serverId": s.b})
	notFound("POST", srv+id(s.a)+"/deploy", map[string]any{"source": "node", "via": s.b})
	notFound("POST", srv+id(s.a)+"/maintain", map[string]any{"op": "upgrade", "source": "node", "via": s.b})
	notFound("POST", srv+id(s.a)+"/geo", map[string]any{"source": "node", "via": s.b})
	// A body that does not decode is refused before the scope is checked.
	code(t, op.do("POST", "/api/v1/chains", map[string]any{"nodes": "x"}, nil), http.StatusBadRequest, "bad_request")

	// A server the user adds or saves keeps one of their tags.
	newSrv := map[string]any{"name": "n", "host": "192.0.2.7", "authType": "password", "password": fakeSSHPass, "tags": []string{"us"}}
	code(t, op.do("POST", "/api/v1/servers", newSrv, nil), http.StatusForbidden, "out_of_scope")
	newSrv["tags"] = []string{"x", " De "}
	if rec := op.do("POST", "/api/v1/servers", newSrv, nil); rec.Code != http.StatusCreated {
		t.Fatalf("add in scope: %d %s", rec.Code, rec.Body)
	}
	edit := map[string]any{"name": "a", "host": "127.0.0.1", "sshPort": 1, "authType": "password", "tags": []string{"us"}}
	code(t, op.do("PATCH", srv+id(s.a), edit, nil), http.StatusForbidden, "out_of_scope")
	delete(edit, "tags")
	code(t, op.do("PATCH", srv+id(s.a), edit, nil), http.StatusForbidden, "out_of_scope")
	edit["tags"] = []string{"de", "us"}
	if rec := op.do("PATCH", srv+id(s.a), edit, nil); rec.Code != http.StatusOK {
		t.Fatalf("save in scope: %d %s", rec.Code, rec.Body)
	}

	// A global route with a server-bound permission is not limited.
	reached("POST", "/api/v1/routing/import", map[string]any{"data": "[]"})
	// The owner reaches everything.
	if rec := s.owner.do("GET", srv+id(s.b), nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("owner: %d", rec.Code)
	}
}

// A retry checks the rights of the job's kind and its servers at the time
// of the retry, as they are then.
func TestRetryRechecksRights(t *testing.T) {
	s := newScoped(t)
	j := s.failedJob(apply.JobKind, s.a, apply.Params{})
	svc := s.failedJob(service.JobKind, s.c, service.Params{Action: "restart"})
	retry := func(c *client, job int64) *httptest.ResponseRecorder {
		return c.do("POST", "/api/v1/jobs/"+id(job)+"/retry", nil, nil)
	}
	for _, u := range []struct{ name, role string }{{"helper", "clients"}, {"viewer", "readonly"}} {
		rec := s.owner.do("POST", "/api/v1/users", map[string]any{"username": u.name, "password": pass, "role": u.role}, nil)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		c := s.login(u.name)
		code(t, retry(c, j), http.StatusForbidden, "forbidden")
		code(t, retry(c, svc), http.StatusForbidden, "forbidden")
	}
	var us []userJSON
	json.Unmarshal(s.owner.do("GET", "/api/v1/users", nil, nil).Body.Bytes(), &us)
	var opID int64
	for _, u := range us {
		if u.Username == "de" {
			opID = u.ID
		}
	}
	patch := func(body map[string]any) {
		t.Helper()
		if rec := s.owner.do("PATCH", userPath(opID, ""), body, nil); rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
	}
	// The scope narrowed after the job: the job is out of reach now.
	patch(map[string]any{"scope": map[string]any{"tags": []string{"us"}}})
	code(t, retry(s.op, j), http.StatusNotFound, "not_found")
	// The role lost config: refused, in the session as it was.
	patch(map[string]any{"role": "readonly", "scope": map[string]any{"all": true}})
	code(t, retry(s.op, j), http.StatusForbidden, "forbidden")
	patch(map[string]any{"role": "clients"})
	code(t, retry(s.op, j), http.StatusForbidden, "forbidden")
	code(t, retry(s.op, svc), http.StatusForbidden, "forbidden")
	patch(map[string]any{"role": "operator"})
	if rec := retry(s.op, j); rec.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
	if rec := retry(s.op, svc); rec.Code != http.StatusOK {
		t.Fatalf("retry: %d %s", rec.Code, rec.Body)
	}
	// Every kind a job of this controller can have needs a permission.
	for _, k := range []string{"deploy", "maintain", "import", "preflight", "apply", "service", "tuning", "geo", "link", "unlink"} {
		if p, ok := jobPerm(model.Job{Kind: k}); !ok || !p.Valid() {
			t.Errorf("kind %s: %q", k, p)
		}
	}
}

// Lists show a user with a narrower scope only their servers, the
// cascades all of whose servers are theirs, and the jobs, job logs and
// metrics of those.
func TestScopeFiltersLists(t *testing.T) {
	s := newScoped(t)
	ctx := context.Background()
	onA := s.failedJob(service.JobKind, s.a, service.Params{Action: "restart"})
	onB := s.failedJob(service.JobKind, s.b, service.Params{Action: "restart"})
	link, err := s.jobs.SubmitOn(ctx, service.JobKind, []int64{s.a, s.b}, service.Params{Action: "restart"}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	link.State = model.JobFailed
	s.db.UpdateJob(ctx, link)
	viaB := s.failedJob(service.JobKind, s.c, map[string]any{"action": "restart", "via": s.b})
	onC := s.failedJob(service.JobKind, s.c, service.Params{Action: "restart"})
	for _, j := range []int64{onA, onB, link.ID, viaB, onC} {
		l := model.JobLog{JobID: j, Time: time.Now(), Level: "info", Message: "line of " + id(j)}
		s.db.AppendJobLog(ctx, &l)
	}
	for _, srv := range []int64{s.a, s.b} {
		s.db.AddMetric(ctx, model.Metric{ServerID: srv, At: time.Now(), MemTotalMiB: 1024})
	}
	get := func(c *client, path string, v any) {
		t.Helper()
		rec := c.do("GET", path, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
		json.Unmarshal(rec.Body.Bytes(), v)
	}

	var ss []serverJSON
	get(s.op, "/api/v1/servers", &ss)
	var names []string
	for _, x := range ss {
		names = append(names, x.Name)
		if !slices.Contains(x.Perms, model.PermConfig) || slices.Contains(x.Perms, model.PermUsers) {
			t.Fatalf("%s: perms %v", x.Name, x.Perms)
		}
		for _, ch := range x.Chains {
			if ch.ID == s.ab {
				t.Fatalf("%s: the cascade with b listed", x.Name)
			}
		}
	}
	if strings.Join(names, ",") != "a,c" {
		t.Fatalf("servers: %v", names)
	}
	var one serverJSON
	get(s.op, "/api/v1/servers/"+id(s.a), &one)
	if len(one.Chains) != 1 || one.Chains[0].ID != s.ac {
		t.Fatalf("chains of a: %+v", one.Chains)
	}

	var cs []chainJSON
	get(s.op, "/api/v1/chains", &cs)
	if len(cs) != 1 || cs[0].ID != s.ac {
		t.Fatalf("chains: %+v", cs)
	}

	var js []jobJSON
	get(s.op, "/api/v1/jobs", &js)
	var got []int64
	for _, j := range js {
		got = append(got, j.ID)
	}
	if !slices.Equal(got, []int64{onC, onA}) {
		t.Fatalf("jobs %v, want %v", got, []int64{onC, onA})
	}
	get(s.op, "/api/v1/jobs?server="+id(s.b), &js)
	if len(js) != 0 {
		t.Fatalf("jobs of b: %+v", js)
	}

	var ls []logEntryJSON
	get(s.op, "/api/v1/logs?source=jobs", &ls)
	got = nil
	for _, l := range ls {
		got = append(got, l.JobID)
	}
	slices.Sort(got)
	if !slices.Equal(got, []int64{onA, onC}) {
		t.Fatalf("job logs of %v", got)
	}
	code(t, s.op.do("GET", "/api/v1/logs", nil, nil), http.StatusForbidden, "forbidden")

	var ms []latestJSON
	get(s.op, "/api/v1/metrics/latest", &ms)
	if len(ms) != 1 || ms[0].ServerID != s.a {
		t.Fatalf("metrics: %+v", ms)
	}

	// Users without the users permission see no scopes.
	rec := s.op.do("GET", "/api/v1/users", nil, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `"scope"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := s.owner.do("GET", "/api/v1/users", nil, nil); !strings.Contains(rec.Body.String(), `"scope":{"tags":["de"]}`) {
		t.Fatalf("owner: %s", rec.Body)
	}

	// The owner sees everything.
	get(s.owner, "/api/v1/servers", &ss)
	get(s.owner, "/api/v1/jobs", &js)
	get(s.owner, "/api/v1/chains", &cs)
	if len(ss) != 3 || len(js) != 5 || len(cs) != 2 {
		t.Fatalf("owner: %d servers, %d jobs, %d chains", len(ss), len(js), len(cs))
	}
}

// A live stream ends once its user may no longer see what it streams: the
// scope narrowed past the job's server.
func TestScopeEndsStreams(t *testing.T) {
	s := newScoped(t)
	release := make(chan struct{})
	defer close(release)
	var broken atomic.Bool
	s.jobs.Register(demoKind(release, &broken))
	s.runJobs()
	j, err := s.jobs.Submit(context.Background(), "demo", s.a, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.waitJob(j.ID, model.JobInstalling)
	ts := httptest.NewServer(s.h)
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/jobs/"+id(j.ID)+"/events", nil)
	req.AddCookie(s.op.cookie)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("%d", res.StatusCode)
	}
	closed := make(chan struct{})
	go func() { io.Copy(io.Discard, res.Body); close(closed) }()
	select {
	case <-closed:
		t.Fatal("the stream ended early")
	case <-time.After(200 * time.Millisecond):
	}
	var us []userJSON
	json.Unmarshal(s.owner.do("GET", "/api/v1/users", nil, nil).Body.Bytes(), &us)
	for _, u := range us {
		if u.Username == "de" {
			if rec := s.owner.do("PATCH", userPath(u.ID, ""), map[string]any{"scope": map[string]any{"tags": []string{"us"}}}, nil); rec.Code != 200 {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
		}
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream outlived the scope")
	}
	// Reconnecting gets what a server out of scope gets.
	code(t, s.op.do("GET", "/api/v1/jobs/"+id(j.ID)+"/events", nil, nil), http.StatusNotFound, "not_found")
}
