package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/importer"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/preflight"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
	"github.com/lardan099/hyroute/internal/srvmgr/tuning"
)

// Access control (P4-04) is checked in one place: every route of the API
// is declared in routes (api.go) with a rule, and guard enforces it before
// the handler runs:
//   - public: no session (health, first run, login); writes still refuse
//     other sites;
//   - signedIn: any logged-in user, writes included (logout, one's own
//     sessions and password, the list of users);
//   - need(permission, finders...): the role holds the permission, then
//     every server the finders name is in the user's scope.
//
// The order is fixed: a session (401), the CSRF check of a write (403), the
// permission of the role (403, whatever the body says), then the servers
// (a server out of scope answers 404, as one that does not exist: its
// existence does not leak). A route that names no server (global) is not
// limited by the scope; lists filter by it in their handlers.

// ruleKind is what a route needs from the caller.
type ruleKind int

const (
	_ ruleKind = iota // the zero rule: an undeclared route, refused
	rulePublic
	ruleSignedIn
	rulePerm
)

// rule is what a route needs from the caller.
type rule struct {
	kind ruleKind
	perm model.Permission
	// find name the servers of the request (none: global).
	find []finder
	// byJob: the permission is the one of the job of the path (jobPerm),
	// for retries; perm is unused.
	byJob bool
	// owner: the owner only (backups, handing the owner role over).
	owner bool
}

var (
	public   = rule{kind: rulePublic}
	signedIn = rule{kind: ruleSignedIn}
)

// need is a route for the holders of p on the servers find name.
func need(p model.Permission, find ...finder) rule {
	return rule{kind: rulePerm, perm: p, find: find}
}

// ownerOnly is r for the owner only.
func ownerOnly(r rule) rule {
	r.owner = true
	return r
}

// retryRule is the retry of the job of the path: the permission of its
// kind on all of its servers, checked at the time of the retry.
var retryRule = rule{kind: rulePerm, byJob: true, find: []finder{onJob}}

// targets are what the finders of a request found.
type targets struct {
	// servers are existing servers the request acts on.
	servers []int64
	// tags are those of a server the request creates or edits: it must
	// stay in the user's scope.
	tags [][]string
	// job is the job of the path (onJob).
	job *model.Job
}

// finder names what a request acts on. Body finders decode the fields
// they need as the handler's input type does (encoding/json, the same
// keys): both see the same values.
type finder struct {
	name string
	find func(s *server, r *http.Request, t *targets) error
}

var (
	// global: the request names no server.
	global = finder{name: "global"}
	// onServer: the server of the path ({id}).
	onServer = finder{name: "server", find: func(s *server, r *http.Request, t *targets) error {
		id, ok := pathID(r)
		if !ok {
			return errNotFound
		}
		t.servers = append(t.servers, id)
		return nil
	}}
	// onChain: every server of the cascade of the path.
	onChain = finder{name: "chain", find: func(s *server, r *http.Request, t *targets) error {
		id, ok := pathID(r)
		if !ok {
			return errNotFound
		}
		c, err := s.Store.ChainByID(r.Context(), id)
		if err != nil {
			return mapError(err)
		}
		t.servers = append(t.servers, c.Nodes...)
		return nil
	}}
	// onJob: every server of the job of the path, its source node too.
	onJob = finder{name: "job", find: func(s *server, r *http.Request, t *targets) error {
		id, ok := pathID(r)
		if !ok {
			return errNotFound
		}
		j, err := s.Store.JobByID(r.Context(), id)
		if err != nil {
			return mapError(err)
		}
		t.job = &j
		t.servers = append(t.servers, jobServers(j)...)
		return nil
	}}
	// bodyVia: the server a binary or the geo databases come through
	// ({"via": id}: deploy, maintain, geo).
	bodyVia = bodyFinder("via", func(b []byte, t *targets) error {
		var in struct {
			Via int64 `json:"via"`
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return err
		}
		if in.Via != 0 {
			t.servers = append(t.servers, in.Via)
		}
		return nil
	})
	// bodyNodes: the servers of a new cascade ({"nodes": [...]}).
	bodyNodes = bodyFinder("nodes", func(b []byte, t *targets) error {
		var in struct {
			Nodes []int64 `json:"nodes"`
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return err
		}
		t.servers = append(t.servers, in.Nodes...)
		return nil
	})
	// bodyServerID: the server a preset is made of ({"serverId": id}).
	bodyServerID = bodyFinder("serverId", func(b []byte, t *targets) error {
		var in struct {
			ServerID int64 `json:"serverId"`
		}
		if err := json.Unmarshal(b, &in); err != nil {
			return err
		}
		if in.ServerID != 0 {
			t.servers = append(t.servers, in.ServerID)
		}
		return nil
	})
	// bodyTags: the tags a server is created or saved with ({"tags": [...]}):
	// a user with a narrower scope keeps it on one of their tags.
	bodyTags = bodyFinder("tags", func(b []byte, t *targets) error {
		var in serverInput
		if err := json.Unmarshal(b, &in); err != nil {
			return err
		}
		t.tags = append(t.tags, in.Tags)
		return nil
	})
)

// bodyFinder finds servers in the JSON body; a body that does not decode
// is refused here (the handler would refuse it too).
func bodyFinder(name string, find func(b []byte, t *targets) error) finder {
	return finder{name: "body:" + name, find: func(s *server, r *http.Request, t *targets) error {
		b, err := body(r)
		if err != nil {
			return err
		}
		if err := find(b, t); err != nil {
			e := *errBadJSON
			e.Details = err.Error()
			return &e
		}
		return nil
	}}
}

type bodyKey struct{}

// body reads the request body once for the finders and leaves it for the
// handler. The bytes stay in the context: a stream's recheck finds them.
func body(r *http.Request) ([]byte, error) {
	if b, ok := r.Context().Value(bodyKey{}).(*[]byte); ok && *b != nil {
		return *b, nil
	}
	if r.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var big *http.MaxBytesError
		if errors.As(err, &big) {
			return nil, &Error{Status: http.StatusRequestEntityTooLarge, Code: "too_large", Message: "Запрос слишком большой: больше " + sizeText(big.Limit) + "."}
		}
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	if p, ok := r.Context().Value(bodyKey{}).(*[]byte); ok {
		*p = b
	}
	return b, nil
}

// jobServers are the servers a job reaches: those it changes and the
// node it downloads through (params "via").
func jobServers(j model.Job) []int64 {
	out := j.AllServers()
	var p struct {
		Via int64 `json:"via"`
	}
	if json.Unmarshal(j.Params, &p) == nil && p.Via != 0 {
		out = append(out, p.Via)
	}
	return out
}

// jobPerms is the permission that retrying a job of each kind needs (the
// one that starts it). A kind not listed is retried by owners and admins
// only.
var jobPerms = map[string]model.Permission{
	deploy.JobKind:      model.PermDeploy,
	deploy.MaintainKind: model.PermDeploy,
	importer.JobKind:    model.PermDeploy,
	preflight.JobKind:   model.PermDeploy,
	apply.JobKind:       model.PermConfig,
	service.JobKind:     model.PermService,
	tuning.JobKind:      model.PermConfig,
	geo.JobKind:         model.PermConfig,
	cascade.JobLink:     model.PermChains,
	cascade.JobUnlink:   model.PermChains,
}

// jobPerm is the permission retrying j needs; false: a kind not in
// jobPerms. An apply job of the client manager needs what made it.
func jobPerm(j model.Job) (model.Permission, bool) {
	if j.Kind == apply.JobKind {
		var p apply.Params
		if json.Unmarshal(j.Params, &p) == nil && p.Change == apply.ChangeClients {
			return model.PermClientsManage, true
		}
	}
	p, ok := jobPerms[j.Kind]
	return p, ok
}

// mayRetrySome: the role holds a permission some kind of job needs.
func mayRetrySome(r model.Role) bool {
	if r.Can(model.PermClientsManage) {
		return true
	}
	for _, p := range jobPerms {
		if r.Can(p) {
			return true
		}
	}
	return false
}

var errOutOfScope = &Error{Status: http.StatusForbidden, Code: "out_of_scope", Message: "Сервер должен остаться в вашей области: оставьте ему хотя бы одну из ваших меток."}

// allowed checks the rule of a route for p: the role first, then the
// servers the finders name. nil: the handler may run.
func (s *server) allowed(r *http.Request, rl rule, p auth.Principal) error {
	u := p.User
	if rl.kind == rulePublic || rl.kind == ruleSignedIn {
		return nil
	}
	if rl.kind != rulePerm {
		return errForbidden
	}
	if rl.owner && u.Role != model.RoleOwner {
		return errForbidden
	}
	if rl.byJob && !mayRetrySome(u.Role) || !rl.byJob && !u.Role.Can(rl.perm) {
		return errForbidden
	}
	var t targets
	for _, f := range rl.find {
		if f.find == nil {
			continue
		}
		if err := f.find(s, r, &t); err != nil {
			return err
		}
	}
	if err := s.inScope(r.Context(), u.Reach(), t); err != nil {
		return err
	}
	if rl.byJob && t.job != nil {
		perm, ok := jobPerm(*t.job)
		if ok && !u.Role.Can(perm) || !ok && !u.Role.Unscoped() {
			return errForbidden
		}
	}
	return nil
}

// inScope: every server of t is in sc (as if it did not exist
// otherwise), and the tags of a server being saved keep it there. A job
// of no server is for users of every server.
func (s *server) inScope(ctx context.Context, sc model.Scope, t targets) error {
	if sc.All {
		return nil
	}
	if t.job != nil && len(t.servers) == 0 {
		return errNotFound
	}
	for _, id := range t.servers {
		srv, err := s.Store.ServerByID(ctx, id)
		if errors.Is(err, store.ErrNotFound) || err == nil && !sc.Covers(srv.Tags) {
			return errNotFound
		} else if err != nil {
			return err
		}
	}
	for _, tags := range t.tags {
		if !sc.Covers(tags) {
			return errOutOfScope
		}
	}
	return nil
}

type ruleCtxKey struct{}

// guard wraps the handler of a route with its rule: public routes refuse
// cross-site writes; the others need a session (401), the CSRF token on
// writes, and what the rule asks (403 or 404).
func (s *server) guard(rl rule, h http.HandlerFunc) http.HandlerFunc {
	if rl.kind == rulePublic {
		return func(w http.ResponseWriter, r *http.Request) {
			if mutating(r.Method) && s.crossSite(r) {
				writeError(w, errCSRF)
				return
			}
			h(w, r)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeError(w, errUnauthorized)
			return
		}
		p, err := s.Auth.Authenticate(r.Context(), c.Value)
		if err != nil {
			if errors.Is(err, auth.ErrUnauthenticated) {
				s.clearSessionCookie(w, r)
			}
			s.fail(w, r, mapError(err))
			return
		}
		if mutating(r.Method) && (s.crossSite(r) || !auth.CheckCSRF(p.Token, r.Header.Get("X-CSRF-Token"))) {
			writeError(w, errCSRF)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, p)
		ctx = context.WithValue(ctx, ruleCtxKey{}, rl)
		ctx = context.WithValue(ctx, bodyKey{}, new([]byte))
		r = r.WithContext(ctx)
		if err := s.allowed(r, rl, p); err != nil {
			s.fail(w, r, err)
			return
		}
		h(w, r)
	}
}

// sessionHolds re-checks a running event stream, which guard checked only
// when it opened: its session still holds, and its user still may see
// what it streams (a role or a scope changed, a server's tags changed).
// The stream ends otherwise (the browser reconnects and gets the answer).
func (s *server) sessionHolds(r *http.Request) bool {
	p, err := s.Auth.Recheck(r.Context(), principal(r).Token)
	if err != nil {
		return false
	}
	rl, ok := r.Context().Value(ruleCtxKey{}).(rule)
	return ok && s.allowed(r, rl, p) == nil
}

// reach is the scope of the caller: what lists show.
func reach(r *http.Request) model.Scope { return principal(r).User.Reach() }

// scopeSet is the servers in the caller's scope, for filtering lists: a
// server out of it is not shown, as if it did not exist.
type scopeSet struct {
	all bool
	ids map[int64]bool
}

// scopeSet reads the servers the caller reaches.
func (s *server) scopeSet(r *http.Request) (scopeSet, error) {
	sc := reach(r)
	if sc.All {
		return scopeSet{all: true}, nil
	}
	ss, err := s.Store.ListServers(r.Context())
	if err != nil {
		return scopeSet{}, err
	}
	set := scopeSet{ids: map[int64]bool{}}
	for _, srv := range ss {
		if sc.Covers(srv.Tags) {
			set.ids[srv.ID] = true
		}
	}
	return set, nil
}

// has: the server is in scope.
func (set scopeSet) has(id int64) bool { return set.all || set.ids[id] }

// hasAll: every one of ids is in scope, and there is one (a cascade, a
// job).
func (set scopeSet) hasAll(ids []int64) bool {
	if set.all {
		return true
	}
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if !set.ids[id] {
			return false
		}
	}
	return true
}

// within is the set for model.JobFilter.Within: nil for all servers.
func (set scopeSet) within() *[]int64 {
	if set.all {
		return nil
	}
	ids := make([]int64, 0, len(set.ids))
	for id := range set.ids {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return &ids
}

// serverPerms are the caller's permissions on a server in their scope:
// those of the role that are held on servers. The UI shows what they
// allow and hides the rest.
func serverPerms(r *http.Request) []model.Permission {
	out := []model.Permission{}
	for _, p := range principal(r).User.Role.Permissions() {
		if p.ServerBound() {
			out = append(out, p)
		}
	}
	return out
}
