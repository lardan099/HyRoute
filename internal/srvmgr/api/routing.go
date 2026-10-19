package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/routing"
)

// routing is the routing editor for the caller of r: a cascade they do
// not see whole is named only as out of their scope.
func (s *server) routing(r *http.Request) *routing.Service {
	rs := &routing.Service{Editor: s.editor(), Applier: s.Apply, Chains: s.Store, Geo: s.Geo.Loader(), Shown: s.shownChains(r)}
	if s.Connect != nil {
		rs.Connect = func(ctx context.Context, id int64) (remote.Executor, error) { return s.Connect.Connect(ctx, id) }
	}
	return rs
}

// routingServer is the server of the path, known to the inventory.
func (s *server) routingServer(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return 0, false
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return 0, false
	}
	return id, true
}

// getRouting is the server's rules, outbounds and resolver, passwords
// hidden, with the checks of the rules.
func (s *server) getRouting(w http.ResponseWriter, r *http.Request) {
	id, ok := s.routingServer(w, r)
	if !ok {
		return
	}
	v, err := s.routing(r).Open(r.Context(), id)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// previewRouting checks the editor's routing: config problems, rule
// problems, diff and the requests it sends elsewhere. Nothing is stored or
// sent to the server.
func (s *server) previewRouting(w http.ResponseWriter, r *http.Request) {
	id, ok := s.routingServer(w, r)
	if !ok {
		return
	}
	var in routing.Input
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	p, err := s.routing(r).Preview(r.Context(), id, in)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// applyRouting queues the apply job with the editor's routing.
func (s *server) applyRouting(w http.ResponseWriter, r *http.Request) {
	id, ok := s.routingServer(w, r)
	if !ok {
		return
	}
	var in routing.Input
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.routing(r).Apply(r.Context(), id, in, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(configError(err)))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}

// routingCheckInput: the editor's rules and outbound names, and a request.
type routingCheckInput struct {
	ACL       acl.Document `json:"acl"`
	Outbounds []string     `json:"outbounds"`
	Request   acl.Request  `json:"request"`
}

// routingCheckJSON is the rule a request matches on the server and, when
// that sends it into the server's deployed cascade, where it goes from
// there (P4-08): the editor's rules on this server, the current ones on
// the next.
type routingCheckJSON struct {
	acl.Verdict
	Chain *routing.Trace `json:"chain,omitempty"`
}

// checkRouting says which rule a request matches, as the server would.
func (s *server) checkRouting(w http.ResponseWriter, r *http.Request) {
	id, ok := s.routingServer(w, r)
	if !ok {
		return
	}
	var in routingCheckInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	g, err := s.routing(r).GeoOf(r.Context(), id)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	v, err := acl.Match(in.ACL, acl.Env{Outbounds: in.Outbounds, Geo: g}, in.Request)
	if err != nil {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: err.Error(), Details: "request"})
		return
	}
	out := routingCheckJSON{Verdict: v}
	if !v.Builtin && strings.EqualFold(v.Outbound, cascade.OutboundName) {
		out.Chain = s.traceFrom(r, id, &routing.Draft{ACL: in.ACL, Outbounds: in.Outbounds}, in.Request)
	}
	writeJSON(w, http.StatusOK, out)
}

// traceFrom follows a request along the deployed cascade server id sends
// through, from that server with the draft rules; nil: it sends through
// none, the cascade is not wholly in the caller's scope (the trace would
// show the names, roles and rules of servers out of it), or the trace
// failed (only logged: the verdict stands alone).
func (s *server) traceFrom(r *http.Request, id int64, draft *routing.Draft, q acl.Request) *routing.Trace {
	cs, err := s.Store.ListChains(r.Context())
	if err != nil {
		s.Log.Warn("routing: chains not read for the trace", "server", id, "err", err)
		return nil
	}
	c, idx, ok := routing.Sender(cs, id)
	if !ok {
		return nil
	}
	if set, err := s.scopeSet(r); err != nil || !set.hasAll(c.Nodes) {
		return nil
	}
	names, err := s.serverNames(r)
	if err != nil {
		return nil
	}
	t, err := s.routing(r).Trace(r.Context(), c, idx, draft, q, names)
	if err != nil {
		s.Log.Warn("routing: trace along the cascade failed", "chain", c.ID, "err", err)
		return nil
	}
	return &t
}

// routingServices is the «По сервисам» tab for the editor's draft ({acl}):
// the catalog's services the controller's geo databases have the
// categories of, and the builder's group of the draft read back.
func (s *server) routingServices(w http.ResponseWriter, r *http.Request) {
	id, ok := s.routingServer(w, r)
	if !ok {
		return
	}
	var in struct {
		ACL acl.Document `json:"acl"`
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	v, err := s.routing(r).Services(r.Context(), id, in.ACL)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// buildRoutingServices puts the group built of a choice per service into
// the editor's draft; nothing is stored. A group changed by hand is
// replaced only with overwrite: 409 services_edited says what changed.
func (s *server) buildRoutingServices(w http.ResponseWriter, r *http.Request) {
	id, ok := s.routingServer(w, r)
	if !ok {
		return
	}
	var in routing.ServicesInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	res, err := s.routing(r).BuildServices(r.Context(), id, in)
	var edited *routing.ServicesEditedError
	if errors.As(err, &edited) {
		writeError(w, &Error{Status: http.StatusConflict, Code: "services_edited", Message: edited.Error()})
		return
	} else if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// exportRouting is the server's routing for download: JSON (format=json,
// the default) or the rules as Hysteria reads them (format=text).
func (s *server) exportRouting(w http.ResponseWriter, r *http.Request) {
	id, ok := s.routingServer(w, r)
	if !ok {
		return
	}
	v, err := s.routing(r).Open(r.Context(), id)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	if v.File != "" {
		// The rules are in acl.file on the server, not in the view.
		release, ok := s.sshSlot(w, r, id, false)
		if !ok {
			return
		}
		defer release()
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		f, err := s.routing(r).File(ctx, id)
		if err != nil {
			s.fail(w, r, configError(err))
			return
		}
		v.ACL = f.ACL
	}
	name := "routing-" + strconv.FormatInt(id, 10)
	switch r.URL.Query().Get("format") {
	case "text":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.acl"`)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(v.ACL.Text()))
	case "", "json":
		b, err := json.MarshalIndent(v.Export(), "", "  ")
		if err != nil {
			s.fail(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
		w.WriteHeader(http.StatusOK)
		w.Write(b)
	default:
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Формат — json или text.", Details: "format"})
	}
}

// importRouting reads an export or a Hysteria ACL (the file's text in
// data) into a draft for the editor; nothing is stored.
func (s *server) importRouting(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Data string `json:"data"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*routing.MaxImport)
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	e, err := routing.Import([]byte(in.Data))
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// routingFile reads the server's acl.file over SSH: its rules, to view or
// move into acl.inline.
func (s *server) routingFile(w http.ResponseWriter, r *http.Request) {
	id, ok := s.routingServer(w, r)
	if !ok {
		return
	}
	release, ok := s.sshSlot(w, r, id, false)
	if !ok {
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	f, err := s.routing(r).File(ctx, id)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// routingTemplates are the built-in rule templates and the presets with
// rules.
func (s *server) routingTemplates(w http.ResponseWriter, r *http.Request) {
	ps, err := s.Store.ListPresets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, routing.Templates(ps))
}

// chainTemplates are the built-in cascade templates.
func (s *server) chainTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, routing.ChainBuiltins())
}

// importChainTemplate reads a cascade template file (data); nothing is
// stored.
func (s *server) importChainTemplate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Data string `json:"data"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4*routing.MaxImport)
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	t, err := routing.ImportChain([]byte(in.Data))
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// chainTemplate is a cascade as a template file: the link's settings and
// the entry's routing, no servers and no secrets.
func (s *server) chainTemplate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	c, err := s.Store.ChainByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	v, err := s.routing(r).Open(r.Context(), c.Entry())
	if errors.Is(err, apply.ErrNoConfig) {
		v = routing.View{Resolver: routing.Resolver{Type: "system"}}
	} else if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	var own []string // the hosts of the cascade's servers
	for _, n := range c.Nodes {
		if srv, err := s.Store.ServerByID(r.Context(), n); err == nil {
			own = append(own, srv.Host)
		}
	}
	t, err := routing.ChainOf(c, v, own)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="chain-`+strconv.FormatInt(id, 10)+`.json"`)
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}
