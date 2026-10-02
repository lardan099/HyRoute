package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/acl"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/routing"
)

func (s *server) routing() *routing.Service {
	r := &routing.Service{Editor: s.editor(), Applier: s.Apply, Chains: s.Store, Geo: s.Geo.Loader()}
	if s.Connect != nil {
		r.Connect = func(ctx context.Context, id int64) (remote.Executor, error) { return s.Connect.Connect(ctx, id) }
	}
	return r
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
	v, err := s.routing().Open(r.Context(), id)
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
	p, err := s.routing().Preview(r.Context(), id, in)
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
	j, err := s.routing().Apply(r.Context(), id, in, principal(r).User.ID)
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

// checkRouting says which rule a request matches, as the server would.
func (s *server) checkRouting(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.routingServer(w, r); !ok {
		return
	}
	var in routingCheckInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	v, err := acl.Match(in.ACL, acl.Env{Outbounds: in.Outbounds, Geo: s.Geo.Loader()}, in.Request)
	if err != nil {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: err.Error(), Details: "request"})
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// exportRouting is the server's routing for download: JSON (format=json,
// the default) or the rules as Hysteria reads them (format=text).
func (s *server) exportRouting(w http.ResponseWriter, r *http.Request) {
	id, ok := s.routingServer(w, r)
	if !ok {
		return
	}
	v, err := s.routing().Open(r.Context(), id)
	if err != nil {
		s.fail(w, r, configError(err))
		return
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
	r.Body = http.MaxBytesReader(w, r.Body, 2*routing.MaxImport+1024)
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
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	f, err := s.routing().File(ctx, id)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, f)
}
