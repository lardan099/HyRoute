package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/topology"
)

// chainJSON is a cascade: its servers in order (entry first) and the
// links between them with their settings; the links' secrets never
// leave the controller.
type chainJSON struct {
	ID        int64           `json:"id"`
	Name      string          `json:"name"`
	Notes     string          `json:"notes"`
	State     model.LinkState `json:"state"`
	Nodes     []chainNodeJSON `json:"nodes"`
	Links     []chainLinkJSON `json:"links"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

type chainNodeJSON struct {
	ServerID int64            `json:"serverId"`
	Name     string           `json:"name"`
	Role     model.ServerRole `json:"role"`
}

type chainLinkJSON struct {
	Idx       int             `json:"idx"`
	From      int64           `json:"from"`
	To        int64           `json:"to"`
	State     model.LinkState `json:"state"`
	Params    cascade.Params  `json:"params"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

func toChainJSON(i topology.Info, names map[int64]string) chainJSON {
	out := chainJSON{ID: i.ID, Name: i.Name, Notes: i.Notes, State: i.State, Nodes: []chainNodeJSON{}, Links: []chainLinkJSON{}, CreatedAt: i.CreatedAt, UpdatedAt: i.UpdatedAt}
	for idx, id := range i.Nodes {
		out.Nodes = append(out.Nodes, chainNodeJSON{ServerID: id, Name: names[id], Role: model.NodeRole(idx, len(i.Nodes))})
	}
	for _, l := range i.Links {
		p, _ := cascade.ParseParams(l.Params)
		out.Links = append(out.Links, chainLinkJSON{Idx: l.Idx, From: l.From, To: l.To, State: l.State, Params: p, UpdatedAt: l.UpdatedAt})
	}
	return out
}

func chainError(err error) error {
	if errors.Is(err, topology.ErrDeployed) {
		return &Error{Status: http.StatusConflict, Code: "chain_deployed", Message: "Каскад развёрнут на серверах: удалите его кнопкой «Удалить каскад», которая сначала снимает связь с серверов."}
	}
	return mapError(err)
}

func (s *server) chains() *topology.Service { return &topology.Service{Store: s.Store} }

// serverNames are the names of all servers by ID.
func (s *server) serverNames(r *http.Request) (map[int64]string, error) {
	ss, err := s.Store.ListServers(r.Context())
	if err != nil {
		return nil, err
	}
	names := make(map[int64]string, len(ss))
	for _, srv := range ss {
		names[srv.ID] = srv.Name
	}
	return names, nil
}

func (s *server) listChains(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Store.ListChains(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	names, err := s.serverNames(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]chainJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, toChainJSON(topology.Of(c), names))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) getChain(w http.ResponseWriter, r *http.Request) {
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
	s.writeChain(w, r, http.StatusOK, topology.Of(c))
}

func (s *server) writeChain(w http.ResponseWriter, r *http.Request, status int, c topology.Info) {
	names, err := s.serverNames(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, status, toChainJSON(c, names))
}

func (s *server) createChain(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name  string         `json:"name"`
		Notes string         `json:"notes"`
		Nodes []int64        `json:"nodes"`
		Link  cascade.Params `json:"link"`
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	c, err := s.chains().Create(r.Context(), topology.Input{Name: in.Name, Notes: in.Notes, Nodes: in.Nodes, Link: in.Link}, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, chainError(err))
		return
	}
	s.writeChain(w, r, http.StatusCreated, c)
}

func (s *server) updateChain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in struct {
		Name  string `json:"name"`
		Notes string `json:"notes"`
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	c, err := s.chains().Update(r.Context(), id, in.Name, in.Notes, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, chainError(err))
		return
	}
	s.writeChain(w, r, http.StatusOK, c)
}

func (s *server) deleteChain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if err := s.chains().Delete(r.Context(), id, principal(r).User.ID); err != nil {
		s.fail(w, r, chainError(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// linkChain queues the job that deploys the chain's link (again).
func (s *server) linkChain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if s.Cascade == nil {
		writeError(w, errNotFound)
		return
	}
	j, err := s.Cascade.Submit(r.Context(), id, 0, principal(r).User.ID)
	switch {
	case errors.Is(err, cascade.ErrNoConfig):
		s.fail(w, r, &Error{Status: http.StatusConflict, Code: "no_config", Message: "HyRoute не знает конфиг одного из серверов каскада: разверните на нём Hysteria или импортируйте его."})
		return
	case errors.Is(err, cascade.ErrNoInstallation):
		s.fail(w, r, &Error{Status: http.StatusConflict, Code: "no_installation", Message: "HyRoute не знает, где Hysteria на одном из серверов каскада: разверните её или импортируйте сервер."})
		return
	case err != nil:
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
