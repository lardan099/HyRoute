package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/topology"
)

// chainJSON is a cascade: its servers in order (entry first) and the
// links between them with their settings; the links' secrets never
// leave the controller.
type chainJSON struct {
	ID    int64           `json:"id"`
	Name  string          `json:"name"`
	Notes string          `json:"notes"`
	State model.LinkState `json:"state"`
	// Health is the worst latest check of its deployed links ("": none
	// checked yet).
	Health model.ServerState `json:"health"`
	// Egress is the exit's address out, when the exit sends straight out
	// (its first outbound is direct) and the chain is not offline.
	Egress    string          `json:"egress"`
	Nodes     []chainNodeJSON `json:"nodes"`
	Links     []chainLinkJSON `json:"links"`
	CreatedAt time.Time       `json:"createdAt"`
	UpdatedAt time.Time       `json:"updatedAt"`
}

// linkCheckJSON is one check of a link (P3-03).
type linkCheckJSON struct {
	At          time.Time         `json:"at"`
	Status      model.ServerState `json:"status"`
	Reason      string            `json:"reason"`
	Service     string            `json:"service"`
	HandshakeMs int               `json:"handshakeMs"`
	TCPMs       int               `json:"tcpMs"`
}

func toLinkCheckJSON(c model.LinkCheck) *linkCheckJSON {
	return &linkCheckJSON{At: c.At, Status: c.Status, Reason: c.Reason, Service: c.Service, HandshakeMs: c.HandshakeMillis, TCPMs: c.TCPMillis}
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
	// Check is the latest check (null: none yet, or not deployed).
	Check *linkCheckJSON `json:"check"`
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
		c = s.sync(r, c)
		j := toChainJSON(topology.Of(c), names)
		s.linkHealth(r, &j, c)
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

// sync marks links stale whose servers changed since they were deployed
// (and active again when the change does not touch them). A failure only
// leaves the state as stored.
func (s *server) sync(r *http.Request, c model.Chain) model.Chain {
	if s.Cascade == nil {
		return c
	}
	got, err := s.Cascade.Sync(r.Context(), c)
	if err != nil {
		s.Log.Warn("cascade: link state not checked", "chain", c.ID, "err", err)
	}
	return got
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
	s.writeChain(w, r, http.StatusOK, topology.Of(s.sync(r, c)))
}

func (s *server) writeChain(w http.ResponseWriter, r *http.Request, status int, c topology.Info) {
	names, err := s.serverNames(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	j := toChainJSON(c, names)
	s.linkHealth(r, &j, c.Chain)
	writeJSON(w, status, j)
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

// unlinkChain queues the job that takes the chain's link off its servers
// ({"delete": true}: the chain goes too).
func (s *server) unlinkChain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.Cascade == nil {
		writeError(w, errNotFound)
		return
	}
	var in struct {
		Delete bool `json:"delete"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &in); err != nil {
			writeError(w, err)
			return
		}
	}
	j, err := s.Cascade.Unlink(r.Context(), id, 0, in.Delete, principal(r).User.ID)
	switch {
	case errors.Is(err, cascade.ErrNotDeployed):
		s.fail(w, r, &Error{Status: http.StatusConflict, Code: "not_deployed", Message: "Связь каскада не развёрнута на серверах: каскад удаляется без задания."})
		return
	case errors.Is(err, cascade.ErrNoConfig):
		s.fail(w, r, &Error{Status: http.StatusConflict, Code: "no_config", Message: "HyRoute не знает конфиг одного из серверов каскада: импортируйте его."})
		return
	case errors.Is(err, cascade.ErrNoInstallation):
		s.fail(w, r, &Error{Status: http.StatusConflict, Code: "no_installation", Message: "HyRoute не знает, где Hysteria на одном из серверов каскада: импортируйте сервер."})
		return
	case err != nil:
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}

// linkHealth adds the latest check of each deployed link, the chain's health
// (the worst of them) and its egress address.
func (s *server) linkHealth(r *http.Request, out *chainJSON, c model.Chain) {
	ctx := r.Context()
	rank := map[model.ServerState]int{model.StateHealthy: 1, model.StateDegraded: 2, model.StateOffline: 3}
	for i, l := range c.Links {
		if i >= len(out.Links) || (l.State != model.LinkActive && l.State != model.LinkStale) {
			continue
		}
		cs, err := s.Store.LinkChecks(ctx, c.ID, l.Idx, time.Time{}, 1)
		if err != nil || len(cs) == 0 {
			continue
		}
		out.Links[i].Check = toLinkCheckJSON(cs[0])
		if rank[cs[0].Status] > rank[out.Health] {
			out.Health = cs[0].Status
		}
	}
	if out.Health == "" || out.Health == model.StateOffline || !s.directOut(r, c.Exit()) {
		return
	}
	if hs, err := s.Store.HealthHistory(ctx, c.Exit(), time.Time{}, 1); err == nil && len(hs) > 0 {
		out.Egress = hs[0].Egress
	}
}

// directOut: the server's current config sends traffic straight out.
func (s *server) directOut(r *http.Request, id int64) bool {
	cur, err := s.Store.CurrentConfig(r.Context(), id)
	if err != nil || s.Keys == nil {
		return false
	}
	b, err := s.Keys.Open(cur.Sealed, model.ConfigContext(id, cur.Revision))
	if err != nil {
		return false
	}
	c, err := hyconfig.ParseServer(b)
	return err == nil && cascade.DirectOut(c)
}

// chainChecks is the check history of a chain's link (?idx=, ?limit=,
// newest first, 7 days at most).
func (s *server) chainChecks(w http.ResponseWriter, r *http.Request) {
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
	idx := int(queryInt(r, "idx"))
	if idx < 0 || idx >= len(c.Links) {
		writeError(w, errNotFound)
		return
	}
	limit := int(queryInt(r, "limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	cs, err := s.Store.LinkChecks(r.Context(), id, idx, time.Time{}, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]*linkCheckJSON, 0, len(cs))
	for _, c := range cs {
		out = append(out, toLinkCheckJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
}
