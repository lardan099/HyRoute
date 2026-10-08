package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/acl"
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
	// Health is the worst latest check of its deployed links, hop by hop
	// ("": none checked yet).
	Health model.ServerState `json:"health"`
	// LatencyMs is the sum of the latest handshakes of its links, from
	// the entry to the exit (0: a deployed link has no answered check).
	LatencyMs int `json:"latencyMs"`
	// Egress is the address out of the last server, when it sends straight
	// out (its first outbound is direct) and the chain is not offline.
	Egress string          `json:"egress"`
	Nodes  []chainNodeJSON `json:"nodes"`
	Links  []chainLinkJSON `json:"links"`
	// Unreachable are the servers the latest «Удалить каскад» could not
	// reach (cascade.Linker.Unreached): owners and admins may delete the
	// chain without them. Only in the answers about one chain.
	Unreachable []unreachableJSON `json:"unreachable,omitempty"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
}

// unreachableJSON is a server the chain is deleted without, with what the
// link leaves there.
type unreachableJSON struct {
	ServerID int64            `json:"serverId"`
	Name     string           `json:"name"`
	Role     model.ServerRole `json:"role"`
	Left     []string         `json:"left"`
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

// listChains is the cascades in the caller's scope: those of servers all
// of which it reaches.
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
	set, err := s.scopeSet(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]chainJSON, 0, len(cs))
	for _, c := range cs {
		if !set.hasAll(c.Nodes) {
			continue
		}
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
	s.unreachable(r, &j, c.Chain, names)
	writeJSON(w, status, j)
}

// firstDeployed is the first link of c on its servers (-1: none): the
// unlink job of a chain covers it.
func firstDeployed(c model.Chain) int {
	for i, l := range c.Links {
		if l.State != model.LinkNew && l.State != model.LinkFailed {
			return i
		}
	}
	return -1
}

// unreachable adds the servers the latest «Удалить каскад» of the chain
// could not reach, with what the links leave on them; a failure only
// leaves them out.
func (s *server) unreachable(r *http.Request, out *chainJSON, c model.Chain, names map[int64]string) {
	idx := firstDeployed(c)
	if s.Cascade == nil || idx < 0 {
		return
	}
	un, err := s.Cascade.Unreached(r.Context(), c, idx)
	if err != nil {
		s.Log.Warn("cascade: unreachable servers not looked up", "chain", c.ID, "err", err)
		return
	}
	for _, u := range un {
		role := model.NodeRole(slices.Index(c.Nodes, u.Server), len(c.Nodes))
		left := u.Left
		if left == nil {
			left = []string{}
		}
		out.Unreachable = append(out.Unreachable, unreachableJSON{ServerID: u.Server, Name: names[u.Server], Role: role, Left: left})
	}
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

// linkChain queues the job that deploys the chain's links that need it
// (again): from the exit towards the entry, one job (P4-08).
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
	j, err := s.Cascade.Deploy(r.Context(), id, principal(r).User.ID)
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

// unlinkChain queues the job that takes the chain's links off its
// servers, from the entry towards the exit ({"delete": true}: the chain
// goes too; with "force": true, without the servers the latest delete
// could not reach, forceDelete).
func (s *server) unlinkChain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.Cascade == nil {
		writeError(w, errNotFound)
		return
	}
	var in struct {
		Delete bool `json:"delete"`
		Force  bool `json:"force"`
	}
	if r.ContentLength != 0 {
		if err := readJSON(r, &in); err != nil {
			writeError(w, err)
			return
		}
	}
	if in.Force {
		s.forceDelete(w, r, id, in.Delete)
		return
	}
	j, err := s.Cascade.UnlinkChain(r.Context(), id, in.Delete, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, unlinkError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}

// unlinkError is the answer to an unlink job that was not queued.
func unlinkError(err error) error {
	switch {
	case errors.Is(err, cascade.ErrNotDeployed):
		return &Error{Status: http.StatusConflict, Code: "not_deployed", Message: "Связь каскада не развёрнута на серверах: каскад удаляется без задания."}
	case errors.Is(err, cascade.ErrReached):
		return &Error{Status: http.StatusConflict, Code: "servers_reached", Message: "Удалить каскад без недоступного сервера можно, только когда «Удалить каскад» не смогло подключиться к одному из его серверов. Сначала удалите каскад обычным способом."}
	case errors.Is(err, cascade.ErrNoConfig):
		return &Error{Status: http.StatusConflict, Code: "no_config", Message: "HyRoute не знает конфиг одного из серверов каскада: импортируйте его."}
	case errors.Is(err, cascade.ErrNoInstallation):
		return &Error{Status: http.StatusConflict, Code: "no_installation", Message: "HyRoute не знает, где Hysteria на одном из серверов каскада: импортируйте сервер."}
	}
	return jobError(err)
}

// forceDelete queues the job that deletes the chain without the servers
// its latest «Удалить каскад» could not reach (cascade.Linker.ForceDelete):
// owners and admins only, written to the audit log.
func (s *server) forceDelete(w http.ResponseWriter, r *http.Request, id int64, del bool) {
	p := principal(r)
	if !p.User.Role.CanForce() {
		writeError(w, errForbidden)
		return
	}
	if !del {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "force — только вместе с delete: каскад удаляется."})
		return
	}
	c, err := s.Store.ChainByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	idx := firstDeployed(c)
	if idx < 0 {
		s.fail(w, r, unlinkError(cascade.ErrNotDeployed))
		return
	}
	j, un, err := s.Cascade.ForceDelete(r.Context(), id, idx, p.User.ID)
	if err != nil {
		s.fail(w, r, unlinkError(err))
		return
	}
	names, err := s.serverNames(r)
	if err != nil {
		names = map[int64]string{}
	}
	without := make([]string, 0, len(un))
	for _, u := range un {
		without = append(without, "«"+names[u.Server]+"»")
	}
	details := fmt.Sprintf("«%s» без %s, задание %d", c.Name, strings.Join(without, ", "), j.ID)
	if err := s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: p.User.ID, Action: "chain_force_delete", Target: "chain/" + strconv.FormatInt(id, 10), Details: details}); err != nil {
		s.Log.Error("audit: chain_force_delete", "chain", id, "err", err)
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}

// linkHealth adds the latest check of each deployed link (each hop is
// checked from the server it starts at), the chain's health (the worst of
// them), its latency (the sum of their handshakes) and its egress
// address.
func (s *server) linkHealth(r *http.Request, out *chainJSON, c model.Chain) {
	ctx := r.Context()
	rank := map[model.ServerState]int{model.StateHealthy: 1, model.StateDegraded: 2, model.StateOffline: 3}
	total, every := 0, true
	for i, l := range c.Links {
		if i >= len(out.Links) || (l.State != model.LinkActive && l.State != model.LinkStale) {
			continue
		}
		cs, err := s.Store.LinkChecks(ctx, c.ID, l.Idx, time.Time{}, 1)
		if err != nil || len(cs) == 0 {
			every = false
			continue
		}
		out.Links[i].Check = toLinkCheckJSON(cs[0])
		if rank[cs[0].Status] > rank[out.Health] {
			out.Health = cs[0].Status
		}
		if cs[0].Status == model.StateOffline || cs[0].HandshakeMillis == 0 {
			every = false
		}
		total += cs[0].HandshakeMillis
	}
	if every && total > 0 {
		out.LatencyMs = total
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

// routeChain says where a request goes along the chain (P4-08): the rule
// it matches on the entry and, while that sends it into the cascade, on
// each next server, as Hysteria matches them there, and the server it
// leaves from for the internet.
func (s *server) routeChain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var q acl.Request
	if err := readJSON(r, &q); err != nil {
		writeError(w, err)
		return
	}
	c, err := s.Store.ChainByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	names, err := s.serverNames(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.routing().Trace(r.Context(), c, 0, nil, q, names)
	if err != nil {
		s.fail(w, r, configError(err))
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// checkFrom checks the deployed links that start at server sid now; false:
// the answer is written (a failure).
func (s *server) checkFrom(w http.ResponseWriter, r *http.Request, sid int64) bool {
	srv, err := s.Store.ServerByID(r.Context(), sid)
	if err != nil {
		s.fail(w, r, mapError(err))
		return false
	}
	release, ok := s.sshSlot(w, r, srv.ID, false)
	if !ok {
		return false
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	ex, err := s.Connect.Connect(ctx, srv.ID)
	if err != nil {
		s.fail(w, r, mapError(err))
		return false
	}
	defer ex.Close()
	k := &cascade.Checker{Store: s.Store, Keys: s.Keys}
	if _, err := k.CheckLinks(ctx, srv, ex); err != nil {
		s.fail(w, r, mapError(err))
		return false
	}
	return true
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

// checkChain checks the chain's links now, each from the server it
// starts at (the entry, then the relays), as the monitor does each round,
// and returns the chain with the results.
func (s *server) checkChain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.Connect == nil {
		writeError(w, errNotFound)
		return
	}
	c, err := s.Store.ChainByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	if st := topology.State(c); st == model.LinkLinking || st == model.LinkUnlinking {
		s.fail(w, r, &Error{Status: http.StatusConflict, Code: "chain_busy", Message: "Задание каскада ещё идёт: проверка — после него."})
		return
	}
	var from []int64
	for _, l := range c.Links {
		if (l.State == model.LinkActive || l.State == model.LinkStale) && !slices.Contains(from, l.From) {
			from = append(from, l.From)
		}
	}
	if len(from) == 0 {
		from = []int64{c.Entry()}
	}
	for _, sid := range from {
		if !s.checkFrom(w, r, sid) {
			return
		}
	}
	if c, err = s.Store.ChainByID(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	s.writeChain(w, r, http.StatusOK, topology.Of(s.sync(r, c)))
}
