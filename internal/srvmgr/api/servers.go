package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/servers"
	"github.com/lardan099/hyroute/internal/srvmgr/topology"
)

// serverJSON is a server as the API returns it: which credentials are
// stored, never the credentials.
type serverJSON struct {
	ID               int64             `json:"id"`
	Name             string            `json:"name"`
	Tags             []string          `json:"tags"`
	Country          string            `json:"country"`
	Location         string            `json:"location"`
	Host             string            `json:"host"`
	SSHPort          int               `json:"sshPort"`
	SSHUser          string            `json:"sshUser"`
	AuthType         model.AuthType    `json:"authType"`
	Role             model.ServerRole  `json:"role"`
	Notes            string            `json:"notes"`
	State            model.ServerState `json:"state"`
	CreatedAt        time.Time         `json:"createdAt"`
	UpdatedAt        time.Time         `json:"updatedAt"`
	HasPassword      bool              `json:"hasPassword"`
	HasKey           bool              `json:"hasKey"`
	HasKeyPassphrase bool              `json:"hasKeyPassphrase"`
	HostKey          *hostKeyJSON      `json:"hostKey"`
	// HopInterval of the client links, seconds (0: the client's default).
	HopInterval int `json:"hopInterval"`
	// Chains are the cascades the server is a node of.
	Chains []serverChainJSON `json:"chains"`
}

// serverChainJSON is a cascade a server is in.
type serverChainJSON struct {
	ID    int64           `json:"id"`
	Name  string          `json:"name"`
	State model.LinkState `json:"state"`
}

func toServerJSON(in servers.Info) serverJSON {
	tags := in.Tags
	if tags == nil {
		tags = []string{}
	}
	return serverJSON{
		ID: in.ID, Name: in.Name, Tags: tags, Country: in.Country, Location: in.Location,
		Host: in.Host, SSHPort: in.SSHPort, SSHUser: in.SSHUser, AuthType: in.AuthType,
		Role: in.Role, Notes: in.Notes, State: in.State, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt,
		HasPassword: in.HasPassword, HasKey: in.HasKey, HasKeyPassphrase: in.HasKeyPassphrase,
		HostKey: toHostKeyJSON(in.HostKey), HopInterval: in.HopInterval,
		Chains: []serverChainJSON{},
	}
}

// serverInput is the body of POST and PATCH. Credentials are optional on
// PATCH: absent keeps the stored value.
type serverInput struct {
	Name          string         `json:"name"`
	Tags          []string       `json:"tags"`
	Country       string         `json:"country"`
	Location      string         `json:"location"`
	Host          string         `json:"host"`
	SSHPort       int            `json:"sshPort"`
	SSHUser       string         `json:"sshUser"`
	AuthType      model.AuthType `json:"authType"`
	Notes         string         `json:"notes"`
	Password      *string        `json:"password,omitempty"`
	Key           *string        `json:"key,omitempty"`
	KeyPassphrase *string        `json:"keyPassphrase,omitempty"`
}

func (in serverInput) toInput() servers.Input {
	return servers.Input{
		Name: in.Name, Tags: in.Tags, Country: in.Country, Location: in.Location, Host: in.Host,
		SSHPort: in.SSHPort, SSHUser: in.SSHUser, AuthType: in.AuthType, Notes: in.Notes,
		Password: in.Password, Key: in.Key, KeyPassphrase: in.KeyPassphrase,
	}
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func (s *server) listServers(w http.ResponseWriter, r *http.Request) {
	list, err := s.Servers.List(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	chains := s.chainsByServer(r)
	out := make([]serverJSON, 0, len(list))
	for _, in := range list {
		j := toServerJSON(in)
		if cs := chains[in.ID]; cs != nil {
			j.Chains = cs
		}
		out = append(out, j)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) getServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	in, err := s.Servers.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	j := toServerJSON(in)
	if cs := s.chainsByServer(r)[in.ID]; cs != nil {
		j.Chains = cs
	}
	writeJSON(w, http.StatusOK, j)
}

// chainsByServer are the cascades of each server (none when they cannot
// be read: the server is shown all the same).
func (s *server) chainsByServer(r *http.Request) map[int64][]serverChainJSON {
	cs, err := s.Store.ListChains(r.Context())
	if err != nil {
		return nil
	}
	m := map[int64][]serverChainJSON{}
	for _, c := range cs {
		for _, n := range c.Nodes {
			m[n] = append(m[n], serverChainJSON{ID: c.ID, Name: c.Name, State: topology.State(c)})
		}
	}
	return m
}

func (s *server) createServer(w http.ResponseWriter, r *http.Request) {
	var req serverInput
	if err := readJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	in, err := s.Servers.Create(r.Context(), principal(r).User.ID, req.toInput())
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusCreated, toServerJSON(in))
}

func (s *server) updateServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var req serverInput
	if err := readJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	in, err := s.Servers.Update(r.Context(), principal(r).User.ID, id, req.toInput())
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	writeJSON(w, http.StatusOK, toServerJSON(in))
}

func (s *server) deleteServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if err := s.Servers.Delete(r.Context(), principal(r).User.ID, id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
