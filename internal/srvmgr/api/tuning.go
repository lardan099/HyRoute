package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/tuning"
)

// tuningJSON is the server's kernel settings and, beside them, the
// congestion settings of Hysteria's config, which are not the kernel's.
type tuningJSON struct {
	tuning.State
	// QUIC: Hysteria's own congestion control (congestion.type,
	// bbrProfile); "" is Hysteria's default, BBR.
	QUIC struct {
		Type    string `json:"type"`
		Profile string `json:"profile"`
	} `json:"quic"`
	// Brutal: the speeds of the server's bandwidth section; with
	// ignoreClient the clients' speeds are not used.
	Brutal struct {
		Up           string `json:"up"`
		Down         string `json:"down"`
		IgnoreClient bool   `json:"ignoreClient"`
	} `json:"brutal"`
}

// getTuning reads the server's kernel settings over SSH (read-only).
func (s *server) getTuning(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	release, ok := s.sshSlot(w, r, id, false)
	if !ok {
		return
	}
	defer release()
	ctx, cancel := context.WithTimeout(r.Context(), statusTimeout)
	defer cancel()
	ex, err := s.Connect.Connect(ctx, id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	defer ex.Close()
	ro := remote.ReadOnly(ex)
	p, err := remote.RunProbe(ctx, ro)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	st, err := tuning.Read(ctx, ro, p.Kernel)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	out := tuningJSON{State: st}
	if _, b, err := s.editor().Current(r.Context(), id); err == nil {
		if c, err := hyconfig.ParseServer(b); err == nil {
			out.QUIC.Type, out.QUIC.Profile = strings.ToLower(c.Congestion.Type), c.Congestion.BBRProfile
			out.Brutal.Up, out.Brutal.Down, out.Brutal.IgnoreClient = c.Bandwidth.Up, c.Bandwidth.Down, c.IgnoreClientBandwidth
		}
	} else if !errors.Is(err, apply.ErrNoConfig) {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// startTuning starts the job that puts the chosen settings in HyRoute's
// sysctl file and applies them.
func (s *server) startTuning(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var in tuning.Params
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if len(in.Keys) == 0 {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Выберите хотя бы одну настройку.", Details: "keys"})
		return
	}
	for _, k := range in.Keys {
		if !slices.Contains(tuning.Keys, k) {
			writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "HyRoute не меняет " + k + ".", Details: "keys"})
			return
		}
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Jobs.Submit(r.Context(), tuning.JobKind, id, in, nil, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
