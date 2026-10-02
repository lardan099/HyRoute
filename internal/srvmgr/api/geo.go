package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

func geoError(err error) error {
	if errors.Is(err, geo.ErrNone) {
		return &Error{Status: http.StatusNotFound, Code: "no_geo", Message: err.Error() + "."}
	}
	return mapError(err)
}

// geoInfo is the geo databases the controller has.
func (s *server) geoInfo(w http.ResponseWriter, r *http.Request) {
	if s.Geo == nil {
		writeError(w, errNotFound)
		return
	}
	i, err := s.Geo.Info()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, i)
}

// geoUpdate downloads the latest geo databases to the controller.
func (s *server) geoUpdate(w http.ResponseWriter, r *http.Request) {
	if s.Geo == nil {
		writeError(w, errNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	i, changed, err := s.Geo.Update(ctx)
	if errors.Is(err, geo.ErrBusy) {
		s.fail(w, r, &Error{Status: http.StatusConflict, Code: "geo_busy", Message: geo.ErrBusy.Error() + ": дождитесь конца."})
		return
	} else if err != nil {
		s.fail(w, r, &Error{Status: http.StatusBadGateway, Code: "geo_download", Message: "Базы geo не скачались: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"info": i, "changed": changed})
}

// geoCategories are the geoip codes (kind=geoip) or geosite names that
// contain q, for the rule editor.
func (s *server) geoCategories(w http.ResponseWriter, r *http.Request) {
	if s.Geo == nil {
		writeError(w, errNotFound)
		return
	}
	kind := r.URL.Query().Get("kind")
	if kind != "geoip" && kind != "geosite" {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "kind — geoip или geosite.", Details: "kind"})
		return
	}
	names, err := s.Geo.Categories(kind, r.URL.Query().Get("q"))
	if err != nil {
		s.fail(w, r, geoError(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"names": names})
}

// serverGeoJSON is what a server has of the geo databases.
type serverGeoJSON struct {
	// Release is what HyRoute put on the server ("": nothing).
	Release string     `json:"release"`
	At      *time.Time `json:"at,omitempty"`
	// Latest: the controller has nothing newer.
	Latest bool `json:"latest"`
	// Paths: the config reads the databases from the files HyRoute puts.
	Paths bool `json:"paths"`
	// Rules: the config's ACL has geoip or geosite rules.
	Rules bool `json:"rules"`
}

// serverGeo is the geo databases of a server and whether its config uses
// them.
func (s *server) serverGeo(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.Geo == nil {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	var out serverGeoJSON
	g, err := s.Store.ServerGeo(r.Context(), id)
	if err == nil {
		out.Release, out.At = g.Release, &g.At
	} else if !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	if i, err := s.Geo.Info(); err == nil && i.Release != "" {
		out.Latest = out.Release == i.Release
	}
	if _, b, err := s.editor().Current(r.Context(), id); err == nil {
		if c, err := hyconfig.ParseServer(b); err == nil {
			out.Paths = c.ACL.GeoIP == geo.ServerDir+"/"+geo.GeoIP && c.ACL.GeoSite == geo.ServerDir+"/"+geo.GeoSite
			out.Rules = geo.UsesGeo(c)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// installGeo queues the job that puts the controller's databases on the
// server: {source: auto|direct|relay|node, via}.
func (s *server) installGeo(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.GeoJobs == nil {
		writeError(w, errNotFound)
		return
	}
	var in struct {
		Source string `json:"source"`
		Via    int64  `json:"via"`
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.GeoJobs.Submit(r.Context(), id, in.Source, in.Via, principal(r).User.ID)
	if errors.Is(err, geo.ErrNone) {
		s.fail(w, r, &Error{Status: http.StatusConflict, Code: "no_geo", Message: geo.ErrNone.Error() + "."})
		return
	} else if err != nil {
		s.fail(w, r, jobError(mapError(err)))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
