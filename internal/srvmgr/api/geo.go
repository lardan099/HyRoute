package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/geo"
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
	if err != nil {
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
