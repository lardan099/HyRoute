package api

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/diag"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// diagJSON lists the files of a diagnostic bundle before its download.
type diagJSON struct {
	Name string `json:"name"`
	Jobs int    `json:"jobs"`
	// ControllerLog: the bundle has the controller's log buffer.
	ControllerLog bool         `json:"controllerLog"`
	Size          int          `json:"size"`
	Files         []diag.Entry `json:"files"`
}

var errNoDiag = &Error{Status: http.StatusNotFound, Code: "not_found", Message: "Диагностический пакет в этой панели не настроен."}

// buildDiag checks the role and builds a bundle with the logs of the
// latest ?jobs= jobs (b.Jobs); false: it has answered.
func (s *server) buildDiag(w http.ResponseWriter, r *http.Request) (*diag.Bundle, diag.Builder, bool) {
	if !principal(r).User.Role.CanDiagnose() {
		writeError(w, errForbidden)
		return nil, diag.Builder{}, false
	}
	if s.Diag == nil {
		writeError(w, errNoDiag)
		return nil, diag.Builder{}, false
	}
	b := *s.Diag
	b.Jobs = diag.DefaultJobs
	if q := r.URL.Query().Get("jobs"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 1 || n > diag.MaxJobs {
			writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: fmt.Sprintf("Журналов заданий в пакете — от 1 до %d.", diag.MaxJobs), Details: "jobs"})
			return nil, b, false
		}
		b.Jobs = n
	}
	bundle, err := b.Build(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return nil, b, false
	}
	return bundle, b, true
}

// diagFiles lists the files the download would give now: the bundle is
// built and dropped.
func (s *server) diagFiles(w http.ResponseWriter, r *http.Request) {
	bundle, b, ok := s.buildDiag(w, r)
	if !ok {
		return
	}
	out := diagJSON{Name: bundle.Name(), Jobs: b.Jobs, ControllerLog: b.Logs != nil, Files: bundle.Entries()}
	for _, f := range out.Files {
		out.Size += f.Size
	}
	writeJSON(w, http.StatusOK, out)
}

// diagBundle sends the bundle as a ZIP; the download is audited.
func (s *server) diagBundle(w http.ResponseWriter, r *http.Request) {
	bundle, b, ok := s.buildDiag(w, r)
	if !ok {
		return
	}
	var buf bytes.Buffer
	if err := bundle.WriteZip(&buf); err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	if err := s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: p.User.ID, Action: "diag_downloaded", Target: "diag/" + bundle.Name(),
		Details: fmt.Sprintf("jobs=%d files=%d", b.Jobs, len(bundle.Files))}); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+bundle.Name()+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}
