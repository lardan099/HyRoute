package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/backup"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
)

type backupsJSON struct {
	// Interval is the schedule in seconds (0: copies by hand only).
	Interval  int64         `json:"interval"`
	Keep      int           `json:"keep"`
	Encrypted bool          `json:"encrypted"`
	Dir       string        `json:"dir"`
	Last      backup.Result `json:"last"`
	Items     []backup.Info `json:"items"`
}

var errNoBackups = &Error{Status: http.StatusNotFound, Code: "not_found", Message: "Резервные копии в этой панели не настроены."}

// listBackups shows the copies of the database: for the owner only, a
// copy holds every password hash and every server.
func (s *server) listBackups(w http.ResponseWriter, r *http.Request) {
	if !principal(r).User.Role.CanBackup() {
		writeError(w, errForbidden)
		return
	}
	if s.Backups == nil {
		writeError(w, errNoBackups)
		return
	}
	items, err := s.Backups.List()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []backup.Info{}
	}
	writeJSON(w, http.StatusOK, backupsJSON{
		Interval: int64(s.Backups.Interval / time.Second), Keep: s.Backups.Keep, Encrypted: s.Backups.Passphrase != "",
		Dir: s.Backups.Dir, Last: s.Backups.Last(), Items: items,
	})
}

// createBackup makes a copy now.
func (s *server) createBackup(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if !p.User.Role.CanBackup() {
		writeError(w, errForbidden)
		return
	}
	if s.Backups == nil {
		writeError(w, errNoBackups)
		return
	}
	info, err := s.Backups.Make(r.Context())
	if err != nil {
		s.fail(w, r, &Error{Status: http.StatusInternalServerError, Code: "backup_failed", Message: "Копия не сделана.", Details: err.Error()})
		return
	}
	s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: p.User.ID, Action: "backup_created", Target: "backup/" + info.Name})
	writeJSON(w, http.StatusCreated, info)
}

// downloadBackup sends a copy; the download is audited.
func (s *server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if !p.User.Role.CanBackup() {
		writeError(w, errForbidden)
		return
	}
	if s.Backups == nil {
		writeError(w, errNoBackups)
		return
	}
	f, info, err := s.Backups.Open(r.PathValue("name"))
	if errors.Is(err, backup.ErrNotFound) {
		writeError(w, errNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer f.Close()
	if err := s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: p.User.ID, Action: "backup_downloaded", Target: "backup/" + info.Name}); err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+info.Name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, info.Name, info.At, f)
}

type keyCheckJSON struct {
	OK bool `json:"ok"`
	secrets.KeyReport
}

// checkMasterKey tells whether a pasted copy of the master key opens the
// database. The key is not kept, logged or audited; the audit records
// that a check was made and its outcome.
func (s *server) checkMasterKey(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if !p.User.Role.CanCheckKey() {
		writeError(w, errForbidden)
		return
	}
	if s.KeyCheck == nil {
		writeError(w, errNotFound)
		return
	}
	var in struct {
		Key string `json:"key"`
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	rep, err := s.KeyCheck(r.Context(), in.Key)
	if errors.Is(err, secrets.ErrNotKeyText) {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "not_a_key", Message: "Это не мастер-ключ: нужен текст файла ключа, «1:<32 байта в base64>», по строке на версию."})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	outcome := "mismatch"
	if rep.OK() {
		outcome = "ok"
	}
	s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: p.User.ID, Action: "master_key_checked", Details: outcome})
	if rep.Versions == nil {
		rep.Versions = []secrets.VersionCheck{}
	}
	if rep.Unused == nil {
		rep.Unused = []uint32{}
	}
	writeJSON(w, http.StatusOK, keyCheckJSON{OK: rep.OK(), KeyReport: rep})
}
