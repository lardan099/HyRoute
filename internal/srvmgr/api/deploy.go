package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/importer"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

var errHostKeyRequired = &Error{Status: http.StatusConflict, Code: "host_key_required", Message: "Сначала проверьте подключение к серверу и подтвердите его ключ SSH."}

// errConfigChanged: the deploy would replace a config no deploy made; the
// UI asks and sends "overwrite": true.
var errConfigChanged = &Error{Status: http.StatusConflict, Code: "config_changed", Message: "Текущий конфиг сервера сделан не развёртыванием: его изменили в редакторе, вернули из истории или импортировали. Развёртывание соберёт конфиг заново из параметров формы, и всё, чего в форме нет (ACL, resolver, дополнительные outbounds и другие настройки), пропадёт; пароли клиентов сохранятся. Подтвердите замену конфига."}

func (s *server) startDeploy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	// The params with the secrets the admin entered beside them: the job
	// keeps the params in the clear and the secrets sealed.
	var req struct {
		deploy.Params
		Secrets deploy.Input `json:"secrets"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	in, err := s.Servers.Get(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	// The job would fail at connect: say what to do now.
	if in.HostKey == nil {
		writeError(w, errHostKeyRequired)
		return
	}
	j, err := s.Deploy.Submit(r.Context(), id, req.Params, req.Secrets, principal(r).User.ID)
	if errors.Is(err, deploy.ErrConfigChanged) {
		writeError(w, errConfigChanged)
		return
	} else if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}

// startMaintain starts an upgrade or a reinstall of Hysteria.
func (s *server) startMaintain(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	var p deploy.MaintainParams
	if err := readJSON(r, &p); err != nil {
		writeError(w, err)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Deploy.Maintain(r.Context(), id, p, principal(r).User.ID)
	switch {
	case errors.Is(err, deploy.ErrNoInstallation):
		writeError(w, errNoInstallation)
	case errors.Is(err, deploy.ErrNotManaged):
		writeError(w, &Error{Status: http.StatusConflict, Code: "not_managed", Message: "Hysteria на этом сервере импортирована: переустановить можно только установку HyRoute. Обновить версию можно и у импортированной."})
	case errors.Is(err, deploy.ErrNotHysteria):
		writeError(w, &Error{Status: http.StatusConflict, Code: "not_hysteria", Message: "Служба этого сервера запускает не программу hysteria* (например, docker или оболочку): HyRoute её не заменяет. Обновите Hysteria там, откуда она запускается, или разверните её с заменой."})
	case err != nil:
		s.fail(w, r, jobError(err))
	default:
		writeJSON(w, http.StatusAccepted, toJobJSON(j))
	}
}

// configJSON is a config revision without the config: what the UI shows
// and what client links need besides the passwords.
type configJSON struct {
	Revision int                `json:"revision"`
	SHA256   string             `json:"sha256"`
	Meta     model.ConfigMeta   `json:"meta"`
	Source   model.ConfigSource `json:"source"`
	// FromRevision is the revision a rollback brought back.
	FromRevision int       `json:"fromRevision,omitempty"`
	JobID        int64     `json:"jobId"`
	CreatedAt    time.Time `json:"createdAt"`
	// Installed is the Hysteria version of the server's installation
	// (when it is a release tag): an upgrade changes it, not the
	// revision's meta, and the deploy form keeps it.
	Installed string `json:"installed,omitempty"`
	// KeepFirewall: the deploy was told to leave the firewall alone (a
	// later deploy form keeps it, whatever made the revision).
	KeepFirewall bool `json:"keepFirewall,omitempty"`
}

func (s *server) currentConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	c, err := s.Store.CurrentConfig(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, &Error{Status: http.StatusNotFound, Code: "no_config", Message: "HyRoute ещё не устанавливал Hysteria на этот сервер."})
		return
	} else if err != nil {
		s.fail(w, r, err)
		return
	}
	c.Meta.Listen = model.ListenWithoutToken(c.Meta.Listen) // kept by older controllers
	out := configJSON{Revision: c.Revision, SHA256: c.SHA256, Meta: c.Meta, Source: c.Source, FromRevision: c.FromRevision, JobID: c.JobID, CreatedAt: c.At}
	if in, err := s.Store.Installation(r.Context(), id); err == nil {
		if hyrelease.CheckVersion(in.Version) == nil {
			out.Installed = in.Version
		}
		out.KeepFirewall = in.Firewall.Keep
	} else if !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) startImport(w http.ResponseWriter, r *http.Request) {
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
	if in.HostKey == nil {
		writeError(w, errHostKeyRequired)
		return
	}
	j, err := s.Jobs.Submit(r.Context(), importer.JobKind, id, struct{}{}, nil, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, jobError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
