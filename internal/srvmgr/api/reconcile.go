package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/reconcile"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// The reconciliation of a server (P4-06). Viewing is for every role (the
// masked diff of the config only for those that may write, as the config
// history); checking now, accepting and reverting need write access. For
// P4-04: GET → view; check → service; accept and revert → config (config,
// geo), deploy (unit, binary), chains (link/…).

// driftThingJSON is a thing a reconciliation compares.
type driftThingJSON struct {
	Key  string          `json:"key"`
	Kind model.DriftKind `json:"kind"`
	// Chain is the cascade of a link, Idx the link, Hops how many links
	// the cascade has.
	Chain *chainRefJSON `json:"chain,omitempty"`
	Idx   int           `json:"idx,omitempty"`
	Hops  int           `json:"hops,omitempty"`
}

type chainRefJSON struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type driftJobJSON struct {
	ID           int64          `json:"id"`
	State        model.JobState `json:"state"`
	ErrorMessage string         `json:"errorMessage,omitempty"`
}

// driftItemJSON is a difference.
type driftItemJSON struct {
	driftThingJSON
	Files    []model.DriftFile `json:"files"`
	Revision int               `json:"revision,omitempty"`
	Units    []string          `json:"units,omitempty"`
	Title    string            `json:"title"`
	Summary  string            `json:"summary"`
	Since    time.Time         `json:"since"`
	// Job is the latest revert job (null: none).
	Job *driftJobJSON `json:"job"`
	// CanRevert: HyRoute has a job that puts its version back;
	// RevertNote says why not.
	CanRevert  bool   `json:"canRevert"`
	RevertNote string `json:"revertNote,omitempty"`
	// Diff and Secrets: the config's masked diff and the paths of the
	// secrets that differ (writers only); DiffNote when none is shown.
	Diff     []apply.Line `json:"diff,omitempty"`
	Secrets  []string     `json:"secrets,omitempty"`
	DiffNote string       `json:"diffNote,omitempty"`
}

// driftJSON is the latest reconciliation of a server.
type driftJSON struct {
	// Interval of the rounds in seconds (0: off).
	Interval int64 `json:"interval"`
	// At is the last check (null: never).
	At      *time.Time       `json:"at"`
	Error   string           `json:"error,omitempty"`
	Checked []driftThingJSON `json:"checked"`
	Skipped []driftThingJSON `json:"skipped"`
	Items   []driftItemJSON  `json:"items"`
}

func reconcileError(err error) error {
	var cr *reconcile.CannotRevertError
	switch {
	case errors.Is(err, reconcile.ErrGone):
		return &Error{Status: http.StatusConflict, Code: "drift_gone", Message: "Этого расхождения уже нет: обновите страницу."}
	case errors.Is(err, reconcile.ErrChanged):
		return &Error{Status: http.StatusConflict, Code: "drift_changed", Message: "На сервере всё изменилось ещё раз после сверки: проверьте сервер снова и решите заново."}
	case errors.As(err, &cr):
		return &Error{Status: http.StatusConflict, Code: "cannot_revert", Message: cr.Msg}
	case errors.Is(err, store.ErrBusy), errors.Is(err, jobs.ErrBusy):
		return &Error{Status: http.StatusConflict, Code: "server_busy", Message: "На сервере выполняется задание: сверьте сервер, когда оно закончится."}
	case errors.Is(err, deploy.ErrNotManaged), errors.Is(err, deploy.ErrNotHysteria):
		return &Error{Status: http.StatusConflict, Code: "cannot_revert", Message: "Эту установку HyRoute не переустанавливает: примите изменения или разверните Hysteria с заменой."}
	case errors.Is(err, deploy.ErrNoInstallation), errors.Is(err, geo.ErrNoInstallation), errors.Is(err, cascade.ErrNoInstallation):
		return errNoInstallation
	case errors.Is(err, geo.ErrNone):
		return &Error{Status: http.StatusConflict, Code: "no_geo", Message: geo.ErrNone.Error() + "."}
	case errors.Is(err, cascade.ErrNoConfig), errors.Is(err, apply.ErrNoConfig):
		return &Error{Status: http.StatusConflict, Code: "no_config", Message: "HyRoute не знает конфиг сервера: импортируйте его."}
	}
	return mapError(err)
}

// driftThing describes key for the UI (the cascade of a link by name).
func (s *server) driftThing(r *http.Request, key string, chains map[int64]model.Chain) driftThingJSON {
	kind, chain, idx, _ := model.ParseDriftKey(key)
	out := driftThingJSON{Key: key, Kind: kind}
	if kind == model.DriftLink {
		c, ok := chains[chain]
		if !ok {
			var err error
			if c, err = s.Store.ChainByID(r.Context(), chain); err == nil {
				chains[chain] = c
				ok = true
			}
		}
		out.Chain, out.Idx = &chainRefJSON{ID: chain}, idx
		if ok {
			out.Chain.Name, out.Hops = c.Name, len(c.Links)
		}
	}
	return out
}

// toDriftJSON is d as the UI shows it to the caller.
func (s *server) toDriftJSON(r *http.Request, serverID int64, d model.Drift) (driftJSON, error) {
	out := driftJSON{Checked: []driftThingJSON{}, Skipped: []driftThingJSON{}, Items: []driftItemJSON{}, Error: d.Error, At: optTime(d.At)}
	if s.Reconcile != nil {
		out.Interval = int64(s.Reconcile.Interval / time.Second)
	}
	chains := map[int64]model.Chain{}
	for _, k := range d.Checked {
		out.Checked = append(out.Checked, s.driftThing(r, k, chains))
	}
	for _, k := range d.Skipped {
		out.Skipped = append(out.Skipped, s.driftThing(r, k, chains))
	}
	in, err := s.Store.Installation(r.Context(), serverID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return out, err
	}
	srv, err := s.Store.ServerByID(r.Context(), serverID)
	if err != nil {
		return out, err
	}
	writer := principal(r).User.Can(model.PermConfig, srv.Tags)
	for _, it := range d.Items {
		x := driftItemJSON{driftThingJSON: s.driftThing(r, it.Key, chains), Files: it.Files, Revision: it.Revision, Units: it.Units, Title: it.Title, Summary: it.Summary, Since: it.Since}
		if s.Reconcile != nil {
			x.CanRevert, x.RevertNote = s.Reconcile.Revertible(in, it)
		}
		if it.Job != 0 {
			if j, err := s.Store.JobByID(r.Context(), it.Job); err == nil {
				x.Job = &driftJobJSON{ID: j.ID, State: j.State, ErrorMessage: j.ErrorMessage}
			}
		}
		if it.Kind == model.DriftConfig && writer && s.Reconcile != nil {
			lines, secrets, err := s.Reconcile.ConfigDiff(r.Context(), serverID)
			switch {
			case errors.Is(err, reconcile.ErrUnreadable):
				x.DiffNote = "Конфиг на сервере не читается как YAML: в нём не скрыть пароли, поэтому diff не показан."
			case err != nil:
				return out, err
			case lines == nil:
				x.DiffNote = "Конфига на сервере нет."
			default:
				x.Diff, x.Secrets = lines, secrets
			}
		}
		out.Items = append(out.Items, x)
	}
	return out, nil
}

// serverDrift is the latest reconciliation of a server.
func (s *server) serverDrift(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.Servers.Get(r.Context(), id); err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	d, err := s.Store.Drift(r.Context(), id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, err)
		return
	}
	out, err := s.toDriftJSON(r, id, d)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// checkDrift checks the server now (read-only).
func (s *server) checkDrift(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.Reconcile == nil {
		writeError(w, errNotFound)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.Reconcile.Check(r.Context(), id)
	if err != nil && d.Error == "" {
		// Not a server that did not answer (that is in the result).
		s.fail(w, r, reconcileError(err))
		return
	}
	s.answerDrift(w, r, id, d)
}

func (s *server) answerDrift(w http.ResponseWriter, r *http.Request, id int64, d model.Drift) {
	out, err := s.toDriftJSON(r, id, d)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// driftKey is the body of accept and revert: the difference.
type driftKey struct {
	Key string `json:"key"`
}

// mayDecide: the route asks for `config`; a difference of the unit or the
// binary needs `deploy` as their jobs do, one of a cascade link `chains`
// on every server of the cascade.
func (s *server) mayDecide(r *http.Request, serverID int64, key string) error {
	u := principal(r).User
	kind, chain, _, ok := model.ParseDriftKey(key)
	if !ok {
		return &Error{Status: http.StatusBadRequest, Code: "bad_request", Message: "Неизвестное расхождение."}
	}
	perm, servers := model.PermConfig, []int64{serverID}
	switch kind {
	case model.DriftUnit, model.DriftBinary:
		perm = model.PermDeploy
	case model.DriftLink:
		perm = model.PermChains
		c, err := s.Store.ChainByID(r.Context(), chain)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		servers = append(servers, c.Nodes...)
	}
	for _, id := range servers {
		srv, err := s.Store.ServerByID(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if !u.Can(perm, srv.Tags) {
			return errForbidden
		}
	}
	return nil
}

// acceptDrift takes what is on the server for a difference.
func (s *server) acceptDrift(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.Reconcile == nil {
		writeError(w, errNotFound)
		return
	}
	var in driftKey
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if err := s.mayDecide(r, id, in.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.Reconcile.Accept(r.Context(), id, in.Key, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, reconcileError(err))
		return
	}
	s.answerDrift(w, r, id, d)
}

// revertDrift queues the job that puts HyRoute's version back.
func (s *server) revertDrift(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.Reconcile == nil {
		writeError(w, errNotFound)
		return
	}
	var in driftKey
	if err := readJSON(r, &in); err != nil {
		writeError(w, err)
		return
	}
	if err := s.mayDecide(r, id, in.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.installed(r, id); err != nil {
		s.fail(w, r, err)
		return
	}
	j, err := s.Reconcile.Revert(r.Context(), id, in.Key, principal(r).User.ID)
	if err != nil {
		s.fail(w, r, reconcileError(err))
		return
	}
	writeJSON(w, http.StatusAccepted, toJobJSON(j))
}
