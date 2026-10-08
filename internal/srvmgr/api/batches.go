package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/batch"
	"github.com/lardan099/hyroute/internal/srvmgr/hyrelease"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Bulk operations (P4-07): a batch is one action over many servers, run
// by batch.Runner as ordinary jobs. Each action has its own route with
// the permission its single-server route needs; every server of the body
// is checked against the caller's scope by the route's rule, so a server
// out of scope refuses the whole batch with 404 (as it would alone)
// instead of silently leaving it.

type batchJobJSON struct {
	State        model.JobState `json:"state"`
	CurrentStep  string         `json:"currentStep"`
	ErrorMessage string         `json:"errorMessage,omitempty"`
}

type batchItemJSON struct {
	Idx      int                  `json:"idx"`
	ServerID int64                `json:"serverId"`
	State    model.BatchItemState `json:"state"`
	JobID    int64                `json:"jobId,omitempty"`
	Canary   bool                 `json:"canary,omitempty"`
	Message  string               `json:"message,omitempty"`
	At       *time.Time           `json:"at"`
	// Job is the item's job as it is now (one batch only).
	Job *batchJobJSON `json:"job,omitempty"`
}

type batchJSON struct {
	ID       int64             `json:"id"`
	Action   model.BatchAction `json:"action"`
	Params   json.RawMessage   `json:"params"`
	Parallel int               `json:"parallel"`
	State    model.BatchState  `json:"state"`
	// Stop is why no more jobs start (user, failed, denied).
	Stop model.BatchStop `json:"stop,omitempty"`
	// StoppedBy and CreatedBy are user names ("" once deleted).
	StoppedBy  string          `json:"stoppedBy,omitempty"`
	RetryOf    int64           `json:"retryOf,omitempty"`
	RetriedBy  int64           `json:"retriedBy,omitempty"`
	CreatedBy  string          `json:"createdBy"`
	CreatedAt  time.Time       `json:"createdAt"`
	UpdatedAt  time.Time       `json:"updatedAt"`
	FinishedAt *time.Time      `json:"finishedAt"`
	Items      []batchItemJSON `json:"items"`
	// MayStop, MayRetry: the caller's role may (the routes check again).
	MayStop  bool `json:"mayStop"`
	MayRetry bool `json:"mayRetry"`
}

// userNames are the names of the users by ID.
func (s *server) userNames(r *http.Request) (map[int64]string, error) {
	us, err := s.Store.ListUsers(r.Context())
	if err != nil {
		return nil, err
	}
	out := make(map[int64]string, len(us))
	for _, u := range us {
		out[u.ID] = u.Username
	}
	return out, nil
}

func toBatchJSON(r *http.Request, b model.Batch, names map[int64]string) batchJSON {
	out := batchJSON{ID: b.ID, Action: b.Action, Params: b.Params, Parallel: b.Parallel, State: b.State, Stop: b.Stop,
		StoppedBy: names[b.StoppedBy], RetryOf: b.RetryOf, RetriedBy: b.RetriedBy, CreatedBy: names[b.CreatedBy],
		CreatedAt: b.CreatedAt, UpdatedAt: b.UpdatedAt, FinishedAt: optTime(b.FinishedAt), Items: make([]batchItemJSON, 0, len(b.Items))}
	if len(out.Params) == 0 {
		out.Params = json.RawMessage("{}")
	}
	retry := false
	for _, it := range b.Items {
		out.Items = append(out.Items, batchItemJSON{Idx: it.Idx, ServerID: it.ServerID, State: it.State, JobID: it.JobID, Canary: it.Canary, Message: it.Message, At: optTime(it.At)})
		retry = retry || it.State == model.ItemFailed || it.State == model.ItemSkipped
	}
	may := mayBatch(principal(r).User.Role, b.Action)
	out.MayStop = may && b.State == model.BatchRunning
	out.MayRetry = may && b.State.Terminal() && b.RetriedBy == 0 && retry
	return out
}

// listBatches is the batches all of whose servers are in the caller's
// scope, newest first (?before=, ?limit=).
func (s *server) listBatches(w http.ResponseWriter, r *http.Request) {
	set, err := s.scopeSet(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	bs, err := s.Store.ListBatches(r.Context(), model.BatchFilter{BeforeID: queryInt(r, "before"), Limit: int(queryInt(r, "limit")), Within: set.within()})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	names, err := s.userNames(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]batchJSON, 0, len(bs))
	for _, b := range bs {
		out = append(out, toBatchJSON(r, b, names))
	}
	writeJSON(w, http.StatusOK, out)
}

// getBatch is a batch with the jobs of its servers as they are now.
func (s *server) getBatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeError(w, errNotFound)
		return
	}
	b, err := s.Store.BatchByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	s.writeBatch(w, r, http.StatusOK, b)
}

func (s *server) writeBatch(w http.ResponseWriter, r *http.Request, status int, b model.Batch) {
	names, err := s.userNames(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := toBatchJSON(r, b, names)
	for i, it := range out.Items {
		if it.JobID == 0 {
			continue
		}
		if j, err := s.Store.JobByID(r.Context(), it.JobID); err == nil {
			out.Items[i].Job = &batchJobJSON{State: j.State, CurrentStep: j.CurrentStep, ErrorMessage: j.ErrorMessage}
		}
	}
	writeJSON(w, status, out)
}

// batchInput is the body of a new batch: its servers in order, how many
// jobs run at once, and the params of its action beside them.
type batchInput struct {
	Servers  []int64 `json:"servers"`
	Parallel int     `json:"parallel"`
}

// createBatch starts a batch of action over the servers of the body. The
// servers must exist, be in the caller's scope (the route's rule) and
// have an installation and a trusted SSH key: what the single-server
// route asks before a job.
func (s *server) createBatch(action model.BatchAction) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Batches == nil {
			writeError(w, errNotFound)
			return
		}
		var raw json.RawMessage
		if err := readJSON(r, &raw); err != nil {
			writeError(w, err)
			return
		}
		var in batchInput
		if err := json.Unmarshal(raw, &in); err != nil {
			e := *errBadJSON
			e.Details = err.Error()
			writeError(w, &e)
			return
		}
		var ids []int64
		for _, id := range in.Servers {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Выберите серверы.", Details: "servers"})
			return
		}
		if in.Parallel < 0 || in.Parallel > batch.MaxParallel {
			writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: fmt.Sprintf("Одновременно — от 1 до %d серверов.", batch.MaxParallel), Details: "parallel"})
			return
		}
		params, err := s.batchActions().Check(r.Context(), action, raw)
		if err != nil {
			s.fail(w, r, mapError(err))
			return
		}
		b := model.Batch{Action: action, Params: params, Parallel: in.Parallel, CreatedBy: principal(r).User.ID}
		if via := batch.Via(b); via != 0 && slices.Contains(ids, via) {
			writeError(w, &Error{Status: http.StatusBadRequest, Code: "invalid", Message: "Сервер, через который идёт загрузка, не может быть в этом же пакете.", Details: "via"})
			return
		}
		if action == model.BatchGeo && s.Geo != nil {
			if info, err := s.Geo.Info(); err == nil && info.Release == "" {
				writeError(w, &Error{Status: http.StatusConflict, Code: "no_geo", Message: "У controller ещё нет баз geo: скачайте их на странице «Правила»."})
				return
			}
		}
		for _, id := range ids {
			if err := s.batchServer(r, id); err != nil {
				s.fail(w, r, err)
				return
			}
			b.Items = append(b.Items, model.BatchItem{ServerID: id})
		}
		b, err = s.Batches.Create(r.Context(), b)
		if err != nil {
			s.fail(w, r, mapError(err))
			return
		}
		s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: b.CreatedBy, Action: "batch_created", Target: batchTarget(b.ID),
			Details: fmt.Sprintf("action=%s servers=%d parallel=%d", b.Action, len(b.Items), b.Parallel)})
		s.writeBatch(w, r, http.StatusCreated, b)
	}
}

// batchServer: a job of a batch could be queued on the server: it exists,
// HyRoute knows its installation and its SSH key is trusted.
func (s *server) batchServer(r *http.Request, id int64) error {
	in, err := s.Servers.Get(r.Context(), id)
	if err != nil {
		return mapError(err)
	}
	if _, err := s.Store.Installation(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		return &Error{Status: http.StatusConflict, Code: "no_installation", Message: "HyRoute не знает, где на сервере «" + in.Name + "» Hysteria: уберите его из пакета или разверните на нём Hysteria.", Details: strconv.FormatInt(id, 10)}
	} else if err != nil {
		return err
	}
	if in.HostKey == nil {
		return &Error{Status: http.StatusConflict, Code: "host_key_required", Message: "Ключ SSH сервера «" + in.Name + "» ещё не подтверждён: проверьте подключение к нему или уберите его из пакета.", Details: strconv.FormatInt(id, 10)}
	}
	return nil
}

func (s *server) batchActions() *batch.Actions { return &batch.Actions{Store: s.Store} }

func batchTarget(id int64) string { return "batch/" + strconv.FormatInt(id, 10) }

// stopBatch starts no more jobs of the batch; the running ones finish.
func (s *server) stopBatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.Batches == nil {
		writeError(w, errNotFound)
		return
	}
	b, err := s.Batches.Stop(r.Context(), id, principal(r).User.ID)
	if errors.Is(err, batch.ErrNotRunning) {
		writeError(w, &Error{Status: http.StatusConflict, Code: "batch_not_running", Message: "Пакет уже не запускает новые задания."})
		return
	} else if err != nil {
		s.fail(w, r, mapError(err))
		return
	}
	s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: principal(r).User.ID, Action: "batch_stopped", Target: batchTarget(id)})
	s.writeBatch(w, r, http.StatusOK, b)
}

// retryBatch starts a new batch over the failed and skipped servers of
// one that ended.
func (s *server) retryBatch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok || s.Batches == nil {
		writeError(w, errNotFound)
		return
	}
	b, err := s.Batches.Retry(r.Context(), id, principal(r).User.ID)
	switch {
	case errors.Is(err, batch.ErrNotFinished):
		writeError(w, &Error{Status: http.StatusConflict, Code: "batch_running", Message: "Пакет ещё идёт: повторить неудачные можно, когда он закончится."})
		return
	case errors.Is(err, batch.ErrRetried):
		writeError(w, &Error{Status: http.StatusConflict, Code: "batch_retried", Message: fmt.Sprintf("Неудачные серверы этого пакета уже повторяет пакет %d.", b.RetriedBy)})
		return
	case errors.Is(err, batch.ErrNothingToRetry):
		writeError(w, &Error{Status: http.StatusConflict, Code: "nothing_to_retry", Message: "В пакете нет неудачных и пропущенных серверов."})
		return
	case err != nil:
		s.fail(w, r, mapError(err))
		return
	}
	s.Store.AddAudit(r.Context(), model.AuditEntry{Time: time.Now(), UserID: principal(r).User.ID, Action: "batch_retried", Target: batchTarget(id),
		Details: fmt.Sprintf("batch=%d servers=%d", b.ID, len(b.Items))})
	s.writeBatch(w, r, http.StatusCreated, b)
}

// releaseJSON is the newest Hysteria release and the servers of the
// caller's scope with an older one.
type releaseJSON struct {
	// Check: the controller looks for releases (-release-interval).
	Check bool `json:"check"`
	// Latest is the newest release found ("": none yet), CheckedAt when.
	Latest    string     `json:"latest"`
	CheckedAt *time.Time `json:"checkedAt"`
	// Target is what «Обновить все» installs: Latest when it is newer
	// than the version HyRoute deploys by default, that one otherwise.
	Target   string         `json:"target"`
	Outdated []outdatedJSON `json:"outdated"`
}

type outdatedJSON struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// hysteriaRelease is the release notice of the overview.
func (s *server) hysteriaRelease(w http.ResponseWriter, r *http.Request) {
	rel := s.Releases.Latest()
	out := releaseJSON{Check: s.Releases != nil, Latest: rel.Version, CheckedAt: optTime(rel.CheckedAt), Target: rel.Target(), Outdated: []outdatedJSON{}}
	set, err := s.scopeSet(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ss, err := s.Store.ListServers(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, srv := range ss {
		if !set.has(srv.ID) {
			continue
		}
		in, err := s.Store.Installation(r.Context(), srv.ID)
		if err != nil {
			continue
		}
		// A service that runs Hysteria through docker, env or a shell is
		// not updated by HyRoute (deploy.ErrNotHysteria): not offered.
		if hyrelease.Older(in.Version, out.Target) && strings.HasPrefix(path.Base(in.Binary), "hysteria") {
			out.Outdated = append(out.Outdated, outdatedJSON{ID: srv.ID, Name: srv.Name, Version: in.Version})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
