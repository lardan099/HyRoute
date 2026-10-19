// Package batch runs bulk operations (P4-07): one action over many
// servers as a stored batch and ordinary jobs. The canary goes first;
// once its job completed, the rest run a few at a time; the first failure
// stops what has not started, and the servers of one cascade never run
// jobs of batches at the same time. The runner lives in the controller
// process and goes on with a batch in progress after a restart: its
// state is in the database. Nothing here writes to a server: every job
// is the one its single-server route queues, with its checks, backups and
// rollback.
package batch

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// How many jobs of a batch run at once after the canary.
const (
	DefaultParallel = 3
	MaxParallel     = 10
)

// MaxServers bounds the servers of one batch.
const MaxServers = 1000

var (
	// ErrNotRunning: only a running batch is stopped.
	ErrNotRunning = errors.New("batch: not running")
	// ErrNotFinished: only an ended batch is retried.
	ErrNotFinished = errors.New("batch: not finished")
	// ErrNothingToRetry: no server of the batch failed or was skipped.
	ErrNothingToRetry = errors.New("batch: nothing failed or was skipped")
	// ErrRetried: a batch retries this one already.
	ErrRetried = errors.New("batch: retried already")
)

// Store is what the runner keeps and reads.
type Store interface {
	store.Batches
	JobByID(ctx context.Context, id int64) (model.Job, error)
	ListJobs(ctx context.Context, f model.JobFilter) ([]model.Job, error)
	UserByID(ctx context.Context, id int64) (model.User, error)
	ServerByID(ctx context.Context, id int64) (model.Server, error)
	ListChains(ctx context.Context) ([]model.Chain, error)
}

// Queuer queues the job of a batch's action on one server for actor
// (Actions.Queue).
type Queuer interface {
	Queue(ctx context.Context, b model.Batch, serverID, actor int64) (model.Job, string, error)
}

// Runner starts the jobs of the batches.
type Runner struct {
	Store   Store
	Actions Queuer
	Log     *slog.Logger
	Now     func() time.Time
	// Poll is how often the batches are looked at without a wake-up (a
	// job that ended, a batch created or stopped).
	Poll time.Duration

	// mu makes a pass and a change from the API (create, stop, retry)
	// one at a time: a job is never queued for an item a stop skipped.
	mu   sync.Mutex
	wake chan struct{}
}

// New returns a runner; Run starts it.
func New(st Store, a Queuer, log *slog.Logger) *Runner {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Runner{Store: st, Actions: a, Log: log, Now: time.Now, Poll: 5 * time.Second, wake: make(chan struct{}, 1)}
}

func (r *Runner) poke() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// JobEnded hears a job that ended (jobs.Engine.OnEnd): the batch it
// belongs to may start the next ones.
func (r *Runner) JobEnded(context.Context, model.Job) { r.poke() }

// Run looks at the unfinished batches until ctx ends: first those an
// earlier process left, then on every wake-up and every Poll.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(r.Poll)
	defer t.Stop()
	for {
		r.Pass(ctx)
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-t.C:
		}
	}
}

// Create stores a batch of b's action, params and servers (b.Items: their
// server IDs in order) and starts it. Parallel 0 is DefaultParallel.
func (r *Runner) Create(ctx context.Context, b model.Batch) (model.Batch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.create(ctx, b)
}

// create is Create for a caller that holds r.mu.
func (r *Runner) create(ctx context.Context, b model.Batch) (model.Batch, error) {
	if b.Parallel == 0 {
		b.Parallel = DefaultParallel
	}
	if b.Parallel < 1 || b.Parallel > MaxParallel {
		return b, &model.FieldError{Field: "parallel", Msg: "Одновременно — от 1 до 10 серверов."}
	}
	if len(b.Items) == 0 {
		return b, &model.FieldError{Field: "servers", Msg: "Выберите серверы."}
	}
	now := r.Now()
	b.State, b.Stop, b.StoppedBy, b.CreatedAt, b.UpdatedAt, b.FinishedAt = model.BatchRunning, model.StopNone, 0, now, now, time.Time{}
	for i := range b.Items {
		b.Items[i] = model.BatchItem{Idx: i, ServerID: b.Items[i].ServerID, State: model.ItemPending, At: now}
	}
	if err := r.Store.CreateBatch(ctx, &b); err != nil {
		return b, err
	}
	r.Log.Info("batch created", "batch", b.ID, "action", b.Action, "servers", len(b.Items), "user", b.CreatedBy)
	r.poke()
	return b, nil
}

// Stop starts no more jobs of the batch: the servers not started are
// skipped, the running jobs go on.
func (r *Runner) Stop(ctx context.Context, id, actor int64) (model.Batch, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b, err := r.Store.BatchByID(ctx, id)
	if err != nil {
		return b, err
	}
	if b.State != model.BatchRunning {
		return b, ErrNotRunning
	}
	r.halt(&b, model.StopUser, actor)
	r.finishIfDone(&b)
	if err := r.save(ctx, &b); err != nil {
		return b, err
	}
	r.Log.Info("batch stopped", "batch", b.ID, "user", actor)
	return b, nil
}

// Retry starts a new batch of the same action over the servers that
// failed or were skipped, the canary first again.
func (r *Runner) Retry(ctx context.Context, id, actor int64) (model.Batch, error) {
	// One lock for the check and the new batch: two retries at once make
	// one batch.
	r.mu.Lock()
	defer r.mu.Unlock()
	b, err := r.Store.BatchByID(ctx, id)
	if err != nil {
		return b, err
	}
	if !b.State.Terminal() {
		return b, ErrNotFinished
	}
	if b.RetriedBy != 0 {
		return b, ErrRetried
	}
	next := model.Batch{Action: b.Action, Params: b.Params, Parallel: b.Parallel, RetryOf: b.ID, CreatedBy: actor}
	for _, it := range b.Items {
		if it.State == model.ItemFailed || it.State == model.ItemSkipped {
			next.Items = append(next.Items, model.BatchItem{ServerID: it.ServerID})
		}
	}
	if len(next.Items) == 0 {
		return b, ErrNothingToRetry
	}
	return r.create(ctx, next)
}

func (r *Runner) save(ctx context.Context, b *model.Batch) error {
	b.UpdatedAt = r.Now()
	// The state must reach the disk also when the controller is stopping.
	err := r.Store.SaveBatch(context.WithoutCancel(ctx), *b)
	if err != nil {
		r.Log.Error("batch: save", "batch", b.ID, "err", err)
	}
	return err
}

// Pass looks at every unfinished batch once: the items whose jobs ended,
// then the jobs that may start now.
func (r *Runner) Pass(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	bs, err := r.Store.UnfinishedBatches(ctx)
	if err != nil {
		if ctx.Err() == nil {
			r.Log.Error("batch: list", "err", err)
		}
		return
	}
	if len(bs) == 0 {
		return
	}
	for i := range bs {
		r.refresh(ctx, &bs[i])
	}
	chains, err := r.Store.ListChains(ctx)
	if err != nil {
		r.Log.Error("batch: cascades", "err", err)
		return
	}
	mates := cascadeMates(chains)
	// busy: the servers with a job of a batch in progress (any batch).
	busy := map[int64]bool{}
	for _, b := range bs {
		for _, it := range b.Items {
			if it.State.Active() {
				busy[it.ServerID] = true
			}
		}
	}
	for i := range bs {
		if ctx.Err() != nil {
			return
		}
		r.start(ctx, &bs[i], mates, busy)
	}
}

// refresh takes the results of the jobs of b that ended, and the item a
// controller restart left between its record and its job.
func (r *Runner) refresh(ctx context.Context, b *model.Batch) {
	changed, failed := false, false
	for i := range b.Items {
		it := &b.Items[i]
		switch it.State {
		case model.ItemRunning:
			j, err := r.Store.JobByID(ctx, it.JobID)
			if errors.Is(err, store.ErrNotFound) {
				it.State, it.Message, it.At = model.ItemFailed, "Задание не найдено.", r.Now()
				changed, failed = true, true
				continue
			} else if err != nil || !j.State.Terminal() {
				continue
			}
			it.At, changed = r.Now(), true
			if j.State == model.JobCompleted {
				it.State = model.ItemCompleted
			} else {
				it.State, it.Message, failed = model.ItemFailed, j.ErrorMessage, true
			}
		case model.ItemStarting:
			// The job may have been queued before the restart: the newest
			// job of the server, of the action's kind and author, queued
			// since the record.
			js, err := r.Store.ListJobs(ctx, model.JobFilter{ServerID: it.ServerID, Limit: 1})
			if err != nil {
				continue
			}
			if len(js) > 0 && js[0].Kind == JobKind(b.Action) && js[0].CreatedBy == b.CreatedBy && !js[0].CreatedAt.Before(it.At) {
				it.State, it.JobID = model.ItemRunning, js[0].ID
			} else {
				it.State = model.ItemPending
			}
			changed = true
		}
	}
	if failed {
		r.halt(b, model.StopFailed, 0)
	}
	if r.finishIfDone(b) {
		changed = true
	}
	if changed {
		r.save(ctx, b)
	}
}

// start queues the jobs of b that may start now: one while no job of the
// batch has completed (the canary), Parallel at a time after it, never on
// a server whose cascade has a job of a batch in progress. The author's
// right is checked as it is now, for every job.
func (r *Runner) start(ctx context.Context, b *model.Batch, mates map[int64][]int64, busy map[int64]bool) {
	if b.State != model.BatchRunning {
		return
	}
	pending := false
	for _, it := range b.Items {
		pending = pending || it.State == model.ItemPending
	}
	if !pending {
		return
	}
	perm := b.Action.Permission()
	u, err := r.author(ctx, b)
	if err != nil {
		return
	}
	if u == nil || !u.Role.Can(perm) {
		r.deny(ctx, b, -1, "Не запускался: у автора пакета больше нет права на это действие.")
		return
	}
	if via := Via(*b); via != 0 {
		srv, err := r.Store.ServerByID(ctx, via)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return
		}
		if err != nil || !u.Can(perm, srv.Tags) {
			r.deny(ctx, b, -1, "Не запускался: сервер, через который идёт загрузка, вне области автора пакета.")
			return
		}
	}
	canary := true
	active := 0
	for _, it := range b.Items {
		canary = canary && it.State != model.ItemCompleted
		if it.State.Active() {
			active++
		}
	}
	limit := b.Parallel
	if canary {
		limit = 1
	}
	for i := range b.Items {
		if active >= limit || ctx.Err() != nil {
			break
		}
		it := &b.Items[i]
		if it.State != model.ItemPending || conflicts(it.ServerID, mates, busy) {
			continue
		}
		srv, err := r.Store.ServerByID(ctx, it.ServerID)
		if errors.Is(err, store.ErrNotFound) {
			continue // deleted just now: the batch loses it
		} else if err != nil {
			return
		}
		if !u.Can(perm, srv.Tags) {
			r.deny(ctx, b, i, "Сервер вне области автора пакета: пакет остановлен.")
			return
		}
		if busy, err := r.serverBusy(ctx, it.ServerID); err != nil {
			return
		} else if busy {
			// Another job runs there: the next pass tries again.
			if it.Message != waitBusy {
				it.Message = waitBusy
				r.save(ctx, b)
			}
			continue
		}
		// The record goes first: a restart before the job is queued finds
		// it either way (refresh).
		it.State, it.At, it.Message = model.ItemStarting, r.Now(), ""
		if r.save(ctx, b) != nil {
			it.State = model.ItemPending
			return
		}
		j, note, err := r.Actions.Queue(ctx, *b, it.ServerID, b.CreatedBy)
		it.At = r.Now()
		var un *Unchanged
		switch {
		case errors.Is(err, jobs.ErrBusy):
			// A job was queued there just now: the next pass tries again.
			it.State, it.Message = model.ItemPending, waitBusy
		case errors.As(err, &un):
			it.State, it.Message = model.ItemUnchanged, un.Msg
		case err != nil:
			it.State, it.Message = model.ItemFailed, Message(err)
			r.Log.Warn("batch: job not queued", "batch", b.ID, "server", it.ServerID, "err", err)
			r.halt(b, model.StopFailed, 0)
			r.finishIfDone(b)
			r.save(ctx, b)
			return
		default:
			it.State, it.JobID, it.Canary, it.Message = model.ItemRunning, j.ID, canary, note
			active++
			busy[it.ServerID] = true
		}
		r.finishIfDone(b)
		r.save(ctx, b)
	}
}

// waitBusy is the message of an item whose server has another job.
const waitBusy = "Ждёт: на сервере выполняется другое задание."

// serverBusy: the server has an unfinished job. A server has one at a
// time, so it is its newest one (as Engine.SubmitOn would find).
func (r *Runner) serverBusy(ctx context.Context, id int64) (bool, error) {
	js, err := r.Store.ListJobs(ctx, model.JobFilter{ServerID: id, Limit: 1})
	if err != nil {
		return false, err
	}
	return len(js) > 0 && !js[0].State.Terminal(), nil
}

// author is the batch's author as now stored (nil: deleted).
func (r *Runner) author(ctx context.Context, b *model.Batch) (*model.User, error) {
	if b.CreatedBy == 0 {
		return nil, nil
	}
	u, err := r.Store.UserByID(ctx, b.CreatedBy)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, nil
	}
	return &u, nil
}

// deny stops b because its author may not go on; item i (-1: none) is
// the server they lost.
func (r *Runner) deny(ctx context.Context, b *model.Batch, i int, msg string) {
	r.halt(b, model.StopDenied, 0)
	if i >= 0 {
		b.Items[i].Message = msg
	}
	r.finishIfDone(b)
	r.save(ctx, b)
	r.Log.Warn("batch stopped: its author lost the right", "batch", b.ID, "user", b.CreatedBy)
}

// halt starts no more jobs of a running b: what is pending is skipped.
func (r *Runner) halt(b *model.Batch, why model.BatchStop, by int64) {
	if b.State != model.BatchRunning {
		return
	}
	b.State, b.Stop, b.StoppedBy = model.BatchStopping, why, by
	msg := map[model.BatchStop]string{
		model.StopUser:   "Не запускался: пакет остановлен.",
		model.StopFailed: "Не запускался: пакет остановлен после ошибки.",
		model.StopDenied: "Не запускался: у автора пакета больше нет права на это действие.",
	}[why]
	for i := range b.Items {
		if b.Items[i].State == model.ItemPending {
			b.Items[i].State, b.Items[i].Message, b.Items[i].At = model.ItemSkipped, msg, r.Now()
		}
	}
}

// finishIfDone ends b once no job of it runs and none is to start;
// true: it ended now.
func (r *Runner) finishIfDone(b *model.Batch) bool {
	if b.State.Terminal() {
		return false
	}
	failed := false
	for _, it := range b.Items {
		if it.State.Active() || it.State == model.ItemPending {
			return false
		}
		failed = failed || it.State == model.ItemFailed
	}
	switch {
	case failed:
		b.State = model.BatchFailed
	case b.Stop == model.StopUser || b.Stop == model.StopDenied:
		b.State = model.BatchStopped
	default:
		b.State = model.BatchCompleted
	}
	b.FinishedAt = r.Now()
	r.Log.Info("batch ended", "batch", b.ID, "state", b.State)
	return true
}

// cascadeMates are, for every server of a cascade, the other servers of
// its cascades.
func cascadeMates(chains []model.Chain) map[int64][]int64 {
	out := map[int64][]int64{}
	for _, c := range chains {
		for _, a := range c.Nodes {
			for _, b := range c.Nodes {
				if a != b {
					out[a] = append(out[a], b)
				}
			}
		}
	}
	return out
}

// conflicts: the server or one of its cascade mates has a job of a batch
// in progress.
func conflicts(id int64, mates map[int64][]int64, busy map[int64]bool) bool {
	if busy[id] {
		return true
	}
	for _, m := range mates[id] {
		if busy[m] {
			return true
		}
	}
	return false
}
