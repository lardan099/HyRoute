package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Connector opens a connection to a server (connect.Connector).
type Connector interface {
	Connect(ctx context.Context, serverID int64) (remote.Executor, error)
}

var (
	// ErrBusy: the server already has an unfinished job.
	ErrBusy = errors.New("the server already has a job in progress")
	// ErrNotRetryable: only failed jobs can be retried.
	ErrNotRetryable = errors.New("only a failed job can be retried")
	// ErrUnknownKind: no kind of this name is registered.
	ErrUnknownKind = errors.New("unknown job kind")
)

// Engine runs jobs.
type Engine struct {
	Store   store.Jobs
	Keys    *secrets.Keyring
	Redact  *redact.Redactor
	Connect Connector
	Log     *slog.Logger
	Now     func() time.Time
	// Workers bounds jobs running at once (different servers).
	Workers int
	// Lease is how long a claimed job is held without a heartbeat.
	Lease time.Duration
	// Poll is how often queued jobs are looked for without a wake-up.
	Poll time.Duration

	kinds  map[string]*Kind
	owner  string
	wake   chan struct{}
	events *broker
}

// New returns an engine; register kinds before Run.
func New(st store.Jobs, keys *secrets.Keyring, red *redact.Redactor, conn Connector, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if red == nil {
		red = redact.New()
	}
	b := make([]byte, 8)
	rand.Read(b)
	return &Engine{
		Store: st, Keys: keys, Redact: red, Connect: conn, Log: log, Now: time.Now,
		Workers: 4, Lease: 2 * time.Minute, Poll: 2 * time.Second,
		kinds: map[string]*Kind{}, owner: hex.EncodeToString(b), wake: make(chan struct{}, 1), events: newBroker(),
	}
}

// Register adds a job kind.
func (e *Engine) Register(k *Kind) { e.kinds[k.Name] = k }

func (e *Engine) poke() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func secretContext(jobID int64) string { return fmt.Sprintf("job/%d/secret", jobID) }

// Submit queues a job. secretParams are sealed and only reach steps
// through Env.Secret.
func (e *Engine) Submit(ctx context.Context, kind string, serverID int64, params any, secretParams map[string]string, actor int64) (model.Job, error) {
	k, ok := e.kinds[kind]
	if !ok {
		return model.Job{}, fmt.Errorf("%w %q", ErrUnknownKind, kind)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return model.Job{}, err
	}
	steps, err := k.Steps(raw)
	if err != nil {
		return model.Job{}, err
	}
	rows := make([]model.JobStep, len(steps))
	for i, s := range steps {
		rows[i] = model.JobStep{Idx: i, Name: s.Name, Phase: s.Phase}
	}
	j := model.Job{Kind: kind, ServerID: serverID, State: model.JobQueued, Params: raw, CreatedBy: actor, CreatedAt: e.Now()}
	var seal func(int64) ([]byte, error)
	if len(secretParams) > 0 {
		seal = func(id int64) ([]byte, error) {
			b, _ := json.Marshal(secretParams)
			return e.Keys.Seal(b, secretContext(id))
		}
	}
	if err := e.Store.CreateJob(ctx, &j, rows, seal); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return model.Job{}, ErrBusy
		}
		return model.Job{}, err
	}
	e.publishState(j)
	e.poke()
	return j, nil
}

// Run recovers interrupted jobs, then runs queued ones until ctx ends. It
// returns after the running jobs stopped.
func (e *Engine) Run(ctx context.Context) {
	e.recoverAll(ctx)
	sem := make(chan struct{}, max(e.Workers, 1))
	var wg sync.WaitGroup
	busy := map[int64]bool{}
	var mu sync.Mutex
	t := time.NewTicker(e.Poll)
	defer t.Stop()
	for {
		js, err := e.Store.UnfinishedJobs(ctx)
		if err != nil && ctx.Err() == nil {
			e.Log.Error("jobs: list", "err", err)
		}
		for _, j := range js {
			mu.Lock()
			skip := j.State != model.JobQueued || busy[j.ID]
			mu.Unlock()
			if skip {
				continue
			}
			ok, err := e.Store.ClaimJob(ctx, j.ID, e.owner, e.Now().Add(e.Lease))
			if err != nil || !ok {
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return
			}
			mu.Lock()
			busy[j.ID] = true
			mu.Unlock()
			wg.Add(1)
			go func(id int64) {
				defer wg.Done()
				defer func() { <-sem }()
				e.runJob(ctx, id)
				mu.Lock()
				delete(busy, id)
				mu.Unlock()
				e.poke()
			}(j.ID)
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-e.wake:
		case <-t.C:
		}
	}
}

// job loads a job with its kind, steps and secrets.
func (e *Engine) prepare(ctx context.Context, id int64) (model.Job, *Kind, []Step, []model.JobStep, *Env, error) {
	j, err := e.Store.JobByID(ctx, id)
	if err != nil {
		return j, nil, nil, nil, nil, err
	}
	k, ok := e.kinds[j.Kind]
	if !ok {
		return j, nil, nil, nil, nil, fmt.Errorf("%w %q", ErrUnknownKind, j.Kind)
	}
	steps, err := k.Steps(j.Params)
	if err != nil {
		return j, k, nil, nil, nil, err
	}
	rows, err := e.Store.JobSteps(ctx, id)
	if err != nil {
		return j, k, nil, nil, nil, err
	}
	if len(rows) != len(steps) {
		return j, k, nil, nil, nil, fmt.Errorf("job has %d steps stored, this controller builds %d", len(rows), len(steps))
	}
	for i := range rows {
		if rows[i].Name != steps[i].Name {
			return j, k, nil, nil, nil, fmt.Errorf("step %d is %q stored, %q in this controller", i, rows[i].Name, steps[i].Name)
		}
	}
	env := &Env{JobID: j.ID, ServerID: j.ServerID, CreatedBy: j.CreatedBy, Params: j.Params, eng: e, data: map[string]string{}}
	for k, v := range j.Data {
		env.data[k] = v
	}
	sealed, err := e.Store.JobSecret(ctx, id)
	if err != nil {
		return j, k, nil, nil, nil, fmt.Errorf("job secrets: %w", err)
	}
	if len(sealed) > 0 {
		b, err := e.Keys.Open(sealed, secretContext(id))
		if err != nil {
			return j, k, nil, nil, nil, fmt.Errorf("job secrets: %w", err)
		}
		if err := json.Unmarshal(b, &env.secrets); err != nil {
			return j, k, nil, nil, nil, err
		}
		for _, v := range env.secrets {
			e.Redact.Add(v)
		}
	}
	return j, k, steps, rows, env, nil
}

// resumeIndex is the first step that is not done or skipped.
func resumeIndex(rows []model.JobStep) int {
	for i, r := range rows {
		if r.State != model.StepDone && r.State != model.StepSkipped {
			return i
		}
	}
	return len(rows)
}

func (e *Engine) save(ctx context.Context, j *model.Job, env *Env) {
	// The data is in the database already (Env.Set); the copy is for the
	// subscribers.
	if env != nil {
		j.Data = env.snapshot()
	}
	// The write outlives a cancelled run: the state must reach the disk.
	if err := e.Store.UpdateJob(context.WithoutCancel(ctx), *j); err != nil {
		e.Log.Error("jobs: save", "job", j.ID, "err", err)
	}
	e.publishState(*j)
}

func (e *Engine) saveStep(ctx context.Context, s model.JobStep) {
	if err := e.Store.UpdateJobStep(context.WithoutCancel(ctx), s); err != nil {
		e.Log.Error("jobs: save step", "job", s.JobID, "step", s.Name, "err", err)
	}
	e.events.publish(s.JobID, Event{Type: "step", Step: &s})
}

// fail ends a job with a message for people and redacted details.
func (e *Engine) fail(ctx context.Context, j *model.Job, env *Env, err error) {
	msg, details := "Задание не выполнено.", err.Error()
	var se *StepError
	if errors.As(err, &se) {
		// Details are the technical cause; the message is already shown.
		msg, details = se.Message, ""
		if se.Err != nil {
			details = se.Err.Error()
		}
	}
	j.State, j.ErrorMessage, j.ErrorDetails = model.JobFailed, msg, e.Redact.String(details)
	j.FinishedAt, j.LeaseOwner, j.LeaseUntil = e.Now(), "", time.Time{}
	line := msg
	if j.ErrorDetails != "" {
		line += " (" + j.ErrorDetails + ")"
	}
	e.log(j.ID, "error", j.CurrentStep, line)
	e.save(ctx, j, env)
	e.finished(ctx, j, env)
}

// finished runs the kind's Finished hook for a job that just ended.
func (e *Engine) finished(ctx context.Context, j *model.Job, env *Env) {
	k := e.kinds[j.Kind]
	if k == nil || k.Finished == nil || env == nil {
		return
	}
	k.Finished(context.WithoutCancel(ctx), env, *j)
}

func (e *Engine) runJob(ctx context.Context, id int64) {
	j, _, steps, rows, env, err := e.prepare(ctx, id)
	if err != nil {
		if j.ID != 0 {
			e.fail(ctx, &j, env, fmt.Errorf("prepare: %w", err))
		}
		return
	}
	defer env.close()

	hbCtx, stopHB := context.WithCancel(ctx)
	defer stopHB()
	go e.heartbeat(hbCtx, j.ID)

	if j.StartedAt.IsZero() {
		j.StartedAt = e.Now()
	}
	e.log(j.ID, "info", "", fmt.Sprintf("Задание запущено (попытка %d).", j.Attempt))
	for i := resumeIndex(rows); i < len(steps); i++ {
		st, row := steps[i], rows[i]
		j.State, j.CurrentStep = st.Phase, st.Name
		e.save(ctx, &j, env)
		env.step = st.Name
		row.State, row.Attempt, row.StartedAt, row.FinishedAt, row.Error = model.StepRunning, row.Attempt+1, e.Now(), time.Time{}, ""
		e.saveStep(ctx, row)

		skipped := false
		if st.Done != nil {
			done, err := st.Done(ctx, env)
			if err == nil && done {
				skipped = true
			} else if err != nil {
				e.stepFailed(ctx, &j, env, steps, rows, i, err)
				return
			}
		}
		if !skipped {
			err = st.Run(ctx, env)
		}
		if serr := env.takeSetErr(); serr != nil && err == nil {
			// What the step changed may not be recorded for the rollback.
			err = Fail("Не удалось сохранить состояние задания в базе controller.", serr)
		}
		if ctx.Err() != nil {
			// The controller is stopping: the job stays as it is and is
			// recovered on the next start.
			return
		}
		if err != nil {
			e.stepFailed(ctx, &j, env, steps, rows, i, err)
			return
		}
		row.State, row.FinishedAt = model.StepDone, e.Now()
		if skipped {
			row.State = model.StepSkipped
			e.log(j.ID, "info", st.Name, "Уже сделано, шаг пропущен.")
		}
		rows[i] = row
		e.saveStep(ctx, row)
	}
	j.State, j.CurrentStep, j.FinishedAt, j.LeaseOwner, j.LeaseUntil = model.JobCompleted, "", e.Now(), "", time.Time{}
	e.log(j.ID, "info", "", "Задание выполнено.")
	e.save(ctx, &j, env)
	e.finished(ctx, &j, env)
}

// stepFailed records the failure of step i, rolls back the steps done in
// this job that can be undone, and fails the job.
func (e *Engine) stepFailed(ctx context.Context, j *model.Job, env *Env, steps []Step, rows []model.JobStep, i int, err error) {
	row := rows[i]
	row.State, row.FinishedAt, row.Error = model.StepFailed, e.Now(), e.Redact.String(err.Error())
	rows[i] = row
	e.saveStep(ctx, row)
	e.rollback(ctx, j, env, steps, rows, i)
	e.fail(ctx, j, env, err)
}

// rollback undoes the failed step i and the steps before it, newest
// first, and records how it went for the Finished hook. Steps rolled back
// already (before a restart) are not undone again.
func (e *Engine) rollback(ctx context.Context, j *model.Job, env *Env, steps []Step, rows []model.JobStep, i int) {
	// The failed step itself may have changed part of what it does (a
	// certificate written, its key not): its Undo goes first. Undo acts on
	// what a step recorded (Env.Set) before changing anything, so it is
	// safe for a step that changed nothing.
	var undo []int
	if i < len(steps) && steps[i].Undo != nil {
		undo = append(undo, i)
	}
	// Skipped steps too: after a restart a step finds its own effect in
	// place and is skipped, yet its record is there to undo.
	for k := min(i, len(steps)) - 1; k >= 0; k-- {
		if (rows[k].State == model.StepDone || rows[k].State == model.StepSkipped) && steps[k].Undo != nil {
			undo = append(undo, k)
		}
	}
	result := RollbackNothing
	if len(undo) > 0 {
		j.State = model.JobRollingBack
		e.save(ctx, j, env)
		e.log(j.ID, "warn", j.CurrentStep, "Откат изменений этого задания.")
		for _, k := range undo {
			env.step = steps[k].Name
			uerr := steps[k].Undo(context.WithoutCancel(ctx), env)
			if errors.Is(uerr, ErrNothingToUndo) {
				continue
			}
			if uerr != nil {
				e.log(j.ID, "error", steps[k].Name, "Откат не удался: "+uerr.Error())
				result = RollbackFailed
				continue
			}
			if result == RollbackNothing {
				result = RollbackClean
			}
			if k != i {
				rows[k].State = model.StepRolledBack
				e.saveStep(ctx, rows[k])
			}
			e.log(j.ID, "info", steps[k].Name, "Откачено.")
		}
	}
	env.mu.Lock()
	env.rollback = result
	env.mu.Unlock()
}

// finishRollback completes a rollback a controller restart interrupted.
// The job failed already: it never goes forward again (a retry is the
// admin's decision). Each Undo acts on its own records, so one that ran
// before the restart finds nothing left to do.
func (e *Engine) finishRollback(ctx context.Context, j *model.Job, env *Env, steps []Step, rows []model.JobStep) {
	i := slices.IndexFunc(rows, func(r model.JobStep) bool { return r.State == model.StepFailed })
	name, cause := j.CurrentStep, errors.New("interrupted")
	if i < 0 {
		i = len(rows)
	} else {
		name = rows[i].Name
		if rows[i].Error != "" {
			cause = errors.New(rows[i].Error)
		}
	}
	e.log(j.ID, "warn", name, "Controller был перезапущен во время отката изменений. Откат продолжается.")
	e.rollback(ctx, j, env, steps, rows, i)
	e.fail(ctx, j, env, Fail("Задание не выполнено на шаге «"+name+"». Controller перезапускался во время отката; после перезапуска откат продолжен.", cause))
}

func (e *Engine) heartbeat(ctx context.Context, id int64) {
	t := time.NewTicker(e.Lease / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Only the lease columns: the job's state belongs to runJob.
			e.Store.ExtendLease(ctx, id, e.owner, e.Now().Add(e.Lease))
		}
	}
}

// Retry requeues a failed job from the nearest safe step at or before the
// first unfinished one.
func (e *Engine) Retry(ctx context.Context, id, actor int64) (model.Job, error) {
	j, _, steps, rows, env, err := e.prepare(ctx, id)
	if err != nil {
		return j, err
	}
	if j.State != model.JobFailed {
		return j, ErrNotRetryable
	}
	e.requeue(ctx, &j, env, steps, rows, fmt.Sprintf("Повтор запрошен пользователем %d.", actor))
	return j, nil
}

func (e *Engine) requeue(ctx context.Context, j *model.Job, env *Env, steps []Step, rows []model.JobStep, why string) {
	from := resumeIndex(rows)
	for from > 0 && from < len(steps) && !steps[from].Safe {
		from--
	}
	if from == len(steps) {
		from = 0
	}
	for i := from; i < len(rows); i++ {
		rows[i].State, rows[i].Error, rows[i].StartedAt, rows[i].FinishedAt = model.StepPending, "", time.Time{}, time.Time{}
		e.saveStep(ctx, rows[i])
	}
	j.State, j.CurrentStep, j.ErrorMessage, j.ErrorDetails = model.JobQueued, "", "", ""
	j.Attempt++
	j.FinishedAt, j.LeaseOwner, j.LeaseUntil = time.Time{}, "", time.Time{}
	stepName := ""
	if from < len(steps) {
		stepName = steps[from].Name
	}
	e.log(j.ID, "info", "", why+" Продолжение с шага «"+stepName+"».")
	e.save(ctx, j, env)
	e.poke()
}

// recoverAll handles jobs a previous controller process left unfinished.
func (e *Engine) recoverAll(ctx context.Context) {
	js, err := e.Store.UnfinishedJobs(ctx)
	if err != nil {
		e.Log.Error("jobs: recovery list", "err", err)
		return
	}
	for _, j := range js {
		if j.State == model.JobQueued {
			// Never started: just release a stale lease.
			if j.LeaseOwner != "" {
				j.LeaseOwner, j.LeaseUntil = "", time.Time{}
				e.Store.UpdateJob(ctx, j)
			}
			continue
		}
		e.recoverJob(ctx, j.ID)
	}
}

func (e *Engine) recoverJob(ctx context.Context, id int64) {
	j, k, steps, rows, env, err := e.prepare(ctx, id)
	if err != nil {
		if j.ID != 0 {
			e.fail(ctx, &j, env, Fail("Задание прервано перезапуском controller и не может быть продолжено.", err))
		}
		return
	}
	defer env.close()
	was, rollingBack := j.CurrentStep, j.State == model.JobRollingBack
	for i := range rows {
		if rows[i].State == model.StepRunning {
			rows[i].State, rows[i].Error = model.StepFailed, "interrupted by a controller restart"
			e.saveStep(ctx, rows[i])
		}
	}
	j.State = model.JobRecovering
	e.save(ctx, &j, env)
	if rollingBack {
		e.finishRollback(ctx, &j, env, steps, rows)
		return
	}
	e.log(j.ID, "warn", was, "Controller был перезапущен во время шага «"+was+"». Проверка фактического состояния сервера.")
	if k.Recover == nil {
		e.fail(ctx, &j, env, Fail("Задание прервано перезапуском controller. Проверьте состояние сервера и повторите.", errors.New("interrupted")))
		return
	}
	env.step = "recover"
	res, rerr := k.Recover(ctx, env)
	switch {
	case rerr != nil || res == ResolveFailed:
		if rerr == nil {
			rerr = errors.New("recovery check failed")
		}
		e.fail(ctx, &j, env, rerr)
	case res == ResolveCompleted:
		for i := range rows {
			if rows[i].State != model.StepDone && rows[i].State != model.StepSkipped {
				rows[i].State = model.StepSkipped
				e.saveStep(ctx, rows[i])
			}
		}
		j.State, j.CurrentStep, j.FinishedAt, j.LeaseOwner, j.LeaseUntil = model.JobCompleted, "", e.Now(), "", time.Time{}
		e.log(j.ID, "info", "", "Проверка показала, что результат задания уже на сервере. Задание выполнено.")
		e.save(ctx, &j, env)
		e.finished(ctx, &j, env)
	case res == ResolveRetry:
		e.requeue(ctx, &j, env, steps, rows, "Проверка после перезапуска: задание продолжится.")
	}
}

// log writes a redacted line to the job log and to subscribers.
func (e *Engine) log(jobID int64, level, step, msg string) {
	l := model.JobLog{JobID: jobID, Time: e.Now(), Level: level, Step: step, Message: e.Redact.String(msg)}
	if err := e.Store.AppendJobLog(context.Background(), &l); err != nil {
		e.Log.Error("jobs: log", "job", jobID, "err", err)
		return
	}
	e.events.publish(jobID, Event{Type: "log", Log: &l})
}

func (e *Engine) publishState(j model.Job) {
	e.events.publish(j.ID, Event{Type: "job", Job: &j})
}

// Subscribe streams the events of a job until cancel is called.
func (e *Engine) Subscribe(jobID int64) (<-chan Event, func()) {
	return e.events.subscribe(jobID)
}
