// Package jobs runs long operations on servers (deploy, preflight,
// import…) as jobs: ordered, idempotent steps with their state in the
// database, a redacted log, retry from a safe step, rollback when starting
// or verifying fails, and recovery after a controller restart that checks
// the actual state of the server instead of blindly continuing.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Step is one step of a job kind.
type Step struct {
	Name  string
	Phase model.JobState
	// Safe: a retry may start at this step; the steps before it need not
	// run again.
	Safe bool
	// Done reports whether the step's effect is already in place; the step
	// is then skipped. Nil: always run.
	Done func(ctx context.Context, env *Env) (bool, error)
	Run  func(ctx context.Context, env *Env) error
	// Undo reverts the step when it or a later step fails, also when the
	// step was skipped (Done) or failed halfway: it acts only on what the
	// step recorded with Env.Set before changing anything, and returns
	// ErrNothingToUndo when there is no record. Nil: nothing to undo.
	Undo func(ctx context.Context, env *Env) error
}

// Resolution is what an interrupted job does after its recovery check.
type Resolution int

const (
	// ResolveFailed: mark the job failed (the recovery error explains).
	ResolveFailed Resolution = iota
	// ResolveCompleted: the server shows the job's effect in place.
	ResolveCompleted
	// ResolveRetry: requeue the job from the nearest safe step.
	ResolveRetry
)

// Kind is a type of job.
type Kind struct {
	Name string
	// Steps lists the steps for the params; it must return the same list
	// for the same params (a restarted controller rebuilds it).
	Steps func(params json.RawMessage) ([]Step, error)
	// Recover inspects the server after a restart interrupted the job.
	// Nil: interrupted jobs fail with an explanation. A job interrupted
	// in its rollback is not asked about: the rollback is finished.
	Recover func(ctx context.Context, env *Env) (Resolution, error)
	// Finished runs once the job has completed or failed (not when the
	// controller stops in the middle), e.g. to record the server's state.
	Finished func(ctx context.Context, env *Env, j model.Job)
}

// StepError is a step failure with a message for people.
type StepError struct {
	Message string
	Err     error
}

func (e *StepError) Error() string {
	if e.Err == nil {
		return e.Message
	}
	return e.Message + " (" + e.Err.Error() + ")"
}

func (e *StepError) Unwrap() error { return e.Err }

// ErrNothingToUndo is returned by an Undo that found nothing of its step
// to revert: the rollback goes on without a log line for it.
var ErrNothingToUndo = errors.New("nothing to undo")

// Fail is a StepError: message is shown in the UI, err is the technical
// cause (redacted before it is stored).
func Fail(message string, err error) error { return &StepError{Message: message, Err: err} }

// Env is what a step sees of its job.
type Env struct {
	JobID    int64
	ServerID int64
	// Servers are the other servers of the job (model.Job.Servers).
	Servers   []int64
	CreatedBy int64 // user who started the job (0: the system)
	Params    json.RawMessage

	eng      *Engine
	step     string
	mu       sync.Mutex
	data     map[string]string
	secrets  map[string]string
	setErr   error
	rollback Rollback
	// links are the connections, one per server of the job.
	links map[int64]*serverConn
}

// serverConn is the job's connection to one of its servers. redial: the
// connection was given up (lost, or before a rollback), and the next
// ExecOn opens a new one once: if that fails, dialErr is what later calls
// get, without dialing again.
type serverConn struct {
	exec    *conn
	redial  bool
	dialErr error
}

// conn is the job's connection. It notes that the connection is lost (an
// operation failed with remote.UnreachableError), so that the next
// Env.Exec opens a new one.
type conn struct {
	remote.Executor
	lost atomic.Bool
}

func (c *conn) note(err error) error {
	var ue *remote.UnreachableError
	if errors.As(err, &ue) {
		c.lost.Store(true)
	}
	return err
}

func (c *conn) Run(ctx context.Context, cmd remote.Cmd) (remote.Result, error) {
	res, err := c.Executor.Run(ctx, cmd)
	return res, c.note(err)
}

func (c *conn) Stream(ctx context.Context, cmd remote.Cmd, line func(string)) error {
	return c.note(c.Executor.Stream(ctx, cmd, line))
}

func (c *conn) ReadFile(ctx context.Context, path string, sudo bool) ([]byte, error) {
	b, err := c.Executor.ReadFile(ctx, path, sudo)
	return b, c.note(err)
}

func (c *conn) WriteFile(ctx context.Context, path string, data []byte, f remote.FileSpec) error {
	return c.note(c.Executor.WriteFile(ctx, path, data, f))
}

// Rollback is how the rollback of a failed job went.
type Rollback int

const (
	// RollbackNotRun: no step failed in this process (the job completed,
	// or failed in its recovery check).
	RollbackNotRun Rollback = iota
	// RollbackNothing: every Undo found nothing of its step to revert.
	RollbackNothing
	// RollbackClean: changes were reverted, every Undo succeeded.
	RollbackClean
	// RollbackFailed: an Undo failed.
	RollbackFailed
)

// Rollback reports how the rollback went (Finished uses it).
func (e *Env) Rollback() Rollback {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rollback
}

// DecodeParams decodes the job's params into v.
func (e *Env) DecodeParams(v any) error { return json.Unmarshal(e.Params, v) }

// Get returns a value an earlier step stored.
func (e *Env) Get(k string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.data[k]
}

// Set stores a value for later steps and the rollback. It is written to
// the database before Set returns, so a step records what it is about to
// change before changing it: a controller that dies in the middle leaves
// the record for the recovery. Never store secrets here. An error also
// fails the step once it returns.
func (e *Env) Set(k, v string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.data == nil {
		e.data = map[string]string{}
	}
	old, had := e.data[k]
	if had && old == v {
		return nil
	}
	e.data[k] = v
	if e.eng == nil {
		return nil
	}
	if err := e.eng.Store.SetJobData(context.Background(), e.JobID, e.data); err != nil {
		if had {
			e.data[k] = old
		} else {
			delete(e.data, k)
		}
		err = fmt.Errorf("save job data %q: %w", k, err)
		if e.setErr == nil {
			e.setErr = err
		}
		return err
	}
	return nil
}

// takeSetErr returns and clears the first failed Set.
func (e *Env) takeSetErr() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	err := e.setErr
	e.setErr = nil
	return err
}

// snapshot is a copy of the data.
func (e *Env) snapshot() map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	m := make(map[string]string, len(e.data))
	for k, v := range e.data {
		m[k] = v
	}
	return m
}

// Secret returns a secret parameter of the job.
func (e *Env) Secret(k string) string { return e.secrets[k] }

// Logf, Warnf: a line of the job log, redacted.
func (e *Env) Logf(format string, args ...any) {
	e.eng.log(e.JobID, "info", e.step, fmt.Sprintf(format, args...))
}

func (e *Env) Warnf(format string, args ...any) {
	e.eng.log(e.JobID, "warn", e.step, fmt.Sprintf(format, args...))
}

// Exec is the connection to the job's server (ServerID), opened on first
// use and closed when the job ends. A lost connection is replaced by a
// new one, once.
func (e *Env) Exec(ctx context.Context) (remote.Executor, error) {
	if e.ServerID == 0 {
		return nil, errors.New("job has no server")
	}
	return e.ExecOn(ctx, e.ServerID)
}

// ExecOn is Exec for any server of the job: ServerID or one of Servers.
// Each server has a connection of its own.
func (e *Env) ExecOn(ctx context.Context, serverID int64) (remote.Executor, error) {
	if serverID == 0 || (serverID != e.ServerID && !slices.Contains(e.Servers, serverID)) {
		return nil, fmt.Errorf("server %d is not one of the job's", serverID)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.links == nil {
		e.links = map[int64]*serverConn{}
	}
	l := e.links[serverID]
	if l == nil {
		l = &serverConn{}
		e.links[serverID] = l
	}
	if l.exec != nil && !l.exec.lost.Load() {
		return l.exec, nil
	}
	if l.exec != nil {
		l.drop()
	}
	if l.dialErr != nil {
		return nil, l.dialErr
	}
	if e.eng.Connect == nil {
		return nil, errors.New("no connector")
	}
	ex, err := e.eng.Connect.Connect(ctx, serverID)
	if err != nil {
		if l.redial {
			l.dialErr = err
		}
		return nil, err
	}
	l.exec, l.redial = &conn{Executor: ex}, false
	return l.exec, nil
}

// drop gives up the connection: it is closed in the background (a dead
// one may take long), and the next ExecOn dials again.
func (l *serverConn) drop() {
	if l.exec != nil {
		go l.exec.Close()
		l.exec = nil
	}
	l.redial = true
}

// reconnect makes the next ExecOn of every server open a new connection,
// for the rollback: the one the failed step used may be dead without
// anything having noticed yet.
func (e *Env) reconnect() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.links == nil {
		e.links = map[int64]*serverConn{}
	}
	for _, id := range append([]int64{e.ServerID}, e.Servers...) {
		if id != 0 && e.links[id] == nil {
			e.links[id] = &serverConn{}
		}
	}
	for _, l := range e.links {
		l.drop()
		l.dialErr = nil
	}
}

func (e *Env) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, l := range e.links {
		if l.exec != nil {
			l.exec.Close()
			l.exec = nil
		}
	}
}
