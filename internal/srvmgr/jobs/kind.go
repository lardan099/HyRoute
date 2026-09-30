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
	"sync"

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
	// Undo reverts the step when a later step fails. Nil: nothing to undo.
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
	// Nil: interrupted jobs fail with an explanation.
	Recover func(ctx context.Context, env *Env) (Resolution, error)
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

// Fail is a StepError: message is shown in the UI, err is the technical
// cause (redacted before it is stored).
func Fail(message string, err error) error { return &StepError{Message: message, Err: err} }

// Env is what a step sees of its job.
type Env struct {
	JobID    int64
	ServerID int64
	Params   json.RawMessage

	eng     *Engine
	step    string
	mu      sync.Mutex
	data    map[string]string
	secrets map[string]string
	exec    remote.Executor
	dirty   bool
}

// DecodeParams decodes the job's params into v.
func (e *Env) DecodeParams(v any) error { return json.Unmarshal(e.Params, v) }

// Get returns a value an earlier step stored.
func (e *Env) Get(k string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.data[k]
}

// Set stores a value for later steps; it survives a restart. Never store
// secrets here.
func (e *Env) Set(k, v string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.data == nil {
		e.data = map[string]string{}
	}
	e.data[k] = v
	e.dirty = true
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

// Exec is the connection to the job's server, opened on first use and
// closed when the job ends.
func (e *Env) Exec(ctx context.Context) (remote.Executor, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exec != nil {
		return e.exec, nil
	}
	if e.ServerID == 0 {
		return nil, errors.New("job has no server")
	}
	if e.eng.Connect == nil {
		return nil, errors.New("no connector")
	}
	ex, err := e.eng.Connect.Connect(ctx, e.ServerID)
	if err != nil {
		return nil, err
	}
	e.exec = ex
	return ex, nil
}

func (e *Env) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.exec != nil {
		e.exec.Close()
		e.exec = nil
	}
}
