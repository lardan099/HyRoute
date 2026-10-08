// Package fake is a scripted remote.Executor for tests: commands are
// answered by rules matched on their argv prefix, files live in a map, and
// every call is recorded so a test can assert what was (not) done.
package fake

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
)

// Call is one recorded operation.
type Call struct {
	Op   string // run, stream, read, write
	Args []string
	Sudo bool
	Path string
	Data []byte // written data
	Spec remote.FileSpec
}

// Rule answers commands whose argv starts with Prefix.
type Rule struct {
	prefix []string
	res    remote.Result
	err    error
	fn     func(remote.Cmd) (remote.Result, error)
	lines  []string
	times  int // answers left; 0 = unlimited
}

// Reply sets stdout and the exit code.
func (r *Rule) Reply(stdout string, code int) *Rule {
	r.res = remote.Result{Stdout: []byte(stdout), ExitCode: code}
	return r
}

// Fail sets stderr and a non-zero exit code.
func (r *Rule) Fail(stderr string, code int) *Rule {
	r.res = remote.Result{Stderr: []byte(stderr), ExitCode: code}
	return r
}

// Err makes the transport fail.
func (r *Rule) Err(err error) *Rule {
	r.err = err
	return r
}

// Do answers with a function.
func (r *Rule) Do(fn func(remote.Cmd) (remote.Result, error)) *Rule {
	r.fn = fn
	return r
}

// Lines sets what Stream emits.
func (r *Rule) Lines(ls ...string) *Rule {
	r.lines = ls
	return r
}

// Times limits the rule to n answers (then later-added or earlier rules
// apply again).
func (r *Rule) Times(n int) *Rule {
	r.times = n
	return r
}

// ErrReadOnly is returned for writes when the executor is read-only.
var ErrReadOnly = errors.New("fake: write on a read-only executor")

// Executor is the scripted executor.
type Executor struct {
	mu    sync.Mutex
	rules []*Rule
	files map[string][]byte
	calls []Call
	// ReadOnly fails WriteFile (import must not write).
	ReadOnly bool
	closed   bool
}

var _ remote.Executor = (*Executor)(nil)

// New returns an executor with no rules and no files.
func New() *Executor { return &Executor{files: map[string][]byte{}} }

// On adds a rule for commands starting with argv; the newest matching rule
// answers.
func (f *Executor) On(argv ...string) *Rule {
	r := &Rule{prefix: argv}
	f.mu.Lock()
	f.rules = append(f.rules, r)
	f.mu.Unlock()
	return r
}

// RootPaths answers what remote.CheckBinary asks: every path is itself
// (readlink -f) and is root's with mode 0755. Add it after other "stat"
// rules: the newest matching rule answers.
func (f *Executor) RootPaths() {
	f.On("readlink", "-f", "--").Do(func(c remote.Cmd) (remote.Result, error) {
		return remote.Result{Stdout: []byte(c.Args[len(c.Args)-1] + "\n")}, nil
	})
	f.On("stat", "-L", "-c", "%u %g %a", "--").Do(func(c remote.Cmd) (remote.Result, error) {
		return remote.Result{Stdout: []byte(strings.Repeat("0 0 755\n", len(c.Args)-5))}, nil
	})
}

// SetFile puts a file on the fake machine.
func (f *Executor) SetFile(path string, data []byte) {
	f.mu.Lock()
	f.files[path] = append([]byte(nil), data...)
	f.mu.Unlock()
}

// DeleteFile removes a file from the fake machine.
func (f *Executor) DeleteFile(path string) {
	f.mu.Lock()
	delete(f.files, path)
	f.mu.Unlock()
}

// File returns a file of the fake machine.
func (f *Executor) File(path string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[path]
	return b, ok
}

// Calls returns every recorded call.
func (f *Executor) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// Writes returns the WriteFile calls.
func (f *Executor) Writes() []Call {
	var ws []Call
	for _, c := range f.Calls() {
		if c.Op == "write" {
			ws = append(ws, c)
		}
	}
	return ws
}

// Commands returns the argv of every run and stream, space-joined.
func (f *Executor) Commands() []string {
	var cs []string
	for _, c := range f.Calls() {
		if c.Op == "run" || c.Op == "stream" {
			cs = append(cs, strings.Join(c.Args, " "))
		}
	}
	return cs
}

// Closed reports whether Close was called.
func (f *Executor) Closed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func (f *Executor) match(args []string) *Rule {
	for i := len(f.rules) - 1; i >= 0; i-- {
		r := f.rules[i]
		if len(r.prefix) > len(args) || r.times < 0 {
			continue
		}
		ok := true
		for j, p := range r.prefix {
			if args[j] != p {
				ok = false
				break
			}
		}
		if ok {
			if r.times > 0 {
				r.times--
				if r.times == 0 {
					r.times = -1 // used up
				}
			}
			return r
		}
	}
	return nil
}

func (f *Executor) answer(cmd remote.Cmd, op string) (*Rule, error) {
	if _, err := remote.CommandLine(cmd); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, errors.New("fake: closed")
	}
	f.calls = append(f.calls, Call{Op: op, Args: append([]string(nil), cmd.Args...), Sudo: cmd.Sudo})
	return f.match(cmd.Args), nil
}

// Run implements remote.Executor. Unmatched commands exit 127.
func (f *Executor) Run(ctx context.Context, cmd remote.Cmd) (remote.Result, error) {
	if err := ctx.Err(); err != nil {
		return remote.Result{}, err
	}
	r, err := f.answer(cmd, "run")
	if err != nil {
		return remote.Result{}, err
	}
	if r == nil {
		return remote.Result{ExitCode: 127, Stderr: []byte(fmt.Sprintf("fake: no rule for %q", strings.Join(cmd.Args, " ")))}, nil
	}
	if r.fn != nil {
		return r.fn(cmd)
	}
	return r.res, r.err
}

// Stream implements remote.Executor.
func (f *Executor) Stream(ctx context.Context, cmd remote.Cmd, line func(string)) error {
	r, err := f.answer(cmd, "stream")
	if err != nil {
		return err
	}
	if r == nil {
		return &remote.ExitError{Op: cmd.Args[0], Code: 127}
	}
	for _, l := range r.lines {
		if ctx.Err() != nil {
			return nil
		}
		line(l)
	}
	return r.err
}

// ReadFile implements remote.Executor.
func (f *Executor) ReadFile(ctx context.Context, path string, sudo bool) ([]byte, error) {
	if err := remote.CheckPath(path); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Op: "read", Path: path, Sudo: sudo})
	b, ok := f.files[path]
	if !ok {
		return nil, fmt.Errorf("%s: %w", path, fs.ErrNotExist)
	}
	return append([]byte(nil), b...), nil
}

// WriteFile implements remote.Executor.
func (f *Executor) WriteFile(ctx context.Context, path string, data []byte, spec remote.FileSpec) error {
	if err := remote.CheckPath(path); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, Call{Op: "write", Path: path, Sudo: spec.Sudo, Data: append([]byte(nil), data...), Spec: spec})
	if f.ReadOnly {
		return ErrReadOnly
	}
	f.files[path] = append([]byte(nil), data...)
	return nil
}

// Close implements remote.Executor.
func (f *Executor) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}
