package netwatch

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// errWorkerDown: too many calls hung; the worker is not restarted.
var errWorkerDown = errors.New("служба не отвечает, запросы к ней отключены до перезапуска HyRoute")

// worker runs calls on one dedicated goroutine (locked to its OS thread
// for COM): the thread starts on the first request and exits after idle
// without requests, so nothing holds a thread while nobody asks. A call not
// answered within timeout is abandoned with its thread (if it ever returns,
// the thread closes its state and exits without answering) and the next
// request starts a fresh one; after maxAbandoned such threads the worker
// is down and requests fail at once. A panic in a call is answered as an
// error and closes its thread normally (not counted).
type worker[S, Q, R any] struct {
	open         func() (S, error)
	call         func(S, Q) (R, error)
	close        func(S)
	timeout      time.Duration
	idle         time.Duration
	maxAbandoned int
	lockThread   bool
	timeoutErr   error

	mu        sync.Mutex
	cur       *wthread[Q, R]
	abandoned int
	down      bool
	starts    int // threads started (tests)
}

type wresult[R any] struct {
	r   R
	err error
}

type wjob[Q, R any] struct {
	q    Q
	resp chan wresult[R] // 1-buffered
}

type wthread[Q, R any] struct {
	reqs      chan wjob[Q, R]
	done      chan struct{} // closed when the thread no longer takes requests
	doneOnce  sync.Once
	abandoned atomic.Bool
}

func (t *wthread[Q, R]) closeDone() { t.doneOnce.Do(func() { close(t.done) }) }

// Down reports whether the worker gave up on its calls.
func (w *worker[S, Q, R]) Down() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.down
}

// Do runs call(q) on the worker's thread.
func (w *worker[S, Q, R]) Do(q Q) (R, error) {
	var zero R
	for {
		w.mu.Lock()
		if w.down {
			w.mu.Unlock()
			return zero, errWorkerDown
		}
		t := w.cur
		if t == nil {
			t = &wthread[Q, R]{reqs: make(chan wjob[Q, R]), done: make(chan struct{})}
			w.cur = t
			w.starts++
			go w.run(t)
		}
		w.mu.Unlock()
		j := wjob[Q, R]{q: q, resp: make(chan wresult[R], 1)}
		// Handing the job over waits for the call before it (another
		// caller's, bounded by that caller's timeout): giving up here says
		// nothing about the thread, so it is not abandoned.
		wait := time.NewTimer(w.timeout)
		select {
		case t.reqs <- j:
			wait.Stop()
		case <-t.done:
			wait.Stop()
			continue // the thread went (idle, a panic, abandoned): a fresh one
		case <-wait.C:
			return zero, w.timeoutErr
		}
		// Only a call the thread took and did not answer in time retires it.
		timer := time.NewTimer(w.timeout)
		select {
		case res := <-j.resp:
			timer.Stop()
			return res.r, res.err
		case <-timer.C:
			w.abandon(t)
			return zero, w.timeoutErr
		}
	}
}

// abandon retires thread t (once): it is no longer given requests.
func (w *worker[S, Q, R]) abandon(t *wthread[Q, R]) {
	w.mu.Lock()
	if w.cur == t {
		w.cur = nil
		w.abandoned++
		if w.abandoned >= w.maxAbandoned {
			w.down = true
		}
	}
	w.mu.Unlock()
	t.abandoned.Store(true)
	t.closeDone()
}

// leave: t takes no more requests.
func (w *worker[S, Q, R]) leave(t *wthread[Q, R]) {
	w.mu.Lock()
	if w.cur == t {
		w.cur = nil
	}
	w.mu.Unlock()
	t.closeDone()
}

func (w *worker[S, Q, R]) run(t *wthread[Q, R]) {
	if w.lockThread {
		// Never unlocked: the thread ends with the goroutine, and its COM
		// state with it.
		runtime.LockOSThread()
	}
	var s S
	opened := false
	idle := time.NewTimer(w.idle)
	defer idle.Stop()
	for {
		select {
		case j := <-t.reqs:
			if !opened {
				var err error
				if s, err = w.safeOpen(); err != nil {
					j.resp <- wresult[R]{err: err}
					w.leave(t)
					return
				}
				opened = true
			}
			r, panicked, err := w.safeCall(s, j.q)
			if t.abandoned.Load() {
				w.close(s) // nobody waits for the answer any more
				return
			}
			j.resp <- wresult[R]{r: r, err: err}
			if panicked {
				w.leave(t)
				w.close(s)
				return
			}
			idle.Reset(w.idle)
		case <-idle.C:
			w.leave(t)
			if opened {
				w.close(s)
			}
			return
		}
	}
}

func (w *worker[S, Q, R]) safeOpen() (s S, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("внутренняя ошибка: %v", p)
		}
	}()
	return w.open()
}

func (w *worker[S, Q, R]) safeCall(s S, q Q) (r R, panicked bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			err, panicked = fmt.Errorf("внутренняя ошибка: %v", p), true
		}
	}()
	r, err = w.call(s, q)
	return r, false, err
}
