package netwatch

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeState is what a worker thread opened.
type fakeState struct{ id int32 }

type fakeWorker struct {
	opens, closes atomic.Int32
	block         chan struct{} // calls wait on it while set
	panicNext     atomic.Bool
	delay         time.Duration // each call takes this long
	mu            sync.Mutex
	callers       []int32 // state IDs the calls ran on
}

func (f *fakeWorker) worker(timeout, idle time.Duration) *worker[*fakeState, int, int] {
	return &worker[*fakeState, int, int]{
		open: func() (*fakeState, error) {
			return &fakeState{id: f.opens.Add(1)}, nil
		},
		call: func(s *fakeState, q int) (int, error) {
			f.mu.Lock()
			f.callers = append(f.callers, s.id)
			b := f.block
			f.mu.Unlock()
			if b != nil {
				<-b
			}
			time.Sleep(f.delay)
			if f.panicNext.CompareAndSwap(true, false) {
				panic("boom")
			}
			return q * 2, nil
		},
		close:        func(*fakeState) { f.closes.Add(1) },
		timeout:      timeout,
		idle:         idle,
		maxAbandoned: 3,
		timeoutErr:   errors.New("NLM не отвечает"),
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); !ok(); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal(what)
		}
	}
}

func TestWorkerLazyAndIdle(t *testing.T) {
	f := &fakeWorker{}
	// The idle is long enough not to pass between two calls on a slow
	// runner.
	w := f.worker(time.Second, 300*time.Millisecond)
	if w.starts != 0 || f.opens.Load() != 0 {
		t.Fatal("started before the first request")
	}
	if r, err := w.Do(21); r != 42 || err != nil {
		t.Fatal(r, err)
	}
	if r, err := w.Do(1); r != 2 || err != nil || f.opens.Load() != 1 {
		t.Fatal(r, err, f.opens.Load())
	}
	waitFor(t, "idle exit", func() bool { return f.closes.Load() == 1 })
	if r, err := w.Do(2); r != 4 || err != nil || f.opens.Load() != 2 {
		t.Fatal("no fresh thread after the idle exit")
	}
}

// testCallTimeout bounds calls that block until released: long enough for
// a fresh thread to take the job on a slow runner (a hand-over that times
// out abandons nothing).
const testCallTimeout = 200 * time.Millisecond

func TestWorkerTimeoutAbandonsAndDown(t *testing.T) {
	f := &fakeWorker{}
	w := f.worker(testCallTimeout, time.Hour)
	release := make(chan struct{})
	f.block = release
	for i := 1; i <= 3; i++ {
		if _, err := w.Do(i); err == nil || err.Error() != "NLM не отвечает" {
			t.Fatal(err)
		}
		if w.Down() != (i == 3) {
			t.Fatalf("down after %d abandoned: %v", i, w.Down())
		}
	}
	if f.opens.Load() != 3 {
		t.Fatalf("each attempt on a fresh thread: %d opens", f.opens.Load())
	}
	start := time.Now()
	if _, err := w.Do(9); !errors.Is(err, errWorkerDown) || time.Since(start) >= testCallTimeout/2 {
		t.Fatal("a down worker does not fail at once", err)
	}
	// The hung calls return: their threads close and answer nobody.
	close(release)
	waitFor(t, "abandoned threads closed", func() bool { return f.closes.Load() == 3 })
}

func TestWorkerTimeoutThenFresh(t *testing.T) {
	f := &fakeWorker{}
	w := f.worker(testCallTimeout, time.Hour)
	release := make(chan struct{})
	f.mu.Lock()
	f.block = release
	f.mu.Unlock()
	if _, err := w.Do(1); err == nil {
		t.Fatal("no timeout")
	}
	f.mu.Lock()
	f.block = nil
	f.mu.Unlock()
	if r, err := w.Do(5); r != 10 || err != nil {
		t.Fatal(r, err)
	}
	f.mu.Lock()
	callers := append([]int32(nil), f.callers...)
	f.mu.Unlock()
	if len(callers) != 2 || callers[0] == callers[1] {
		t.Fatalf("the next request ran on the abandoned thread: %v", callers)
	}
	close(release)
	waitFor(t, "abandoned thread closed", func() bool { return f.closes.Load() == 1 })
	if w.Down() {
		t.Fatal("down after one")
	}
}

func TestWorkerPanic(t *testing.T) {
	f := &fakeWorker{}
	w := f.worker(time.Second, time.Hour)
	f.panicNext.Store(true)
	if _, err := w.Do(1); err == nil {
		t.Fatal("a panic answered no error")
	}
	waitFor(t, "thread closed", func() bool { return f.closes.Load() == 1 })
	for i := 0; i < 5; i++ {
		f.panicNext.Store(true)
		w.Do(1)
	}
	if w.Down() {
		t.Fatal("panics counted as hung calls")
	}
	if r, err := w.Do(3); r != 6 || err != nil {
		t.Fatal(r, err)
	}
}

func TestWorkerConcurrent(t *testing.T) {
	f := &fakeWorker{}
	w := f.worker(time.Second, 5*time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r, err := w.Do(i); r != 2*i || err != nil {
				t.Error(i, r, err)
			}
			time.Sleep(time.Duration(i%7) * time.Millisecond)
		}(i)
	}
	wg.Wait()
}

// A slow but healthy thread: callers queued behind a call are not counted
// as hung calls, and the thread is not abandoned.
func TestWorkerQueuedNotAbandoned(t *testing.T) {
	f := &fakeWorker{delay: 200 * time.Millisecond}
	w := f.worker(300*time.Millisecond, time.Hour)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r, err := w.Do(i); err == nil && r == 2*i {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	w.mu.Lock()
	abandoned, down := w.abandoned, w.down
	w.mu.Unlock()
	if abandoned != 0 || down || f.opens.Load() != 1 || ok.Load() < 2 {
		t.Fatalf("abandoned %d, down %v, opens %d, answered %d", abandoned, down, f.opens.Load(), ok.Load())
	}
}
