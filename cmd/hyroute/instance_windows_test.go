package main

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type claimResult struct {
	in         *instance
	handedOver bool
}

// testCopy is a HyRoute copy on a thread of its own, as a process of its
// own would be: the instance mutex belongs to a thread. end ends that
// thread the way a process ends, and Windows abandons the mutex.
type testCopy struct {
	claimed chan claimResult
	done    chan struct{}
	thread  chan windows.Handle
}

func startCopy(t *testing.T, id string) *testCopy {
	c := &testCopy{claimed: make(chan claimResult, 1), done: make(chan struct{}), thread: make(chan windows.Handle, 1)}
	go func() {
		runtime.LockOSThread() // never unlocked: the thread ends with the goroutine
		th, _ := windows.OpenThread(windows.SYNCHRONIZE, false, windows.GetCurrentThreadId())
		c.thread <- th
		in, handedOver := claimInstance(id)
		c.claimed <- claimResult{in, handedOver}
		<-c.done
	}()
	t.Cleanup(c.exit)
	return c
}

func (c *testCopy) exit() {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
}

// end is exit for a copy that runs: it returns once its thread is gone,
// as a process that ended is.
func (c *testCopy) end(t *testing.T) {
	t.Helper()
	c.exit()
	th := <-c.thread
	defer windows.CloseHandle(th)
	if r, _ := windows.WaitForSingleObject(th, 5000); r != windows.WAIT_OBJECT_0 {
		t.Fatal("the copy's thread did not end")
	}
}

func (c *testCopy) result(t *testing.T) claimResult {
	t.Helper()
	select {
	case r := <-c.claimed:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("claimInstance did not return")
		return claimResult{}
	}
}

func (c *testCopy) waits(t *testing.T) {
	t.Helper()
	select {
	case r := <-c.claimed:
		t.Fatalf("claimInstance returned (runs: %v, handed over: %v) while the other copy holds the mutex", r.in != nil, r.handedOver)
	case <-time.After(3 * instancePoll):
	}
}

func testInstanceID() string {
	var b [8]byte
	rand.Read(b[:])
	return fmt.Sprintf("HyRoute-test-%x", b)
}

// notify returns a show callback that never blocks (a waiting copy may
// ask more than once).
func notify(ch chan struct{}) func() {
	return func() {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func primary(t *testing.T, id string) (*testCopy, *instance) {
	t.Helper()
	c := startCopy(t, id)
	r := c.result(t)
	if r.in == nil || r.handedOver {
		t.Fatalf("the first copy does not run (handed over: %v)", r.handedOver)
	}
	return c, r.in
}

// A second start only brings the running window up: it must not run main.
func TestInstanceHandsOverToRunningCopy(t *testing.T) {
	id := testInstanceID()
	_, first := primary(t, id)
	shown := make(chan struct{}, 1)
	first.serve(notify(shown))

	r := startCopy(t, id).result(t)
	if r.in != nil || !r.handedOver {
		t.Fatalf("second copy: runs %v, handed over %v", r.in != nil, r.handedOver)
	}
	select {
	case <-shown:
	case <-time.After(5 * time.Second):
		t.Fatal("the running copy was not asked to show its window")
	}
}

// Before the first copy has a window, a second start waits and hands over
// once it has one.
func TestInstanceWaitsForStartingCopy(t *testing.T) {
	id := testInstanceID()
	_, first := primary(t, id)
	second := startCopy(t, id)
	second.waits(t)
	shown := make(chan struct{}, 1)
	first.serve(notify(shown))
	if r := second.result(t); r.in != nil || !r.handedOver {
		t.Fatalf("second copy: runs %v, handed over %v", r.in != nil, r.handedOver)
	}
	<-shown
}

// A start during a long exit (Disconnect waiting for a proxy client) must
// not hand over to the closing window: it waits, then runs itself.
func TestInstanceWaitsForExitingCopy(t *testing.T) {
	id := testInstanceID()
	firstCopy, first := primary(t, id)
	shown := make(chan struct{}, 1)
	first.serve(notify(shown))
	first.leaving()

	second := startCopy(t, id)
	second.waits(t)
	firstCopy.end(t)
	r := second.result(t)
	if r.in == nil || r.handedOver {
		t.Fatalf("after the first copy ended the second does not run (handed over: %v)", r.handedOver)
	}
	select {
	case <-shown:
		t.Fatal("the exiting copy was asked to show its window")
	default:
	}
}

// A request the running copy does not answer (it crossed leaving) must
// not make the later copy exit: it waits, then runs itself.
func TestInstanceUnansweredRequest(t *testing.T) {
	id := testInstanceID()
	firstCopy, first := primary(t, id)
	windows.SetEvent(first.running) // "window up", but nothing serves requests

	second := startCopy(t, id)
	second.waits(t)
	first.leaving()
	second.waits(t)
	firstCopy.end(t)
	if r := second.result(t); r.in == nil || r.handedOver {
		t.Fatalf("after the first copy ended the second does not run (handed over: %v)", r.handedOver)
	}
}

// A copy that crashed leaves "running" set; the next one still runs, and
// does not count as having a window until it serves.
func TestInstanceAfterCrash(t *testing.T) {
	id := testInstanceID()
	firstCopy, first := primary(t, id)
	first.serve(func() {})
	firstCopy.end(t) // no leaving(): a crash

	_, second := primary(t, id)
	if r, _ := windows.WaitForSingleObject(second.running, 0); r == windows.WAIT_OBJECT_0 {
		t.Fatal("the crashed copy's window still counts")
	}
	startCopy(t, id).waits(t)
}
