package main

import (
	"time"

	"golang.org/x/sys/windows"
)

// One HyRoute at a time. Wails has a single-instance lock of its own, but
// it acts inside wails.Run: a second start would first run all of main
// (clean the update folder under the running copy, take over the kill
// switch, connect), and it hands over even to a copy that is exiting,
// which then leaves nothing running.
//
// The copy that runs owns a named mutex from the start of main until its
// process ends (Windows releases it then, after a crash too). An event is
// set while its window is up and it is not exiting: a later copy then
// asks it through a second event to show the window, and exits once a
// third one confirms it did. While the first is still starting or already
// exiting (a request it no longer answers), the later copy waits for the
// mutex and runs itself.

const instanceID = "HyRoute-7f3c1a52"

// instancePoll: how often a waiting copy checks whether the running one
// has its window up, and how long it waits for it to answer.
const instancePoll = 250 * time.Millisecond

type instance struct {
	mutex   windows.Handle
	running windows.Handle // manual reset: the window is up, not exiting
	show    windows.Handle // auto reset: a later copy asks for the window
	shown   windows.Handle // auto reset: the window was shown for it
}

func instanceName(id, what string) *uint16 {
	p, _ := windows.UTF16PtrFromString(`Local\` + id + "-" + what)
	return p
}

// claimInstance returns once this copy may run; the mutex then belongs to
// the calling thread, which must live as long as the process (main is
// locked to its thread). When another copy runs and has its window up, it
// is asked to show it and handedOver is true: exit. If the named objects
// cannot be made (not expected) this copy runs unguarded (nil); Wails'
// own lock still stands behind.
func claimInstance(id string) (in *instance, handedOver bool) {
	in = &instance{}
	in.mutex, _ = windows.CreateMutex(nil, false, instanceName(id, "instance"))
	in.running, _ = windows.CreateEvent(nil, 1, 0, instanceName(id, "running"))
	in.show, _ = windows.CreateEvent(nil, 0, 0, instanceName(id, "show"))
	in.shown, _ = windows.CreateEvent(nil, 0, 0, instanceName(id, "shown"))
	if in.mutex == 0 || in.running == 0 || in.show == 0 || in.shown == 0 {
		in.close()
		return nil, false
	}
	poll := uint32(instancePoll / time.Millisecond)
	for wait := uint32(0); ; wait = poll {
		r, err := windows.WaitForSingleObject(in.mutex, wait)
		if err != nil {
			in.close()
			return nil, false
		}
		if r == windows.WAIT_OBJECT_0 || r == windows.WAIT_ABANDONED {
			// A copy that crashed left the events as they were.
			windows.ResetEvent(in.running)
			windows.ResetEvent(in.show)
			windows.ResetEvent(in.shown)
			return in, false
		}
		if r, _ := windows.WaitForSingleObject(in.running, 0); r != windows.WAIT_OBJECT_0 {
			continue
		}
		// This copy was started by the user: the running one may take the
		// foreground to show its window.
		procAllowSetForegroundWindow.Call(asfwAny)
		windows.ResetEvent(in.shown) // a late answer to an earlier copy
		windows.SetEvent(in.show)
		if r, _ := windows.WaitForSingleObject(in.shown, poll); r == windows.WAIT_OBJECT_0 {
			in.close()
			return nil, true
		}
	}
}

var procAllowSetForegroundWindow = user32.NewProc("AllowSetForegroundWindow")

// asfwAny: AllowSetForegroundWindow for any process.
const asfwAny = ^uintptr(0)

func (in *instance) close() {
	for _, h := range []windows.Handle{in.mutex, in.running, in.show, in.shown} {
		if h != 0 {
			windows.CloseHandle(h)
		}
	}
}

// serve is called once the window is up: from then on a later copy has
// it shown instead of waiting.
func (in *instance) serve(show func()) {
	if in == nil {
		return
	}
	go func() {
		for {
			r, err := windows.WaitForSingleObject(in.show, windows.INFINITE)
			if err != nil || r != windows.WAIT_OBJECT_0 {
				return
			}
			// A request that crossed leaving goes unanswered: the later
			// copy then waits for this one to end and runs.
			if r, _ := windows.WaitForSingleObject(in.running, 0); r == windows.WAIT_OBJECT_0 {
				show()
				windows.SetEvent(in.shown)
			}
		}
	}()
	windows.SetEvent(in.running)
}

// leaving: this copy exits. A copy started from now on waits for it to
// end and then runs, instead of handing over to a closing window.
func (in *instance) leaving() {
	if in != nil {
		windows.ResetEvent(in.running)
	}
}
