package procinfo

import (
	"fmt"
	"testing"
	"time"
)

type fakeSys struct {
	procs map[uint32]struct {
		path    string
		created int64
		ppid    uint32
	}
	// withCreated: snapshots carry creation times (as on Windows).
	withCreated bool
	// fastCreated: System.Created is set (as on Windows).
	fastCreated bool
	// denied: processes that cannot be opened.
	denied map[uint32]bool
}

func (f *fakeSys) sys() System {
	s := System{
		Query: func(pid uint32) (string, int64, bool) {
			p, ok := f.procs[pid]
			if f.denied[pid] {
				return "", 0, false
			}
			return p.path, p.created, ok
		},
		Snapshot: func() []ProcEntry {
			var out []ProcEntry
			for pid, p := range f.procs {
				e := ProcEntry{PID: pid, PPID: p.ppid}
				if f.withCreated {
					e.Created = p.created
				}
				out = append(out, e)
			}
			return out
		},
	}
	if f.fastCreated {
		s.Created = func(pid uint32) (int64, bool, bool) {
			p, ok := f.procs[pid]
			if f.denied[pid] {
				return 0, false, false
			}
			return p.created, ok, !ok
		}
	}
	return s
}

func (f *fakeSys) set(pid uint32, path string, created int64, ppid uint32) {
	f.procs[pid] = struct {
		path    string
		created int64
		ppid    uint32
	}{path, created, ppid}
}

func newFake() *fakeSys {
	return &fakeSys{procs: map[uint32]struct {
		path    string
		created int64
		ppid    uint32
	}{}}
}

func TestCachePIDReuse(t *testing.T) {
	for _, fast := range []bool{false, true} {
		t.Run(fmt.Sprint("fast=", fast), func(t *testing.T) { testCachePIDReuse(t, fast) })
	}
}

func testCachePIDReuse(t *testing.T, fast bool) {
	f := newFake()
	f.fastCreated = fast
	f.set(100, `C:\Program Files\curl\CURL.EXE`, 1, 0)
	c := NewCacheWith(f.sys())
	in := c.Get(100)
	if in.Name != "curl.exe" || in.Path != `C:\Program Files\curl\CURL.EXE` {
		t.Fatalf("%+v", in)
	}
	// The PID goes to another program before Revalidate runs: the cached
	// entry of the exited one must not be handed out.
	f.set(100, `C:\Windows\notepad.exe`, 2, 0)
	if in := c.Get(100); in.Name != "notepad.exe" || in.Created != 2 {
		t.Fatalf("stale entry for a reused PID: %+v", in)
	}
	c.Revalidate()
	if c.Get(100).Name != "notepad.exe" {
		t.Fatal("entry lost on revalidation")
	}
	// A process that exited keeps its entry until Revalidate: nothing
	// else has the PID, so its last flows are still its own.
	delete(f.procs, 100)
	if c.Get(100).Name != "notepad.exe" {
		t.Fatal("exited process forgotten before revalidation")
	}
	c.Revalidate()
	if in := c.Get(100); in.Name != "" {
		t.Fatalf("stale entry survived revalidation: %+v", in)
	}
	if in := c.Get(200); in.Path != "" || in.Name != "" {
		t.Fatalf("%+v", in)
	}
	if c.Get(4).Name != "system" {
		t.Fatal("system pid")
	}
	if !fast {
		return // Query cannot tell a denied process from a gone one
	}
	// The PID goes to a process that cannot be opened: whose it is is
	// unknown, so the cached entry is not handed out either.
	f.set(300, `C:\Tools\app.exe`, 5, 0)
	if c.Get(300).Name != "app.exe" {
		t.Fatal("pid 300")
	}
	f.set(300, `C:\Windows\protected.exe`, 6, 0)
	f.denied = map[uint32]bool{300: true}
	if in := c.Get(300); in.Name != "" {
		t.Fatalf("stale entry for an unreadable PID: %+v", in)
	}
}

// TestCachePIDReuseChild: the PID of a program that exited goes to
// another one (with another parent): the new process gets neither the old
// one's identity nor its ancestors, whether or not the tracker saw it.
func TestCachePIDReuseChild(t *testing.T) {
	for i := range 4 {
		tracked, fast := i&1 != 0, i&2 != 0
		f := newFake()
		f.withCreated, f.fastCreated = true, fast
		f.set(1, `C:\Windows\explorer.exe`, 10, 0)
		f.set(50, `C:\Telegram\telegram.exe`, 20, 1)
		f.set(7340, `C:\Games\game.exe`, 30, 1)
		c := NewCacheWith(f.sys())
		c.Track()
		if in := c.Get(7340); in.Name != "game.exe" {
			t.Fatalf("%+v", in)
		}
		f.set(7340, `C:\Telegram\updater.exe`, 40, 50)
		if tracked {
			c.Track()
		}
		in := c.Get(7340)
		if in.Name != "updater.exe" || in.Parent == nil || in.Parent.Name != "telegram.exe" {
			t.Fatalf("tracked %v fast %v: reused PID: %+v parent %+v", tracked, fast, in, in.Parent)
		}
	}
}

func TestParentChainSurvivesLauncherExit(t *testing.T) {
	f := newFake()
	f.set(10, `C:\Launcher\launcher.exe`, 100, 1)
	f.set(1, `C:\Windows\explorer.exe`, 50, 0)
	c := NewCacheWith(f.sys())
	now := time.Unix(1000, 0)
	c.nowFn = func() time.Time { return now }
	c.Track() // tracker sees the launcher while it runs
	f.set(20, `C:\Games\game.exe`, 200, 10)
	delete(f.procs, 10) // launcher exits before the game connects
	now = now.Add(2 * time.Second)
	in := c.Get(20)
	if in.Parent == nil || in.Parent.Name != "launcher.exe" || in.Parent.Parent == nil || in.Parent.Parent.Name != "explorer.exe" {
		t.Fatalf("chain: %+v", in.Parent)
	}
	// Dead launcher is forgotten after the keep period.
	now = now.Add(c.keep + time.Second)
	c.Track()
	f.set(21, `C:\Games\game2.exe`, 300, 10)
	if in := c.Get(21); in.Parent != nil {
		t.Fatalf("expired parent still linked: %+v", in.Parent)
	}
}

func TestParentPIDReuseRejected(t *testing.T) {
	f := newFake()
	// PPID 10 now belongs to a process created after the child.
	f.set(10, `C:\evil.exe`, 500, 0)
	f.set(20, `C:\child.exe`, 200, 10)
	c := NewCacheWith(f.sys())
	if in := c.Get(20); in.Parent != nil {
		t.Fatalf("reused PPID accepted: %+v", in.Parent)
	}
}

// TestSiblingReusesPID: a launcher's helper exits and the game it starts
// next gets the same PID (same parent). The game must not inherit the
// helper's identity: its parent is the launcher, and its own children
// see the game, not the helper. That holds whether or not the tracker
// saw the PID free in between, with or without creation times in the
// snapshot, and whichever of the two is looked up first.
func TestSiblingReusesPID(t *testing.T) {
	for _, withCreated := range []bool{true, false} {
		for _, sawFree := range []bool{true, false} {
			for _, childFirst := range []bool{false, true} {
				f := newFake()
				f.withCreated = withCreated
				f.set(10, `C:\Launcher\launcher.exe`, 100, 1)
				f.set(20, `C:\Launcher\helper.exe`, 200, 10)
				c := NewCacheWith(f.sys())
				now := time.Unix(1000, 0)
				c.nowFn = func() time.Time { return now }
				c.Track()
				delete(f.procs, 20)
				if sawFree {
					now = now.Add(time.Second)
					c.Track()
				}
				f.set(20, `C:\Games\game.exe`, 300, 10)
				now = now.Add(time.Second)
				c.Track()
				f.set(30, `C:\Games\child.exe`, 400, 20)
				name := fmt.Sprintf("created %v, saw free %v, child first %v", withCreated, sawFree, childFirst)
				checkGame := func() {
					if in := c.Get(20); in.Parent == nil || in.Parent.Name != "launcher.exe" {
						t.Fatalf("%s: game parent %+v", name, in.Parent)
					}
				}
				if !childFirst {
					checkGame()
				}
				if in := c.Get(30); in.Parent == nil || in.Parent.Name != "game.exe" || in.Parent.Created != 300 {
					t.Fatalf("%s: child parent %+v", name, in.Parent)
				}
				checkGame()
			}
		}
	}
}
