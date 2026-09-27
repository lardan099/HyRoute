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
}

func (f *fakeSys) sys() System {
	return System{
		Query: func(pid uint32) (string, int64, bool) {
			p, ok := f.procs[pid]
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
	f := newFake()
	f.set(100, `C:\Program Files\curl\CURL.EXE`, 1, 0)
	c := NewCacheWith(f.sys())
	in := c.Get(100)
	if in.Name != "curl.exe" || in.Path != `C:\Program Files\curl\CURL.EXE` {
		t.Fatalf("%+v", in)
	}
	f.set(100, `C:\Windows\notepad.exe`, 2, 0)
	if c.Get(100).Name != "curl.exe" {
		t.Fatal("cached value expected before revalidation")
	}
	c.Revalidate()
	if c.Get(100).Name != "notepad.exe" {
		t.Fatal("stale entry survived revalidation")
	}
	if in := c.Get(200); in.Path != "" || in.Name != "" {
		t.Fatalf("%+v", in)
	}
	if c.Get(4).Name != "system" {
		t.Fatal("system pid")
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
