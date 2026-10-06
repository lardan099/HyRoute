// Package procinfo resolves PIDs to executable paths with a cache keyed by
// (pid, creation time), so PID reuse cannot attribute a flow to the wrong
// program, and keeps a process tree for rules that apply to child
// processes. The tree remembers exited processes for a while: a launcher
// that started a game and quit still counts as the game's parent.
package procinfo

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Info struct {
	PID     uint32
	Path    string // full Win32 path; empty for System/Idle or on failure
	Name    string // lower-case basename, e.g. "curl.exe"
	Created int64  // creation time (ns), 0 if unknown
	// Parent is the parent process (possibly already exited), nil if
	// unknown. Chains are at most MaxDepth long.
	Parent *Info
}

const MaxDepth = 8

func baseName(path string) string {
	if path == "" {
		return ""
	}
	return strings.ToLower(filepath.Base(strings.ReplaceAll(path, `\`, "/")))
}

func newInfo(pid uint32, path string, created int64) *Info {
	in := &Info{PID: pid, Path: path, Name: baseName(path), Created: created}
	switch pid {
	case 0:
		in.Name = "idle"
	case 4:
		in.Name = "system"
	}
	return in
}

// ProcEntry is one row of a process snapshot.
type ProcEntry struct {
	PID, PPID uint32
	// Created is the creation time as Query reports it, 0 if the
	// snapshot does not have it.
	Created int64
}

// System is the OS access used by the cache (replaced in tests).
type System struct {
	// Query returns path and creation time; ok=false if the process is gone.
	Query func(pid uint32) (path string, created int64, ok bool)
	// Snapshot lists running processes with their parent PIDs.
	Snapshot func() []ProcEntry
	// Created returns only the creation time, cheaper than Query: ok=false
	// if it cannot be read, gone=true if no process has the PID. nil uses
	// Query.
	Created func(pid uint32) (created int64, ok, gone bool)
}

type node struct {
	path     string
	created  int64
	ppid     uint32
	lastSeen time.Time
	alive    bool
	// timed: the last snapshot confirmed the process by its creation
	// time (false on the Toolhelp fallback, which has none).
	timed bool
}

// Cache is safe for concurrent use.
type Cache struct {
	sys System

	mu    sync.Mutex
	m     map[uint32]*Info
	tree  map[uint32]*node
	keep  time.Duration
	nowFn func() time.Time
}

// NewCacheWith builds a cache over the given system access.
func NewCacheWith(sys System) *Cache {
	return &Cache{sys: sys, m: make(map[uint32]*Info), tree: make(map[uint32]*node),
		keep: 10 * time.Minute, nowFn: time.Now}
}

// Get returns process info, querying the OS on a cache miss. A cached
// entry is used only while the process under pid is still the one it
// describes (same creation time): a freed PID is soon given to another
// program, and Revalidate runs only every few seconds. An entry whose
// process has exited is still returned: nothing else has the PID, so the
// flow is that process's own. When the check itself fails (access denied)
// the entry is not trusted: the PID may belong to another process.
func (c *Cache) Get(pid uint32) *Info {
	c.mu.Lock()
	in, ok := c.m[pid]
	c.mu.Unlock()
	if ok {
		if created, alive, gone := c.created(pid); gone || alive && created == in.Created {
			return in
		}
	}
	path, created, ok := c.sys.Query(pid)
	in = newInfo(pid, path, created)
	if !ok {
		return in
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.tree[pid]
	if n == nil || n.created != created {
		// Not seen by the tracker yet: take a fresh snapshot for the PPID.
		c.refreshLocked()
		n = c.currentLocked(pid)
	}
	if n != nil && n.created == created {
		in.Parent = c.parentLocked(n, 1)
	}
	c.m[pid] = in
	return in
}

// created is the creation time of the process under pid now (see
// System.Created).
func (c *Cache) created(pid uint32) (created int64, ok, gone bool) {
	if c.sys.Created != nil {
		return c.sys.Created(pid)
	}
	_, created, ok = c.sys.Query(pid)
	return created, ok, !ok
}

// parentLocked builds the ancestor chain from the tree. A parent must have
// been created before its child, otherwise the PPID was reused.
func (c *Cache) parentLocked(child *node, depth int) *Info {
	if depth > MaxDepth || child.ppid == 0 {
		return nil
	}
	p := c.currentLocked(child.ppid)
	if p == nil || (p.created != 0 && child.created != 0 && p.created > child.created) {
		return nil
	}
	in := newInfo(child.ppid, p.path, p.created)
	in.Parent = c.parentLocked(p, depth+1)
	return in
}

// currentLocked is the tree's node for pid, made sure to be the process
// running under that PID now. A snapshot without creation times cannot
// tell a sibling that took over a freed PID between two refreshes from
// the process that had it (same parent, still running); for such a node
// the creation time is queried, and a different one replaces the node.
func (c *Cache) currentLocked(pid uint32) *node {
	n := c.tree[pid]
	if n == nil || n.timed || !n.alive {
		return n
	}
	path, created, ok := c.sys.Query(pid)
	if !ok || created == n.created {
		return n
	}
	n = &node{path: path, created: created, ppid: n.ppid, lastSeen: n.lastSeen, alive: true}
	c.tree[pid] = n
	return n
}

// Track refreshes the process tree; call it periodically (about 1 s).
func (c *Cache) Track() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshLocked()
}

func (c *Cache) refreshLocked() {
	if c.sys.Snapshot == nil {
		return
	}
	now := c.nowFn()
	seen := make(map[uint32]bool, len(c.tree))
	for _, e := range c.sys.Snapshot() {
		n := c.tree[e.PID]
		// Still the same process? A freed PID is soon reused, often by a
		// sibling (same parent), so the parent alone does not tell. The
		// creation time does; without it, only a node that was running at
		// the last refresh is trusted.
		same := n != nil && n.ppid == e.PPID
		if e.Created != 0 {
			same = same && n.created == e.Created
		} else {
			same = same && n.alive
		}
		if same {
			seen[e.PID] = true
			n.lastSeen, n.timed = now, e.Created != 0
			continue
		}
		// New process (or PID reused): query outside the hot path is not
		// possible here, but snapshots only add a handful of processes.
		path, created, ok := c.sys.Query(e.PID)
		if !ok {
			continue
		}
		c.tree[e.PID] = &node{path: path, created: created, ppid: e.PPID, lastSeen: now, timed: e.Created != 0}
		seen[e.PID] = true
	}
	for pid, n := range c.tree {
		n.alive = seen[pid]
		if !n.alive && now.Sub(n.lastSeen) > c.keep {
			delete(c.tree, pid)
		}
	}
}

// Revalidate drops cached entries whose process exited or whose PID now
// belongs to a different process (creation time changed).
func (c *Cache) Revalidate() {
	c.mu.Lock()
	snapshot := make(map[uint32]*Info, len(c.m))
	for k, v := range c.m {
		snapshot[k] = v
	}
	c.mu.Unlock()
	for pid, in := range snapshot {
		_, created, ok := c.sys.Query(pid)
		if !ok || created != in.Created {
			c.mu.Lock()
			if c.m[pid] == in {
				delete(c.m, pid)
			}
			c.mu.Unlock()
		}
	}
}

// trackEvery is how often Run reads the process tree. A launcher that
// starts a child and exits between two reads without using the network
// is never seen, and "with children" rules miss its child: the shorter
// the period, the shorter-lived a launcher that is still caught.
const trackEvery = 500 * time.Millisecond

// Run tracks the tree every trackEvery and revalidates the cache every
// 5 s until stop is closed.
func (c *Cache) Run(stop <-chan struct{}) {
	t := time.NewTicker(trackEvery)
	defer t.Stop()
	per := int(5 * time.Second / trackEvery)
	for i := 1; ; i++ {
		select {
		case <-stop:
			return
		case <-t.C:
			c.Track()
			if i%per == 0 {
				c.Revalidate()
			}
		}
	}
}

// Running is one program with at least one running process.
type Running struct {
	Name        string `json:"name"`        // file name as on disk, e.g. "Discord.exe"
	Path        string `json:"path"`        // full path
	Description string `json:"description"` // FileDescription from the version resource
	Windowed    bool   `json:"windowed"`    // has a visible top-level window
	System      bool   `json:"system"`      // under the Windows folder
	Count       int    `json:"count"`       // running processes
}
