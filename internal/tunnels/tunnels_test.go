package tunnels

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
)

type fakeRunner struct {
	p       hysteria.Profile
	h       Hooks
	mu      sync.Mutex
	running bool
	starts  *int
}

func (f *fakeRunner) Start() error {
	f.mu.Lock()
	f.running = true
	*f.starts++
	f.mu.Unlock()
	return f.h.SetServerIPs([]netip.Addr{netip.MustParseAddr(f.p.Host)})
}
func (f *fakeRunner) Stop() { f.mu.Lock(); f.running = false; f.mu.Unlock() }
func (f *fakeRunner) Status() hysteria.Status {
	return hysteria.Status{State: hysteria.Connected}
}
func (f *fakeRunner) Available() bool    { return true }
func (f *fakeRunner) UDPAvailable() bool { return true }
func (f *fakeRunner) Dial(context.Context, socks5.Addr) (net.Conn, error) {
	return nil, nil
}
func (f *fakeRunner) UDPAssociate(context.Context) (*socks5.UDPAssoc, error) { return nil, nil }
func (f *fakeRunner) SOCKS() socks5.Client                                   { return socks5.Client{Server: "127.0.0.1:1"} }

type rig struct {
	m      *Manager
	starts int
	ips    []netip.Addr
	runs   map[string]*fakeRunner
}

func newRig() *rig {
	r := &rig{runs: map[string]*fakeRunner{}}
	r.m = &Manager{
		New: func(p hysteria.Profile, h Hooks) Runner {
			f := &fakeRunner{p: p, h: h, starts: &r.starts}
			r.runs[h.RedactGroup] = f
			return f
		},
		SetServerIPs: func(ips []netip.Addr) error { r.ips = ips; return nil },
	}
	return r
}

func prof(id, host string) hysteria.Profile {
	return hysteria.Profile{ID: id, Name: id, Host: host, Ports: "443"}
}

func ipList(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func TestSyncStartsOnlyWantedAndKeepsIPUnion(t *testing.T) {
	r := newRig()
	de, nl := prof("de", "198.51.100.1"), prof("nl", "198.51.100.2")
	r.m.Sync([]hysteria.Profile{de, nl})
	if r.starts != 2 || r.m.Get("de") == nil || r.m.Get("nl") == nil || r.m.Get("us") != nil {
		t.Fatalf("starts %d", r.starts)
	}
	if !slices.Equal(r.ips, ipList("198.51.100.1", "198.51.100.2")) {
		t.Fatalf("union %v", r.ips)
	}
	// Renaming does not restart; a connection change does.
	de2 := de
	de2.Name = "Germany"
	r.m.Sync([]hysteria.Profile{de2, nl})
	if r.starts != 2 || r.m.Get("de").Profile.Name != "Germany" {
		t.Fatalf("rename restarted: %d", r.starts)
	}
	nl.Host = "198.51.100.3"
	r.m.Sync([]hysteria.Profile{de2, nl})
	if r.starts != 3 || !slices.Equal(r.ips, ipList("198.51.100.1", "198.51.100.3")) {
		t.Fatalf("starts %d union %v", r.starts, r.ips)
	}
	// Unused profiles stop and leave the exclusion.
	r.m.Sync([]hysteria.Profile{nl})
	if r.m.Get("de") != nil || r.runs["profile:de"].running || !slices.Equal(r.ips, ipList("198.51.100.3")) {
		t.Fatalf("de still running, union %v", r.ips)
	}
	if st := r.m.Statuses(); len(st) != 1 || st[0].ID != "nl" || st[0].State != "connected" {
		t.Fatalf("%+v", st)
	}
	r.m.StopAll()
	if len(r.ips) != 0 || r.runs["profile:nl"].running {
		t.Fatal("StopAll left state")
	}
	r.m.Sync([]hysteria.Profile{nl})
	if r.m.Get("nl") != nil {
		t.Fatal("Sync after StopAll must not start")
	}
}

func TestAcquireUsesRunningOrTemporary(t *testing.T) {
	r := newRig()
	de, us := prof("de", "198.51.100.1"), prof("us", "198.51.100.9")
	r.m.Sync([]hysteria.Profile{de})
	e, rel := r.m.Acquire(de)
	if e != r.m.Get("de") || r.starts != 1 {
		t.Fatal("running endpoint not reused")
	}
	rel()
	e1, rel1 := r.m.Acquire(us)
	e2, rel2 := r.m.Acquire(us)
	if e1 != e2 || !e1.Test || r.starts != 2 || r.m.Get("us") != nil {
		t.Fatal("temporary endpoint")
	}
	if !slices.Contains(r.ips, netip.MustParseAddr("198.51.100.9")) {
		t.Fatalf("test server not excluded: %v", r.ips)
	}
	rel1()
	if !r.runs["profile:test:us"].running {
		t.Fatal("stopped while still used")
	}
	rel2()
	if r.runs["profile:test:us"].running || slices.Contains(r.ips, netip.MustParseAddr("198.51.100.9")) {
		t.Fatal("temporary endpoint left running")
	}
}

// Concurrent checks of one profile share its temporary Hysteria: none is
// left running and the server IP leaves the exclusion with the last one.
func TestAcquireConcurrent(t *testing.T) {
	var mu sync.Mutex
	var runs []*fakeRunner
	var ips []netip.Addr
	m := &Manager{
		New: func(p hysteria.Profile, h Hooks) Runner {
			f := &fakeRunner{p: p, h: h, starts: new(int)}
			mu.Lock()
			runs = append(runs, f)
			mu.Unlock()
			return f
		},
		SetServerIPs: func(l []netip.Addr) error { ips = l; return nil },
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	us := prof("us", "198.51.100.9")
	for range 100 {
		var wg sync.WaitGroup
		gate := make(chan struct{})
		for range 3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				_, rel := m.Acquire(us)
				rel()
			}()
		}
		close(gate)
		wg.Wait()
	}
	for i, f := range runs {
		f.mu.Lock()
		running := f.running
		f.mu.Unlock()
		if running {
			t.Fatalf("runner %d of %d left running", i, len(runs))
		}
	}
	if len(ips) != 0 || len(m.Statuses()) != 0 {
		t.Fatalf("ips %v statuses %+v", ips, m.Statuses())
	}
}

// A check of an edited profile replaces the temporary Hysteria of the
// previous version: the old one stops, the new one keeps its exclusion
// when the old check releases.
func TestAcquireReplacesChangedProfile(t *testing.T) {
	r := newRig()
	old, edited := prof("us", "198.51.100.9"), prof("us", "198.51.100.10")
	e1, rel1 := r.m.Acquire(old)
	first := r.runs["profile:test:us"]
	e2, rel2 := r.m.Acquire(edited)
	if e1 == e2 || first.running || !r.runs["profile:test:us"].running {
		t.Fatal("old version not replaced")
	}
	rel1()
	if !slices.Equal(r.ips, ipList("198.51.100.10")) || !r.runs["profile:test:us"].running {
		t.Fatalf("old release touched the new endpoint: %v", r.ips)
	}
	rel2()
	if len(r.ips) != 0 || r.runs["profile:test:us"].running {
		t.Fatal("temporary endpoint left running")
	}
}

// slowStopRunner reports when its Stop begins and finishes it only once
// told to: Hysteria takes a moment to die.
type slowStopRunner struct {
	*fakeRunner
	stopping, proceed chan struct{}
}

func (f *slowStopRunner) Stop() {
	close(f.stopping)
	<-f.proceed
	f.fakeRunner.Stop()
}

// A check that starts while the previous check's temporary Hysteria is
// still stopping keeps its server exclusion when that stop completes.
func TestReleaseWhileNewCheckStarts(t *testing.T) {
	var mu sync.Mutex
	var ips []netip.Addr
	stopping, proceed := make(chan struct{}), make(chan struct{})
	n := 0
	m := &Manager{
		New: func(p hysteria.Profile, h Hooks) Runner {
			n++
			f := &fakeRunner{p: p, h: h, starts: new(int)}
			if n == 1 {
				return &slowStopRunner{fakeRunner: f, stopping: stopping, proceed: proceed}
			}
			return f
		},
		SetServerIPs: func(l []netip.Addr) error { mu.Lock(); ips = l; mu.Unlock(); return nil },
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	us := prof("us", "198.51.100.9")
	_, rel1 := m.Acquire(us)
	released := make(chan struct{})
	go func() { rel1(); close(released) }()
	<-stopping // the first Hysteria is going away, its key is free
	e2, rel2 := m.Acquire(us)
	close(proceed)
	<-released
	mu.Lock()
	got := ips
	mu.Unlock()
	if !slices.Equal(got, ipList("198.51.100.9")) || !e2.Available() {
		t.Fatalf("the stopped check removed the running one's exclusion: %v", got)
	}
	rel2()
	mu.Lock()
	defer mu.Unlock()
	if len(ips) != 0 {
		t.Fatalf("exclusion left after the last check: %v", ips)
	}
}

// dialRunner fails its dials with err and reports its status through the
// hook when it starts.
type dialRunner struct {
	fakeRunner
	err error
}

func (d *dialRunner) Start() error {
	d.fakeRunner.Start()
	d.h.OnStatus(hysteria.Status{State: hysteria.Connected})
	return nil
}
func (d *dialRunner) Dial(ctx context.Context, _ socks5.Addr) (net.Conn, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, d.err
}
func (d *dialRunner) UDPAssociate(context.Context) (*socks5.UDPAssoc, error) { return nil, d.err }

type dialNote struct {
	id, dst string
	err     error
}

// Only routing endpoints report their dials and health (server groups):
// not temporary ones, not canceled dials, not check (Quiet) dials.
func TestDialAndHealthHooks(t *testing.T) {
	var mu sync.Mutex
	var dials []dialNote
	var health, status []string
	errUnreach := errors.New("socks5: host unreachable")
	m := &Manager{
		New: func(p hysteria.Profile, h Hooks) Runner {
			return &dialRunner{fakeRunner: fakeRunner{p: p, h: h, starts: new(int)}, err: errUnreach}
		},
		SetServerIPs: func([]netip.Addr) error { return nil },
		OnDial: func(id, dst string, err error) {
			mu.Lock()
			dials = append(dials, dialNote{id, dst, err})
			mu.Unlock()
		},
		OnHealth: func(id string, st hysteria.Status) { mu.Lock(); health = append(health, id); mu.Unlock() },
		OnStatus: func(id string, st hysteria.Status) { mu.Lock(); status = append(status, id); mu.Unlock() },
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	de := prof("de", "198.51.100.1")
	m.Sync([]hysteria.Profile{de})
	e := m.Get("de")
	dst := socks5.Addr{Host: "example.com", Port: 443}
	e.Dial(t.Context(), dst)
	e.UDPAssociate(t.Context())
	e.Dial(Quiet(t.Context()), dst)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	e.Dial(canceled, dst)
	expired, cancel2 := context.WithTimeout(t.Context(), time.Nanosecond)
	defer cancel2()
	<-expired.Done()
	e.Dial(expired, dst)
	// A temporary endpoint of another server reports nothing.
	us := prof("us", "198.51.100.9")
	te, rel := m.Acquire(us)
	te.Dial(t.Context(), dst)
	rel()
	mu.Lock()
	defer mu.Unlock()
	if len(dials) != 3 || dials[0] != (dialNote{"de", "example.com:443", errUnreach}) || dials[1].dst != "udp" ||
		!errors.Is(dials[2].err, context.DeadlineExceeded) {
		t.Fatalf("%+v", dials)
	}
	if !slices.Equal(health, []string{"de"}) || !slices.Contains(status, "us") || !slices.Contains(status, "de") {
		t.Fatalf("health %v status %v", health, status)
	}
}
