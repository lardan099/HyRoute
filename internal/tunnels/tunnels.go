// Package tunnels runs one Hysteria per profile that the rules use and
// hands each profile's SOCKS5 endpoint to the relay and the engine. It
// keeps the union of all server IPs excluded from interception.
package tunnels

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
)

// Runner is one profile's Hysteria (hysteria.Supervisor, or a stub).
type Runner interface {
	Start() error
	Stop()
	Status() hysteria.Status
	Available() bool
	UDPAvailable() bool
	Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error)
	UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error)
	SOCKS() socks5.Client
}

// Hooks connect a runner to its manager.
type Hooks struct {
	// SetServerIPs must be called before Hysteria sends its first packet.
	SetServerIPs func([]netip.Addr) error
	OnStatus     func(hysteria.Status)
	LogLine      func(hysteria.LogLine)
	// RedactGroup is the redactor group for this runner's secrets.
	RedactGroup string
}

// Factory creates a runner for a profile.
type Factory func(p hysteria.Profile, h Hooks) Runner

// Endpoint is one running profile. It implements the relay's and the
// engine's tunnel interfaces and counts per-profile traffic.
type Endpoint struct {
	ID      string
	Profile hysteria.Profile
	Test    bool // temporary endpoint for "Check profile"
	Started time.Time
	r       Runner

	rejected atomic.Int64
	sent     atomic.Int64
	recv     atomic.Int64
	users    int           // Acquire references (test endpoints)
	started  chan struct{} // closed once r.Start has returned
}

func (e *Endpoint) Available() bool    { return e.r.Available() }
func (e *Endpoint) UDPAvailable() bool { return e.r.UDPAvailable() }
func (e *Endpoint) Dial(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
	return e.r.Dial(ctx, dst)
}
func (e *Endpoint) UDPAssociate(ctx context.Context) (*socks5.UDPAssoc, error) {
	return e.r.UDPAssociate(ctx)
}
func (e *Endpoint) SOCKS() socks5.Client    { return e.r.SOCKS() }
func (e *Endpoint) Status() hysteria.Status { return e.r.Status() }
func (e *Endpoint) NoteRejected()           { e.rejected.Add(1) }
func (e *Endpoint) NoteTraffic(sent, recv int64) {
	e.sent.Add(sent)
	e.recv.Add(recv)
}

// Status is one endpoint for the UI.
type Status struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	State     string    `json:"state"` // stopped | connecting | connected | failed
	Message   string    `json:"message"`
	UDP       bool      `json:"udp"`
	SOCKS     string    `json:"socks"`
	ServerIPs []string  `json:"serverIPs"`
	Restarts  int       `json:"restarts"`
	RetryIn   float64   `json:"retryIn"` // seconds
	Started   time.Time `json:"started"`
	Rejected  int64     `json:"rejected"`
	Sent      int64     `json:"sent"`
	Recv      int64     `json:"recv"`
	Test      bool      `json:"test"`
}

type Manager struct {
	New Factory
	// SetServerIPs receives the union of every endpoint's server IPs (nil
	// when HyRoute is not routing, e.g. a profile check while disconnected).
	SetServerIPs func([]netip.Addr) error
	// OnStatus is called on every endpoint status change.
	OnStatus func(id string, st hysteria.Status)
	LogLine  func(id string, l hysteria.LogLine)
	Log      *slog.Logger

	mu     sync.Mutex
	ipMu   sync.Mutex
	eps    map[string]*Endpoint // key: profile ID, or "test:"+ID
	ips    map[string][]netip.Addr
	closed bool
}

func (m *Manager) log() *slog.Logger {
	if m.Log == nil {
		return slog.Default()
	}
	return m.Log
}

// Get returns the running endpoint of a profile, or nil.
func (m *Manager) Get(profile string) *Endpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eps[profile]
}

// Sync makes the running set equal to want: missing profiles start,
// unused ones stop, changed ones restart. Test endpoints are untouched.
func (m *Manager) Sync(want []hysteria.Profile) {
	wanted := map[string]hysteria.Profile{}
	for _, p := range want {
		wanted[p.ID] = p
	}
	var stop []*Endpoint
	var start []hysteria.Profile
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if m.eps == nil {
		m.eps = map[string]*Endpoint{}
	}
	for id, e := range m.eps {
		if e.Test {
			continue
		}
		p, ok := wanted[id]
		if !ok || !hysteria.SameConnection(p, e.Profile) {
			stop = append(stop, e)
			delete(m.eps, id)
		} else {
			e.Profile = p // new name or bookkeeping only
		}
	}
	for id, p := range wanted {
		if _, ok := m.eps[id]; !ok {
			start = append(start, p)
		}
	}
	m.mu.Unlock()
	for _, e := range stop {
		m.stop(e)
	}
	sort.Slice(start, func(i, j int) bool { return start[i].ID < start[j].ID })
	for _, p := range start {
		m.start(p.ID, p, false)
	}
}

func (m *Manager) start(key string, p hysteria.Profile, test bool) *Endpoint {
	e := m.newEndpoint(key, p, test)
	m.mu.Lock()
	if m.eps == nil {
		m.eps = map[string]*Endpoint{}
	}
	m.eps[key] = e
	m.mu.Unlock()
	m.run(e, p)
	return e
}

// newEndpoint creates an endpoint that is neither registered nor started.
// It holds no resources yet, so dropping it costs nothing.
func (m *Manager) newEndpoint(key string, p hysteria.Profile, test bool) *Endpoint {
	e := &Endpoint{ID: p.ID, Profile: p, Test: test, Started: time.Now(), started: make(chan struct{})}
	e.r = m.New(p, Hooks{
		SetServerIPs: func(ips []netip.Addr) error { return m.setIPs(key, ips) },
		OnStatus: func(st hysteria.Status) {
			if m.OnStatus != nil {
				m.OnStatus(p.ID, st)
			}
		},
		LogLine: func(l hysteria.LogLine) {
			if m.LogLine != nil {
				m.LogLine(p.ID, l)
			}
		},
		RedactGroup: "profile:" + key,
	})
	return e
}

// run starts a registered endpoint. m.mu must not be held: the runner
// reports its server IPs through setIPs.
func (m *Manager) run(e *Endpoint, p hysteria.Profile) {
	defer close(e.started)
	if err := e.r.Start(); err != nil {
		m.log().Error("hysteria not started", "profile", p.Name, "err", err)
	} else {
		m.log().Info("hysteria started", "profile", p.Name, "test", e.Test)
	}
}

func (m *Manager) stop(e *Endpoint) {
	// An endpoint is registered before it starts: a Stop that came first
	// would be a no-op and leave the Hysteria started after it running.
	<-e.started
	e.r.Stop()
	key := e.ID
	if e.Test {
		key = "test:" + e.ID
	}
	m.setIPs(key, nil)
	m.log().Info("hysteria stopped", "profile", e.Profile.Name, "test", e.Test)
}

func (m *Manager) setIPs(key string, ips []netip.Addr) error {
	// Serialized end to end: two profiles reporting at once must not apply
	// their unions out of order (the older one would drop an exclusion).
	m.ipMu.Lock()
	defer m.ipMu.Unlock()
	m.mu.Lock()
	if m.ips == nil {
		m.ips = map[string][]netip.Addr{}
	}
	prev, had := m.ips[key]
	if len(ips) == 0 {
		delete(m.ips, key)
	} else {
		m.ips[key] = slices.Clone(ips)
	}
	var union []netip.Addr
	for _, l := range m.ips {
		union = append(union, l...)
	}
	set := m.SetServerIPs
	m.mu.Unlock()
	slices.SortFunc(union, func(a, b netip.Addr) int { return a.Compare(b) })
	union = slices.Compact(union)
	if set == nil {
		return nil
	}
	err := set(union)
	if err != nil && len(ips) > 0 {
		// The filter still excludes the previous list. Keeping the new one
		// in the union would fail the changes of every other profile too
		// (too many server addresses) while this one retries. A failed
		// removal stays done: the extra exclusion is harmless, and the next
		// change drops it.
		m.mu.Lock()
		if had {
			m.ips[key] = prev
		} else {
			delete(m.ips, key)
		}
		m.mu.Unlock()
	}
	return err
}

// Acquire returns a running endpoint for p: the routing one when the
// profile is in use, otherwise a temporary one (its server IPs are
// excluded like any other). release stops a temporary endpoint when the
// last user is done.
func (m *Manager) Acquire(p hysteria.Profile) (e *Endpoint, release func()) {
	key := "test:" + p.ID
	m.mu.Lock()
	e, release = m.reuse(key, p)
	m.mu.Unlock()
	if e != nil {
		return e, release
	}
	// The runner is created unlocked, then the lookup is repeated under the
	// lock that registers it: concurrent Acquires of one profile share one
	// Hysteria instead of each starting its own (the overwritten one was
	// never stopped).
	e = m.newEndpoint(key, p, true)
	m.mu.Lock()
	if cur, rel := m.reuse(key, p); cur != nil {
		m.mu.Unlock()
		return cur, rel
	}
	old := m.eps[key] // a temporary endpoint of the profile's previous version
	if m.eps == nil {
		m.eps = map[string]*Endpoint{}
	}
	m.eps[key] = e
	e.users++
	m.mu.Unlock()
	if old != nil {
		// Stopped now, not by its last release: two Hysterias must not
		// share the key's server exclusion.
		m.stop(old)
	}
	m.run(e, p)
	return e, func() { m.releaseTest(key, e) }
}

// reuse returns the running endpoint that already serves p, if any. m.mu
// must be held.
func (m *Manager) reuse(key string, p hysteria.Profile) (*Endpoint, func()) {
	if e := m.eps[p.ID]; e != nil && hysteria.SameConnection(e.Profile, p) {
		return e, func() {}
	}
	if e := m.eps[key]; e != nil && hysteria.SameConnection(e.Profile, p) {
		e.users++
		return e, func() { m.releaseTest(key, e) }
	}
	return nil, nil
}

func (m *Manager) releaseTest(key string, e *Endpoint) {
	m.mu.Lock()
	e.users--
	last := e.users == 0 && m.eps[key] == e
	if last {
		delete(m.eps, key)
	}
	m.mu.Unlock()
	if last {
		m.stop(e)
	}
}

// StopAll stops every endpoint; Sync is a no-op afterwards.
func (m *Manager) StopAll() {
	m.mu.Lock()
	m.closed = true
	eps := m.eps
	m.eps = nil
	m.mu.Unlock()
	var wg sync.WaitGroup
	for _, e := range eps {
		wg.Add(1)
		go func() { defer wg.Done(); m.stop(e) }()
	}
	wg.Wait()
}

// Statuses lists the endpoints, routing ones first, by name.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	out := make([]Status, 0, len(m.eps))
	for _, e := range m.eps {
		out = append(out, e.status())
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Test != out[j].Test {
			return !out[i].Test
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (e *Endpoint) status() Status {
	st := e.r.Status()
	s := Status{
		ID: e.ID, Name: e.Profile.Name, State: st.State.String(), Message: st.Message,
		UDP: st.UDPEnabled, Restarts: st.Restarts, RetryIn: st.RetryIn.Seconds(),
		Started: e.Started, Test: e.Test, ServerIPs: []string{},
		Rejected: e.rejected.Load(), Sent: e.sent.Load(), Recv: e.recv.Load(),
	}
	if st.State == hysteria.Connected || st.State == hysteria.Connecting {
		s.SOCKS = e.r.SOCKS().Server
	}
	for _, ip := range st.ServerIPs {
		s.ServerIPs = append(s.ServerIPs, ip.String())
	}
	return s
}
