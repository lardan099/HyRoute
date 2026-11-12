package app

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/lardan099/hyroute/internal/groups"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/socks5"
)

// «Проверить все» on the servers page: the delay of every server, or of
// the ones named, so that the fastest working one is seen at once. It is
// measured the way a group's check measures its members: a request for
// the probe address through the server, the time to the first byte of the
// answer (the better of two). A server that routes now is measured in
// place, the others through a temporary Hysteria or Xray each, a few at a
// time. The results live in memory until HyRoute exits and are shown with
// the servers (ProfileSummary); they take no part in what groups pick.

const (
	// pingWorkers is how many servers are measured at a time: each one
	// that does not route starts a core of its own.
	pingWorkers = 6
	// pingTries: the first request through a server just started also
	// resolves the name and warms the connection up.
	pingTries = 2
)

// Bounds (variables for tests): how long a server may take to connect
// (connectWait makes it longer for Xray), and a whole run.
var (
	pingConnectWait = 8 * time.Second
	pingBudget      = 10 * time.Minute
)

// pingResult is the last measurement of a server.
type pingResult struct {
	ms   int64 // 0: no answer, err says why
	err  string
	at   time.Time
	conn string // connKey of what was measured: a server changed since has no result
}

// pingRun is a run under way.
type pingRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	left   map[string]bool // not measured yet
	total  int
}

// pingState is guarded by Controller.mu.
type pingState struct {
	pings   map[string]pingResult
	pingRun *pingRun
}

// PingState is a run as the page shows it.
type PingState struct {
	Running bool `json:"running"`
	Done    int  `json:"done"`
	Total   int  `json:"total"`
}

func (c *Controller) pingStateLocked() PingState {
	r := c.pingRun
	if r == nil {
		return PingState{}
	}
	return PingState{Running: true, Done: r.total - len(r.left), Total: r.total}
}

// PingState is the run under way, if any.
func (c *Controller) PingState() PingState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pingStateLocked()
}

// pingLocked fills a summary with the server's last measurement.
func (c *Controller) pingLocked(p *hysteria.Profile, s *ProfileSummary) {
	if r, ok := c.pings[p.ID]; ok && r.conn == connKey(*p) {
		s.PingMs, s.PingErr, s.PingAt = r.ms, r.err, r.at.Unix()
	}
	s.Pinging = c.pingRun != nil && c.pingRun.left[p.ID]
}

// PingServers starts measuring the servers named, all of them when ids is
// empty, and returns at once: the results come with Profiles as they
// arrive (OnChange). While a run is under way it only reports that run.
func (c *Controller) PingServers(ids []string) PingState {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	c.mu.Lock()
	if c.pingRun != nil {
		defer c.mu.Unlock()
		return c.pingStateLocked()
	}
	var list []hysteria.Profile
	known := map[string]bool{}
	for _, p := range c.profiles.List {
		known[p.ID] = true
		if len(want) == 0 || want[p.ID] {
			list = append(list, p)
		}
	}
	if c.pings == nil {
		c.pings = map[string]pingResult{}
	}
	for id := range c.pings { // servers deleted since
		if !known[id] {
			delete(c.pings, id)
		}
	}
	if len(list) == 0 {
		c.mu.Unlock()
		return PingState{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), pingBudget)
	run := &pingRun{cancel: cancel, done: make(chan struct{}), left: map[string]bool{}, total: len(list)}
	for _, p := range list {
		run.left[p.ID] = true
	}
	c.pingRun = run
	st := c.pingStateLocked()
	var probe groups.Probe
	if c.groupsFile.Probe != nil {
		probe = *c.groupsFile.Probe
	}
	c.mu.Unlock()
	rawURL, _ := probe.Effective()
	go c.runPing(ctx, run, list, rawURL)
	c.changed()
	return st
}

// PingStop ends the run under way: the servers not measured yet keep what
// they had.
func (c *Controller) PingStop() {
	c.mu.Lock()
	run := c.pingRun
	c.mu.Unlock()
	if run != nil {
		run.cancel()
	}
}

// stopPing ends the run and waits for its temporary cores to stop (the
// exit).
func (c *Controller) stopPing() {
	c.mu.Lock()
	run := c.pingRun
	c.mu.Unlock()
	if run == nil {
		return
	}
	run.cancel()
	select {
	case <-run.done:
	case <-time.After(3 * time.Second):
	}
}

func (c *Controller) runPing(ctx context.Context, run *pingRun, list []hysteria.Profile, rawURL string) {
	defer run.cancel()
	// The page reloads the servers on every change: results that come
	// together are reported together.
	var dirty sync.Mutex
	changed := false
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	stopTick := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopTick:
				return
			case <-tick.C:
				dirty.Lock()
				was := changed
				changed = false
				dirty.Unlock()
				if was {
					c.changed()
				}
			}
		}
	}()

	room := &pingRoom{}
	jobs := make(chan hysteria.Profile)
	var wg sync.WaitGroup
	answered := 0
	for i := 0; i < min(pingWorkers, len(list)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				rtt, err := c.pingOne(ctx, p, rawURL, room)
				c.mu.Lock()
				delete(run.left, p.ID)
				switch {
				case ctx.Err() != nil || errors.Is(err, groups.ErrCanceled):
					// Stopped: no result, the last one stays.
				case err != nil:
					c.pings[p.ID] = pingResult{err: err.Error(), at: time.Now(), conn: connKey(p)}
				default:
					c.pings[p.ID] = pingResult{ms: max(1, rtt.Milliseconds()), at: time.Now(), conn: connKey(p)}
					answered++
				}
				c.mu.Unlock()
				dirty.Lock()
				changed = true
				dirty.Unlock()
			}
		}()
	}
feed:
	for _, p := range list {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	close(stopTick)
	c.mu.Lock()
	c.pingRun = nil
	c.mu.Unlock()
	close(run.done)
	c.Log.Info("servers measured", "servers", run.total, "answered", answered)
	c.changed()
}

// pingRoom counts the temporary cores of a run: while HyRoute routes,
// each takes room in the list of server addresses left alone.
type pingRoom struct {
	mu       sync.Mutex
	inFlight int
}

// take waits for room for one more temporary core. false: there is none
// even with no other of the run started, or the run ended.
func (r *pingRoom) take(ctx context.Context, sess Session) bool {
	for {
		r.mu.Lock()
		if sess == nil || sess.ServerIPRoom() >= 4*(r.inFlight+1) {
			r.inFlight++
			r.mu.Unlock()
			return true
		}
		alone := r.inFlight == 0
		r.mu.Unlock()
		if alone {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (r *pingRoom) give() { r.mu.Lock(); r.inFlight--; r.mu.Unlock() }

// pingOne measures one server. Routing that started or stopped meanwhile
// took the server's core with it: the server is measured once more.
func (c *Controller) pingOne(ctx context.Context, p hysteria.Profile, rawURL string, room *pingRoom) (time.Duration, error) {
	for try := 0; ; try++ {
		c.mu.Lock()
		sess := c.sess
		c.mu.Unlock()
		rtt, err := c.pingVia(ctx, sess, p, rawURL, room)
		c.mu.Lock()
		same := c.sess == sess
		c.mu.Unlock()
		if err == nil || same || try > 0 || ctx.Err() != nil {
			return rtt, err
		}
	}
}

func (c *Controller) pingVia(ctx context.Context, sess Session, p hysteria.Profile, rawURL string, room *pingRoom) (time.Duration, error) {
	if sess != nil && sess.Endpoint(p.ID) != nil {
		// A routing endpoint, measured in place and past its Dial: a
		// probe that fails is not a connection of the user's that failed.
		return pingBest(ctx, rawURL, func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
			return c.probeDial(ctx, p.ID, dst)
		})
	}
	if !room.take(ctx, sess) {
		if ctx.Err() != nil {
			return 0, groups.ErrCanceled
		}
		return 0, errors.New("не проверен: запущено слишком много серверов")
	}
	defer room.give()
	ep, release := c.acquire(p)
	defer release()
	if ep == nil {
		return 0, errors.New("сервер не запустился")
	}
	if _, err := waitConnectedCtx(ctx, ep, connectWait(p, pingConnectWait)); err != nil {
		return 0, err
	}
	return pingBest(ctx, rawURL, func(ctx context.Context, dst socks5.Addr) (net.Conn, error) {
		cl := ep.SOCKS()
		return cl.Connect(ctx, dst)
	})
}

// pingBest is the better of pingTries probes; an error only when none
// passed.
func pingBest(ctx context.Context, rawURL string, dial func(context.Context, socks5.Addr) (net.Conn, error)) (time.Duration, error) {
	var best time.Duration
	var last error
	for i := 0; i < pingTries; i++ {
		rtt, err := groups.ProbeOnce(ctx, dial, rawURL, nil)
		switch {
		case errors.Is(err, groups.ErrCanceled):
			return 0, err
		case err != nil:
			last = err
		case best == 0 || rtt < best:
			best = rtt
		}
	}
	if best > 0 {
		return best, nil
	}
	return 0, last
}
