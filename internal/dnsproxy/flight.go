package dnsproxy

import "sync"

// flight lets concurrent resolutions of one key share one upstream round
// trip (Windows retransmits a query after a second, and asks every
// adapter's server at once). Its mutex is a leaf.
type flight struct {
	mu    sync.Mutex
	calls map[flightKey]*call
}

// flightKey is a query's cache key and the resolver generation it was sent
// in: after Configure a query never joins a round trip to the old server.
type flightKey struct {
	cacheKey
	gen uint64
}

type call struct {
	done chan struct{}
	msg  []byte
	err  error
}

// do runs fn once for concurrent callers of k; each gets its own copy.
func (f *flight) do(k flightKey, fn func() ([]byte, error)) ([]byte, error) {
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[flightKey]*call{}
	}
	if c := f.calls[k]; c != nil {
		f.mu.Unlock()
		<-c.done
		return append([]byte(nil), c.msg...), c.err
	}
	c := &call{done: make(chan struct{}), err: errAnswer} // the waiters' answer if fn panics
	f.calls[k] = c
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.calls, k)
		f.mu.Unlock()
		close(c.done)
	}()
	c.msg, c.err = fn()
	return append([]byte(nil), c.msg...), c.err
}
