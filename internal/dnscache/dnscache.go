// Package dnscache keeps IP <-> name mappings learned by passively parsing
// DNS responses. One IP may belong to many names (CDNs), so the cache is a
// hint for routing, never proof.
package dnscache

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/rules"
)

type Cache struct {
	// TTLs from responses are clamped to [MinTTL, MaxTTL]: the OS cache may
	// keep an answer a little longer than the record says.
	MinTTL, MaxTTL time.Duration
	// MaxEntries bounds memory; the oldest-expiring pairs go first.
	MaxEntries int
	// QueryTTL is how long a query seen on the wire waits for its answer;
	// MaxQueries bounds the queries in flight.
	QueryTTL   time.Duration
	MaxQueries int

	mu     sync.RWMutex
	byIP   map[netip.Addr]map[string]time.Time
	byName map[string]map[netip.Addr]time.Time
	pairs  int
	now    func() time.Time

	qmu     sync.Mutex
	queries map[queryKey]time.Time
}

// queryKey is everything a response must repeat to answer a query: the
// transport, both endpoints, the message ID and the question.
type queryKey struct {
	tcp            bool
	client, server netip.AddrPort
	id             uint16
	name           string // lower-cased wire name
	qtype          dnsmessage.Type
	class          dnsmessage.Class
}

func New() *Cache {
	return &Cache{
		MinTTL: time.Minute, MaxTTL: time.Hour, MaxEntries: 200000,
		QueryTTL: 30 * time.Second, MaxQueries: 16384,
		byIP:    make(map[netip.Addr]map[string]time.Time),
		byName:  make(map[string]map[netip.Addr]time.Time),
		queries: make(map[queryKey]time.Time),
		now:     time.Now,
	}
}

// ErrNotResponse is returned for queries and malformed messages.
var ErrNotResponse = errors.New("dnscache: not a DNS response")

// ErrNotQuery is returned by AddQuery for responses and malformed messages.
var ErrNotQuery = errors.New("dnscache: not a DNS query")

// ErrUnsolicited is returned by AddAnswer for a response that answers no
// query in flight.
var ErrUnsolicited = errors.New("dnscache: unsolicited DNS response")

// maxMsgPairs bounds the pairs one message may add: real answers carry a
// handful of addresses and a short CNAME chain, while a crafted one could
// otherwise push thousands of pairs (and the evictions they force) at once.
const maxMsgPairs = 256

// AddQuery remembers a DNS query that client sent to server (a UDP payload,
// or a TCP segment), so that AddAnswer accepts the response to it. Queries
// expire after QueryTTL.
func (c *Cache) AddQuery(tcp bool, client, server netip.AddrPort, msg []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrNotQuery
		}
	}()
	if tcp {
		// Usually the length prefix and the message share a segment; when
		// the prefix went alone, this segment is the bare message.
		if m, ok := unframe(msg); ok {
			msg = m
		}
	}
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response {
		return ErrNotQuery
	}
	q, err := p.Question()
	if err != nil {
		return ErrNotQuery
	}
	k := newQueryKey(tcp, client, server, h.ID, q)
	exp := c.now().Add(c.QueryTTL)
	c.qmu.Lock()
	defer c.qmu.Unlock()
	if c.queries == nil {
		c.queries = make(map[queryKey]time.Time)
	}
	if _, ok := c.queries[k]; !ok && len(c.queries) >= c.MaxQueries {
		// Full (a query flood, or answers that come back through the tunnel
		// and never pass the sniff handle): drop an arbitrary query.
		for old := range c.queries {
			delete(c.queries, old)
			break
		}
	}
	c.queries[k] = exp
	return nil
}

// AddAnswer records a response that client received from server, but only
// when it answers a query remembered by AddQuery (same transport, endpoints,
// ID and question), and only once. Anyone who can deliver a packet from port
// 53 would otherwise write arbitrary name -> IP pairs into the cache and
// steer routing; such messages return ErrUnsolicited.
func (c *Cache) AddAnswer(tcp bool, client, server netip.AddrPort, msg []byte) (n int, err error) {
	defer func() {
		if recover() != nil {
			n, err = 0, ErrNotResponse
		}
	}()
	if tcp {
		m, ok := unframe(msg)
		if !ok {
			return 0, ErrNotResponse // split across segments: skipped
		}
		msg = m
	}
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response {
		return 0, ErrNotResponse
	}
	q, err := p.Question()
	if err != nil {
		return 0, ErrNotResponse
	}
	k := newQueryKey(tcp, client, server, h.ID, q)
	now := c.now()
	c.qmu.Lock()
	exp, ok := c.queries[k]
	if ok {
		delete(c.queries, k)
	}
	c.qmu.Unlock()
	if !ok || !now.Before(exp) {
		return 0, ErrUnsolicited
	}
	return c.AddResponse(msg)
}

func newQueryKey(tcp bool, client, server netip.AddrPort, id uint16, q dnsmessage.Question) queryKey {
	// Resolvers may echo the question in randomized case (DNS 0x20).
	return queryKey{tcp, client, server, id, strings.ToLower(q.Name.String()), q.Type, q.Class}
}

// unframe strips the 2-byte length prefix of a DNS-over-TCP segment that
// holds exactly one whole message.
func unframe(payload []byte) ([]byte, bool) {
	if len(payload) < 2 || int(binary.BigEndian.Uint16(payload)) != len(payload)-2 {
		return nil, false
	}
	return payload[2:], true
}

// AddResponse parses a DNS message (UDP payload) and records its A/AAAA
// answers. CNAME chains are followed so an address is linked both to the
// queried name and to every name along the chain. Returns pairs added.
// It is not matched to a query: packets sniffed off the wire go through
// AddAnswer.
func (c *Cache) AddResponse(msg []byte) (n int, err error) {
	// The message comes from the network: a parser bug (such as
	// GO-2026-5942) must cost this message, not the process.
	defer func() {
		if recover() != nil {
			n, err = 0, ErrNotResponse
		}
	}()
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return 0, ErrNotResponse
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return 0, ErrNotResponse
	}
	answers, err := p.AllAnswers()
	if err != nil {
		return 0, ErrNotResponse
	}
	// alias target -> names pointing at it
	aliases := map[string][]string{}
	type rec struct {
		name string
		ip   netip.Addr
		ttl  uint32
	}
	var addrs []rec
	for _, a := range answers {
		name := rules.NormalizeDomain(a.Header.Name.String())
		switch b := a.Body.(type) {
		case *dnsmessage.CNAMEResource:
			target := rules.NormalizeDomain(b.CNAME.String())
			aliases[target] = append(aliases[target], name)
		case *dnsmessage.AResource:
			addrs = append(addrs, rec{name, netip.AddrFrom4(b.A), a.Header.TTL})
		case *dnsmessage.AAAAResource:
			addrs = append(addrs, rec{name, netip.AddrFrom16(b.AAAA).Unmap(), a.Header.TTL})
		}
	}
	if len(addrs) == 0 {
		return 0, nil
	}
	query := ""
	if len(qs) > 0 {
		query = rules.NormalizeDomain(qs[0].Name.String())
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	n = 0
	tried := 0
add:
	for _, r := range addrs {
		exp := now.Add(c.clamp(r.ttl))
		for _, name := range chain(r.name, aliases, query) {
			if tried++; tried > maxMsgPairs {
				break add
			}
			if c.addLocked(name, r.ip, exp) {
				n++
			}
		}
	}
	if c.pairs > c.MaxEntries {
		c.evictLocked(c.MaxEntries)
	}
	return n, nil
}

// chain returns name plus every alias leading to it (bounded).
func chain(name string, aliases map[string][]string, query string) []string {
	out := []string{name}
	seen := map[string]bool{name: true}
	for i := 0; i < len(out) && len(out) < 16; i++ {
		for _, a := range aliases[out[i]] {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	// Responses without explicit CNAMEs for the query name still belong to it
	// when there is a single owner (some resolvers flatten chains).
	if query != "" && !seen[query] && len(aliases) == 0 && name != query {
		out = append(out, query)
	}
	return out
}

func (c *Cache) clamp(ttl uint32) time.Duration {
	d := time.Duration(ttl) * time.Second
	return max(c.MinTTL, min(d, c.MaxTTL))
}

func (c *Cache) addLocked(name string, ip netip.Addr, exp time.Time) bool {
	if name == "" {
		return false
	}
	m := c.byIP[ip]
	if m == nil {
		m = make(map[string]time.Time)
		c.byIP[ip] = m
	}
	old, existed := m[name]
	if !existed {
		c.pairs++
	}
	if exp.After(old) {
		m[name] = exp
		n := c.byName[name]
		if n == nil {
			n = make(map[netip.Addr]time.Time)
			c.byName[name] = n
		}
		n[ip] = exp
	}
	return !existed
}

// Names returns the unexpired names for ip, sorted.
func (c *Cache) Names(ip netip.Addr) []string {
	ip = ip.Unmap()
	now := c.now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []string
	for name, exp := range c.byIP[ip] {
		if now.Before(exp) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// IPs returns the unexpired addresses of name.
func (c *Cache) IPs(name string) []netip.Addr {
	name = rules.NormalizeDomain(name)
	now := c.now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []netip.Addr
	for ip, exp := range c.byName[name] {
		if now.Before(exp) {
			out = append(out, ip)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

// Sweep drops expired pairs and queries that got no answer.
func (c *Cache) Sweep() {
	now := c.now()
	c.mu.Lock()
	c.sweepLocked(now)
	c.mu.Unlock()
	c.qmu.Lock()
	for k, exp := range c.queries {
		if !now.Before(exp) {
			delete(c.queries, k)
		}
	}
	c.qmu.Unlock()
}

func (c *Cache) sweepLocked(now time.Time) {
	for ip, m := range c.byIP {
		for name, exp := range m {
			if !exp.After(now) {
				c.deleteLocked(ip, name)
			}
		}
	}
}

// evictSamples is how many random pairs compete for each eviction.
const evictSamples = 8

// evictLocked drops pairs until at most target remain. Each victim is the
// earliest-expiring of a few random pairs (map iteration starts at a random
// place): close to "oldest first", at a cost that does not grow with the
// cache, so a full cache costs no full pass per response.
func (c *Cache) evictLocked(target int) {
	for c.pairs > max(target, 0) {
		var vip netip.Addr
		var vname string
		var vexp time.Time
		for i := range evictSamples {
			ip, name, exp, ok := c.randomLocked()
			if !ok {
				return
			}
			if i == 0 || exp.Before(vexp) {
				vip, vname, vexp = ip, name, exp
			}
		}
		c.deleteLocked(vip, vname)
	}
}

// randomLocked returns an arbitrary pair.
func (c *Cache) randomLocked() (netip.Addr, string, time.Time, bool) {
	for ip, m := range c.byIP {
		for name, exp := range m {
			return ip, name, exp, true
		}
	}
	return netip.Addr{}, "", time.Time{}, false
}

func (c *Cache) deleteLocked(ip netip.Addr, name string) {
	m := c.byIP[ip]
	if _, ok := m[name]; !ok {
		return
	}
	delete(m, name)
	if len(m) == 0 {
		delete(c.byIP, ip)
	}
	c.pairs--
	if n := c.byName[name]; n != nil {
		delete(n, ip)
		if len(n) == 0 {
			delete(c.byName, name)
		}
	}
}

// Len returns the number of name/IP pairs.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pairs
}
