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
	// TTLs from responses are clamped to [MinTTL, MaxTTL]. MinTTL is a grace
	// for very short records. MaxTTL is not below the DNS client service's
	// default MaxCacheTtl (a day): Windows answers applications from its own
	// cache for the whole TTL without a query on the wire, so a pair dropped
	// earlier would stay unknown until then.
	MinTTL, MaxTTL time.Duration
	// MaxEntries bounds memory; the oldest-expiring pairs go first.
	MaxEntries int
	// QueryTTL is how long a query seen on the wire waits for its answer;
	// MaxQueries bounds the queries in flight.
	QueryTTL   time.Duration
	MaxQueries int

	mu     sync.RWMutex
	byIP   map[netip.Addr]map[siteName]time.Time
	byName map[string]map[siteIP]time.Time
	pairs  int
	now    func() time.Time
	// public: ECH public names learned from HTTPS/SVCB answers (PublicName).
	public map[string]time.Time

	qmu     sync.Mutex
	queries map[queryKey]time.Time
}

// siteName is one name of a site learned for an address. The site is the
// name the application asked for; the name is the site itself or a CNAME on
// the way from it to the address. All names of a site are one destination:
// a rule on either the queried name or its CDN name applies to it.
type siteName struct{ site, name string }

// siteIP is the byName side of a siteName entry.
type siteIP struct {
	site string
	ip   netip.Addr
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
		MinTTL: time.Minute, MaxTTL: 24 * time.Hour, MaxEntries: 200000,
		QueryTTL: 30 * time.Second, MaxQueries: 16384,
		byIP:    make(map[netip.Addr]map[siteName]time.Time),
		byName:  make(map[string]map[siteIP]time.Time),
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
		// Full (a query flood, or queries that got no answer): drop an
		// arbitrary query.
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

// AddAnswerFor records the answer to a query HyRoute sent itself (dns: an
// upstream resolution or a TCP pass-through): the answer must repeat the
// query's ID and question (DoH answers carry ID 0 like the query). Nothing
// else is accepted, so no one but the resolver HyRoute asked can add
// pairs. HyRoute's own injected answers never pass the DNS sniff handle,
// so this is the only way their pairs reach the cache.
func (c *Cache) AddAnswerFor(query, answer []byte) (n int, err error) {
	defer func() {
		if recover() != nil {
			n, err = 0, ErrNotResponse
		}
	}()
	var qp, ap dnsmessage.Parser
	qh, err := qp.Start(query)
	if err != nil || qh.Response {
		return 0, ErrNotQuery
	}
	qq, err := qp.Question()
	if err != nil {
		return 0, ErrNotQuery
	}
	ah, err := ap.Start(answer)
	if err != nil || !ah.Response {
		return 0, ErrNotResponse
	}
	aq, err := ap.Question()
	if err != nil {
		return 0, ErrNotResponse
	}
	if ah.ID != qh.ID || aq.Type != qq.Type || aq.Class != qq.Class || !strings.EqualFold(aq.Name.String(), qq.Name.String()) {
		return 0, ErrUnsolicited
	}
	return c.AddResponse(answer)
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
// queried name and to every name along the chain, all as one site (see
// Sites). The ECH public names of HTTPS/SVCB answers are kept too
// (PublicName). Returns pairs added. It is not matched to a query: every
// DNS answer from the network goes through AddAnswer.
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
	type pubName struct {
		name string
		ttl  uint32
	}
	var pub []pubName
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
		case *dnsmessage.HTTPSResource:
			for _, n := range echPublicNames(&b.SVCBResource) {
				pub = append(pub, pubName{n, a.Header.TTL})
			}
		case *dnsmessage.SVCBResource:
			for _, n := range echPublicNames(b) {
				pub = append(pub, pubName{n, a.Header.TTL})
			}
		}
	}
	if len(addrs) == 0 && len(pub) == 0 {
		return 0, nil
	}
	query := ""
	if len(qs) > 0 {
		query = rules.NormalizeDomain(qs[0].Name.String())
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range pub[:min(len(pub), 16)] {
		c.addPublicLocked(p.name, now.Add(min(c.clamp(p.ttl), maxPublicTTL)))
	}
	n = 0
	tried := 0
add:
	for _, r := range addrs {
		exp := now.Add(c.clamp(r.ttl))
		names := chain(r.name, aliases, query)
		// The chain is one site, named after the query when it leads there.
		site := r.name
		if slices.Contains(names, query) {
			site = query
		}
		for _, name := range names {
			if tried++; tried > maxMsgPairs {
				break add
			}
			if c.addLocked(siteName{site, name}, r.ip, exp) {
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

func (c *Cache) addLocked(k siteName, ip netip.Addr, exp time.Time) bool {
	if k.name == "" || k.site == "" {
		return false
	}
	m := c.byIP[ip]
	if m == nil {
		m = make(map[siteName]time.Time)
		c.byIP[ip] = m
	}
	old, existed := m[k]
	if !existed {
		c.pairs++
	}
	if exp.After(old) {
		m[k] = exp
		n := c.byName[k.name]
		if n == nil {
			n = make(map[siteIP]time.Time)
			c.byName[k.name] = n
		}
		n[siteIP{k.site, ip}] = exp
	}
	return !existed
}

// Names returns the unexpired names for ip, sorted.
func (c *Cache) Names(ip netip.Addr) []string {
	var out []string
	for _, site := range c.Sites(ip) {
		out = append(out, site...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Sites returns the unexpired names for ip grouped by site: the queried
// name first, then the CNAMEs that led from it to ip, sorted; sites are
// sorted by their first name. Different sites on one address are CDN
// neighbours; a rule matches a site when it matches any of its names
// (rules.Set.EvaluateSites).
func (c *Cache) Sites(ip netip.Addr) [][]string {
	ip = ip.Unmap()
	now := c.now()
	c.mu.RLock()
	var bySite map[string][]string
	for k, exp := range c.byIP[ip] {
		if now.Before(exp) {
			if bySite == nil {
				bySite = map[string][]string{}
			}
			bySite[k.site] = append(bySite[k.site], k.name)
		}
	}
	c.mu.RUnlock()
	var out [][]string
	for site, names := range bySite {
		slices.Sort(names)
		if i := slices.Index(names, site); i > 0 {
			copy(names[1:i+1], names[:i])
			names[0] = site
		}
		out = append(out, names)
	}
	slices.SortFunc(out, slices.Compare)
	return out
}

// IPs returns the unexpired addresses of name.
func (c *Cache) IPs(name string) []netip.Addr {
	name = rules.NormalizeDomain(name)
	now := c.now()
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []netip.Addr
	for k, exp := range c.byName[name] {
		if now.Before(exp) {
			out = append(out, k.ip)
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// Sweep drops expired pairs and queries that got no answer. It looks at no
// more than sweepBudget pairs, so the lock it holds does not stall the
// lookups of new connections even when the cache is full.
func (c *Cache) Sweep() {
	now := c.now()
	c.mu.Lock()
	c.sweepLocked(now)
	for name, exp := range c.public {
		if !exp.After(now) {
			delete(c.public, name)
		}
	}
	c.mu.Unlock()
	c.qmu.Lock()
	for k, exp := range c.queries {
		if !now.Before(exp) {
			delete(c.queries, k)
		}
	}
	c.qmu.Unlock()
}

// sweepBudget bounds the pairs one Sweep looks at (about a millisecond).
// Map iteration starts at a random place, so successive sweeps cover the
// whole cache; an expired pair waiting for its turn is invisible to lookups
// and among the first to go on eviction.
const sweepBudget = 4096

func (c *Cache) sweepLocked(now time.Time) {
	seen := 0
	for ip, m := range c.byIP {
		for k, exp := range m {
			if !exp.After(now) {
				c.deleteLocked(ip, k)
			}
			if seen++; seen >= sweepBudget {
				return
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
		var vname siteName
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
func (c *Cache) randomLocked() (netip.Addr, siteName, time.Time, bool) {
	for ip, m := range c.byIP {
		for k, exp := range m {
			return ip, k, exp, true
		}
	}
	return netip.Addr{}, siteName{}, time.Time{}, false
}

func (c *Cache) deleteLocked(ip netip.Addr, k siteName) {
	m := c.byIP[ip]
	if _, ok := m[k]; !ok {
		return
	}
	delete(m, k)
	if len(m) == 0 {
		delete(c.byIP, ip)
	}
	c.pairs--
	if n := c.byName[k.name]; n != nil {
		delete(n, siteIP{k.site, ip})
		if len(n) == 0 {
			delete(c.byName, k.name)
		}
	}
}

// Len returns the number of name/IP pairs (a CDN name shared by two
// queried names is counted once for each), expired pairs that the next
// sweeps have yet to drop included.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pairs
}
