// Package dnsproxy resolves the DNS queries the DNS policy sends upstream:
// message checks and rewriting, a small answer cache, singleflight, the
// DoH/DoT/TCP clients and their health. Everything it parses comes from
// local programs or the network: every parse is bounded and recovers from
// a parser panic.
package dnsproxy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/rules"
)

// Query is a standard recursive query HyRoute may answer.
type Query struct {
	ID      uint16
	Name    string          // rules.NormalizeDomain(question name)
	Wire    dnsmessage.Name // as asked (case kept, 0x20)
	Type    dnsmessage.Type
	Class   dnsmessage.Class
	RD      bool
	EDNS    bool
	UDPSize int // from OPT; 0 without EDNS
	DO, CD  bool
}

const (
	// MaxTunnelTTL (s): Windows keeps a tunnel answer at most this long.
	MaxTunnelTTL = 300
	// MaxNegativeTTL (s): and a tunnel negative (and the synthesized ones).
	MaxNegativeTTL = 60
	// maxMessage is the largest DNS message (TCP length prefix).
	maxMessage = 65535
	// ednsSize is the UDP size HyRoute advertises in its answers.
	ednsSize = 1232
)

// ParseQuery accepts only a standard recursive query: opcode QUERY, one
// question of class IN, no response bit, no answer or authority records,
// at most one additional record which is OPT, RD set, and a type other
// than AXFR, IXFR and ANY. Anything else (and garbage) is not ok: it goes
// on as before.
func ParseQuery(msg []byte) (q Query, ok bool) {
	defer func() {
		if recover() != nil {
			q, ok = Query{}, false
		}
	}()
	if len(msg) < 12 || len(msg) > maxMessage {
		return Query{}, false
	}
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response || h.OpCode != 0 || !h.RecursionDesired {
		return Query{}, false
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return Query{}, false
	}
	qq := qs[0]
	switch qq.Type {
	case dnsmessage.TypeAXFR, dnsmessage.TypeALL, 251: // 251: IXFR
		return Query{}, false
	}
	if qq.Class != dnsmessage.ClassINET {
		return Query{}, false
	}
	return parseRest(msg, h, qq)
}

// parseRest checks the authority and additional sections of a query whose
// header and question passed (a fresh parser: the sections are counted by
// reading them).
func parseRest(msg []byte, h dnsmessage.Header, qq dnsmessage.Question) (Query, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return Query{}, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return Query{}, false
	}
	if ans, err := p.AllAnswers(); err != nil || len(ans) != 0 {
		return Query{}, false
	}
	if auth, err := p.AllAuthorities(); err != nil || len(auth) != 0 {
		return Query{}, false
	}
	extra, err := p.AllAdditionals()
	if err != nil || len(extra) > 1 {
		return Query{}, false
	}
	name := rules.NormalizeDomain(qq.Name.String())
	if name == "" {
		return Query{}, false
	}
	q := Query{ID: h.ID, Name: name, Wire: qq.Name, Type: qq.Type, Class: qq.Class, RD: h.RecursionDesired, CD: h.CheckingDisabled}
	if len(extra) == 1 {
		if extra[0].Header.Type != dnsmessage.TypeOPT {
			return Query{}, false
		}
		q.EDNS = true
		q.UDPSize = int(extra[0].Header.Class)
		q.DO = extra[0].Header.DNSSECAllowed()
	}
	return q, true
}

// MaxUDP is the largest UDP answer the client takes.
func (q Query) MaxUDP() int {
	if !q.EDNS {
		return 512
	}
	return min(max(q.UDPSize, 512), 4096)
}

// UpstreamQuery is the query HyRoute sends upstream: ID 0, RD, CD as
// asked, one question (lower-cased), OPT with 4096 and DO as asked, padded
// to a multiple of 128 bytes (RFC 8467). No other options: no client
// subnet, no cookies.
func UpstreamQuery(q Query) []byte {
	name, err := dnsmessage.NewName(strings.ToLower(q.Wire.String()))
	if err != nil {
		name = q.Wire
	}
	build := func(pad int) []byte {
		b := dnsmessage.NewBuilder(make([]byte, 0, 128), dnsmessage.Header{RecursionDesired: true, CheckingDisabled: q.CD})
		b.EnableCompression()
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: name, Type: q.Type, Class: q.Class})
		_ = b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		_ = rh.SetEDNS0(4096, dnsmessage.RCodeSuccess, q.DO)
		_ = b.OPTResource(rh, dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: make([]byte, pad)}}})
		m, _ := b.Finish()
		return m
	}
	m := build(0)
	if r := len(m) % 128; r != 0 {
		m = build(128 - r)
	}
	return m
}

// ReplyOpts shapes an upstream answer for the client.
type ReplyOpts struct {
	Max    int           // the client's size limit (q.MaxUDP() or 65535 on TCP)
	Age    time.Duration // how long the answer sat in the resolver cache
	Tunnel bool          // a tunnel answer: clamp TTLs
	// NoTC: the client's retry over TCP would not come back to us (an
	// IPv6 link-local server: TCP to it is not intercepted), so an answer
	// over the limit keeps as many records of the asked type as fit
	// instead of TC; when even one does not fit, Reply fails.
	NoTC bool
}

var errAnswer = errors.New("dns: bad upstream answer")

// errServerRcode: the upstream answered with an error of its own
// (SERVFAIL, REFUSED, NOTIMP, FORMERR, …). It fails that query like no
// answer: a direct query then goes on as before, a tunnel one gets
// SERVFAIL, nothing is cached. It does not count toward the client's
// health (see errKind).
var errServerRcode = fmt.Errorf("%w: server error", errAnswer)

// serverError reports an upstream answer whose rcode is neither NOERROR
// nor NXDOMAIN (unparseable: false; Reply has checked it).
func serverError(up []byte) bool {
	var p dnsmessage.Parser
	h, err := p.Start(up)
	return err == nil && h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError
}

// Reply turns the upstream answer up to UpstreamQuery(q) into the answer
// to q: its ID and question as asked, RD as asked, RA set, TTLs aged (and
// clamped for a tunnel answer, its negatives to MaxNegativeTTL), OPT as the
// client asked. Too big for Max: authority and additional records go
// first, then the answer is truncated (TC).
func Reply(q Query, up []byte, o ReplyOpts) (out []byte, truncated bool, err error) {
	defer func() {
		if recover() != nil {
			out, truncated, err = nil, false, errAnswer
		}
	}()
	var m dnsmessage.Message
	if err := m.Unpack(up); err != nil {
		return nil, false, errAnswer
	}
	if !m.Header.Response || m.Header.ID != 0 || len(m.Questions) != 1 {
		return nil, false, errAnswer
	}
	mq := m.Questions[0]
	if !strings.EqualFold(mq.Name.String(), q.Wire.String()) || mq.Type != q.Type || mq.Class != q.Class {
		return nil, false, errAnswer
	}
	m.Header.ID = q.ID
	m.Header.RecursionDesired = q.RD
	m.Header.RecursionAvailable = true
	m.Questions[0].Name = q.Wire
	age := uint32(max(o.Age, 0) / time.Second)
	negative := negativeMsg(&m)
	for _, sec := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for i := range sec {
			r := &sec[i]
			if r.Header.Type == dnsmessage.TypeOPT {
				continue
			}
			r.Header.TTL = r.Header.TTL - min(r.Header.TTL, age)
			if o.Tunnel {
				r.Header.TTL = min(r.Header.TTL, MaxTunnelTTL)
			}
		}
	}
	if negative && o.Tunnel {
		for i := range m.Authorities {
			if soa, ok := m.Authorities[i].Body.(*dnsmessage.SOAResource); ok {
				m.Authorities[i].Header.TTL = min(m.Authorities[i].Header.TTL, MaxNegativeTTL)
				soa.MinTTL = min(soa.MinTTL, MaxNegativeTTL)
			}
		}
	}
	// OPT: only for a client that sent one; our size, no options.
	var opt *dnsmessage.Resource
	extra := m.Additionals[:0]
	for _, r := range m.Additionals {
		if r.Header.Type == dnsmessage.TypeOPT {
			if opt == nil {
				cp := r
				opt = &cp
			}
			continue
		}
		extra = append(extra, r)
	}
	m.Additionals = extra
	if q.EDNS {
		if opt == nil {
			var rh dnsmessage.ResourceHeader
			_ = rh.SetEDNS0(ednsSize, dnsmessage.RCodeSuccess, q.DO)
			opt = &dnsmessage.Resource{Header: rh}
		}
		opt.Header.Class = ednsSize
		opt.Body = &dnsmessage.OPTResource{}
		m.Additionals = append(m.Additionals, *opt)
	}
	limit := o.Max
	if limit <= 0 {
		limit = maxMessage
	}
	b, err := m.Pack()
	if err != nil {
		return nil, false, errAnswer
	}
	if len(b) <= limit {
		return b, false, nil
	}
	m.Authorities = nil
	m.Additionals = keepOPT(m.Additionals)
	if b, err = m.Pack(); err != nil {
		return nil, false, errAnswer
	}
	if len(b) <= limit {
		return b, false, nil
	}
	if o.NoTC {
		// Drop records of the asked type from the end; the chain to them
		// (CNAMEs) stays.
		for n := len(m.Answers) - 1; n >= 0; n-- {
			if m.Answers[n].Header.Type != q.Type || !hasType(m.Answers[:n], q.Type) {
				continue
			}
			m.Answers = append(m.Answers[:n], m.Answers[n+1:]...)
			if b, err = m.Pack(); err != nil {
				return nil, false, errAnswer
			}
			if len(b) <= limit {
				return b, false, nil
			}
		}
		return nil, false, errAnswer
	}
	m.Header.Truncated = true
	m.Answers = nil
	if b, err = m.Pack(); err != nil {
		return nil, false, errAnswer
	}
	return b, true, nil
}

func hasType(rs []dnsmessage.Resource, t dnsmessage.Type) bool {
	for _, r := range rs {
		if r.Header.Type == t {
			return true
		}
	}
	return false
}

func keepOPT(rs []dnsmessage.Resource) []dnsmessage.Resource {
	var out []dnsmessage.Resource
	for _, r := range rs {
		if r.Header.Type == dnsmessage.TypeOPT {
			out = append(out, r)
		}
	}
	return out
}

// negativeSOA is the authority of HyRoute's own negative answers: clients
// cache the negative for at most MaxNegativeTTL.
func negativeSOA(owner dnsmessage.Name) dnsmessage.Resource {
	inv := dnsmessage.MustNewName("hyroute.invalid.")
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: MaxNegativeTTL},
		Body: &dnsmessage.SOAResource{NS: inv, MBox: inv, Serial: 1, Refresh: MaxNegativeTTL, Retry: MaxNegativeTTL,
			Expire: MaxNegativeTTL, MinTTL: MaxNegativeTTL},
	}
}

// Synth is HyRoute's own answer to q: NXDOMAIN, NODATA (RCodeSuccess
// without answers) or SERVFAIL. The negatives carry an SOA with TTL 60.
func Synth(q Query, rcode dnsmessage.RCode) []byte {
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RD, RecursionAvailable: true, RCode: rcode},
		Questions: []dnsmessage.Question{{Name: q.Wire, Type: q.Type, Class: q.Class}},
	}
	if rcode == dnsmessage.RCodeNameError || rcode == dnsmessage.RCodeSuccess {
		m.Authorities = []dnsmessage.Resource{negativeSOA(q.Wire)}
	}
	if q.EDNS {
		var rh dnsmessage.ResourceHeader
		_ = rh.SetEDNS0(ednsSize, dnsmessage.RCodeSuccess, q.DO)
		m.Additionals = []dnsmessage.Resource{{Header: rh, Body: &dnsmessage.OPTResource{}}}
	}
	b, err := m.Pack()
	if err != nil {
		// Only a name that does not pack: answer without the authority.
		m.Authorities = nil
		b, _ = m.Pack()
	}
	return b
}

// Negative reports an upstream answer that says the name does not exist
// (NXDOMAIN), or, when any is set or q.Type is A, that it has no record
// of the type asked (NOERROR without an answer of q.Type and without a
// CNAME). Unparseable: false.
func Negative(q Query, up []byte, any bool) (neg bool) {
	defer func() {
		if recover() != nil {
			neg = false
		}
	}()
	var p dnsmessage.Parser
	h, err := p.Start(up)
	if err != nil || !h.Response {
		return false
	}
	switch h.RCode {
	case dnsmessage.RCodeNameError:
		return true
	case dnsmessage.RCodeSuccess:
	default:
		return false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return false
	}
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return false
		}
		if rh.Type == q.Type || rh.Type == dnsmessage.TypeCNAME {
			return false
		}
		if err := p.SkipAnswer(); err != nil {
			return false
		}
	}
	return any || q.Type == dnsmessage.TypeA
}

// negativeMsg: NXDOMAIN, or NOERROR without a record of the type asked
// (NODATA, RFC 2308), also after a CNAME chain, whose answer then holds
// only the CNAMEs. A CNAME or ANY question is answered by any record.
func negativeMsg(m *dnsmessage.Message) bool {
	switch {
	case m.Header.RCode == dnsmessage.RCodeNameError:
		return true
	case m.Header.RCode != dnsmessage.RCodeSuccess:
		return false
	case len(m.Questions) != 1 || m.Questions[0].Type == dnsmessage.TypeCNAME || m.Questions[0].Type == dnsmessage.TypeALL:
		return len(m.Answers) == 0
	}
	for _, r := range m.Answers {
		if r.Header.Type == m.Questions[0].Type {
			return false
		}
	}
	return true
}

// ttlOf is how long an answer may be cached: the smallest TTL of its
// answer and authority records (not OPT), at most MaxTunnelTTL; for a
// negative, the SOA's min(TTL, MINIMUM), at most MaxNegativeTTL. 0 = not
// cacheable (SERVFAIL and the like, or no TTL).
func ttlOf(msg []byte) (ttl time.Duration) {
	defer func() {
		if recover() != nil {
			ttl = 0
		}
	}()
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		return 0
	}
	switch m.Header.RCode {
	case dnsmessage.RCodeSuccess, dnsmessage.RCodeNameError:
	default:
		return 0
	}
	if m.Header.Truncated {
		return 0
	}
	if negativeMsg(&m) {
		for _, r := range m.Authorities {
			if soa, ok := r.Body.(*dnsmessage.SOAResource); ok {
				return time.Duration(min(r.Header.TTL, soa.MinTTL, MaxNegativeTTL)) * time.Second
			}
		}
		return 0
	}
	least := uint32(MaxTunnelTTL)
	for _, sec := range [][]dnsmessage.Resource{m.Answers, m.Authorities} {
		for _, r := range sec {
			if r.Header.Type != dnsmessage.TypeOPT {
				least = min(least, r.Header.TTL)
			}
		}
	}
	return time.Duration(least) * time.Second
}
