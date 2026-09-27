package dnscache

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type ans struct {
	name  string
	cname string
	ip    string
	ttl   uint32
}

func response(t *testing.T, q string, answers ...ans) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RecursionAvailable: true})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(q), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	for _, a := range answers {
		h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(a.name), Class: dnsmessage.ClassINET, TTL: a.ttl}
		switch {
		case a.cname != "":
			b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(a.cname)})
		case netip.MustParseAddr(a.ip).Is4():
			b.AResource(h, dnsmessage.AResource{A: netip.MustParseAddr(a.ip).As4()})
		default:
			b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(a.ip).As16()})
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func newCache() (*Cache, *time.Time) {
	c := New()
	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }
	return c, &now
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestTTLAndExpiry(t *testing.T) {
	c, now := newCache()
	c.AddResponse(response(t, "Example.COM.", ans{name: "example.com.", ip: "93.184.216.34", ttl: 5}))
	if got := c.Names(ip("93.184.216.34")); !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Fatal(got)
	}
	// TTL 5 s is clamped up to MinTTL (60 s).
	*now = now.Add(59 * time.Second)
	if len(c.Names(ip("93.184.216.34"))) != 1 {
		t.Fatal("expired before MinTTL")
	}
	*now = now.Add(2 * time.Second)
	if len(c.Names(ip("93.184.216.34"))) != 0 {
		t.Fatal("not expired after MinTTL")
	}
	// Huge TTL is clamped down to MaxTTL.
	c.AddResponse(response(t, "long.test.", ans{name: "long.test.", ip: "1.1.1.1", ttl: 86400}))
	*now = now.Add(time.Hour + time.Second)
	if len(c.Names(ip("1.1.1.1"))) != 0 {
		t.Fatal("MaxTTL not applied")
	}
	c.Sweep()
	if c.Len() != 0 {
		t.Fatalf("sweep left %d pairs", c.Len())
	}
}

func TestMultipleNamesPerIPAndIPChange(t *testing.T) {
	c, now := newCache()
	c.AddResponse(response(t, "a.cdn.test.", ans{name: "a.cdn.test.", ip: "10.0.0.1", ttl: 300}))
	c.AddResponse(response(t, "b.cdn.test.", ans{name: "b.cdn.test.", ip: "10.0.0.1", ttl: 300}))
	if got := c.Names(ip("10.0.0.1")); !reflect.DeepEqual(got, []string{"a.cdn.test", "b.cdn.test"}) {
		t.Fatal(got)
	}
	// Domain moves to a new IP: the old pair stays until its TTL.
	*now = now.Add(100 * time.Second)
	c.AddResponse(response(t, "a.cdn.test.", ans{name: "a.cdn.test.", ip: "10.0.0.2", ttl: 300}))
	if got := c.IPs("a.cdn.test"); !reflect.DeepEqual(got, []netip.Addr{ip("10.0.0.1"), ip("10.0.0.2")}) {
		t.Fatal(got)
	}
	*now = now.Add(201 * time.Second)
	if got := c.IPs("A.CDN.TEST."); !reflect.DeepEqual(got, []netip.Addr{ip("10.0.0.2")}) {
		t.Fatal(got)
	}
	// Unknown IP / name.
	if c.Names(ip("192.0.2.1")) != nil || c.IPs("nope.test") != nil {
		t.Fatal("unknown should be empty")
	}
}

func TestCNAMEChain(t *testing.T) {
	c, _ := newCache()
	c.AddResponse(response(t, "www.example.com.",
		ans{name: "www.example.com.", cname: "www.example.com.cdn.net."},
		ans{name: "www.example.com.cdn.net.", cname: "edge.cdn.net."},
		ans{name: "edge.cdn.net.", ip: "203.0.113.5", ttl: 120},
		ans{name: "edge.cdn.net.", ip: "2001:db8::5", ttl: 120},
	))
	want := []string{"edge.cdn.net", "www.example.com", "www.example.com.cdn.net"}
	if got := c.Names(ip("203.0.113.5")); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	if got := c.Names(ip("2001:db8::5")); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
	if got := c.Names(ip("::ffff:203.0.113.5")); !reflect.DeepEqual(got, want) {
		t.Fatal("mapped lookup", got)
	}
}

func TestIDNAndRejects(t *testing.T) {
	c, _ := newCache()
	c.AddResponse(response(t, "xn--e1afmkfd.xn--p1ai.", ans{name: "xn--e1afmkfd.xn--p1ai.", ip: "198.51.100.7", ttl: 300}))
	if got := c.IPs("пример.рф"); len(got) != 1 {
		t.Fatal("IDN lookup", got)
	}
	if _, err := c.AddResponse([]byte{1, 2, 3}); err == nil {
		t.Fatal("garbage accepted")
	}
	// A query (not a response) is ignored.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("q.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	if _, err := c.AddResponse(q); err == nil {
		t.Fatal("query accepted")
	}
	// NXDOMAIN ignored.
	b = dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeNameError})
	nx, _ := b.Finish()
	if _, err := c.AddResponse(nx); err == nil {
		t.Fatal("nxdomain accepted")
	}
}

// query builds a query for q with message ID id.
func query(t *testing.T, id uint16, q string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(q), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// withID sets the message ID of a built message.
func withID(msg []byte, id uint16) []byte {
	msg = append([]byte(nil), msg...)
	binary.BigEndian.PutUint16(msg, id)
	return msg
}

func framed(msg []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
}

var (
	client = netip.MustParseAddrPort("192.168.1.5:50000")
	server = netip.MustParseAddrPort("192.168.1.1:53")
)

func TestAnswerNeedsQuery(t *testing.T) {
	c, now := newCache()
	resp := withID(response(t, "yandex.ru.", ans{name: "yandex.ru.", ip: "198.51.100.1", ttl: 300}), 0x1234)
	// Unsolicited: nobody asked, nothing is cached.
	if _, err := c.AddAnswer(false, client, server, resp); err != ErrUnsolicited || c.Len() != 0 {
		t.Fatal("unsolicited response accepted", err)
	}
	if err := c.AddQuery(false, client, server, query(t, 0x1234, "yandex.ru.")); err != nil {
		t.Fatal(err)
	}
	// Anything that differs from the query is rejected and keeps it open.
	for name, a := range map[string]struct {
		tcp            bool
		client, server netip.AddrPort
		msg            []byte
	}{
		"id":       {false, client, server, withID(resp, 0x1235)},
		"port":     {false, netip.MustParseAddrPort("192.168.1.5:50001"), server, resp},
		"local ip": {false, netip.MustParseAddrPort("192.168.1.6:50000"), server, resp},
		"server":   {false, client, netip.MustParseAddrPort("192.168.1.2:53"), resp},
		"tcp":      {true, client, server, framed(resp)},
		"question": {false, client, server, withID(response(t, "mail.ru.", ans{name: "yandex.ru.", ip: "198.51.100.1", ttl: 300}), 0x1234)},
	} {
		if _, err := c.AddAnswer(a.tcp, a.client, a.server, a.msg); err != ErrUnsolicited {
			t.Fatalf("%s mismatch: %v", name, err)
		}
	}
	if c.Len() != 0 {
		t.Fatal("mismatched response cached")
	}
	// The answer is taken once, the question compared case-insensitively
	// (DNS 0x20).
	resp0x20 := withID(response(t, "YaNdEx.Ru.", ans{name: "yandex.ru.", ip: "198.51.100.1", ttl: 300}), 0x1234)
	if n, err := c.AddAnswer(false, client, server, resp0x20); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err := c.AddAnswer(false, client, server, resp); err != ErrUnsolicited {
		t.Fatal("replayed response accepted", err)
	}
	// A query waits QueryTTL for its answer.
	c.AddQuery(false, client, server, query(t, 7, "late.test."))
	*now = now.Add(c.QueryTTL)
	if _, err := c.AddAnswer(false, client, server, withID(response(t, "late.test.", ans{name: "late.test.", ip: "198.51.100.2", ttl: 300}), 7)); err != ErrUnsolicited {
		t.Fatal("answer after QueryTTL accepted", err)
	}
	if got := c.Names(ip("198.51.100.1")); !reflect.DeepEqual(got, []string{"yandex.ru"}) {
		t.Fatal(got)
	}
	// Responses are not queries.
	if err := c.AddQuery(false, client, server, resp); err != ErrNotQuery {
		t.Fatal("response taken as a query", err)
	}
}

func TestQueriesBoundedAndSwept(t *testing.T) {
	c, now := newCache()
	c.MaxQueries = 8
	for i := range 20 {
		c.AddQuery(false, client, server, query(t, uint16(i), "q.test."))
	}
	if len(c.queries) != 8 {
		t.Fatalf("%d queries in flight, limit 8", len(c.queries))
	}
	*now = now.Add(c.QueryTTL)
	c.Sweep()
	if len(c.queries) != 0 {
		t.Fatalf("sweep left %d queries", len(c.queries))
	}
}

func TestTCPMessage(t *testing.T) {
	c, _ := newCache()
	msg := withID(response(t, "tcp.test.", ans{name: "tcp.test.", ip: "192.0.2.9", ttl: 300}), 9)
	c.AddQuery(true, client, server, framed(query(t, 9, "tcp.test.")))
	// Split across segments: skipped in MVP.
	if _, err := c.AddAnswer(true, client, server, framed(msg)[:20]); err == nil {
		t.Fatal("partial TCP message accepted")
	}
	if n, err := c.AddAnswer(true, client, server, framed(msg)); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	// The length prefix sent in a segment of its own.
	c.AddQuery(true, client, server, query(t, 10, "tcp2.test."))
	msg = withID(response(t, "tcp2.test.", ans{name: "tcp2.test.", ip: "192.0.2.10", ttl: 300}), 10)
	if n, err := c.AddAnswer(true, client, server, framed(msg)); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}

func TestMaxEntries(t *testing.T) {
	c, _ := newCache()
	c.MaxEntries = 10
	for i := 0; i < 30; i++ {
		c.AddResponse(response(t, "n.test.", ans{name: "n.test.", ip: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}).String(), ttl: 60}))
	}
	if c.Len() > 10 {
		t.Fatalf("len %d over limit", c.Len())
	}
}

func TestMaxEntriesLongTTL(t *testing.T) {
	c, now := newCache()
	c.MaxEntries = 100
	for i := range 1000 {
		*now = now.Add(time.Second)
		c.AddResponse(response(t, "n.test.", ans{name: "n.test.", ip: netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}).String(), ttl: 300}))
		if c.Len() > 100 {
			t.Fatalf("len %d over limit after %d responses", c.Len(), i+1)
		}
		if len(c.byIP) != c.Len() || len(c.byName["n.test"]) != c.Len() {
			t.Fatal("maps out of step with the pair count")
		}
	}
	// The pairs that expire first went (all expired ones, practically
	// surely), the newest answer is kept.
	live := 0
	for _, m := range c.byIP {
		for _, exp := range m {
			if exp.After(*now) {
				live++
			}
		}
	}
	if c.Len() != 100 || live != 100 || len(c.Names(ip("10.0.3.231"))) != 1 {
		t.Fatal("wrong pairs evicted", c.Len(), live)
	}
}

func TestPairsPerMessageBounded(t *testing.T) {
	c, _ := newCache()
	var answers []ans
	for i := range 400 {
		answers = append(answers, ans{name: "many.test.", ip: netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}).String(), ttl: 300})
	}
	if n, err := c.AddResponse(response(t, "many.test.", answers...)); err != nil || n != maxMsgPairs {
		t.Fatal(n, err)
	}
}
