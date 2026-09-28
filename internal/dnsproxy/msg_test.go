package dnsproxy

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// query builds a query; edns > 0 adds an OPT with that size.
func query(t testing.TB, name string, qt dnsmessage.Type, edns uint16, do bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qt, Class: dnsmessage.ClassINET})
	if edns > 0 {
		b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		rh.SetEDNS0(int(edns), dnsmessage.RCodeSuccess, do)
		b.OPTResource(rh, dnsmessage.OPTResource{})
	}
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mustQuery(t testing.TB, msg []byte) Query {
	t.Helper()
	q, ok := ParseQuery(msg)
	if !ok {
		t.Fatal("not a query")
	}
	return q
}

// answer is an upstream answer (ID 0) to UpstreamQuery(q).
type rr struct {
	name string
	typ  dnsmessage.Type
	ttl  uint32
	val  string // A/AAAA address, CNAME target
}

func answer(t testing.TB, q Query, rcode dnsmessage.RCode, ans []rr, soa *dnsmessage.SOAResource, soaTTL uint32, opt bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: rcode})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(q.Name + "."), Type: q.Type, Class: q.Class})
	b.StartAnswers()
	for _, a := range ans {
		h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(a.name), Class: dnsmessage.ClassINET, TTL: a.ttl}
		switch a.typ {
		case dnsmessage.TypeA:
			b.AResource(h, dnsmessage.AResource{A: netip.MustParseAddr(a.val).As4()})
		case dnsmessage.TypeAAAA:
			b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(a.val).As16()})
		case dnsmessage.TypeCNAME:
			b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(a.val)})
		case dnsmessage.TypeTXT:
			b.TXTResource(h, dnsmessage.TXTResource{TXT: []string{a.val}})
		}
	}
	b.StartAuthorities()
	if soa != nil {
		b.SOAResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.com."), Class: dnsmessage.ClassINET, TTL: soaTTL}, *soa)
	}
	b.StartAdditionals()
	if opt {
		var rh dnsmessage.ResourceHeader
		rh.SetEDNS0(4096, dnsmessage.RCodeSuccess, true)
		b.OPTResource(rh, dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 10, Data: []byte("cookie12")}}})
	}
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func unpack(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseQuery(t *testing.T) {
	q := mustQuery(t, query(t, "WwW.Example.COM.", dnsmessage.TypeA, 0, false))
	if q.ID != 0x1234 || q.Name != "www.example.com" || q.Wire.String() != "WwW.Example.COM." || !q.RD || q.EDNS || q.MaxUDP() != 512 {
		t.Fatalf("%+v", q)
	}
	q = mustQuery(t, query(t, "example.com.", dnsmessage.TypeAAAA, 1232, true))
	if !q.EDNS || q.UDPSize != 1232 || !q.DO || q.MaxUDP() != 1232 {
		t.Fatalf("edns: %+v", q)
	}
	if q := mustQuery(t, query(t, "example.com.", dnsmessage.TypeA, 65000, false)); q.MaxUDP() != 4096 {
		t.Fatal(q.MaxUDP())
	}
	build := func(h dnsmessage.Header, qs []dnsmessage.Question, ans bool, extra int) []byte {
		b := dnsmessage.NewBuilder(nil, h)
		b.StartQuestions()
		for _, x := range qs {
			b.Question(x)
		}
		b.StartAnswers()
		if ans {
			b.AResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("a.example."), Class: dnsmessage.ClassINET}, dnsmessage.AResource{})
		}
		b.StartAdditionals()
		for range extra {
			b.AResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("a.example."), Class: dnsmessage.ClassINET}, dnsmessage.AResource{})
		}
		m, _ := b.Finish()
		return m
	}
	one := []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}
	rd := dnsmessage.Header{RecursionDesired: true}
	for label, msg := range map[string][]byte{
		"response":    build(dnsmessage.Header{Response: true, RecursionDesired: true}, one, false, 0),
		"no rd":       build(dnsmessage.Header{}, one, false, 0),
		"opcode":      build(dnsmessage.Header{RecursionDesired: true, OpCode: 5}, one, false, 0),
		"two":         build(rd, append(one, one...), false, 0),
		"none":        build(rd, nil, false, 0),
		"answers":     build(rd, one, true, 0),
		"extra A":     build(rd, one, false, 1),
		"chaos":       build(rd, []dnsmessage.Question{{Name: dnsmessage.MustNewName("version.bind."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassCHAOS}}, false, 0),
		"axfr":        build(rd, []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example."), Type: dnsmessage.TypeAXFR, Class: dnsmessage.ClassINET}}, false, 0),
		"ixfr":        build(rd, []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example."), Type: 251, Class: dnsmessage.ClassINET}}, false, 0),
		"any":         build(rd, []dnsmessage.Question{{Name: dnsmessage.MustNewName("a.example."), Type: dnsmessage.TypeALL, Class: dnsmessage.ClassINET}}, false, 0),
		"root":        build(rd, []dnsmessage.Question{{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET}}, false, 0),
		"garbage":     []byte{1, 2, 3},
		"empty":       nil,
		"truncated":   query(t, "example.com.", dnsmessage.TypeA, 0, false)[:20],
		"header only": make([]byte, 12),
	} {
		if _, ok := ParseQuery(msg); ok {
			t.Errorf("%s accepted", label)
		}
	}
}

func FuzzParseQuery(f *testing.F) {
	f.Add(query(f, "example.com.", dnsmessage.TypeA, 1232, true))
	f.Add([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if q, ok := ParseQuery(b); ok {
			_ = Synth(q, dnsmessage.RCodeNameError)
			_ = UpstreamQuery(q)
			_, _, _ = Reply(q, b, ReplyOpts{Max: 512})
			_ = Negative(q, b, true)
		}
		_ = ttlOf(b)
	})
}

func TestUpstreamQuery(t *testing.T) {
	q := mustQuery(t, query(t, "WwW.Example.COM.", dnsmessage.TypeAAAA, 1232, true))
	q.CD = true
	b := UpstreamQuery(q)
	if len(b)%128 != 0 {
		t.Fatalf("not padded: %d", len(b))
	}
	m := unpack(t, b)
	if m.Header.ID != 0 || !m.Header.RecursionDesired || !m.Header.CheckingDisabled || m.Header.Response {
		t.Fatalf("header %+v", m.Header)
	}
	if len(m.Questions) != 1 || m.Questions[0].Name.String() != "www.example.com." || m.Questions[0].Type != dnsmessage.TypeAAAA {
		t.Fatalf("question %+v", m.Questions)
	}
	if len(m.Additionals) != 1 || m.Additionals[0].Header.Class != 4096 || !m.Additionals[0].Header.DNSSECAllowed() {
		t.Fatalf("opt %+v", m.Additionals)
	}
	opts := m.Additionals[0].Body.(*dnsmessage.OPTResource).Options
	if len(opts) != 1 || opts[0].Code != 12 {
		t.Fatalf("options: only padding expected: %+v", opts)
	}
	q.DO, q.CD = false, false
	if m := unpack(t, UpstreamQuery(q)); m.Additionals[0].Header.DNSSECAllowed() || m.Header.CheckingDisabled {
		t.Fatal("DO/CD not copied")
	}
}

func TestReply(t *testing.T) {
	q := mustQuery(t, query(t, "WwW.Example.COM.", dnsmessage.TypeA, 0, false))
	up := answer(t, q, dnsmessage.RCodeSuccess, []rr{{"www.example.com.", dnsmessage.TypeA, 86400, "93.184.216.34"}}, nil, 0, true)
	out, trunc, err := Reply(q, up, ReplyOpts{Max: 512, Age: 10 * time.Second, Tunnel: true})
	if err != nil || trunc {
		t.Fatal(err, trunc)
	}
	m := unpack(t, out)
	if m.Header.ID != 0x1234 || m.Questions[0].Name.String() != "WwW.Example.COM." || !m.Header.RecursionAvailable || !m.Header.RecursionDesired {
		t.Fatalf("%+v", m)
	}
	if m.Answers[0].Header.TTL != MaxTunnelTTL {
		t.Fatalf("tunnel TTL %d", m.Answers[0].Header.TTL)
	}
	if len(m.Additionals) != 0 {
		t.Fatal("OPT kept for a client without EDNS")
	}
	// Direct: only aged.
	out, _, _ = Reply(q, up, ReplyOpts{Max: 512, Age: 10 * time.Second})
	if m := unpack(t, out); m.Answers[0].Header.TTL != 86390 {
		t.Fatalf("direct TTL %d", m.Answers[0].Header.TTL)
	}
	// Negatives through the tunnel: SOA TTL and MINIMUM clamped.
	soa := &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.example.com."), MBox: dnsmessage.MustNewName("h.example.com."), MinTTL: 900}
	for _, rc := range []dnsmessage.RCode{dnsmessage.RCodeNameError, dnsmessage.RCodeSuccess} {
		out, _, err := Reply(q, answer(t, q, rc, nil, soa, 3600, false), ReplyOpts{Max: 512, Tunnel: true})
		if err != nil {
			t.Fatal(err)
		}
		m := unpack(t, out)
		s := m.Authorities[0].Body.(*dnsmessage.SOAResource)
		if m.Authorities[0].Header.TTL != 60 || s.MinTTL != 60 || m.Header.RCode != rc {
			t.Fatalf("negative %v: ttl %d min %d", rc, m.Authorities[0].Header.TTL, s.MinTTL)
		}
	}
	// EDNS client: our size, no options.
	qe := mustQuery(t, query(t, "www.example.com.", dnsmessage.TypeA, 4096, true))
	out, _, _ = Reply(qe, answer(t, qe, dnsmessage.RCodeSuccess, []rr{{"www.example.com.", dnsmessage.TypeA, 60, "1.2.3.4"}}, nil, 0, true), ReplyOpts{Max: 4096})
	m = unpack(t, out)
	if len(m.Additionals) != 1 || m.Additionals[0].Header.Class != 1232 || len(m.Additionals[0].Body.(*dnsmessage.OPTResource).Options) != 0 || !m.Additionals[0].Header.DNSSECAllowed() {
		t.Fatalf("opt %+v", m.Additionals)
	}
	// Too big: authority goes first, then TC.
	var many []rr
	for i := range 40 {
		many = append(many, rr{"www.example.com.", dnsmessage.TypeA, 60, netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}).String()})
	}
	big := answer(t, q, dnsmessage.RCodeSuccess, many, soa, 60, false)
	out, trunc, _ = Reply(q, big, ReplyOpts{Max: 700})
	if m := unpack(t, out); trunc || len(m.Authorities) != 0 || len(m.Answers) != 40 {
		t.Fatalf("authority not dropped first: trunc %v auth %d", trunc, len(m.Authorities))
	}
	out, trunc, _ = Reply(qe, big, ReplyOpts{Max: 512})
	if m := unpack(t, out); !trunc || !m.Header.Truncated || len(m.Answers) != 0 || len(m.Questions) != 1 || len(m.Additionals) != 1 {
		t.Fatalf("truncated: %v %+v", trunc, m)
	}
	// Mismatches are errors.
	other := mustQuery(t, query(t, "other.example.", dnsmessage.TypeA, 0, false))
	if _, _, err := Reply(q, answer(t, other, dnsmessage.RCodeSuccess, nil, nil, 0, false), ReplyOpts{}); err == nil {
		t.Fatal("other question accepted")
	}
	withID := append([]byte(nil), up...)
	withID[1] = 7
	if _, _, err := Reply(q, withID, ReplyOpts{}); err == nil {
		t.Fatal("answer with an ID accepted")
	}
	if _, _, err := Reply(q, UpstreamQuery(q), ReplyOpts{}); err == nil {
		t.Fatal("a query accepted as answer")
	}
	if _, _, err := Reply(q, []byte{1, 2}, ReplyOpts{}); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestSynth(t *testing.T) {
	q := mustQuery(t, query(t, "Ads.Example.", dnsmessage.TypeA, 0, false))
	for _, rc := range []dnsmessage.RCode{dnsmessage.RCodeNameError, dnsmessage.RCodeSuccess, dnsmessage.RCodeServerFailure} {
		m := unpack(t, Synth(q, rc))
		if m.Header.ID != q.ID || !m.Header.Response || m.Header.RCode != rc || m.Questions[0].Name.String() != "Ads.Example." || len(m.Answers) != 0 || len(m.Additionals) != 0 {
			t.Fatalf("%v: %+v", rc, m)
		}
		if rc == dnsmessage.RCodeServerFailure {
			if len(m.Authorities) != 0 {
				t.Fatal("SERVFAIL with SOA")
			}
			continue
		}
		if s, ok := m.Authorities[0].Body.(*dnsmessage.SOAResource); !ok || m.Authorities[0].Header.TTL != 60 || s.MinTTL != 60 {
			t.Fatalf("%v: SOA %+v", rc, m.Authorities)
		}
	}
	qe := mustQuery(t, query(t, "a.example.", dnsmessage.TypeA, 4096, true))
	if m := unpack(t, Synth(qe, dnsmessage.RCodeNameError)); len(m.Additionals) != 1 || m.Additionals[0].Header.Class != 1232 || !m.Additionals[0].Header.DNSSECAllowed() {
		t.Fatalf("opt %+v", m.Additionals)
	}
}

func TestNegative(t *testing.T) {
	qa := mustQuery(t, query(t, "a.example.", dnsmessage.TypeA, 0, false))
	q6 := mustQuery(t, query(t, "a.example.", dnsmessage.TypeAAAA, 0, false))
	nx := func(q Query) []byte { return answer(t, q, dnsmessage.RCodeNameError, nil, nil, 0, false) }
	nodata := func(q Query) []byte { return answer(t, q, dnsmessage.RCodeSuccess, nil, nil, 0, false) }
	for _, c := range []struct {
		label string
		q     Query
		up    []byte
		any   bool
		want  bool
	}{
		{"nx", qa, nx(qa), false, true},
		{"nx any", q6, nx(q6), true, true},
		{"nodata A", qa, nodata(qa), false, true},
		{"nodata A any", qa, nodata(qa), true, true},
		{"nodata AAAA", q6, nodata(q6), false, false},
		{"nodata AAAA any", q6, nodata(q6), true, true},
		{"cname only", qa, answer(t, qa, dnsmessage.RCodeSuccess, []rr{{"a.example.", dnsmessage.TypeCNAME, 60, "b.example."}}, nil, 0, false), true, false},
		{"A", qa, answer(t, qa, dnsmessage.RCodeSuccess, []rr{{"a.example.", dnsmessage.TypeA, 60, "1.2.3.4"}}, nil, 0, false), true, false},
		{"other type only", qa, answer(t, qa, dnsmessage.RCodeSuccess, []rr{{"a.example.", dnsmessage.TypeTXT, 60, "x"}}, nil, 0, false), false, true},
		{"servfail", qa, answer(t, qa, dnsmessage.RCodeServerFailure, nil, nil, 0, false), true, false},
		{"garbage", qa, []byte{1, 2, 3}, true, false},
	} {
		if got := Negative(c.q, c.up, c.any); got != c.want {
			t.Errorf("%s: %v", c.label, got)
		}
	}
}
