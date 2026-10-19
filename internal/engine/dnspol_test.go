package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/lardan099/hyroute/internal/dnspolicy"
	"github.com/lardan099/hyroute/internal/dnsproxy"
	"github.com/lardan099/hyroute/internal/engine/nat"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/packet"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/sysdns"
)

const firefoxPID = 700

func init() { procs[firefoxPID] = `C:\Firefox\firefox.exe` }

// polQuery is a query with ID 0x2222 (edns > 0: with an OPT of that size).
func polQuery(t testing.TB, name string, typ dnsmessage.Type, edns int) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x2222, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET})
	if edns > 0 {
		b.StartAdditionals()
		var rh dnsmessage.ResourceHeader
		rh.SetEDNS0(edns, dnsmessage.RCodeSuccess, false)
		b.OPTResource(rh, dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: make([]byte, max(0, edns-100))}}})
	}
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// upAnswer is an upstream answer (ID 0) to q: ips as A/AAAA of the asked
// type (none: NODATA), or rcode.
func upAnswer(q dnsproxy.Query, rcode dnsmessage.RCode, ips ...string) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RecursionAvailable: true, RCode: rcode})
	b.StartQuestions()
	name := dnsmessage.MustNewName(strings.ToLower(q.Wire.String()))
	b.Question(dnsmessage.Question{Name: name, Type: q.Type, Class: q.Class})
	b.StartAnswers()
	for _, ip := range ips {
		a := netip.MustParseAddr(ip)
		h := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 3600}
		if a.Is4() {
			b.AResource(h, dnsmessage.AResource{A: a.As4()})
		} else {
			b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
	}
	m, _ := b.Finish()
	return m
}

// fakeRes is the resolver: by default it answers 93.184.216.34 (A) or
// 2606:2800::1 (AAAA).
type fakeRes struct {
	mu    sync.Mutex
	calls []string // "tunnel:<profile> name" | "direct name"
	fn    func(via dnspolicy.Via, profile string, q dnsproxy.Query) ([]byte, error)
	hang  bool // wait for the context to end
}

func (f *fakeRes) Exchange(ctx context.Context, via dnspolicy.Via, profile string, q dnsproxy.Query) ([]byte, time.Duration, error) {
	f.mu.Lock()
	call := "direct " + q.Name
	if via == dnspolicy.ViaTunnel {
		call = "tunnel:" + profile + " " + q.Name
	}
	f.calls = append(f.calls, call)
	fn, hang := f.fn, f.hang
	f.mu.Unlock()
	if hang {
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}
	if fn != nil {
		b, err := fn(via, profile, q)
		return b, 0, err
	}
	if q.Type == dnsmessage.TypeAAAA {
		return upAnswer(q, dnsmessage.RCodeSuccess, "2606:2800::1"), 0, nil
	}
	return upAnswer(q, dnsmessage.RCodeSuccess, "93.184.216.34"), 0, nil
}

func (f *fakeRes) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

func (f *fakeRes) set(fn func(via dnspolicy.Via, profile string, q dnsproxy.Query) ([]byte, error)) {
	f.mu.Lock()
	f.fn = fn
	f.mu.Unlock()
}

type dnsRig struct {
	*harness
	res   *fakeRes
	snaps atomic.Int32
	info  sysdns.Info
}

const (
	cli     = "192.168.1.5:5353"
	router  = "192.168.1.1:53"
	google  = "8.8.8.8:53"
	dnscach = 300
)

// newDNSRig: a harness with a policy, the Windows DNS client (PID 300),
// the router 192.168.1.1 and 8.8.8.8 as the gateway adapter's servers.
func newDNSRig(t *testing.T, cfg rules.Config, pc dnspolicy.Config, opt Options) *dnsRig {
	t.Helper()
	r := &dnsRig{harness: newHarness(t, cfg, opt), res: &fakeRes{}}
	quiet(r.harness)
	r.c.DnscachePID.Store(dnscach)
	r.info = sysdns.Info{
		Primary: map[netip.Addr]bool{netip.MustParseAddr("192.168.1.1"): true, netip.MustParseAddr("8.8.8.8"): true},
		All: map[netip.Addr]bool{netip.MustParseAddr("192.168.1.1"): true, netip.MustParseAddr("8.8.8.8"): true,
			netip.MustParseAddr("10.8.0.1"): true, netip.MustParseAddr("8.8.4.4"): true, netip.MustParseAddr("100.100.100.100"): true},
		Suffixes: []string{"corp.example"},
	}
	r.c.SysDNS = NewSysDNSView(func() (sysdns.Info, error) { r.snaps.Add(1); return r.info, nil }, r.c.Log)
	r.c.SysDNS.Refresh()
	r.setPolicy(t, pc)
	r.c.Resolver = r.res
	return r
}

func (r *dnsRig) setPolicy(t *testing.T, pc dnspolicy.Config) {
	t.Helper()
	pol, err := dnspolicy.Compile(pc, dnspolicy.Names{Servers: []string{"hy.server.example"}})
	if err != nil {
		t.Fatal(err)
	}
	r.c.DNSPol.Store(pol)
}

// ask sends a UDP query from src to dst, owned by pid (0: no owner).
func (r *dnsRig) ask(src, dst string, pid uint32, msg []byte) {
	if pid != 0 {
		r.own(17, src, dst, pid)
	}
	r.sendUDP(src, dst, msg)
}

// answer waits for the injected answer to a query from src to dst.
func (r *dnsRig) answer(t *testing.T, src, dst string) dnsmessage.Message {
	t.Helper()
	i := r.next(t)
	if i.addr.Outbound() || i.pkt.Src() != netip.MustParseAddrPort(dst) || i.pkt.Dst() != netip.MustParseAddrPort(src) {
		t.Fatalf("not an answer: %v -> %v outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.addr.Outbound())
	}
	var m dnsmessage.Message
	if err := m.Unpack(i.pkt.Payload()); err != nil {
		t.Fatal(err)
	}
	if m.Header.ID != 0x2222 || !m.Header.Response {
		t.Fatalf("header %+v", m.Header)
	}
	return m
}

// passed waits for the query to leave unchanged to dst.
func (r *dnsRig) passed(t *testing.T, dst string) {
	t.Helper()
	i := r.next(t)
	if !i.addr.Outbound() || i.pkt.Dst() != netip.MustParseAddrPort(dst) {
		t.Fatalf("not passed on: %v -> %v outbound=%v", i.pkt.Src(), i.pkt.Dst(), i.addr.Outbound())
	}
}

// dnsRowsNow are the DNS rows, open and closed.
func dnsRowsNow(c *Core) []flows.View {
	var out []flows.View
	for _, v := range append(c.Flows.Active(time.Now()), c.Flows.Closed()...) {
		if v.Stage == flows.StageDNS {
			out = append(out, v)
		}
	}
	return out
}

func lastDNSRow(t *testing.T, c *Core) flows.View {
	t.Helper()
	var last flows.View
	for _, v := range dnsRowsNow(c) {
		if v.ID > last.ID {
			last = v
		}
	}
	if last.ID == 0 {
		t.Fatal("no DNS row")
	}
	return last
}

var tunnelAll = rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
	{Name: "ads", Domains: []string{"ads.example"}, Action: rules.Block},
	{Name: "direct names", Domains: []string{".direct.example"}, Action: rules.Direct},
}}

var byRules = dnspolicy.Config{ByRules: true}

// Without a policy DNS takes today's paths.
func TestDNSOffUnchanged(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	r.c.DNSPol.Store(nil)
	r.ask(cli, google, dnscach, polQuery(t, "example.org.", dnsmessage.TypeA, 0))
	r.passed(t, google)
	if v := lastRecord(t, r.c); v.Excluded != "system-dns" || v.Stage != "packet" {
		t.Fatalf("%+v", v)
	}
	r.ask("192.168.1.5:5354", router, dnscach, polQuery(t, "example.org.", dnsmessage.TypeA, 0))
	r.passed(t, router)
	if len(r.res.take()) != 0 || len(dnsRowsNow(r.c)) != 0 {
		t.Fatal("resolved without a policy")
	}
}

func TestDNSUDPTunnel(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	for i, dst := range []string{google, router} {
		src := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(6000+i)).String()
		r.ask(src, dst, dnscach, polQuery(t, "WWW.Example.org.", dnsmessage.TypeA, 0))
		m := r.answer(t, src, dst)
		if m.Questions[0].Name.String() != "WWW.Example.org." || len(m.Answers) != 1 || m.Answers[0].Header.TTL > 300 {
			t.Fatalf("%s: %+v", dst, m)
		}
		r.none(t)
	}
	if calls := r.res.take(); len(calls) != 2 || calls[0] != "tunnel: www.example.org" {
		t.Fatalf("calls %v", calls)
	}
	v := lastDNSRow(t, r.c)
	if v.Route != "tunnel" || v.Outcome != dnspolicy.OutTunnel || v.DomainSrc != "query" || v.Domain != "www.example.org" ||
		v.Attrib != "dnscache" || v.Rule != "default" || v.Count != 2 || v.Proto != "udp" {
		t.Fatalf("row %+v", v)
	}
	if r.c.DNSTunnel.Load() != 2 {
		t.Fatal(r.c.DNSTunnel.Load())
	}
	if names := r.c.DNS.Names(netip.MustParseAddr("93.184.216.34")); len(names) != 1 || names[0] != "www.example.org" {
		t.Fatalf("cache not fed: %v", names)
	}
}

func TestDNSUDPTunnelDownFailClosed(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	servfail := func(label, outcome string) {
		t.Helper()
		r.ask(cli, google, dnscach, polQuery(t, "example.org.", dnsmessage.TypeA, 0))
		if m := r.answer(t, cli, google); m.Header.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("%s: %v", label, m.Header.RCode)
		}
		r.none(t) // never sent on
		found := false
		for _, v := range dnsRowsNow(r.c) {
			found = found || v.Outcome == outcome
		}
		if !found {
			t.Fatalf("%s: no row with %q", label, outcome)
		}
	}
	r.tun.up.Store(false)
	servfail("tunnel down", dnspolicy.OutTunnelDown)
	if len(r.res.take()) != 0 {
		t.Fatal("resolver asked while the tunnel is down")
	}
	r.tun.up.Store(true)
	r.res.set(func(dnspolicy.Via, string, dnsproxy.Query) ([]byte, error) { return nil, errors.New("tls") })
	servfail("upstream error", dnspolicy.OutFailed)
	r.res.set(func(dnspolicy.Via, string, dnsproxy.Query) ([]byte, error) { return nil, dnsproxy.ErrUpstreamDown })
	servfail("upstream down", dnspolicy.OutUpstreamDown)
	r.res.set(func(dnspolicy.Via, string, dnsproxy.Query) ([]byte, error) { return []byte("garbage"), nil })
	servfail("bad answer", dnspolicy.OutFailed)
	r.c.Resolver = nil
	servfail("no resolver", dnspolicy.OutTunnelDown)
	if r.c.DNSFailed.Load() != 5 {
		t.Fatal(r.c.DNSFailed.Load())
	}
}

// Server hosts, Windows' probes and HyRoute's own names pass whatever the
// rules say and whether the tunnel is up.
func TestDNSUDPServerAndServiceNames(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{{Name: "block",
		Domains: []string{"hy.server.example", "www.msftconnecttest.com", "sub.example", "github.com"}, Action: rules.Block}}}
	r := newDNSRig(t, cfg, byRules, Options{})
	r.tun.up.Store(false)
	own := &dnspolicy.OwnNames{}
	own.Add("Sub.Example.", 2*time.Minute)
	r.c.OwnName = own.Has
	for i, name := range []string{"hy.server.example.", "www.msftconnecttest.com.", "sub.example."} {
		src := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(7000+i)).String()
		r.ask(src, google, dnscach, polQuery(t, name, dnsmessage.TypeA, 0))
		r.passed(t, google)
	}
	if len(dnsRowsNow(r.c)) != 0 {
		t.Fatal("rows for names passed as before")
	}
	r.ask(cli, google, dnscach, polQuery(t, "github.com.", dnsmessage.TypeA, 0))
	if m := r.answer(t, cli, google); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("an unregistered name is not HyRoute's")
	}
}

// Other adapters' servers: only tunnel and block names are taken; tunnel
// negatives go to that server.
func TestDNSUDPSecondary(t *testing.T) {
	r := newDNSRig(t, tunnelAll, dnspolicy.Config{ByRules: true, Direct: dnspolicy.Upstream{Preset: "quad9"}}, Options{})
	for i, srv := range []string{"10.8.0.1:53", "8.8.4.4:53", "100.100.100.100:53"} {
		src := func(n int) string {
			return netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(8000+10*i+n)).String()
		}
		r.ask(src(0), srv, dnscach, polQuery(t, "x.direct.example.", dnsmessage.TypeA, 0))
		r.passed(t, srv)
		if calls := r.res.take(); len(calls) != 0 {
			t.Fatalf("%s: direct name resolved: %v", srv, calls)
		}
		r.ask(src(1), srv, dnscach, polQuery(t, "ads.example.", dnsmessage.TypeA, 0))
		if m := r.answer(t, src(1), srv); m.Header.RCode != dnsmessage.RCodeNameError {
			t.Fatalf("%s: block", srv)
		}
		r.ask(src(2), srv, dnscach, polQuery(t, "site.example.", dnsmessage.TypeA, 0))
		if m := r.answer(t, src(2), srv); len(m.Answers) != 1 {
			t.Fatalf("%s: tunnel", srv)
		}
		r.res.set(func(_ dnspolicy.Via, _ string, q dnsproxy.Query) ([]byte, error) {
			return upAnswer(q, dnsmessage.RCodeNameError), nil
		})
		r.ask(src(3), srv, dnscach, polQuery(t, "intranet-only.example.", dnsmessage.TypeA, 0))
		r.passed(t, srv)
		r.res.set(func(_ dnspolicy.Via, _ string, q dnsproxy.Query) ([]byte, error) {
			return upAnswer(q, dnsmessage.RCodeSuccess), nil // NODATA for the asked type
		})
		r.ask(src(4), srv, dnscach, polQuery(t, "v4only.example.", dnsmessage.TypeAAAA, 0))
		r.passed(t, srv)
		r.res.set(nil)
		r.tun.up.Store(false)
		r.ask(src(5), srv, dnscach, polQuery(t, "site.example.", dnsmessage.TypeA, 0))
		if m := r.answer(t, src(5), srv); m.Header.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("%s: tunnel down", srv)
		}
		r.tun.up.Store(true)
		r.res.take()
	}
	// A public server in Primary is a main one: direct names go to the
	// direct upstream.
	r.ask(cli, google, dnscach, polQuery(t, "x.direct.example.", dnsmessage.TypeA, 0))
	if m := r.answer(t, cli, google); len(m.Answers) != 1 {
		t.Fatal("main server")
	}
	if calls := r.res.take(); len(calls) != 1 || calls[0] != "direct x.direct.example" {
		t.Fatal(calls)
	}
	// A public address of no adapter: main, and a refresh is asked for.
	r.c.SysDNS.last.Store(0)
	done := make(chan struct{}, 4)
	r.c.SysDNS.done = func() { done <- struct{}{} }
	before := r.snaps.Load()
	r.ask("192.168.1.5:9001", "1.2.3.4:53", dnscach, polQuery(t, "ads.example.", dnsmessage.TypeA, 0))
	if m := r.answer(t, "192.168.1.5:9001", "1.2.3.4:53"); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("public non-adapter server not intercepted")
	}
	<-done
	if r.snaps.Load() != before+1 {
		t.Fatal("no refresh for an unknown server")
	}
	// A private address of no adapter: not intercepted.
	r.c.SysDNS.last.Store(0)
	r.ask("192.168.1.5:9002", "10.9.9.9:53", dnscach, polQuery(t, "ads.example.", dnsmessage.TypeA, 0))
	r.passed(t, "10.9.9.9:53")
	<-done
}

// HyRoute's and its Hysteria's own DNS is never taken; own agrees with
// exclusion.
func TestDNSOwnTraffic(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	paths := map[uint32]string{1: `C:\Windows\explorer.exe`, 999: `C:\HyRoute\HyRoute.exe`, 500: `C:\HyRoute\core\hysteria.exe`, 501: `C:\Other\hysteria.exe`}
	r.c.Procs = procinfo.NewCacheWith(procinfo.System{
		Query: func(pid uint32) (string, int64, bool) { p, ok := paths[pid]; return p, 1, ok },
		Snapshot: func() []procinfo.ProcEntry {
			return []procinfo.ProcEntry{{PID: 1}, {PID: 999, PPID: 1}, {PID: 500, PPID: 999}, {PID: 501, PPID: 1}}
		},
	})
	r.c.SelfPID = 999
	r.ask("192.168.1.5:9100", google, 999, polQuery(t, "ads.example.", dnsmessage.TypeA, 0))
	r.passed(t, google)
	r.ask("192.168.1.5:9101", google, 500, polQuery(t, "ads.example.", dnsmessage.TypeA, 0))
	r.passed(t, google)
	r.ask("192.168.1.5:9102", google, 501, polQuery(t, "ads.example.", dnsmessage.TypeA, 0))
	if m := r.answer(t, "192.168.1.5:9102", google); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("another hysteria.exe follows the policy")
	}
	for _, pid := range []uint32{999, 500, 501, 1} {
		proc := r.c.Procs.Get(pid)
		_, kind := r.c.exclusion(pid, true, proc, 6, netip.MustParseAddrPort("203.0.113.1:443"))
		if own := kind == "self" || kind == "hysteria"; own != r.c.own(pid, true, proc) {
			t.Fatalf("pid %d: own %v, exclusion %q", pid, !own, kind)
		}
	}
}

func TestDNSUDPBlockAndSpecials(t *testing.T) {
	r := newDNSRig(t, tunnelAll, dnspolicy.Config{ByRules: true, BlockBrowserDoH: true, StripECH: true}, Options{BlockIPv6Tunnel: true})
	ask := func(i int, name string, typ dnsmessage.Type) dnsmessage.Message {
		t.Helper()
		src := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(9200+i)).String()
		r.ask(src, google, dnscach, polQuery(t, name, typ, 1232))
		return r.answer(t, src, google)
	}
	m := ask(0, "ads.example.", dnsmessage.TypeA)
	if m.Header.RCode != dnsmessage.RCodeNameError || len(m.Authorities) != 1 || len(m.Additionals) != 1 {
		t.Fatalf("block: %+v", m)
	}
	if v := lastDNSRow(t, r.c); v.Route != "block" || v.Rule != "ads" || v.Outcome != dnspolicy.OutBlocked {
		t.Fatalf("%+v", v)
	}
	if m := ask(1, "use-application-dns.net.", dnsmessage.TypeA); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("canary")
	}
	if v := lastDNSRow(t, r.c); v.Route != "block" || v.Rule != dnspolicy.RuleCanary {
		t.Fatalf("%+v", v)
	}
	if m := ask(2, "site.example.", dnsmessage.TypeHTTPS); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatal("ECH")
	}
	if m := ask(3, "site.example.", dnsmessage.TypeAAAA); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatal("AAAA")
	}
	if v := lastDNSRow(t, r.c); v.Route != "tunnel" || v.Rule != dnspolicy.RuleNoIPv6 {
		t.Fatalf("%+v", v)
	}
	if r.c.DNSBlocked.Load() != 1 || r.c.DNSDoH.Load() != 1 || len(r.res.take()) != 0 {
		t.Fatal("counters or resolver")
	}
}

func TestDNSUDPDirect(t *testing.T) {
	direct := rules.Config{DefaultAction: rules.Direct}
	r := newDNSRig(t, direct, dnspolicy.Config{BlockBrowserDoH: true}, Options{})
	r.ask(cli, google, dnscach, polQuery(t, "example.org.", dnsmessage.TypeA, 0))
	r.passed(t, google)
	r.setPolicy(t, dnspolicy.Config{Direct: dnspolicy.Upstream{Preset: "quad9"}})
	n := 0
	ask := func(name string, typ dnsmessage.Type) string {
		n++
		src := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(9300+n)).String()
		r.ask(src, google, dnscach, polQuery(t, name, typ, 0))
		return src
	}
	src := ask("example.org.", dnsmessage.TypeA)
	if m := r.answer(t, src, google); len(m.Answers) != 1 || m.Answers[0].Header.TTL != 3600 {
		t.Fatalf("direct TTLs are the upstream's: %+v", m.Answers)
	}
	if v := lastDNSRow(t, r.c); v.Route != "direct" || v.Outcome != dnspolicy.OutDirect {
		t.Fatalf("%+v", v)
	}
	rows := len(dnsRowsNow(r.c))
	r.res.set(func(dnspolicy.Via, string, dnsproxy.Query) ([]byte, error) {
		return nil, errors.New("blocked by the ISP")
	})
	ask("fail.example.", dnsmessage.TypeA)
	r.passed(t, google)
	r.res.set(func(_ dnspolicy.Via, _ string, q dnsproxy.Query) ([]byte, error) {
		if q.Type == dnsmessage.TypeA && q.Name == "nas.example" {
			return upAnswer(q, dnsmessage.RCodeNameError), nil
		}
		return upAnswer(q, dnsmessage.RCodeSuccess), nil
	})
	ask("nas.example.", dnsmessage.TypeA)
	r.passed(t, google)
	ask("v6less.example.", dnsmessage.TypeA)
	r.passed(t, google)
	src = ask("v6less.example.", dnsmessage.TypeAAAA)
	if m := r.answer(t, src, google); m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatal("NODATA for AAAA is answered")
	}
	if got := len(dnsRowsNow(r.c)); got != rows+1 {
		t.Fatalf("rows for passed queries: %d -> %d", rows, got)
	}
}

// A program's own resolver: the owner is awaited off the loop.
func TestDNSUDPLateOwner(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{{Name: "chrome x", Apps: []rules.AppMatch{{Pattern: "chrome.exe"}},
		Domains: []string{"x.example"}, Action: rules.Block}}}
	r := newDNSRig(t, cfg, byRules, Options{})
	src := "192.168.1.5:9400"
	r.ask(src, google, 0, polQuery(t, "x.example.", dnsmessage.TypeA, 0))
	time.Sleep(10 * time.Millisecond)
	r.own(17, src, google, 200)
	if m := r.answer(t, src, google); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("judged without the program")
	}
	if v := lastDNSRow(t, r.c); v.Attrib != "pending" || v.Process != "chrome.exe" {
		t.Fatalf("%+v", v)
	}
	// The same socket again: the owner is known now, the same decision.
	r.ask(src, google, 0, polQuery(t, "x.example.", dnsmessage.TypeA, 0))
	if m := r.answer(t, src, google); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("second query decided otherwise")
	}
	// Never: judged as unknown (program rules conditional: direct wins).
	r.ask("192.168.1.5:9401", google, 0, polQuery(t, "x.example.", dnsmessage.TypeA, 0))
	r.passed(t, google)
	// HyRoute itself, learned late: passed.
	r.c.SelfPID = 999
	r.ask("192.168.1.5:9402", google, 0, polQuery(t, "x.example.", dnsmessage.TypeA, 0))
	time.Sleep(10 * time.Millisecond)
	r.own(17, "192.168.1.5:9402", google, 999)
	r.passed(t, google)
	// No room to wait: judged at once, on the loop.
	for range dnsMaxInflight {
		r.c.dnsSem <- struct{}{}
	}
	r.ask("192.168.1.5:9403", google, 0, polQuery(t, "x.example.", dnsmessage.TypeA, 0))
	r.passed(t, google)
	for range dnsMaxInflight {
		<-r.c.dnsSem
	}
}

func TestDNSRows(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	decisions := 0
	var mu sync.Mutex
	r.c.OnDecision = func(v flows.View) {
		if v.Stage == flows.StageDNS {
			mu.Lock()
			decisions++
			mu.Unlock()
		}
	}
	for i, q := range []struct {
		dst string
		typ dnsmessage.Type
	}{{google, dnsmessage.TypeA}, {google, dnsmessage.TypeAAAA}, {router, dnsmessage.TypeA}} {
		src := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(9500+i)).String()
		r.ask(src, q.dst, dnscach, polQuery(t, "site.example.", q.typ, 0))
		r.answer(t, src, q.dst)
	}
	rows := dnsRowsNow(r.c)
	if len(rows) != 1 || rows[0].Count != 3 || rows[0].Closed || decisions != 1 {
		t.Fatalf("rows %+v decisions %d", rows, decisions)
	}
	r.tun.up.Store(false)
	r.ask("192.168.1.5:9510", google, dnscach, polQuery(t, "site.example.", dnsmessage.TypeA, 0))
	r.answer(t, "192.168.1.5:9510", google)
	if rows := dnsRowsNow(r.c); len(rows) != 2 {
		t.Fatalf("another outcome, another row: %d", len(rows))
	}
	r.c.Maintain(time.Now().Add(31 * time.Second))
	for _, v := range dnsRowsNow(r.c) {
		if !v.Closed {
			t.Fatal("idle row not closed")
		}
	}
	// The open rows are bounded: the least recently used closes first.
	now := time.Now()
	for i := range dnsRowsMax + 1 {
		k := dnsRowKey{name: string(rune('a'+i%26)) + strings.Repeat("x", i/26)}
		r.c.noteDNS(now.Add(time.Duration(i)*time.Millisecond), k, 1, 1, func() *flows.Record {
			rec := &flows.Record{}
			rec.Set(func(f *flows.Fields) { f.Stage = flows.StageDNS })
			return rec
		})
	}
	r.c.dnsRows.mu.Lock()
	_, first := r.c.dnsRows.m[dnsRowKey{name: "a"}]
	n := len(r.c.dnsRows.m)
	r.c.dnsRows.mu.Unlock()
	if first || n != dnsRowsMax {
		t.Fatalf("LRU: first kept %v, %d open", first, n)
	}
	// A query moves its row to the front: the next oldest goes instead.
	build := func() *flows.Record { return &flows.Record{} }
	r.c.noteDNS(now.Add(time.Hour), dnsRowKey{name: "b"}, 1, 1, build)
	r.c.noteDNS(now.Add(time.Hour), dnsRowKey{name: "new"}, 1, 1, build)
	r.c.dnsRows.mu.Lock()
	_, b := r.c.dnsRows.m[dnsRowKey{name: "b"}]
	_, cc := r.c.dnsRows.m[dnsRowKey{name: "c"}]
	r.c.dnsRows.mu.Unlock()
	if !b || cc {
		t.Fatalf("LRU order: b kept %v, c kept %v", b, cc)
	}
	// Closed DNS rows do not push connections out.
	c := r.c
	c.sweepDNSRows(now, true)
	if c.dnsRows.lru.Len() != 0 || len(c.dnsRows.m) != 0 {
		t.Fatal("rows left after closing all")
	}
	c.Flows = flows.NewRegistry(5)
	for range 5 {
		rec := c.Flows.Open(&flows.Record{})
		c.Flows.Close(rec, now)
	}
	for i := range 10 {
		c.noteDNS(now, dnsRowKey{name: "n" + string(rune('a'+i))}, 1, 1, func() *flows.Record {
			rec := &flows.Record{}
			rec.Set(func(f *flows.Fields) { f.Stage = flows.StageDNS })
			return rec
		})
	}
	c.sweepDNSRows(now.Add(time.Hour), false)
	conns, dns := 0, 0
	for _, v := range c.Flows.Closed() {
		if v.Stage == flows.StageDNS {
			dns++
		} else {
			conns++
		}
	}
	if conns != 5 || dns != 10 {
		t.Fatalf("closed: %d connections, %d DNS rows", conns, dns)
	}
}

// HyRoute's own names (dnspolicy.OwnNames, the controller's) pass while
// they are registered, whatever the rules say.
func TestTransientNames(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{{Name: "gh", Domains: []string{"github.com"}, Action: rules.Block}}}
	r := newDNSRig(t, cfg, byRules, Options{})
	now := time.Unix(1000, 0)
	var mu sync.Mutex
	own := &dnspolicy.OwnNames{Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }}
	r.c.OwnName = own.Has
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	own.Add("GitHub.com.", 2*time.Minute)
	pol := r.c.DNSPol.Load()
	d := pol.Classify(dnspolicy.Question{Name: "github.com", Type: dnsmessage.TypeA}, dnspolicy.Requester{System: true}, r.c.dnsEnv())
	if d.Kind != dnspolicy.Pass || d.Local != "service" {
		t.Fatalf("%+v", d)
	}
	r.ask(cli, google, dnscach, polQuery(t, "github.com.", dnsmessage.TypeA, 0))
	r.passed(t, google)
	advance(2 * time.Minute)
	r.ask("192.168.1.5:9600", google, dnscach, polQuery(t, "github.com.", dnsmessage.TypeA, 0))
	if m := r.answer(t, "192.168.1.5:9600", google); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("the rule applies once the name expired")
	}
}

func TestPortalPause(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	r.tun.up.Store(false)
	n := 0
	ask := func(name string) string {
		n++
		src := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.5"), uint16(9700+n)).String()
		r.ask(src, google, dnscach, polQuery(t, name, dnsmessage.TypeA, 0))
		return src
	}
	r.c.DNSPauseUntil.Store(time.Now().Add(5 * time.Minute).UnixNano())
	ask("portal.example.")
	r.passed(t, google)
	if v := lastDNSRow(t, r.c); v.Outcome != dnspolicy.OutPortal || v.Route != "direct" || r.c.DNSPortalPassed.Load() != 1 {
		t.Fatalf("%+v", v)
	}
	src := ask("ads.example.")
	if m := r.answer(t, src, google); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("block names stay blocked in the pause")
	}
	r.tun.up.Store(true)
	src = ask("site.example.")
	if m := r.answer(t, src, google); len(m.Answers) != 1 {
		t.Fatal("a tunnel that is up resolves")
	}
	r.res.set(func(dnspolicy.Via, string, dnsproxy.Query) ([]byte, error) { return nil, errors.New("timeout") })
	src = ask("site2.example.")
	if m := r.answer(t, src, google); m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("the pause covers only a tunnel that is down")
	}
	r.res.set(nil)
	r.tun.up.Store(false)
	r.c.DNSPauseUntil.Store(time.Now().Add(-time.Second).UnixNano())
	src = ask("portal.example.")
	if m := r.answer(t, src, google); m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("expired pause")
	}
}

// ---- TCP ----

// dnsSYN sends a SYN from src to dst owned by pid; it returns the NAT entry.
func (r *dnsRig) dnsSYN(t *testing.T, src, dst string, pid uint32) *nat.Entry {
	t.Helper()
	if pid != 0 {
		r.own(6, src, dst, pid)
	}
	r.sendTCP(src, dst, packet.FlagSYN, "")
	return r.c.NAT.LookupFlow(nat.FlowKey{Src: netip.MustParseAddrPort(src), Dst: netip.MustParseAddrPort(dst)})
}

func TestDNSTCPReflect(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	for _, dst := range []string{google, router, "10.8.0.1:53"} {
		e := r.dnsSYN(t, "192.168.1.5:41000", dst, dnscach)
		if i := r.next(t); i.addr.Outbound() || i.pkt.DstPort() != relayPort {
			t.Fatalf("%s: not reflected", dst)
		}
		want := uint8(dnsMain)
		if dst == "10.8.0.1:53" {
			want = uint8(dnsSecondary)
		}
		if e == nil || e.Mode != nat.DNS || e.DNSDest != want {
			t.Fatalf("%s: %+v", dst, e)
		}
		if p, ok := e.Meta.(*procinfo.Info); !ok || p == nil || p.PID != dnscach {
			t.Fatalf("%s: Meta %T %v", dst, e.Meta, e.Meta)
		}
		if e.Rec.ID != 0 {
			t.Fatal("the connection's record was opened")
		}
		r.c.NAT.FlowDeleted(e.Flow, time.Now())
		r.c.NAT.RemoveClosed(e)
	}
	// HyRoute's own: as before.
	r.c.SelfPID = 999
	r.dnsSYN(t, "192.168.1.5:41001", router, 999)
	if i := r.next(t); !i.addr.Outbound() || i.pkt.Dst() != netip.MustParseAddrPort(router) {
		t.Fatal("own SYN to the router not passed as before")
	}
	r.dnsSYN(t, "192.168.1.5:41002", google, 999)
	if i := r.next(t); !i.addr.Outbound() {
		t.Fatal("own SYN not direct")
	}
	// IPv6 link-local TCP: not intercepted.
	r.info.Primary[netip.MustParseAddr("fe80::1")] = true
	r.c.SysDNS.Refresh()
	r.dnsSYN(t, "[fe80::5]:41003", "[fe80::1]:53", dnscach)
	if i := r.next(t); !i.addr.Outbound() {
		t.Fatal("link-local TCP DNS intercepted")
	}
	// A private server that is no adapter's: as before.
	r.dnsSYN(t, "192.168.1.5:41004", "10.9.9.9:53", dnscach)
	if i := r.next(t); !i.addr.Outbound() {
		t.Fatal("private non-adapter server intercepted")
	}
}

func TestDNSTCPDest(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	e := r.dnsSYN(t, "192.168.1.5:42000", "8.8.4.4:53", 200)
	r.next(t)
	if e == nil || e.DNSDest != uint8(dnsSecondary) {
		t.Fatalf("%+v", e)
	}
	if p, ok := e.Meta.(*procinfo.Info); !ok || p.Name != "chrome.exe" {
		t.Fatal("Meta is not the process")
	}
}

// serveDNSRig runs ServeDNS over a pipe; pass dials a loopback server that
// answers every framed query with an A answer (the client's ID).
type tcpDNS struct {
	client   net.Conn
	done     chan struct{}
	mu       sync.Mutex
	routes   []rules.Result
	origin   net.Listener
	failPass bool
}

func (r *dnsRig) serveTCP(t *testing.T, e *nat.Entry) *tcpDNS {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					msg, err := readFramed(c)
					if err != nil {
						return
					}
					q, ok := dnsproxy.ParseQuery(msg)
					if !ok {
						q.ID = binary.BigEndian.Uint16(msg)
						q.Wire = dnsmessage.MustNewName("rd0.example.")
						q.Type, q.Class = dnsmessage.TypeA, dnsmessage.ClassINET
					}
					a := upAnswer(q, dnsmessage.RCodeSuccess, "198.51.100.7")
					binary.BigEndian.PutUint16(a, q.ID)
					if writeFramed(c, a) != nil {
						return
					}
				}
			}()
		}
	}()
	cl, srv := net.Pipe()
	s := &tcpDNS{client: cl, done: make(chan struct{}), origin: ln}
	t.Cleanup(func() { cl.Close() })
	go func() {
		defer close(s.done)
		r.c.ServeDNS(context.Background(), e, srv, func(ctx context.Context, res rules.Result) (net.Conn, error) {
			s.mu.Lock()
			s.routes = append(s.routes, res)
			fail := s.failPass
			s.mu.Unlock()
			if fail {
				return nil, errors.New("tunnel unavailable")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		})
		srv.Close()
	}()
	return s
}

func (s *tcpDNS) ask(t *testing.T, msg []byte) (dnsmessage.Message, error) {
	t.Helper()
	s.client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeFramed(s.client, msg); err != nil {
		return dnsmessage.Message{}, err
	}
	b, err := readFramed(s.client)
	if err != nil {
		return dnsmessage.Message{}, err
	}
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatal(err)
	}
	return m, nil
}

func (s *tcpDNS) passRoutes() []rules.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rules.Result(nil), s.routes...)
}

func dnsEntry(pid uint32, proc *procinfo.Info, dst string, dest dnsDest) *nat.Entry {
	return &nat.Entry{Flow: nat.FlowKey{Src: netip.MustParseAddrPort("192.168.1.5:43000"), Dst: netip.MustParseAddrPort(dst)},
		PID: pid, Mode: nat.DNS, DNSDest: uint8(dest), Meta: proc, Rec: &flows.Record{}}
}

func TestServeDNS(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	svchost := r.c.Procs.Get(dnscach)
	s := r.serveTCP(t, dnsEntry(dnscach, svchost, google, dnsMain))
	m, err := s.ask(t, polQuery(t, "site.example.", dnsmessage.TypeA, 0))
	if err != nil || len(m.Answers) != 1 || m.Header.ID != 0x2222 {
		t.Fatalf("tunnel: %+v %v", m, err)
	}
	m, err = s.ask(t, polQuery(t, "x.direct.example.", dnsmessage.TypeA, 0))
	if err != nil || len(m.Answers) != 1 {
		t.Fatalf("passed on: %+v %v", m, err)
	}
	if routes := s.passRoutes(); len(routes) != 1 || routes[0].Action != rules.Direct {
		t.Fatalf("the DNS client's pass route: %+v", routes)
	}
	if names := r.c.DNS.Names(netip.MustParseAddr("198.51.100.7")); len(names) != 1 || names[0] != "x.direct.example" {
		t.Fatalf("pass-through answer not cached: %v", names)
	}
	r.tun.up.Store(false)
	if m, err := s.ask(t, polQuery(t, "site2.example.", dnsmessage.TypeA, 0)); err != nil || m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("tunnel down: %+v %v", m, err)
	}
	if v := lastDNSRow(t, r.c); v.Proto != "tcp" || v.Outcome != dnspolicy.OutTunnelDown {
		t.Fatalf("%+v", v)
	}
	// Bounds: idle time, message count (dnsTCPIdle is read by the serving
	// goroutines: every one ends before it changes).
	s.client.Close()
	<-s.done
	old := dnsTCPIdle
	dnsTCPIdle = 100 * time.Millisecond
	t.Cleanup(func() { dnsTCPIdle = old })
	s2 := r.serveTCP(t, dnsEntry(dnscach, svchost, google, dnsMain))
	select {
	case <-s2.done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle connection kept")
	}
	r.tun.up.Store(true)
	s3 := r.serveTCP(t, dnsEntry(dnscach, svchost, google, dnsMain))
	for i := range dnsTCPMessages {
		if _, err := s3.ask(t, polQuery(t, "ads.example.", dnsmessage.TypeA, 0)); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	if _, err := s3.ask(t, polQuery(t, "ads.example.", dnsmessage.TypeA, 0)); err == nil {
		t.Fatal("more than the message limit served")
	}
	// Garbage closes the connection.
	s4 := r.serveTCP(t, dnsEntry(dnscach, svchost, google, dnsMain))
	s4.client.Write([]byte{0, 0})
	select {
	case <-s4.done:
	case <-time.After(2 * time.Second):
		t.Fatal("garbage kept the connection")
	}
	s3.client.Close()
	<-s3.done
}

func TestServeDNSPassRoute(t *testing.T) {
	cfg := rules.Config{DefaultAction: rules.Tunnel, Rules: []rules.Rule{
		{Name: "block curl", Apps: []rules.AppMatch{{Pattern: "curl.exe"}}, Domains: []string{"203.0.113.53"}, Action: rules.Block},
		{Name: "direct names", Domains: []string{".direct.example"}, Action: rules.Direct},
	}}
	r := newDNSRig(t, cfg, byRules, Options{})
	chrome := r.c.Procs.Get(200)
	s := r.serveTCP(t, dnsEntry(200, chrome, google, dnsMain))
	if _, err := s.ask(t, polQuery(t, "x.direct.example.", dnsmessage.TypeA, 0)); err != nil {
		t.Fatal(err)
	}
	if routes := s.passRoutes(); len(routes) != 1 || routes[0].Action != rules.Tunnel {
		t.Fatalf("a program's pass route follows the rules: %+v", routes)
	}
	// A non-recursive query goes on as before.
	rd0 := polQuery(t, "x.example.", dnsmessage.TypeA, 0)
	rd0[2] &^= 1 // RD off
	if m, err := s.ask(t, rd0); err != nil || len(m.Answers) != 1 {
		t.Fatalf("RD=0: %+v %v", m, err)
	}
	// The policy goes off between messages: the next is passed on.
	r.c.DNSPol.Store(nil)
	if m, err := s.ask(t, polQuery(t, "ads.example.", dnsmessage.TypeA, 0)); err != nil || m.Header.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("policy off: %+v %v", m, err)
	}
	r.setPolicy(t, byRules)
	// The tunnel dial fails: reset, never direct.
	s2 := r.serveTCP(t, dnsEntry(200, chrome, google, dnsMain))
	s2.mu.Lock()
	s2.failPass = true
	s2.mu.Unlock()
	if _, err := s2.ask(t, polQuery(t, "x.direct.example.", dnsmessage.TypeA, 0)); err == nil {
		t.Fatal("answered without the tunnel")
	}
	if routes := s2.passRoutes(); len(routes) != 1 || routes[0].Action != rules.Tunnel {
		t.Fatalf("fell back: %+v", routes)
	}
	// A block rule for the program and the address: reset, not dialled.
	curl := r.c.Procs.Get(100)
	s3 := r.serveTCP(t, dnsEntry(100, curl, "203.0.113.53:53", dnsMain))
	if _, err := s3.ask(t, polQuery(t, "x.direct.example.", dnsmessage.TypeA, 0)); err == nil {
		t.Fatal("block rule ignored")
	}
	if len(s3.passRoutes()) != 0 {
		t.Fatal("dialled a blocked route")
	}
}

func TestAbortDNS(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	e := r.dnsSYN(t, "192.168.1.5:44000", google, dnscach)
	r.next(t)
	other := reflected(t, r.harness)
	if e == nil || other == nil || other.Mode == nat.DNS {
		t.Fatal("setup")
	}
	r.c.AbortDNS()
	i := r.next(t)
	if i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 || i.pkt.Dst() != e.Flow.Src {
		t.Fatalf("no RST to the DNS connection: %v -> %v", i.pkt.Src(), i.pkt.Dst())
	}
	r.none(t)
}

func TestDNSUDPNotTargets(t *testing.T) {
	r := newDNSRig(t, tunnelAll, dnspolicy.Config{ByRules: true, Direct: dnspolicy.Upstream{Preset: "quad9"}}, Options{})
	r.ask(cli, "10.9.9.9:53", dnscach, polQuery(t, "ads.example.", dnsmessage.TypeA, 0))
	r.passed(t, "10.9.9.9:53")
	r.ask("192.168.1.5:9800", google, dnscach, []byte("not dns"))
	r.passed(t, google)
	// No room: a tunnel name fails closed, a direct one goes as before.
	for range dnsMaxInflight {
		r.c.dnsSem <- struct{}{}
	}
	r.ask("192.168.1.5:9801", google, dnscach, polQuery(t, "site.example.", dnsmessage.TypeA, 0))
	if m := r.answer(t, "192.168.1.5:9801", google); m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("tunnel name with no room")
	}
	r.ask("192.168.1.5:9802", google, dnscach, polQuery(t, "x.direct.example.", dnsmessage.TypeA, 0))
	r.passed(t, google)
	for range dnsMaxInflight {
		<-r.c.dnsSem
	}
}

// ---- browser DoH ----

func TestBrowserDoHBlock(t *testing.T) {
	r := newDNSRig(t, rules.Config{DefaultAction: rules.Direct}, dnspolicy.Config{BlockBrowserDoH: true}, Options{})
	rst := func(label string) {
		t.Helper()
		if i := r.next(t); i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 {
			t.Fatalf("%s: not reset", label)
		}
	}
	r.own(6, "192.168.1.5:45000", "8.8.8.8:443", 200)
	r.sendTCP("192.168.1.5:45000", "8.8.8.8:443", packet.FlagSYN, "")
	rst("chrome to 8.8.8.8")
	if v := lastRecord(t, r.c); v.Rule != dnspolicy.RuleBrowserDoH || v.Route != "block" {
		t.Fatalf("%+v", v)
	}
	r.ask("192.168.1.5:45001", "1.1.1.1:443", firefoxPID, []byte("quic"))
	r.none(t)
	r.c.DNS.AddResponse(dnsResponse(t, "dns.nextdns.io.", "203.0.113.50"))
	r.own(6, "192.168.1.5:45002", "203.0.113.50:443", 200)
	r.sendTCP("192.168.1.5:45002", "203.0.113.50:443", packet.FlagSYN, "")
	rst("cached DoH name")
	r.own(6, "192.168.1.5:45003", "8.8.8.8:443", 100)
	r.sendTCP("192.168.1.5:45003", "8.8.8.8:443", packet.FlagSYN, "")
	if i := r.next(t); !i.addr.Outbound() {
		t.Fatal("a non-browser blocked")
	}
	// An untracked segment of a browser: reset once.
	r.own(6, "192.168.1.5:45004", "1.1.1.1:443", 200)
	r.sendTCP("192.168.1.5:45004", "1.1.1.1:443", packet.FlagACK, "data")
	rst("untracked")
	// SNI seen in the relay.
	e := &nat.Entry{Flow: nat.FlowKey{Src: netip.MustParseAddrPort(L), Dst: netip.MustParseAddrPort("203.0.113.60:443")}, Meta: r.c.Procs.Get(200)}
	if res := r.c.RelayDecide(e, "mozilla.cloudflare-dns.com", rules.SrcSNI); res.Action != rules.Block || res.Rule != dnspolicy.RuleBrowserDoH {
		t.Fatalf("%+v", res)
	}
	// The option off: not blocked.
	r.setPolicy(t, byRules)
	r.own(6, "192.168.1.5:45005", "1.1.1.1:443", 200)
	r.sendTCP("192.168.1.5:45005", "1.1.1.1:443", packet.FlagSYN, "")
	if i := r.next(t); !i.addr.Outbound() {
		t.Fatal("blocked with the option off")
	}
}

func TestDropDoH(t *testing.T) {
	r := newDNSRig(t, rules.Config{DefaultAction: rules.Direct}, byRules, Options{})
	// Before the option: a direct chrome TCP flow, a chrome UDP flow, a
	// relayed chrome connection to a sniffed DoH name, and others.
	r.own(6, "192.168.1.5:46000", "1.1.1.1:443", 200)
	r.sendTCP("192.168.1.5:46000", "1.1.1.1:443", packet.FlagSYN, "")
	r.next(t)
	r.ask("192.168.1.5:46001", "8.8.8.8:443", 200, []byte("quic"))
	r.next(t)
	r.own(6, "192.168.1.5:46002", "93.184.216.34:443", firefoxPID)
	r.sendTCP("192.168.1.5:46002", "93.184.216.34:443", packet.FlagSYN, "")
	r.next(t)
	r.own(6, "192.168.1.5:46003", "1.1.1.1:443", 100)
	r.sendTCP("192.168.1.5:46003", "1.1.1.1:443", packet.FlagSYN, "")
	r.next(t)
	rec := &flows.Record{}
	rec.Set(func(f *flows.Fields) { f.Domain = "dns.google" })
	ent, err := r.c.NAT.Insert(&nat.Entry{Flow: nat.FlowKey{Src: netip.MustParseAddrPort("192.168.1.5:46004"), Dst: netip.MustParseAddrPort("203.0.113.70:443")},
		Mode: nat.Sniff, Meta: r.c.Procs.Get(200), Rec: rec}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	syn := packet.BuildTCP(ent.Flow.Src, ent.Flow.Dst, packet.FlagSYN, 1, 0, nil)
	sp, _ := packet.Parse(syn)
	r.c.NAT.TouchPacket(ent, &sp, true, outAddr(), time.Now())

	r.setPolicy(t, dnspolicy.Config{BlockBrowserDoH: true})
	pred := r.c.DropDoH()
	if i := r.next(t); i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 || i.pkt.Dst() != ent.Flow.Src {
		t.Fatal("relayed DoH connection not reset")
	}
	if !pred(ent) {
		t.Fatal("pred misses the relayed connection")
	}
	r.none(t)
	// The direct chrome flow: its next segment is reset.
	r.sendTCP("192.168.1.5:46000", "1.1.1.1:443", packet.FlagACK, "data")
	if i := r.next(t); i.addr.Outbound() || i.pkt.TCPFlags()&packet.FlagRST == 0 {
		t.Fatal("tracked DoH flow not reset")
	}
	// The UDP flow is blocked now: closed, and its next datagram decided
	// again.
	r.sendUDP("192.168.1.5:46001", "8.8.8.8:443", []byte("quic"))
	r.none(t)
	if v := lastRecord(t, r.c); v.Dst != "8.8.8.8:443" || v.Route != "block" || v.Rule != dnspolicy.RuleBrowserDoH {
		t.Fatalf("%+v", v)
	}
	if !slices.ContainsFunc(r.c.Flows.Closed(), func(v flows.View) bool { return v.Dst == "8.8.8.8:443" && v.Route == "direct" }) {
		t.Fatal("the direct UDP flow not closed")
	}
	// Others go on.
	r.sendTCP("192.168.1.5:46002", "93.184.216.34:443", packet.FlagACK, "data")
	if i := r.next(t); !i.addr.Outbound() {
		t.Fatal("firefox to a normal site touched")
	}
	r.sendTCP("192.168.1.5:46003", "1.1.1.1:443", packet.FlagACK, "data")
	if i := r.next(t); !i.addr.Outbound() {
		t.Fatal("a non-browser's DoH touched")
	}
}

func TestSystemDoHCounter(t *testing.T) {
	r := newDNSRig(t, rules.Config{DefaultAction: rules.Direct}, byRules, Options{})
	r.c.SystemDNS = func(a netip.Addr) bool { return a == netip.MustParseAddr("9.9.9.9") }
	r.own(6, "192.168.1.5:47000", "9.9.9.9:443", dnscach)
	r.sendTCP("192.168.1.5:47000", "9.9.9.9:443", packet.FlagSYN, "")
	r.next(t)
	if r.c.SystemDoH.Load() != 1 {
		t.Fatal(r.c.SystemDoH.Load())
	}
}

// ---- fragments (bigudp × dns) ----

// A fragmented query to the router is held while a policy is on: the
// policy answers it; other fragmented traffic to the router passes.
func TestFragmentedDNSQueryPolicy(t *testing.T) {
	r := newDNSRig(t, tunnelAll, dnspolicy.Config{ByRules: true, BlockBrowserDoH: true}, Options{})
	q := polQuery(t, "ads.example.", dnsmessage.TypeA, 2000)
	r.own(17, cli, router, dnscach)
	frs := udpFrags(cli, router, q, 77, 1000)
	r.sendFrags(frs)
	if m := r.answer(t, cli, router); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("fragmented query not answered by the policy")
	}
	select {
	case f := <-r.frags:
		t.Fatalf("a fragment of the query left: %d bytes", len(f))
	case <-time.After(50 * time.Millisecond):
	}
	// Another port of the router: the fragments pass as before.
	other := udpFrags("192.168.1.5:5000", "192.168.1.1:5000", make([]byte, 2000), 78, 1000)
	r.sendFrags(other)
	for range other {
		select {
		case <-r.frags:
		case <-time.After(2 * time.Second):
			t.Fatal("fragments to the router held")
		}
	}
	// TCP fragments to the router's port 53 (never reassembled): dropped.
	tcp := splitIP(packet.BuildTCP(netip.MustParseAddrPort("192.168.1.5:5001"), netip.MustParseAddrPort(router), packet.FlagACK, 1, 1, make([]byte, 2000)), 79, 1000)
	r.sendFrags(tcp)
	select {
	case <-r.frags:
		t.Fatal("a TCP DNS fragment passed")
	case <-time.After(50 * time.Millisecond):
	}
	// Without a policy the router is not held.
	r.c.DNSPol.Store(nil)
	frs = udpFrags(cli, router, q, 80, 1000)
	r.sendFrags(frs)
	for range frs {
		select {
		case <-r.frags:
		case <-time.After(2 * time.Second):
			t.Fatal("held without a policy")
		}
	}
}

func TestDNSTargetRules(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	for dst, want := range map[string]dnsDest{
		"192.168.1.1:53": dnsMain, "8.8.8.8:53": dnsMain, "10.8.0.1:53": dnsSecondary, "8.8.4.4:53": dnsSecondary,
		"100.100.100.100:53": dnsSecondary, "1.2.3.4:53": dnsMain, "10.9.9.9:53": dnsUnknown, "100.64.1.1:53": dnsUnknown,
		"127.0.0.1:53": dnsNone, "0.0.0.0:53": dnsNone, "8.8.8.8:443": dnsNone, "[fe80::1]:53": dnsUnknown,
	} {
		if got := r.c.dnsTarget(netip.MustParseAddrPort(dst), false); got != want {
			t.Errorf("%s: %d, want %d", dst, got, want)
		}
		// Over TCP an address the snapshot lacks is not intercepted.
		if want == dnsUnknown {
			if got := r.c.dnsTarget(netip.MustParseAddrPort(dst), true); got != dnsNone {
				t.Errorf("%s over TCP: %d", dst, got)
			}
		}
	}
	if !r.c.dnsHold(netip.MustParseAddr("192.168.1.1")) || r.c.dnsHold(netip.MustParseAddr("192.168.1.7")) {
		t.Fatal("dnsHold")
	}
	r.c.DNSPol.Store(nil)
	if r.c.dnsHold(netip.MustParseAddr("192.168.1.1")) {
		t.Fatal("held without a policy")
	}
	var nilView *SysDNSView
	if nilView.Get() != nil || nilView.Local("x.corp.example") {
		t.Fatal("nil view")
	}
	nilView.Kick()
	_ = io.EOF
}

// A zone transfer (many answers to one query) goes on as a plain copy for
// the rest of the connection: every answer reaches the program, in step.
func TestServeDNSZoneTransfer(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		for {
			msg, err := readFramed(c)
			if err != nil {
				return
			}
			n := 1
			if zoneTransfer(msg) {
				n = 3
			}
			for i := range n {
				a := append([]byte(nil), msg...)
				a[2] |= 0x80 // QR
				a[11] = byte(i)
				if writeFramed(c, a) != nil {
					return
				}
			}
		}
	}()
	cl, srv := net.Pipe()
	t.Cleanup(func() { cl.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.c.ServeDNS(context.Background(), dnsEntry(dnscach, r.c.Procs.Get(dnscach), google, dnsMain), srv, func(ctx context.Context, _ rules.Result) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", ln.Addr().String())
		})
		srv.Close()
	}()
	cl.SetDeadline(time.Now().Add(3 * time.Second))
	axfr := polQuery(t, "zone.example.", dnsmessage.TypeAXFR, 0)
	if _, ok := dnsproxy.ParseQuery(axfr); ok {
		t.Fatal("AXFR parsed as a standard query")
	}
	if err := writeFramed(cl, axfr); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		a, err := readFramed(cl)
		if err != nil || a[11] != byte(i) {
			t.Fatalf("answer %d: %v", i, err)
		}
	}
	q := polQuery(t, "next.example.", dnsmessage.TypeA, 0)
	q[0], q[1] = 0x33, 0x44
	if err := writeFramed(cl, q); err != nil {
		t.Fatal(err)
	}
	if a, err := readFramed(cl); err != nil || a[0] != 0x33 || a[1] != 0x44 {
		t.Fatalf("out of step after the transfer: %v", err)
	}
	cl.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeDNS kept running")
	}
}

// The relay's context ends a TCP query's resolution (its Abort).
func TestServeDNSCancel(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	r.res.mu.Lock()
	r.res.hang = true
	r.res.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cl, srv := net.Pipe()
	t.Cleanup(func() { cl.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.c.ServeDNS(ctx, dnsEntry(dnscach, r.c.Procs.Get(dnscach), google, dnsMain), srv, func(context.Context, rules.Result) (net.Conn, error) {
			return nil, errors.New("not used")
		})
		srv.Close()
	}()
	cl.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeFramed(cl, polQuery(t, "site.example.", dnsmessage.TypeA, 0)); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(2 * time.Second); len(r.res.take()) == 0; {
		if time.Now().After(deadline) {
			t.Fatal("not resolving")
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	cancel()
	cl.SetDeadline(time.Now().Add(time.Second)) // well under dnsTunnelWait
	a, err := readFramed(cl)
	if err != nil {
		t.Fatalf("the resolution outlived the relay's context: %v", err)
	}
	var m dnsmessage.Message
	if m.Unpack(a) != nil || m.Header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("%+v", m.Header)
	}
	if time.Since(start) > time.Second {
		t.Fatal("slow")
	}
	cl.Close()
	<-done
}

// After a network change the new network's DNS server is a private
// address the last snapshot lacks: the query waits off the loop for a
// fresh snapshot and is intercepted, not passed on to that server. One a
// fresh snapshot lacks too passes, and later ones do not wait again.
func TestDNSNewPrivateServerWaitsForSnapshot(t *testing.T) {
	r := newDNSRig(t, tunnelAll, byRules, Options{})
	srv := netip.MustParseAddr("192.168.0.1")
	primary, all := map[netip.Addr]bool{srv: true}, map[netip.Addr]bool{srv: true}
	for a := range r.info.All {
		all[a] = true
	}
	r.info.Primary, r.info.All = primary, all // the network changed; no refresh yet
	before := r.snaps.Load()
	r.ask("192.168.1.5:9003", "192.168.0.1:53", dnscach, polQuery(t, "ads.example.", dnsmessage.TypeA, 0))
	if m := r.answer(t, "192.168.1.5:9003", "192.168.0.1:53"); m.Header.RCode != dnsmessage.RCodeNameError {
		t.Fatal("new network's DNS server not intercepted")
	}
	if r.snaps.Load() == before {
		t.Fatal("no fresh snapshot")
	}
	r.ask("192.168.1.5:9004", "10.9.9.9:53", dnscach, polQuery(t, "ads.example.", dnsmessage.TypeA, 0))
	r.passed(t, "10.9.9.9:53")
	if r.c.dnsTarget(netip.MustParseAddrPort("10.9.9.9:53"), false) != dnsNone {
		t.Fatal("an address a fresh snapshot lacked is waited for again")
	}
}
