package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/dnscache"
	"github.com/lardan099/hyroute/internal/flows"
	"github.com/lardan099/hyroute/internal/hysteria"
	"github.com/lardan099/hyroute/internal/procinfo"
	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/settings"
)

// connSess is a running session as conn-rules sees it: a flow registry,
// the DNS cache's sites and the ECH public names it learned.
type connSess struct {
	NopSession
	reg    *flows.Registry
	sites  map[netip.Addr][][]string
	public map[string]bool
	mu     sync.Mutex
	set    *rules.Set
}

func (s *connSess) Flows() *flows.Registry            { return s.reg }
func (s *connSess) DNSSites(ip netip.Addr) [][]string { return s.sites[ip] }
func (s *connSess) ECHPublicName(n string) bool       { return s.public[n] || dnscache.KnownPublicName(n) }
func (s *connSess) SetRules(set *rules.Set, _ []hysteria.Profile) {
	s.mu.Lock()
	s.set = set
	s.mu.Unlock()
}

// connCtl is a controller with three servers and a running fake session.
func connCtl(t *testing.T) (c *Controller, s *connSess, s1, s2 string) {
	t.Helper()
	c, _ = newCtl(t)
	s1, s2, _ = servers(t, c)
	s = &connSess{reg: flows.NewRegistry(100), sites: map[netip.Addr][][]string{}, public: map[string]bool{}}
	c.mu.Lock()
	st := *c.settings
	c.sess, c.lastFlows, c.sessSet = s, s.reg, &st
	c.mu.Unlock()
	return c, s, s1, s2
}

func setConnRules(t *testing.T, c *Controller, rs ...rules.Rule) {
	t.Helper()
	st := c.Settings()
	st.Config = rules.Config{DefaultAction: rules.Direct, Rules: rs}
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
}

// record opens a flow as the engine records it and returns its row.
func (s *connSess) record(r *flows.Record, f func(*flows.Fields)) ConnFacts {
	s.reg.Open(r)
	if f != nil {
		r.Set(f)
	}
	return factsOf(r.View(time.Now()))
}

func factsOf(v flows.View) ConnFacts {
	return ConnFacts{ID: v.ID, Process: v.Process, Path: v.Path, PID: v.PID, Proto: v.Proto, Dst: v.Dst, Domain: v.Domain,
		DomainSrc: v.DomainSrc, ECH: v.ECH, Excluded: v.Excluded, Attrib: v.Attrib, Stage: v.Stage}
}

func sniRow(s *connSess, exe, dst, name string) ConnFacts {
	return s.record(&flows.Record{PID: 10, Process: strings.ToLower(exe), Path: `C:\Apps\` + exe, Proto: 6, Dst: netip.MustParseAddrPort(dst)},
		func(f *flows.Fields) { f.Domain, f.DomainSrc = name, "sni" })
}

func settingsFile(t *testing.T, c *Controller) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.Store.Dir, "settings.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return b
}

func siteRule(pattern string, a rules.Action, profile string) rules.Rule {
	return rules.Rule{Domains: []string{pattern}, Action: a, Profile: profile}
}

func appRule(exe string, a rules.Action) rules.Rule {
	return rules.Rule{Apps: []rules.AppMatch{{Pattern: exe}}, Action: a}
}

func quick(f ConnFacts, r rules.Rule) ConnRuleRequest {
	return ConnRuleRequest{Facts: f, Rule: r, Source: "quick"}
}

func TestBuildFlow(t *testing.T) {
	base := ConnFacts{Process: "x.exe", Path: `C:\X\X.exe`, Proto: "tcp", Dst: "1.2.3.4:443"}
	for _, c := range []struct {
		mod  func(*ConnFacts)
		fail bool
	}{
		{func(f *ConnFacts) { f.Proto = "icmp" }, true},
		{func(f *ConnFacts) { f.Dst = "nonsense" }, true},
		{func(f *ConnFacts) { f.DomainSrc, f.Domain = "sni", "a.test,b.test" }, true},
		{func(f *ConnFacts) { f.Stage, f.DomainSrc, f.Domain = "dns", "dns", "a.test" }, true},
		{func(f *ConnFacts) { f.Proto = "UDP" }, false},
	} {
		f := base
		c.mod(&f)
		if _, err := buildFlow(f, nil, nil, false); (err != nil) != c.fail {
			t.Errorf("%+v: %v", f, err)
		}
	}
	f := base
	f.Dst, f.DomainSrc, f.Domain = "[fe80::1%eth0]:443", "sni", "A.Test."
	fl, err := buildFlow(f, []string{`C:\Steam\steam.exe`, "explorer.exe"}, nil, false)
	if err != nil || fl.Name != "a.test" || fl.Dst.Addr().Zone() != "" || fl.Proto != 6 {
		t.Fatalf("%+v %v", fl, err)
	}
	if fl.Proc.Name != "x.exe" || fl.Proc.Parent.Name != "steam.exe" || fl.Proc.Parent.Path != `C:\Steam\steam.exe` || fl.Proc.Parent.Parent.Name != "explorer.exe" {
		t.Fatalf("chain %+v", fl.Proc)
	}
	f = base
	f.Dst = "[::ffff:1.2.3.4]:443"
	f.DomainSrc, f.Domain = "dns", "b.test,a.test"
	fl, _ = buildFlow(f, nil, [][]string{{"B.test", "1.2.3.4", "b.test"}, {}, {"a.test"}}, false)
	if !fl.DNSName || len(fl.Sites) != 2 || !slices.Equal(fl.Sites[0], []string{"b.test"}) || fl.Dst.Addr().String() != "1.2.3.4" {
		t.Fatalf("%+v", fl)
	}
	// An IP as the name, and an unknown owner.
	fl, _ = buildFlow(ConnFacts{Proto: "tcp", Dst: "1.2.3.4:80", DomainSrc: "host", Domain: "1.2.3.4"}, nil, nil, false)
	if fl.Name != "" || fl.Proc != nil {
		t.Fatalf("%+v", fl)
	}
	long := base
	long.Path = strings.Repeat("a", maxFactLen+1)
	c, _ := newCtl(t)
	if _, err := c.resolveFlow(long); err == nil {
		t.Fatal("length cap")
	}
}

func TestResolveFlow(t *testing.T) {
	c, s, _, _ := connCtl(t)
	rec := &flows.Record{PID: 7, Process: "game.exe", Path: `C:\G\game.exe`, Proto: 17, Dst: netip.MustParseAddrPort("198.51.100.1:27015"),
		Parents: []string{`C:\Steam\steam.exe`}, Sites: [][]string{{"game.example.com", "xyz.elb.amazonaws.com"}}}
	f := s.record(rec, func(f *flows.Fields) {
		f.Domain, f.DomainSrc, f.ECH, f.Excluded = "game.example.com,xyz.elb.amazonaws.com", "dns", true, "hysteria"
	})
	lie := f
	lie.Excluded, lie.ECH, lie.Domain = "", false, "other.test"
	fl, err := c.resolveFlow(lie)
	if err != nil || fl.Excluded != "hysteria" || !fl.ECHMarker || len(fl.parents) != 1 || len(fl.Sites) != 1 || len(fl.Sites[0]) != 2 {
		t.Fatalf("record not used: %+v %v", fl, err)
	}
	// Same ID, another identity: the facts.
	other := lie
	other.PID = 8
	if fl, _ = c.resolveFlow(other); fl.Excluded != "" || len(fl.parents) != 0 {
		t.Fatalf("identity: %+v", fl)
	}
	// Evicted: the live cache regroups the row's names.
	ip := netip.MustParseAddr("198.51.100.2")
	s.sites[ip] = [][]string{{"game.example.com", "xyz.elb.amazonaws.com"}, {"other.test"}}
	row := ConnFacts{ID: 999, Process: "game.exe", Proto: "udp", Dst: "198.51.100.2:1", DomainSrc: "dns",
		Domain: "game.example.com,other.test,xyz.elb.amazonaws.com"}
	fl, _ = c.resolveFlow(row)
	if len(fl.Sites) != 2 || !slices.Equal(fl.Sites[0], []string{"game.example.com", "xyz.elb.amazonaws.com"}) || fl.SitesPartial {
		t.Fatalf("regrouped: %+v", fl)
	}
	row.Domain += ",gone.test"
	if fl, _ = c.resolveFlow(row); len(fl.Sites) != 3 || !fl.SitesPartial {
		t.Fatalf("gone name: %+v", fl)
	}
	c.mu.Lock()
	c.sess = nil
	c.mu.Unlock()
	if fl, _ = c.resolveFlow(row); len(fl.Sites) != 4 || !fl.SitesPartial {
		t.Fatalf("no session: %+v", fl)
	}
}

func TestConnScopes(t *testing.T) {
	c, s, _, _ := connCtl(t)
	info := func(f ConnFacts) ConnRuleInfo {
		t.Helper()
		i, err := c.ConnRuleInfo(f)
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	kinds := func(sc []ConnScope) string {
		var out []string
		for _, x := range sc {
			out = append(out, x.Kind+":"+x.Pattern)
		}
		return strings.Join(out, " ")
	}
	if got := kinds(info(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")).Scopes); got != "site:.example.com host:a.example.com ip:1.2.3.4" {
		t.Fatal(got)
	}
	if got := kinds(info(sniRow(s, "x.exe", "1.2.3.4:443", "example.com")).Scopes); got != "site:.example.com host:example.com ip:1.2.3.4" {
		t.Fatal(got)
	}
	if got := kinds(info(sniRow(s, "x.exe", "1.2.3.4:443", "u.github.io")).Scopes); got != "site:.u.github.io host:u.github.io ip:1.2.3.4" {
		t.Fatal(got)
	}
	if got := kinds(info(sniRow(s, "x.exe", "1.2.3.4:443", "router")).Scopes); got != "host:router ip:1.2.3.4" {
		t.Fatal(got)
	}
	idn := info(sniRow(s, "x.exe", "1.2.3.4:443", "пример.рф")).Scopes[0]
	if idn.Pattern != ".xn--e1afmkfd.xn--p1ai" || idn.Label != "пример.рф" || idn.ASCII != "xn--e1afmkfd.xn--p1ai" {
		t.Fatalf("%+v", idn)
	}
	dnsRow := func(sites ...[]string) ConnFacts {
		return s.record(&flows.Record{Process: "g.exe", Proto: 17, Dst: netip.MustParseAddrPort("198.51.100.3:1"), Sites: sites},
			func(f *flows.Fields) { f.DomainSrc, f.Domain = "dns", "x" })
	}
	chain := []string{"game.example.com", "xyz.elb.amazonaws.com"}
	if got := kinds(info(dnsRow(chain)).Scopes); got != "site:.example.com host:game.example.com ip:198.51.100.3 alias:xyz.elb.amazonaws.com" {
		t.Fatal(got)
	}
	got := kinds(info(dnsRow(chain, []string{"b.test", "e1.akamaiedge.net"}, []string{"c.test"}, []string{"d.test"})).Scopes)
	if got != "site:.example.com host:game.example.com site:.b.test host:b.test site:.c.test host:c.test ip:198.51.100.3 alias:xyz.elb.amazonaws.com" {
		t.Fatal(got)
	}
}

func TestConnRuleInfoCNAME(t *testing.T) {
	c, s, s1, _ := connCtl(t)
	setConnRules(t, c, siteRule(".example.com", rules.Tunnel, s1))
	rec := &flows.Record{Process: "g.exe", Proto: 17, Dst: netip.MustParseAddrPort("198.51.100.4:1"),
		Sites: [][]string{{"game.example.com", "xyz.elb.amazonaws.com"}}}
	i, _ := c.ConnRuleInfo(s.record(rec, func(f *flows.Fields) { f.DomainSrc, f.Domain = "dns", "x" }))
	if i.Current.Index != 0 || i.Current.Ambiguous || i.Sites != 1 || i.SharedIP || !i.DNSName || i.Current.Profile != s1 {
		t.Fatalf("%+v", i)
	}
	rec2 := &flows.Record{Process: "g.exe", Proto: 17, Dst: netip.MustParseAddrPort("198.51.100.4:1"),
		Sites: [][]string{{"game.example.com", "xyz.elb.amazonaws.com"}, {"other.test"}}}
	i, _ = c.ConnRuleInfo(s.record(rec2, func(f *flows.Fields) { f.DomainSrc, f.Domain = "dns", "x" }))
	if i.Current.Index != -1 || !i.Current.Ambiguous || i.Sites != 2 || !i.SharedIP {
		t.Fatalf("%+v", i)
	}
}

func TestConnRuleInfoECH(t *testing.T) {
	c, s, _, _ := connCtl(t)
	ech := func(name, src string) ConnRuleInfo {
		f := s.record(&flows.Record{Process: "chrome.exe", Proto: 6, Dst: netip.MustParseAddrPort("104.16.1.1:443")},
			func(f *flows.Fields) { f.Domain, f.DomainSrc, f.ECH = name, src, true })
		i, err := c.ConnRuleInfo(f)
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	i := ech("cloudflare-ech.com", "sni")
	if i.ECH != "public" || i.ECHName != "cloudflare-ech.com" || !i.SharedIP || i.ExplainTarget != "104.16.1.1" || len(i.Scopes) != 1 || i.Scopes[0].Kind != "ip" {
		t.Fatalf("%+v", i)
	}
	s.public["pub.example"] = true
	if i = ech("pub.example", "sni"); i.ECH != "public" || len(i.Scopes) != 1 {
		t.Fatalf("learned: %+v", i)
	}
	if i = ech("a.example.com", "dns"); i.ECH != "hidden" || i.Scopes[0].Kind != "site" {
		t.Fatalf("hidden: %+v", i)
	}
	if i = ech("grease.example", "sni"); i.ECH != "" || i.Scopes[0].Pattern != ".grease.example" {
		t.Fatalf("grease: %+v", i)
	}
}

func TestAddConnRuleRefusesECHPublic(t *testing.T) {
	c, s, _, _ := connCtl(t)
	f := s.record(&flows.Record{Process: "chrome.exe", Proto: 6, Dst: netip.MustParseAddrPort("104.16.1.1:443")},
		func(f *flows.Fields) { f.Domain, f.DomainSrc, f.ECH = "cloudflare-ech.com", "sni", true })
	before := settingsFile(t, c)
	if _, err := c.AddConnRule(quick(f, siteRule(".cloudflare-ech.com", rules.Block, ""))); err == nil || !strings.Contains(err.Error(), "Сайт скрыт ECH") {
		t.Fatalf("%v", err)
	}
	if !slices.Equal(before, settingsFile(t, c)) {
		t.Fatal("written")
	}
	ed := quick(f, siteRule(".cloudflare-ech.com", rules.Block, ""))
	ed.Source = "editor"
	if _, err := c.AddConnRule(ed); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddConnRule(quick(f, siteRule("104.16.1.1", rules.Block, ""))); err != nil {
		t.Fatal(err)
	}
}

func TestConnRuleInfoBlocked(t *testing.T) {
	c, s, _, _ := connCtl(t)
	f := sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")
	c.mu.Lock()
	c.settingsBroken = errors.New("broken")
	c.mu.Unlock()
	i, err := c.ConnRuleInfo(f)
	if err != nil || !strings.Contains(i.Blocked, "settings.json не загружен") || len(i.Scopes) == 0 || i.Current.Index != -1 {
		t.Fatalf("%+v %v", i, err)
	}
	if _, err := c.AddConnRule(quick(f, siteRule(".example.com", rules.Block, ""))); err == nil || !strings.Contains(err.Error(), "settings.json не загружен") {
		t.Fatal(err)
	}
}

func TestConnRuleInfo(t *testing.T) {
	c, s, _, _ := connCtl(t)
	c.SystemRoot = func() string { return `C:\Windows` }
	for kind, want := range map[string]string{"hysteria": "Hysteria", "system-dns": "Системный DNS", "odd": "Служебное соединение"} {
		f := s.record(&flows.Record{Process: "x.exe", Proto: 6, Dst: netip.MustParseAddrPort("1.2.3.4:443")},
			func(f *flows.Fields) { f.Excluded = kind })
		if i, _ := c.ConnRuleInfo(f); !strings.Contains(i.Excluded, want) {
			t.Errorf("%s: %q", kind, i.Excluded)
		}
		if _, err := c.AddConnRule(quick(f, siteRule("1.2.3.4", rules.Block, ""))); err == nil {
			t.Errorf("%s: service flow accepted", kind)
		}
	}
	f := s.record(&flows.Record{Process: "x.exe", Proto: 6, Dst: netip.MustParseAddrPort("1.2.3.4:443")},
		func(f *flows.Fields) { f.Rule = "exclusion: self" })
	if i, _ := c.ConnRuleInfo(f); i.Excluded != "" {
		t.Fatal("excluded by the label")
	}
	row := func(path string, parents ...string) ConnRuleInfo {
		r := &flows.Record{Process: strings.ToLower(baseName(path)), Path: path, Proto: 6, Dst: netip.MustParseAddrPort("1.2.3.4:443"), Parents: parents}
		i, err := c.ConnRuleInfo(s.record(r, nil))
		if err != nil {
			t.Fatal(err)
		}
		return i
	}
	if i := row(`C:\Windows\explorer.exe`); i.App != "explorer.exe" || !i.AppSystem || !i.AppLauncher {
		t.Fatalf("%+v", i)
	}
	if i := row(`C:\Program Files\PowerShell\7\pwsh.exe`); !i.AppLauncher || i.AppSystem {
		t.Fatalf("%+v", i)
	}
	if i := row(`C:\VS\Code.exe`, "explorer.exe"); i.App != "Code.exe" || !i.AppLauncher || !i.HasParents {
		t.Fatalf("%+v", i)
	}
	if i := row(`C:\T\Telegram.exe`); i.App != "Telegram.exe" || i.AppLauncher || i.AppSystem || i.HasParents {
		t.Fatalf("%+v", i)
	}
	sys := s.record(&flows.Record{Process: "system", PID: 4, Proto: 6, Dst: netip.MustParseAddrPort("1.2.3.4:445")}, nil)
	if i, _ := c.ConnRuleInfo(sys); !i.AppSystem || i.App != "system" {
		t.Fatalf("%+v", i)
	}
	setConnRules(t, c, siteRule(".example.com", rules.Block, ""))
	i, _ := c.ConnRuleInfo(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com"))
	if i.Current.Index != 0 || i.Current.Rule == nil || i.Current.Rule.Domains[0] != ".example.com" || i.Current.Action != rules.Block {
		t.Fatalf("%+v", i.Current)
	}
	i, _ = c.ConnRuleInfo(sniRow(s, "x.exe", "1.2.3.4:443", "b.test"))
	if i.Current.Index != -1 || i.Current.Rule != nil || i.Current.Action != rules.Direct {
		t.Fatalf("%+v", i.Current)
	}
}

// TestDNSQueryRow: the rows «DNS по правилам» records for name lookups.
func TestDNSQueryRow(t *testing.T) {
	c, s, _, _ := connCtl(t)
	q := func(attrib, src string) ConnFacts {
		return s.record(&flows.Record{Process: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`, Proto: 17, Dst: netip.MustParseAddrPort("8.8.8.8:53")},
			func(f *flows.Fields) {
				f.Stage, f.DomainSrc, f.Domain, f.Attrib = flows.StageDNS, src, "a.example.com", attrib
			})
	}
	query := rules.SrcQuery.String()
	f := q("dnscache", query)
	i, err := c.ConnRuleInfo(f)
	if err != nil || !i.DNSQuery || i.App != "" || i.AppNote == "" || i.DNSName || len(i.Scopes) != 2 || i.ExplainTarget != "a.example.com" {
		t.Fatalf("%+v %v", i, err)
	}
	if i, _ := c.ConnRuleInfo(q("packet", query)); i.App != "svchost.exe" || i.AppNote != "" {
		t.Fatalf("%+v", i)
	}
	if _, err := c.ConnRuleInfo(q("packet", "dns")); err == nil {
		t.Fatal("dns row without a query name")
	}
	before := settingsFile(t, c)
	if _, err := c.AddConnRule(quick(f, appRule("svchost.exe", rules.Direct))); !errors.Is(err, errNoProgram) || !slices.Equal(before, settingsFile(t, c)) {
		t.Fatal(err)
	}
	setConnRules(t, c, rules.Rule{Domains: []string{".example.com"}, Protocol: "udp", Action: rules.Block})
	res, err := c.AddConnRule(quick(f, siteRule(".example.com", rules.Tunnel, "")))
	if err != nil || res.Index != 0 || res.Kind != "added" {
		t.Fatalf("%+v %v", res, err)
	}
	// A closed DNS row is found in its own ring after the connections ring
	// has moved on: the record's attribution wins over the row's.
	rec := &flows.Record{Process: "svchost.exe", Path: `C:\Windows\System32\svchost.exe`, Proto: 17, Dst: netip.MustParseAddrPort("8.8.4.4:53")}
	g := dnsClientRow(s, rec)
	now := time.Now()
	s.reg.Close(rec, now)
	for i := 0; i < 150; i++ {
		s.reg.Close(s.reg.Open(&flows.Record{Proto: 6, Dst: netip.MustParseAddrPort("192.0.2.1:443")}), now)
	}
	lie := g
	lie.Attrib = "packet"
	if i, err := c.ConnRuleInfo(lie); err != nil || !i.DNSQuery || i.App != "" || i.AppNote == "" {
		t.Fatalf("closed DNS row: %+v %v", i, err)
	}
}

// TestDNSQueryRowAboveIPRule: the connection that follows a lookup may go
// to an address an IP rule catches, so a site rule from the lookup goes
// above that rule instead of changing the site rule below it.
func TestDNSQueryRowAboveIPRule(t *testing.T) {
	c, s, _, _ := connCtl(t)
	setConnRules(t, c, rules.Rule{Domains: []string{"1.2.3.0/24"}, Action: rules.Direct}, siteRule(".example.com", rules.Block, ""))
	f := s.record(&flows.Record{Process: "app.exe", Path: `C:\Apps\app.exe`, Proto: 17, Dst: netip.MustParseAddrPort("8.8.8.8:53")},
		func(f *flows.Fields) {
			f.Stage, f.DomainSrc, f.Domain, f.Attrib = flows.StageDNS, rules.SrcQuery.String(), "a.example.com", "packet"
		})
	res, err := c.AddConnRule(quick(f, siteRule(".example.com", rules.Tunnel, "")))
	if err != nil || res.Kind != "added" || res.Index != 0 || res.AboveIndex != 1 || res.NotEffective {
		t.Fatalf("%+v %v", res, err)
	}
}

// dnsClientRow records a DNS row of the Windows DNS client for b.example.com.
func dnsClientRow(s *connSess, rec *flows.Record) ConnFacts {
	return s.record(rec, func(f *flows.Fields) {
		f.Stage, f.DomainSrc, f.Domain, f.Attrib = flows.StageDNS, rules.SrcQuery.String(), "b.example.com", "dnscache"
	})
}

func TestAddConnRuleInsertsAboveWinner(t *testing.T) {
	c, s, s1, s2 := connCtl(t)
	setConnRules(t, c, appRule("y.exe", rules.Direct), siteRule(".example.com", rules.Tunnel, s1), appRule("x.exe", rules.Block))
	f := sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")
	// The host scope: B decides the flow, so the rule goes right above it
	// (the site scope, identical to B, would change B in place).
	res, err := c.AddConnRule(quick(f, siteRule("a.example.com", rules.Tunnel, s2)))
	if err != nil || res.Kind != "added" || res.Index != 1 || res.AboveIndex != 2 || len(res.RuleID) != 12 || res.Undo == "" || res.Seq != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if !slices.ContainsFunc(res.Refs, func(r ConnRuleRef) bool { return r.Index == 2 && r.Rule.Profile == s1 }) {
		t.Fatalf("refs %+v", res.Refs)
	}
	st, _, err := c.Store.LoadSettings()
	if err != nil || st.Rules[1].ID != res.RuleID || st.Rules[0].Apps[0].Pattern != "y.exe" {
		t.Fatalf("%+v %v", st.Rules, err)
	}
	s.mu.Lock()
	got := s.set.EvaluateDomain(rules.Subject{Proc: &procinfo.Info{Name: "x.exe"}, Proto: 6, Dst: netip.MustParseAddrPort("1.2.3.4:443")}, "a.example.com", rules.SrcSNI)
	s.mu.Unlock()
	if got.Action != rules.Tunnel || got.Profile != s2 {
		t.Fatalf("engine: %+v", got)
	}
	if res.Rev != c.SettingsRev() {
		t.Fatal("rev")
	}
	f = sniRow(s, "y.exe", "1.2.3.4:443", "a.example.com")
	if res, _ = c.AddConnRule(quick(f, siteRule("a.example.com", rules.Tunnel, s1))); res.Index != 0 || res.Kind != "added" {
		t.Fatalf("%+v", res)
	}
}

// TestAddConnRuleQUICNameless: with ExactWeb and BlockQUIC (the defaults)
// the engine decides QUIC without the DNS names the row shows, so a site
// rule made from it does not decide it.
func TestAddConnRuleQUICNameless(t *testing.T) {
	c, s, s1, _ := connCtl(t)
	setConnRules(t, c, appRule("chrome.exe", rules.Direct))
	rec := &flows.Record{PID: 10, Process: "chrome.exe", Path: `C:\Apps\chrome.exe`, Proto: 17, Dst: netip.MustParseAddrPort("1.2.3.4:443"),
		Sites: [][]string{{"a.example.com"}}, Nameless: true}
	f := s.record(rec, func(f *flows.Fields) { f.Domain, f.DomainSrc = "a.example.com", "dns" })
	i, err := c.ConnRuleInfo(f)
	if err != nil || !i.Nameless || i.Current.Index != 0 || i.Current.Ambiguous || !slices.ContainsFunc(i.Scopes, func(s ConnScope) bool { return s.Kind == "site" }) {
		t.Fatalf("%+v %v", i, err)
	}
	res, err := c.AddConnRule(quick(f, siteRule(".example.com", rules.Tunnel, s1)))
	if err != nil || res.Kind != "added" || res.Index != 0 || !res.Matches || !res.NotEffective || !res.Nameless || res.Unchanged || res.PlacedByRule {
		t.Fatalf("%+v %v", res, err)
	}
	// The record is gone: the settings say how the engine decides QUIC.
	row := ConnFacts{ID: 999, Process: "chrome.exe", PID: 10, Proto: "udp", Dst: "1.2.3.5:443", DomainSrc: "dns", Domain: "b.example.com"}
	if fl, err := c.resolveFlow(row); err != nil || !fl.Nameless || len(fl.Sites) != 1 {
		t.Fatalf("gone: %+v %v", fl, err)
	}
	row.Proto = "tcp"
	if fl, _ := c.resolveFlow(row); fl.Nameless {
		t.Fatal("tcp nameless")
	}
	st := c.Settings()
	off := false
	st.BlockQUIC = &off
	if _, err := c.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	row.Proto = "udp"
	if fl, _ := c.resolveFlow(row); fl.Nameless {
		t.Fatal("nameless without BlockQUIC")
	}
}

func TestAddConnRuleLauncherNoChildren(t *testing.T) {
	c, s, _, _ := connCtl(t)
	f := s.record(&flows.Record{Process: "pwsh.exe", Path: `C:\PS\pwsh.exe`, Proto: 6, Dst: netip.MustParseAddrPort("1.2.3.4:443")}, nil)
	i, _ := c.ConnRuleInfo(f)
	r := rules.Rule{Apps: []rules.AppMatch{{Pattern: i.App, InheritChildren: !i.AppLauncher}}, Action: rules.Direct}
	res, err := c.AddConnRule(quick(f, r))
	if err != nil || res.Rule.Apps[0].InheritChildren || res.Rule.Apps[0].Pattern != "pwsh.exe" {
		t.Fatalf("%+v %v", res, err)
	}
	if b := settingsFile(t, c); strings.Contains(string(b), "inheritChildren") {
		t.Fatalf("%s", b)
	}
}

// geoPending: every category is still downloading, except "nope" (unknown).
type geoPending struct{}

func (geoPending) Site(n string) (rules.DomainMatcher, error) {
	if n == "nope" {
		return nil, errors.New("категории нет")
	}
	return nil, rules.ErrGeoNoData
}
func (geoPending) IP(string) (rules.IPMatcher, error) { return nil, rules.ErrGeoNoData }

func withConnGeo(t *testing.T) {
	rules.SetGeo(geoPending{})
	t.Cleanup(func() { rules.SetGeo(nil) })
}

func TestAddConnRuleGeoAboveIdentical(t *testing.T) {
	c, s, s1, s2 := connCtl(t)
	withConnGeo(t)
	setConnRules(t, c, siteRule("geosite:foo", rules.Tunnel, s1), siteRule(".example.com", rules.Direct, ""))
	res, err := c.AddConnRule(quick(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com"), siteRule(".example.com", rules.Tunnel, s2)))
	if err != nil || res.Kind != "added" || res.Index != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	cfg := c.Settings().Config
	if cfg.Rules[2].Action != rules.Direct {
		t.Fatal("rule 1 changed")
	}
	lint := rules.Lint(cfg)
	if !slices.ContainsFunc(lint, func(x rules.Issue) bool { return x.Index == 2 && strings.Contains(x.Text, "сработает") }) {
		t.Fatalf("lint %+v", lint)
	}
}

func TestAddConnRuleUnknownGeoNotMayMatch(t *testing.T) {
	c, s, s1, s2 := connCtl(t)
	withConnGeo(t)
	setConnRules(t, c, siteRule("geosite:nope", rules.Tunnel, s1), siteRule(".example.com", rules.Direct, ""))
	res, err := c.AddConnRule(quick(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com"), siteRule(".example.com", rules.Tunnel, s2)))
	if err != nil || res.Kind != "changed" || res.Index != 1 || len(c.Settings().Rules) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestAddConnRuleCNAMEChain(t *testing.T) {
	c, s, s1, s2 := connCtl(t)
	setConnRules(t, c, appRule("y.exe", rules.Direct), siteRule(".example.com", rules.Tunnel, s1))
	chain := []string{"game.example.com", "xyz.elb.amazonaws.com"}
	row := func(sites ...[]string) ConnFacts {
		return s.record(&flows.Record{Process: "x.exe", Path: `C:\G\x.exe`, Proto: 17, Dst: netip.MustParseAddrPort("198.51.100.5:1"), Sites: sites},
			func(f *flows.Fields) { f.DomainSrc, f.Domain = "dns", "x" })
	}
	res, err := c.AddConnRule(quick(row(chain), siteRule(".example.com", rules.Direct, "")))
	if err != nil || res.Kind != "changed" || res.Index != 1 || res.Unchanged || res.NotEffective {
		t.Fatalf("%+v %v", res, err)
	}
	setConnRules(t, c, appRule("y.exe", rules.Direct), siteRule(".example.com", rules.Tunnel, s1), siteRule(".other.test", rules.Block, ""))
	res, err = c.AddConnRule(quick(row(chain, []string{"other.test"}), siteRule(".example.com", rules.Tunnel, s2)))
	if err != nil || res.Kind != "added" || res.Index != 1 || !res.NotEffective {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestAddConnRuleNarrowed(t *testing.T) {
	c, s, s1, s2 := connCtl(t)
	withConnGeo(t)
	setConnRules(t, c, siteRule("geosite:foo", rules.Tunnel, s1), siteRule("geosite:bar-telemetry", rules.Block, ""), siteRule(".example.com", rules.Direct, ""))
	res, err := c.AddConnRule(quick(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com"), siteRule(".example.com", rules.Tunnel, s2)))
	if err != nil || res.Index != 0 || !slices.Equal(res.Narrowed, []int{2, 1}) {
		t.Fatalf("%+v %v", res, err)
	}
	for _, j := range []int{1, 2} {
		if !slices.ContainsFunc(res.Refs, func(r ConnRuleRef) bool { return r.Index == j }) {
			t.Fatalf("refs %+v", res.Refs)
		}
	}
}

func TestAddConnRuleChangesIdenticalWinner(t *testing.T) {
	c, s, s1, s2 := connCtl(t)
	r := siteRule(".example.com", rules.Tunnel, s1)
	r.Name, r.Fallback = "Мой сайт", []string{s2}
	setConnRules(t, c, r)
	f := sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")
	res, err := c.AddConnRule(quick(f, siteRule(".example.com", rules.Tunnel, s2)))
	got := c.Settings().Rules[0]
	if err != nil || res.Kind != "changed" || got.Name != "Мой сайт" || got.Profile != s2 || got.Fallback != nil || got.ID == "" || res.RuleID != got.ID {
		t.Fatalf("%+v %+v %v", res, got, err)
	}
	// Same target: nothing is written, no undo.
	before := settingsFile(t, c)
	res, err = c.AddConnRule(quick(f, siteRule(".example.com", rules.Tunnel, s2)))
	if err != nil || res.Kind != "same" || res.Undo != "" || res.Seq != 0 || res.Rev != c.SettingsRev() || !slices.Equal(before, settingsFile(t, c)) {
		t.Fatalf("same: %+v %v", res, err)
	}
	// Fallback kept while the target stays.
	r.Profile, r.Fallback, r.ID = s1, []string{s2}, "abc"
	setConnRules(t, c, r)
	r2 := siteRule(".example.com", rules.Tunnel, s1)
	r2.Action = rules.Tunnel
	c.AddConnRule(quick(f, siteRule(".example.com", rules.Direct, "")))
	if got := c.Settings().Rules[0]; got.Fallback != nil || got.ID != "abc" || got.Action != rules.Direct {
		t.Fatalf("%+v", got)
	}
}

func TestAddConnRuleEditor(t *testing.T) {
	c, s, s1, s2 := connCtl(t)
	setConnRules(t, c, siteRule(".example.com", rules.Tunnel, s1), siteRule(".other.test", rules.Block, ""))
	f := sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")
	ed := ConnRuleRequest{Facts: f, Rule: rules.Rule{Name: "Своё", Domains: []string{".example.com"}, Action: rules.Tunnel, Profile: s2}, Source: "editor"}
	res, err := c.AddConnRule(ed)
	if err != nil || res.Kind != "added" || res.Index != 0 || res.Rule.Name != "Своё" || res.PlacedByRule {
		t.Fatalf("never in place: %+v %v", res, err)
	}
	ed.Rule = rules.Rule{Domains: []string{"x.other.test"}, Action: rules.Direct}
	res, err = c.AddConnRule(ed)
	if err != nil || !res.PlacedByRule || res.Index != 2 || res.Matches {
		t.Fatalf("not matching: %+v %v", res, err)
	}
}

func TestAddConnRuleDefaultGoesToEnd(t *testing.T) {
	c, s, _, _ := connCtl(t)
	setConnRules(t, c, appRule("y.exe", rules.Block))
	res, err := c.AddConnRule(quick(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com"), siteRule(".example.com", rules.Direct, "")))
	if err != nil || res.Index != 1 || res.AboveIndex != -1 || !res.Unchanged {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestAddConnRuleShadowedOverridden(t *testing.T) {
	c, s, s1, _ := connCtl(t)
	setConnRules(t, c,
		rules.Rule{Apps: []rules.AppMatch{{Pattern: "telegram.exe"}}, Domains: []string{".telegram.org"}, Action: rules.Tunnel, Profile: s1},
		appRule("y.exe", rules.Direct),
		rules.Rule{Apps: []rules.AppMatch{{Pattern: "telegram.exe"}}, Domains: []string{".example.com"}, Action: rules.Block},
	)
	f := sniRow(s, "Telegram.exe", "1.2.3.4:443", "a.example.com")
	res, err := c.AddConnRule(quick(f, rules.Rule{Apps: []rules.AppMatch{{Pattern: "Telegram.exe", InheritChildren: true}}, Action: rules.Direct}))
	if err != nil || res.Index != 2 || !slices.Equal(res.OverriddenBy, []int{0}) || !slices.Equal(res.Shadowed, []int{3}) {
		t.Fatalf("%+v %v", res, err)
	}
	if !slices.ContainsFunc(res.Refs, func(r ConnRuleRef) bool { return r.Index == 0 }) {
		t.Fatalf("refs %+v", res.Refs)
	}
}

func TestAddConnRuleRefusals(t *testing.T) {
	c, s, _, _ := connCtl(t)
	f := sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")
	before := settingsFile(t, c)
	for i, req := range []ConnRuleRequest{
		quick(f, siteRule(".example.com", rules.Tunnel, "deadbeef0000")),
		quick(f, siteRule(".example.com", rules.Tunnel, "grp_gone")),
		quick(f, rules.Rule{Action: rules.Block}),
		quick(f, siteRule("regexp:(", rules.Block, "")),
		{Facts: f, Rule: siteRule(".example.com", rules.Block, ""), Source: "other"},
		quick(ConnFacts{Proto: "tcp", Dst: "1.2.3.4:443"}, appRule("x.exe", rules.Block)),
		// An inactive profile's edit token: only the active rules are written.
		{Facts: f, Rule: siteRule(".example.com", rules.Block, ""), Source: "quick", Ruleset: editTokenPrefix + "abc"},
	} {
		if _, err := c.AddConnRule(req); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	// A server that left its subscription.
	c.mu.Lock()
	c.profiles.List[0].Missing = true
	id := c.profiles.List[0].ID
	c.mu.Unlock()
	if _, err := c.AddConnRule(quick(f, siteRule(".example.com", rules.Tunnel, id))); err == nil || !strings.Contains(err.Error(), "Сервер удалён") {
		t.Fatal(err)
	}
	if !slices.Equal(before, settingsFile(t, c)) {
		t.Fatal("written")
	}
}

// A quick rule never carries a name: one made from a site or an IP would
// show it unmasked (PITFALLS-v12 #1).
func TestAddConnRuleQuickDropsName(t *testing.T) {
	c, s, _, _ := connCtl(t)
	f := sniRow(s, "x.exe", "1.2.3.4:443", "example-private.com")
	r := siteRule("example-private.com", rules.Block, "")
	r.Name = "example-private.com"
	res, err := c.AddConnRule(quick(f, r))
	if err != nil || res.Rule.Name != "" || c.Settings().Rules[0].Name != "" {
		t.Fatalf("%+v %v", res, err)
	}
	if b := strings.ReplaceAll(string(settingsFile(t, c)), " ", ""); strings.Contains(b, `"name":"example-private.com"`) {
		t.Fatal("name saved")
	}
}

func TestAddConnRuleWriteFailureNoUndo(t *testing.T) {
	c, s, _, _ := connCtl(t)
	f := sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")
	rev, at := c.SettingsRev(), rulesAt(c)
	before := c.Settings()
	if err := os.MkdirAll(filepath.Join(c.Store.Dir, "settings.json", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddConnRule(quick(f, siteRule(".example.com", rules.Block, ""))); err == nil {
		t.Fatal("no error")
	}
	c.undoMu.Lock()
	n := len(c.connUndo)
	c.undoMu.Unlock()
	if n != 0 || c.SettingsRev() != rev || rulesAt(c) != at || !sameRules(before.Config, c.Settings().Config) {
		t.Fatal("state changed")
	}
}

func TestUndoConnRule(t *testing.T) {
	c, s, s1, s2 := connCtl(t)
	setConnRules(t, c, siteRule(".example.com", rules.Tunnel, s1))
	orig := c.Settings().Rules
	f := sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")
	add, err := c.AddConnRule(quick(f, appRule("x.exe", rules.Direct)))
	if err != nil || add.Kind != "added" {
		t.Fatal(err)
	}
	if err := c.UndoConnRule(add.Undo); err != nil || !slices.EqualFunc(c.Settings().Rules, orig, func(a, b rules.Rule) bool { return a.Profile == b.Profile && a.ID == b.ID }) || len(c.Settings().Rules) != 1 {
		t.Fatalf("%v %+v", err, c.Settings().Rules)
	}
	if err := c.UndoConnRule(add.Undo); !errors.Is(err, errUndoGone) {
		t.Fatal(err)
	}
	ch, _ := c.AddConnRule(quick(f, siteRule(".example.com", rules.Tunnel, s2)))
	if ch.Kind != "changed" || ch.Seq != 2 {
		t.Fatalf("%+v", ch)
	}
	if err := c.UndoConnRule(ch.Undo); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(c.Settings().Rules)
	b, _ := json.Marshal(orig)
	if string(a) != string(b) {
		t.Fatalf("restored %s, want %s", a, b)
	}
	// Edited since: refused, nothing written, entry dropped.
	add, _ = c.AddConnRule(quick(f, appRule("x.exe", rules.Block)))
	cfg := c.Settings().Config.Clone()
	cfg.Rules[0].Name = "правка"
	if _, err := c.SaveRulesIn(EditGuard{}, cfg); err != nil {
		t.Fatal(err)
	}
	before := settingsFile(t, c)
	if err := c.UndoConnRule(add.Undo); !errors.Is(err, errUndoEdited) || !slices.Equal(before, settingsFile(t, c)) {
		t.Fatal(err)
	}
	if err := c.UndoConnRule(add.Undo); !errors.Is(err, errUndoGone) {
		t.Fatal(err)
	}
	// Removed since.
	add, _ = c.AddConnRule(quick(f, appRule("x.exe", rules.Direct)))
	setConnRules(t, c)
	if err := c.UndoConnRule(add.Undo); !errors.Is(err, errUndoNotFound) {
		t.Fatal(err)
	}
	// A transient write failure keeps the entry.
	add, _ = c.AddConnRule(quick(f, appRule("x.exe", rules.Block)))
	bad := filepath.Join(c.Store.Dir, "settings.json")
	good := bad + ".keep"
	os.Rename(bad, good)
	os.MkdirAll(filepath.Join(bad, "x"), 0o700)
	if err := c.UndoConnRule(add.Undo); err == nil {
		t.Fatal("no write error")
	}
	os.RemoveAll(bad)
	os.Rename(good, bad)
	if err := c.UndoConnRule(add.Undo); err != nil {
		t.Fatalf("retry: %v", err)
	}
	// Capacity: the 21st operation drops the oldest.
	var first string
	for i := 0; i <= connUndoCapacity; i++ {
		res, err := c.AddConnRule(quick(f, siteRule(fmt.Sprintf("h%d.example.com", i), rules.Block, "")))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = res.Undo
		}
	}
	if err := c.UndoConnRule(first); !errors.Is(err, errUndoGone) {
		t.Fatal(err)
	}
}

func TestUndoConcurrentSameToken(t *testing.T) {
	c, s, _, _ := connCtl(t)
	res, _ := c.AddConnRule(quick(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com"), appRule("x.exe", rules.Block)))
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = c.UndoConnRule(res.Undo) }()
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) || !errors.Is(errors.Join(errs...), errUndoGone) {
		t.Fatalf("%v", errs)
	}
}

func TestUndoConnRuleAfterRulesetSwitch(t *testing.T) {
	c, s, _, _ := connCtl(t)
	res, err := c.AddConnRule(quick(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com"), appRule("x.exe", rules.Block)))
	if err != nil {
		t.Fatal(err)
	}
	home := c.Settings()
	created := rsCreate(t, c, RulesetInput{Name: "Копия", From: "active", Activate: true, FirstName: "Дом"})
	if c.Settings().Rules[0].ID != res.RuleID {
		t.Fatal("copy lost the ID")
	}
	b1, b2 := settingsFile(t, c), rsBytes(t, c)
	err = c.UndoConnRule(res.Undo)
	if err == nil || !strings.Contains(err.Error(), "Профиль правил сменился: переключитесь на «Дом»") {
		t.Fatal(err)
	}
	if !slices.Equal(b1, settingsFile(t, c)) || !slices.Equal(b2, rsBytes(t, c)) {
		t.Fatal("written")
	}
	var homeID string
	c.mu.Lock()
	for _, e := range c.rulesets.List {
		if e.ID != created.View.ID {
			homeID = e.ID
		}
	}
	c.mu.Unlock()
	if _, err := c.SwitchRuleset(homeID, SourceUser, SwitchOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := c.UndoConnRule(res.Undo); err != nil {
		t.Fatal(err)
	}
	if len(c.Settings().Rules) != len(home.Rules)-1 {
		t.Fatalf("%+v", c.Settings().Rules)
	}
}

func TestClearConnUndo(t *testing.T) {
	c, s, _, _ := connCtl(t)
	res, _ := c.AddConnRule(quick(sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com"), appRule("x.exe", rules.Block)))
	c.clearConnUndo()
	if err := c.UndoConnRule(res.Undo); !errors.Is(err, errUndoGone) || len(c.Settings().Rules) != 1 {
		t.Fatal(err)
	}
}

// TestAddConnRuleSerializes: parallel writers never lose one another's rule.
func TestAddConnRuleSerializes(t *testing.T) {
	c, s, _, _ := connCtl(t)
	f := sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var ids []string
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.AddConnRule(quick(f, siteRule(fmt.Sprintf("p%d.example.com", i), rules.Block, "")))
			if err != nil {
				t.Error(err)
				return
			}
			if i%4 == 0 {
				c.UndoConnRule(res.Undo)
				return
			}
			mu.Lock()
			ids = append(ids, res.RuleID)
			mu.Unlock()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.ApplyRulesText("x.exe -> напрямую", false, EditGuard{})
	}()
	wg.Wait()
	st, _, err := c.Store.LoadSettings()
	if err != nil || !sameRules(st.Config, c.Settings().Config) {
		t.Fatalf("file and memory differ: %v", err)
	}
	for _, id := range ids {
		if !slices.ContainsFunc(st.Rules, func(r rules.Rule) bool { return r.ID == id }) {
			t.Fatalf("rule %s lost", id)
		}
	}
}

// TestConnRuleSettingsReadByV1: the saved file has only keys v1.0.0 knows.
func TestConnRuleSettingsReadByV1(t *testing.T) {
	c, s, s1, _ := connCtl(t)
	f := sniRow(s, "x.exe", "1.2.3.4:443", "a.example.com")
	c.AddConnRule(quick(f, siteRule(".example.com", rules.Tunnel, s1)))
	c.AddConnRule(quick(f, rules.Rule{Apps: []rules.AppMatch{{Pattern: "x.exe", InheritChildren: true}}, Action: rules.Direct}))
	b := settingsFile(t, c)
	if _, _, err := settings.Parse(b); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"defaultAction": true, "rules": true, "id": true, "name": true, "domains": true, "apps": true,
		"pattern": true, "inheritChildren": true, "action": true, "profile": true}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if !allowed[k] {
					t.Errorf("key %q", k)
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	var v any
	json.Unmarshal(b, &v)
	walk(v)
}
