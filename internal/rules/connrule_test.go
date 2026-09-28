package rules

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"testing"

	"github.com/lardan099/hyroute/internal/procinfo"
)

// connGeo: "foo" and "bar-telemetry" are still downloading, "known" is
// available, anything else is an unknown category.
type connGeo struct{}

type unknownCat struct{}

func (unknownCat) Error() string { return "категории нет в базе" }

func (connGeo) Site(n string) (DomainMatcher, error) {
	switch n {
	case "foo", "bar-telemetry":
		return nil, fmt.Errorf("x: %w", ErrGeoNoData)
	case "known":
		return fakeSite{"known.test": true}, nil
	}
	return nil, unknownCat{}
}

func (connGeo) IP(n string) (IPMatcher, error) {
	switch n {
	case "pend":
		return nil, ErrGeoNoData
	case "ru":
		return fakeIP{netip.MustParsePrefix("77.88.0.0/18")}, nil
	}
	return nil, unknownCat{}
}

func cproc(name string, parents ...string) *procinfo.Info {
	p := &procinfo.Info{Name: name, Path: `C:\P\` + name}
	cur := p
	for _, n := range parents {
		cur.Parent = &procinfo.Info{Name: n, Path: `C:\P\` + n}
		cur = cur.Parent
	}
	return p
}

func dst(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func off() *bool { f := false; return &f }

func TestPlace(t *testing.T) {
	withGeo(t, connGeo{})
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Name: "off", Domains: []string{".example.com"}, Enabled: off(), Action: Block},                  // 0 disabled
		{Name: "udp", Domains: []string{".example.com"}, Protocol: "udp", Action: Block},                 // 1 protocol
		{Name: "app", Apps: []AppMatch{{Pattern: "x.exe"}}, Action: Tunnel},                              // 2
		{Name: "ip", Domains: []string{"1.2.3.4"}, Action: Block},                                        // 3
		{Name: "site", Domains: []string{"a.example.com"}, Action: Tunnel},                               // 4
		{Name: "steam", Apps: []AppMatch{{Pattern: "steam.exe", InheritChildren: true}}, Action: Direct}, // 5
		{Name: "cdn", Domains: []string{".amazonaws.com"}, Action: Direct},                               // 6
		{Name: "geo", Domains: []string{"geosite:foo"}, Action: Tunnel},                                  // 7
		{Name: "unk", Domains: []string{"geosite:nope"}, Action: Tunnel},                                 // 8
	}}
	cases := []struct {
		f    Flow
		want int
	}{
		{Flow{Proc: cproc("x.exe"), Proto: 6, Dst: dst("9.9.9.9:443")}, 2},
		{Flow{Proc: cproc("y.exe"), Proto: 6, Dst: dst("1.2.3.4:443")}, 3},
		{Flow{Proc: cproc("y.exe"), Proto: 6, Dst: dst("9.9.9.9:443"), Name: "a.example.com"}, 4},
		{Flow{Proc: cproc("y.exe"), Proto: 17, Dst: dst("9.9.9.9:443"), Name: "a.example.com"}, 1},
		{Flow{Proc: cproc("game.exe", "steam.exe"), Proto: 6, Dst: dst("9.9.9.9:443")}, 5},
		{Flow{Proc: cproc("y.exe"), Proto: 6, Dst: dst("9.9.9.9:443"), Sites: [][]string{{"b.example.com", "x.elb.amazonaws.com"}}}, 6},
		{Flow{Proc: cproc("y.exe"), Proto: 6, Dst: dst("9.9.9.9:443"), Sites: [][]string{{"b.test"}, {"a.example.com"}}}, 4},
		// With an exact name the site names do not count.
		{Flow{Proc: cproc("y.exe"), Proto: 6, Dst: dst("9.9.9.9:443"), Name: "b.test", Sites: [][]string{{"a.example.com"}}}, 7},
		// Pending geosite counts, the unknown category does not.
		{Flow{Proc: cproc("y.exe"), Proto: 6, Dst: dst("9.9.9.9:443"), Name: "z.test"}, 7},
	}
	for i, tc := range cases {
		if got := Place(c, tc.f); got != tc.want {
			t.Errorf("case %d: Place = %d, want %d", i, got, tc.want)
		}
		if w, _ := Winner(c, tc.f); w >= 0 && Place(c, tc.f) > w {
			t.Errorf("case %d: Place > Winner %d", i, w)
		}
	}
	// Without inherit a parent does not count.
	c2 := Config{Rules: []Rule{{Apps: []AppMatch{{Pattern: "steam.exe"}}, Action: Direct}}}
	if got := Place(c2, Flow{Proc: cproc("game.exe", "steam.exe"), Proto: 6, Dst: dst("9.9.9.9:443")}); got != 1 {
		t.Fatalf("no inherit: %d", got)
	}
	// Default only: the end.
	if got := Place(Config{Rules: []Rule{{Apps: []AppMatch{{Pattern: "q.exe"}}, Action: Block}}}, Flow{Proto: 6, Dst: dst("9.9.9.9:1")}); got != 1 {
		t.Fatalf("default: %d", got)
	}
	// geoip: pending counts for any address, unknown does not; nil Geo is pending too.
	c3 := Config{Rules: []Rule{{Domains: []string{"geoip:nope"}, Action: Block}, {Domains: []string{"geoip:pend"}, Action: Block}}}
	if got := Place(c3, Flow{Proto: 6, Dst: dst("9.9.9.9:1")}); got != 1 {
		t.Fatalf("geoip: %d", got)
	}
	withGeo(t, nil)
	if got := Place(Config{Rules: []Rule{{Domains: []string{"geosite:any"}, Action: Block}}}, Flow{Proto: 6, Dst: dst("9.9.9.9:1"), Name: "a.test"}); got != 0 {
		t.Fatalf("nil geo: %d", got)
	}
}

func TestPlaceRule(t *testing.T) {
	c := Config{Rules: []Rule{
		{Domains: []string{".example.com"}, Enabled: off(), Action: Block},
		{Apps: []AppMatch{{Pattern: "y.exe"}}, Domains: []string{".other.test"}, Action: Block},
		{Domains: []string{"a.example.com"}, Action: Direct},
	}}
	if got := PlaceRule(c, Rule{Domains: []string{".example.com"}, Action: Tunnel}); got != 2 {
		t.Fatalf("%d", got)
	}
	if got := PlaceRule(c, Rule{Domains: []string{".none.test"}, Action: Tunnel}); got != 3 {
		t.Fatalf("%d", got)
	}
}

func TestWinner(t *testing.T) {
	sub := func(sites ...[]string) Flow {
		return Flow{Proc: cproc("x.exe"), Proto: 17, Dst: dst("9.9.9.9:27015"), Sites: sites}
	}
	c := Config{DefaultAction: Direct, Rules: []Rule{{Domains: []string{".example.com"}, Action: Tunnel, Profile: "S1"}}}
	chain := []string{"game.example.com", "xyz.elb.amazonaws.com"}
	if w, amb := Winner(c, sub(chain)); w != 0 || amb {
		t.Fatalf("chain: %d %v", w, amb)
	}
	c2 := c
	c2.Rules = append(slices.Clone(c.Rules), Rule{Domains: []string{".amazonaws.com"}, Action: Direct})
	if w, amb := Winner(c2, sub(chain)); w != 0 || amb {
		t.Fatalf("chain + cdn rule: %d %v", w, amb)
	}
	if w, amb := Winner(c, sub(chain, []string{"other.test"})); w != -1 || !amb {
		t.Fatalf("neighbours: %d %v", w, amb)
	}
	// Different rules, same route: not ambiguous, the first site's rule.
	c3 := Config{DefaultAction: Direct, Rules: []Rule{
		{Domains: []string{".example.com"}, Action: Tunnel, Profile: "S1"},
		{Domains: []string{".other.test"}, Action: Tunnel, Profile: "S1"},
	}}
	if w, amb := Winner(c3, sub([]string{"other.test"}, chain)); w != 1 || amb {
		t.Fatalf("same route: %d %v", w, amb)
	}
	f := sub(chain)
	f.SitesPartial = true
	if w, amb := Winner(c, f); w != 0 || !amb {
		t.Fatalf("partial: %d %v", w, amb)
	}
	if w, amb := Winner(c, Flow{Proto: 6, Dst: dst("9.9.9.9:443"), Name: "a.example.com"}); w != 0 || amb {
		t.Fatalf("name: %d %v", w, amb)
	}
	if w, amb := Winner(c, Flow{Proto: 6, Dst: dst("9.9.9.9:443")}); w != -1 || amb {
		t.Fatalf("nothing: %d %v", w, amb)
	}
}

// TestPlaceUnknownProto: a DNS-query row (protocol and port unknown).
func TestPlaceUnknownProto(t *testing.T) {
	c := Config{Rules: []Rule{
		{Domains: []string{"9.9.9.9"}, Action: Block},
		{Domains: []string{".example.com"}, Protocol: "udp", Action: Block},
		{Domains: []string{".example.com"}, Ports: PortList{"443"}, Action: Block},
		{Domains: []string{".example.com"}, Action: Tunnel},
	}}
	f := Flow{Proc: cproc("x.exe"), Name: "a.example.com"}
	// The address is unknown too: the IP rule may take the connection.
	if p := Place(c, f); p != 0 {
		t.Fatalf("Place = %d", p)
	}
	if w, _ := Winner(c, f); w != 3 {
		t.Fatalf("Winner = %d", w)
	}
	if p := Place(Config{Rules: c.Rules[1:]}, f); p != 0 {
		t.Fatalf("Place without the IP rule = %d", p)
	}
}

// TestPlaceDNSQueryBelowIPRule: a site rule from a DNS-query row goes above
// an enabled IP rule, which would otherwise decide the connection that
// follows the lookup; a disabled one or one for another program does not
// count.
func TestPlaceDNSQueryBelowIPRule(t *testing.T) {
	withGeo(t, connGeo{})
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Domains: []string{"1.2.3.0/24"}, Enabled: off(), Action: Block},
		{Apps: []AppMatch{{Pattern: "y.exe"}}, Domains: []string{"1.2.3.0/24"}, Action: Block},
		{Domains: []string{"1.2.3.0/24"}, Action: Direct},
		{Domains: []string{".example.com"}, Action: Tunnel},
	}}
	f := Flow{Proc: cproc("x.exe"), Name: "a.example.com"}
	if p := Place(c, f); p != 2 {
		t.Fatalf("Place = %d", p)
	}
	c.Rules[2].Domains = []string{"geoip:ru"}
	if p := Place(c, f); p != 2 {
		t.Fatalf("geoip: Place = %d", p)
	}
	// With the address known, the IP rule counts only when it matches.
	f.Proto, f.Dst = 6, dst("9.9.9.9:443")
	if p := Place(c, f); p != 3 {
		t.Fatalf("known address: Place = %d", p)
	}
}

// TestNamelessFlow: QUIC decided without a name (NamelessUDP): Winner and
// Place ignore the cached sites, Matches still sees them.
func TestNamelessFlow(t *testing.T) {
	c := Config{DefaultAction: Direct, Rules: []Rule{
		{Domains: []string{".example.com"}, Action: Tunnel},
		{Apps: []AppMatch{{Pattern: "x.exe"}}, Action: Block},
	}}
	f := Flow{Proc: cproc("x.exe"), Proto: 17, Dst: dst("1.2.3.4:443"), Sites: [][]string{{"a.example.com"}}}
	if w, amb := Winner(c, f); w != 0 || amb {
		t.Fatalf("named: %d %v", w, amb)
	}
	f.Nameless = true
	if w, amb := Winner(c, f); w != 1 || amb {
		t.Fatalf("nameless: %d %v", w, amb)
	}
	if p := Place(c, f); p != 1 {
		t.Fatalf("nameless: Place = %d", p)
	}
	if ok, err := Matches(c.Rules[0], f); !ok || err != nil {
		t.Fatalf("Matches = %v %v", ok, err)
	}
}

// TestWinnerAgreesWithEngine: Winner's route is the compiled Set's.
func TestWinnerAgreesWithEngine(t *testing.T) {
	withGeo(t, nil)
	rnd := rand.New(rand.NewSource(1))
	names := []string{"a.example.com", "b.example.com", "x.cdn.test", "y.cdn.test", "other.org", "z.org"}
	patterns := []string{".example.com", "a.example.com", ".cdn.test", "keyword:cdn", "other.org", "1.2.3.4", "10.0.0.0/8"}
	apps := []string{"x.exe", "y.exe"}
	pick := func(l []string) string { return l[rnd.Intn(len(l))] }
	for n := 0; n < 2000; n++ {
		c := Config{DefaultAction: Action(rnd.Intn(3)), Rules: []Rule{}}
		for i := rnd.Intn(9); i > 0; i-- {
			r := Rule{Action: Action(rnd.Intn(3))}
			if r.Action == Tunnel {
				r.Profile = []string{"", "S1", "S2"}[rnd.Intn(3)]
			}
			if rnd.Intn(3) == 0 {
				r.Apps = []AppMatch{{Pattern: pick(apps)}}
			}
			if rnd.Intn(4) != 0 || len(r.Apps) == 0 {
				r.Domains = []string{pick(patterns)}
				if rnd.Intn(3) == 0 {
					r.Domains = append(r.Domains, pick(patterns))
				}
			}
			if rnd.Intn(5) == 0 {
				r.Protocol = []string{"tcp", "udp"}[rnd.Intn(2)]
			}
			if rnd.Intn(8) == 0 {
				r.Enabled = off()
			}
			c.Rules = append(c.Rules, r)
		}
		f := Flow{Proc: cproc(pick(apps)), Proto: []uint8{6, 17}[rnd.Intn(2)],
			Dst: dst([]string{"1.2.3.4:443", "10.1.1.1:53", "8.8.8.8:80"}[rnd.Intn(3)]), Main: "M"}
		if rnd.Intn(3) == 0 && f.Proto == 17 {
			f.Nameless = true
		}
		if rnd.Intn(3) == 0 {
			f.Name = pick(names)
		} else {
			for i := rnd.Intn(4); i > 0; i-- {
				var site []string
				for j := 1 + rnd.Intn(3); j > 0; j-- {
					site = append(site, pick(names))
				}
				f.Sites = append(f.Sites, site)
			}
		}
		set, err := Compile(c)
		if err != nil {
			t.Fatal(err)
		}
		set.Main = "M"
		sub := Subject{Proc: f.Proc, Proto: f.Proto, Dst: f.Dst}
		var want Result
		needs := false
		switch {
		case f.Nameless:
			if want = set.EvaluateSites(sub, nil); want.NeedsDomain {
				want = set.EvaluateNoDomain(sub)
			}
		case f.Name != "":
			want = set.EvaluateDomain(sub, f.Name, SrcSNI)
		default:
			want = set.EvaluateSites(sub, f.Sites)
			if want.NeedsDomain {
				needs = true
				want = set.EvaluateNoDomain(sub)
			}
		}
		w, amb := Winner(c, f)
		var got Result
		if w < 0 {
			got = set.result(nil)
		} else {
			cr, _ := compileRule(w, c.Rules[w], nil)
			got = set.result(&cr)
		}
		if !sameRoute(got, want) {
			t.Fatalf("case %d: winner %d route %+v, engine %+v\n%+v\n%+v", n, w, got, want, c, f)
		}
		if f.Nameless && amb {
			t.Fatalf("case %d: nameless ambiguous", n)
		}
		if !f.Nameless && f.Name == "" && len(f.Sites) > 0 && amb != needs {
			t.Fatalf("case %d: ambiguous %v, engine NeedsDomain %v\n%+v\n%+v", n, amb, needs, c, f)
		}
		if w >= 0 && Place(c, f) > w {
			t.Fatalf("case %d: Place %d > Winner %d", n, Place(c, f), w)
		}
	}
}

func TestMatches(t *testing.T) {
	chain := Flow{Proto: 17, Dst: dst("9.9.9.9:1"), Sites: [][]string{{"game.example.com", "xyz.elb.amazonaws.com"}}}
	for _, c := range []struct {
		r    Rule
		f    Flow
		want bool
	}{
		{Rule{Domains: []string{".example.com"}}, chain, true},
		{Rule{Domains: []string{"xyz.elb.amazonaws.com"}}, chain, true},
		{Rule{Domains: []string{"9.9.9.9"}}, chain, true},
		{Rule{Apps: []AppMatch{{Pattern: "x.exe"}}}, Flow{Proc: cproc("x.exe"), Proto: 6, Dst: dst("9.9.9.9:1")}, true},
		{Rule{Apps: []AppMatch{{Pattern: "x.exe"}}}, Flow{Proc: cproc("y.exe"), Proto: 6, Dst: dst("9.9.9.9:1")}, false},
		{Rule{Domains: []string{".example.com"}}, Flow{Proto: 6, Dst: dst("9.9.9.9:1"), Name: "other.test", Sites: chain.Sites}, false},
	} {
		if got, err := Matches(c.r, c.f); got != c.want || err != nil {
			t.Errorf("%+v: %v %v", c.r, got, err)
		}
	}
	if _, err := Matches(Rule{Domains: []string{"regexp:("}}, chain); err == nil {
		t.Fatal("compile error")
	}
}

func TestCatchesName(t *testing.T) {
	withGeo(t, connGeo{})
	for _, c := range []struct {
		r    Rule
		want bool
	}{
		{Rule{Domains: []string{".cloudflare-ech.com"}}, true},
		{Rule{Domains: []string{"cloudflare-ech.com"}}, true},
		{Rule{Domains: []string{"keyword:cloudflare"}}, true},
		{Rule{Domains: []string{"geosite:foo"}}, true},
		{Rule{Domains: []string{".example.com"}}, false},
		{Rule{Apps: []AppMatch{{Pattern: "x.exe"}}}, false},
		{Rule{Domains: []string{"1.2.3.4"}}, false},
	} {
		if got, err := CatchesName(c.r, "cloudflare-ech.com"); got != c.want || err != nil {
			t.Errorf("%+v: %v %v", c.r, got, err)
		}
	}
}

func TestNarrowed(t *testing.T) {
	withGeo(t, connGeo{})
	old := Config{DefaultAction: Direct, Rules: []Rule{
		{Domains: []string{"geosite:foo"}, Action: Tunnel, Profile: "S1"},
		{Domains: []string{"geosite:bar-telemetry"}, Action: Block},
		{Domains: []string{".example.com"}, Action: Direct},
	}}
	f := Flow{Proto: 6, Dst: dst("9.9.9.9:443"), Name: "a.example.com"}
	if p := Place(old, f); p != 0 {
		t.Fatalf("place %d", p)
	}
	nw := Rule{Domains: []string{".example.com"}, Action: Tunnel, Profile: "S2"}
	c := old
	c.Rules = slices.Insert(slices.Clone(old.Rules), 0, nw)
	if got := Narrowed(c, "", 0, 1, 3); !slices.Equal(got, []int{2, 1}) {
		t.Fatalf("%v", got)
	}
	// A rule with the same route is not listed; a covered one is Shadowed.
	c.Rules[1].Profile = "S2"
	if got := Narrowed(c, "", 0, 1, 3); !slices.Equal(got, []int{2}) {
		t.Fatalf("same route: %v", got)
	}
	c.Rules[2] = Rule{Domains: []string{"b.example.com"}, Action: Block}
	if got := Narrowed(c, "", 0, 1, 3); len(got) != 0 {
		t.Fatalf("covered: %v", got)
	}
	if got := Shadowed(c, 0); !slices.Contains(got, 2) {
		t.Fatalf("shadowed %v", got)
	}
	// An empty Tunnel profile is the main target: the same route as naming it.
	c.Rules[1] = Rule{Domains: []string{"geosite:foo"}, Action: Tunnel}
	if got := Narrowed(c, "S2", 0, 1, 2); len(got) != 0 {
		t.Fatalf("main target: %v", got)
	}
	if got := Narrowed(c, "S1", 0, 1, 2); !slices.Equal(got, []int{1}) {
		t.Fatalf("other main: %v", got)
	}
}

func TestSameMatch(t *testing.T) {
	a := Rule{Apps: []AppMatch{{Pattern: "Chrome.exe"}, {Pattern: `C:\X\y.exe`}}, Domains: []string{".Example.com", "b.test"}, Action: Tunnel}
	for _, b := range []Rule{
		{Apps: []AppMatch{{Pattern: `c:/x/Y.exe`}, {Pattern: "chrome.exe", Kind: "name"}, {Pattern: "chrome.exe"}}, Domains: []string{"b.test", ".example.com"}, Protocol: "any", Action: Block},
		{App: &AppMatch{Pattern: "chrome.exe"}, Apps: []AppMatch{{Pattern: `C:\X\y.exe`}}, Domain: &DomainMatch{Pattern: "domain:example.com"}, Domains: []string{"full:b.test"}},
	} {
		if !SameMatch(a, b) {
			t.Errorf("%+v should match %+v", b, a)
		}
	}
	for _, b := range []Rule{
		{Apps: []AppMatch{{Pattern: "chrome.exe", InheritChildren: true}, {Pattern: `C:\X\y.exe`}}, Domains: []string{".example.com", "b.test"}},
		{Apps: a.Apps, Domains: []string{"example.com", "b.test"}},
		{Apps: a.Apps, Domains: a.Domains, Protocol: "udp"},
		{Apps: a.Apps, Domains: a.Domains, Ports: PortList{"443"}},
	} {
		if SameMatch(a, b) {
			t.Errorf("%+v should differ from %+v", b, a)
		}
	}
	if !SameMatch(Rule{Domains: []string{"пример.рф"}}, Rule{Domains: []string{"xn--e1afmkfd.xn--p1ai"}}) {
		t.Fatal("IDN")
	}
}

func TestIntersects(t *testing.T) {
	withGeo(t, connGeo{})
	d := func(p ...string) Rule { return Rule{Domains: p} }
	app := func(p string) Rule { return Rule{Apps: []AppMatch{{Pattern: p}}} }
	for i, c := range []struct {
		a, b Rule
		want bool
	}{
		{app("telegram.exe"), app("Telegram.exe"), true},
		{app("telegram.exe"), app("y.exe"), false},
		{app("telegram.exe"), app(`C:\T\telegram.exe`), true},
		{app(`C:\T\*.exe`), app(`C:\T\telegram.exe`), true},
		{app(`C:\T\*.exe`), app(`D:\telegram.exe`), false},
		{app(`C:\T\*.exe`), app("x.exe"), true},
		{app("x.exe"), d(".example.com"), true},
		{d(".telegram.org"), d("web.telegram.org"), true},
		{d(".telegram.org"), d("telegram.org"), true},
		{d(".telegram.org"), d(".example.com"), false},
		{d("keyword:gram"), d("web.telegram.org"), true},
		{d("keyword:zzz"), d("web.telegram.org"), false},
		{d("keyword:zzz"), d(".telegram.org"), true},
		{d("regexp:^web\\."), d("web.telegram.org"), true},
		{d("regexp:^web\\."), d("api.telegram.org"), false},
		{d("geosite:foo"), d("a.test"), true},
		{d("geosite:nope"), d("a.test"), false},
		{d("geosite:known"), d("known.test"), true},
		{d("geosite:known"), d("other.test"), false},
		{d("geosite:known"), d("geosite:known"), true},
		{d("geosite:known"), d("keyword:x"), true},
		{d("geosite:nope"), d("keyword:x"), false},
		{d("10.0.0.0/8"), d("10.1.0.0/16"), true},
		{d("10.0.0.0/8"), d("11.0.0.0/8"), false},
		{d("geoip:pend"), d("1.2.3.4"), true},
		{d("geoip:nope"), d("1.2.3.4"), false},
		{d("geoip:ru"), d("77.88.1.1"), true},
		{d("geoip:ru"), d("geoip:RU"), true},
		{d("geoip:ru"), d("geoip:pend"), false},
		{d(".example.com"), d("1.2.3.4"), false},
		{Rule{Domains: []string{".x.test"}, Protocol: "tcp"}, Rule{Domains: []string{".x.test"}, Protocol: "udp"}, false},
		{Rule{Domains: []string{".x.test"}, Ports: PortList{"443"}}, Rule{Domains: []string{".x.test"}, Ports: PortList{"80"}}, false},
	} {
		for k := range 2 {
			a, b := c.a, c.b
			if k == 1 {
				a, b = b, a
			}
			a.Action, b.Action = Block, Block
			if got := Intersects(a, b); got != c.want {
				t.Errorf("case %d/%d: %v", i, k, got)
			}
		}
	}
}

func TestOverriddenByTelegram(t *testing.T) {
	c := Config{Rules: []Rule{
		{Apps: []AppMatch{{Pattern: "telegram.exe"}}, Domains: []string{".telegram.org"}, Action: Tunnel, Profile: "NL"},
		{Apps: []AppMatch{{Pattern: "y.exe"}}, Action: Direct},
		{Domains: []string{".example.com"}, Action: Block},
	}}
	c.Rules = slices.Insert(c.Rules, 2, Rule{Apps: []AppMatch{{Pattern: "Telegram.exe", InheritChildren: true}}, Action: Direct})
	if got := OverriddenBy(c, 2); !slices.Equal(got, []int{0}) {
		t.Fatalf("%v", got)
	}
}

func TestShadowed(t *testing.T) {
	c := Config{Rules: []Rule{
		{Apps: []AppMatch{{Pattern: "x.exe"}}, Action: Direct},
		{Apps: []AppMatch{{Pattern: "x.exe"}}, Domains: []string{".a.test"}, Action: Block},
		{Apps: []AppMatch{{Pattern: "y.exe"}}, Action: Block},
	}}
	if got := Shadowed(c, 0); !slices.Equal(got, []int{1}) {
		t.Fatalf("%v", got)
	}
}

func TestPending(t *testing.T) {
	withGeo(t, connGeo{})
	for src, want := range map[string]bool{"geosite:foo": true, "geosite:nope": false, "geoip:pend": true, "geoip:nope": false} {
		cr, err := compileRule(0, Rule{Domains: []string{src}, Action: Block}, currentGeo())
		if err != nil {
			t.Fatal(err)
		}
		got := len(cr.doms) > 0 && cr.doms[0].pending || len(cr.ips) > 0 && cr.ips[0].pending
		if got != want || len(cr.warns) != 1 {
			t.Errorf("%s: pending %v warns %q", src, got, cr.warns)
		}
	}
	cr, _ := compileRule(0, Rule{Domains: []string{"geosite:x", "geoip:y"}}, nil)
	if !cr.doms[0].pending || !cr.ips[0].pending {
		t.Fatal("nil geo")
	}
	if !errors.Is(fmt.Errorf("x: %w", ErrGeoNoData), ErrGeoNoData) {
		t.Fatal("sentinel")
	}
}
