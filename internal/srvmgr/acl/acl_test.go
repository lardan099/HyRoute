package acl

import (
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/hyconfig"
	hacl "github.com/lardan099/hyroute/third_party/hysteria-acl"
	"github.com/lardan099/hyroute/third_party/hysteria-acl/v2geo"
)

// foreign are ACLs written by hand or by other tools.
var foreign = []string{
	"",
	"direct(all)",
	// The example of Hysteria's documentation.
	`# Comments
reject(suffix:v2ex.com)
reject(all, udp/443)
reject(geoip:cn)
reject(geosite:netflix)

direct(192.168.0.0/16)
v4_only(suffix:google.com)
v6_only(2001:db8::/32, tcp/80)
my_proxy(*.example.com, tcp)
direct(example.org, udp/53, 1.1.1.1)
`,
	// Odd spacing, case, CRLF, comments everywhere, a line Hysteria
	// cannot read, HyRoute's marks.
	"  Direct( 1.2.3.4 ,TCP/443 )   #  note  \r\n\r\n#~group Реклама\r\n reject(geosite:category-ads-all@ads)\r\n#~off direct(all) # later\r\n#~group\r\nnot a rule\r\n#~off not a rule either\r\n# end\r\n",
	"#~group A\n#~group B\ndirect(all)\n#~group C\n",
	"\n\n\n",
}

func TestRoundTrip(t *testing.T) {
	for _, text := range foreign {
		d := Parse(text)
		if got := d.Text(); got != text {
			t.Errorf("Text() changed\nwant %q\n got %q", text, got)
		}
		lines := strings.Split(text, "\n")
		if got := ParseInline(lines).Inline(); text != "" && !slices.Equal(got, lines) {
			t.Errorf("Inline() changed\nwant %q\n got %q", lines, got)
		}
		// The text Hysteria reads has the same rules.
		want, err1 := hacl.ParseTextRules(text)
		got, err2 := hacl.ParseTextRules(d.Text())
		if (err1 == nil) != (err2 == nil) || len(want) != len(got) {
			t.Errorf("Hysteria reads %d rules (%v), then %d (%v)", len(want), err1, len(got), err2)
		}
	}
}

func TestParse(t *testing.T) {
	d := Parse(foreign[3])
	want := []Rule{
		{Outbound: "Direct", Address: "1.2.3.4", Proto: "tcp", Port: "443", Comment: "note"},
		{Outbound: "reject", Address: "geosite:category-ads-all@ads", Group: "Реклама"},
		{Outbound: "direct", Address: "all", Comment: "later", Off: true, Group: "Реклама"},
		{},
	}
	if len(d.Rules) != len(want) {
		t.Fatalf("%d rules: %+v", len(d.Rules), d.Rules)
	}
	for i, w := range want {
		r := d.Rules[i]
		if !same(r, w) || r.Group != w.Group {
			t.Errorf("rule %d: %+v, want %+v", i, r, w)
		}
	}
	if !d.Rules[3].Bad() || d.Rules[3].Text != "not a rule\r" || d.Rules[3].Group != "" {
		t.Errorf("bad line: %+v", d.Rules[3])
	}
	if d.Rules[1].Before[1] != "#~group Реклама\r" {
		t.Errorf("before: %q", d.Rules[1].Before)
	}
	if len(d.Tail) != 3 || d.Tail[0] != "#~off not a rule either\r" {
		t.Errorf("tail %q", d.Tail)
	}

	pp := map[string][2]string{"": {}, "*": {}, "*/*": {}, "tcp": {"tcp", ""}, "UDP/53": {"udp", "53"}, "*/80-90": {"", "80-90"}, "tcp/*": {"tcp", ""}, "icmp": {"icmp", ""}}
	for in, w := range pp {
		if p, q := splitProtoPort(in); p != w[0] || q != w[1] {
			t.Errorf("%q: %q %q", in, p, q)
		}
	}
}

// Changing a rule rewrites its line only; the comments around it stay.
func TestEdit(t *testing.T) {
	d := Parse(foreign[2])
	d.Rules[1].Outbound = "direct"
	d.Rules[8].Hijack = ""
	d.Rules[8].Comment = "DNS"
	want := strings.Replace(foreign[2], "reject(all, udp/443)", "direct(all, udp/443)", 1)
	want = strings.Replace(want, "direct(example.org, udp/53, 1.1.1.1)", "direct(example.org, udp/53) # DNS", 1)
	if got := d.Text(); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}

	// New rules in canonical form.
	for _, c := range []struct {
		r    Rule
		line string
	}{
		{Rule{Outbound: "direct", Address: "all"}, "direct(all)"},
		{Rule{Outbound: "proxy", Address: "1.2.3.4", Port: "443"}, "proxy(1.2.3.4, */443)"},
		{Rule{Outbound: "proxy", Address: "1.2.3.4", Proto: "udp"}, "proxy(1.2.3.4, udp)"},
		{Rule{Outbound: "direct", Address: "example.org", Hijack: "1.1.1.1"}, "direct(example.org, *, 1.1.1.1)"},
		{Rule{Outbound: "reject", Address: "geoip:cn", Off: true, Comment: "позже"}, "#~off reject(geoip:cn) # позже"},
		{Rule{Outbound: "a", Address: "b", Proto: "tcp", Port: "1-2", Hijack: "::1"}, "a(b, tcp/1-2, ::1)"},
	} {
		if got := c.r.line(); got != c.line {
			t.Errorf("%+v: %q, want %q", c.r, got, c.line)
		}
	}

	// Moving a rule moves its comments.
	d = Parse("# first\ndirect(a.com)\n# second\nreject(b.com)")
	d.Rules[0], d.Rules[1] = d.Rules[1], d.Rules[0]
	if got := d.Text(); got != "# second\nreject(b.com)\n# first\ndirect(a.com)" {
		t.Fatalf("moved: %q", got)
	}
}

func TestGroups(t *testing.T) {
	d := Document{Rules: []Rule{
		{Outbound: "reject", Address: "geosite:category-ads-all", Group: "Реклама"},
		{Outbound: "reject", Address: "suffix:ads.example", Group: "Реклама"},
		{Outbound: "direct", Address: "geoip:ru"},
		{Outbound: "proxy", Address: "all", Group: "Остальное"},
	}}
	text := d.Text()
	want := "#~group Реклама\nreject(geosite:category-ads-all)\nreject(suffix:ads.example)\n#~group\ndirect(geoip:ru)\n#~group Остальное\nproxy(all)"
	if text != want {
		t.Fatalf("got\n%s", text)
	}
	back := Parse(text)
	for i, r := range back.Rules {
		if r.Group != d.Rules[i].Group {
			t.Errorf("rule %d in %q", i, r.Group)
		}
	}
	if back.Text() != text {
		t.Fatal("not stable")
	}
	// Into another group: the stale header goes, a new one comes; a
	// header that changes nothing stays (the text is kept as written).
	back.Rules[1].Group = ""
	back.Rules[0].Group = "Блок"
	if got := back.Text(); got != "#~group Блок\nreject(geosite:category-ads-all)\n#~group\nreject(suffix:ads.example)\n#~group\ndirect(geoip:ru)\n#~group Остальное\nproxy(all)" {
		t.Fatalf("regrouped:\n%s", got)
	}
}

// testGeo is a small database: geoip ru, private; geosite google with an
// ads entry.
type testGeo struct{}

func (testGeo) LoadGeoIP() (map[string]*v2geo.GeoIP, error) {
	return map[string]*v2geo.GeoIP{
		"ru":      {CountryCode: "RU", Cidr: []*v2geo.CIDR{{Ip: net.IPv4(5, 0, 0, 0).To4(), Prefix: 8}}},
		"private": privateGeoIP,
	}, nil
}

func (testGeo) LoadGeoSite() (map[string]*v2geo.GeoSite, error) {
	return map[string]*v2geo.GeoSite{"google": {CountryCode: "GOOGLE", Domain: []*v2geo.Domain{
		{Type: v2geo.Domain_RootDomain, Value: "google.com"},
		{Type: v2geo.Domain_Full, Value: "ads.google.com", Attribute: []*v2geo.Domain_Attribute{{Key: "ads"}}},
	}}}, nil
}

// codes are the problem codes per rule (-1: the whole ACL).
func codes(ps []Problem) map[int][]string {
	m := map[int][]string{}
	for _, p := range ps {
		m[p.Rule] = append(m[p.Rule], p.Code)
	}
	return m
}

// safe are rules that keep the private-network lint quiet.
const safe = "reject(geoip:private)\n"

func TestCheckCompiler(t *testing.T) {
	text := safe + strings.Join([]string{
		"proxy(all)",                       // 1 unknown outbound
		"direct(all, tcp/70000)",           // 2
		"direct(all, icmp)",                // 3
		"direct(all, udp/90-80)",           // 4
		"direct(example.com, *, foo)",      // 5
		"direct(10.0.0.0/33)",              // 6
		"direct(geoip:)",                   // 7
		"direct(geosite:)",                 // 8
		"direct(suffix:)",                  // 9
		"direct(geoip:zz)",                 // 10
		"direct(geosite:nope@ads)",         // 11
		"what is this",                     // 12
		"Default(geosite:google@ads, tcp)", // 13 fine
		"#~off proxy(all)",                 // 14 off: not checked
	}, "\n")
	ps := Check(Parse(text), Env{Geo: testGeo{}})
	want := map[int]string{1: "unknown_outbound", 2: "bad_port", 3: "bad_port", 4: "bad_port", 5: "bad_hijack", 6: "bad_cidr",
		7: "empty_geo", 8: "empty_geo", 9: "empty_suffix", 10: "unknown_geo", 11: "unknown_geo", 12: "syntax"}
	got := codes(ps)
	for i, c := range want {
		if !slices.Contains(got[i], c) {
			t.Errorf("rule %d: %v, want %s", i, got[i], c)
		}
	}
	for _, i := range []int{0, 13, 14} {
		if len(got[i]) != 0 {
			t.Errorf("rule %d: %v", i, got[i])
		}
	}
	for _, p := range ps {
		if p.Code == "unknown_outbound" && (p.Line != 2 || p.Message != "Нет выхода «proxy»: добавьте его в outbounds или выберите другой." || p.Detail != "outbound proxy not found") {
			t.Errorf("%+v", p)
		}
	}

	// The config's outbounds; without a database geo names pass, empty
	// ones do not.
	ps = Check(Parse(safe+"proxy(geoip:zz)\nproxy(geosite:nope)\nPROXY(geoip:)\nnope(geoip:zz)"), Env{Outbounds: []string{"Proxy"}})
	if got := codes(ps); len(got[1])+len(got[2]) != 0 || !slices.Equal(got[3], []string{"empty_geo"}) || !slices.Equal(got[4], []string{"unknown_outbound"}) {
		t.Fatalf("without geo: %v", got)
	}

	// Fields the line cannot hold.
	d := Parse(safe)
	d.Rules = append(d.Rules, Rule{Outbound: "direct", Address: "a.com, tcp"}, Rule{Outbound: "my-proxy", Address: "all"}, Rule{Outbound: "direct", Address: "x # y"}, Rule{Outbound: "direct", Address: "all", Group: "a\nb"})
	if got := codes(Check(d, Env{Outbounds: []string{"my-proxy"}})); !slices.Equal(got[1], []string{"chars"}) || !slices.Equal(got[2], []string{"outbound_name"}) || !slices.Equal(got[3], []string{"chars"}) || !slices.Equal(got[4], []string{"chars"}) {
		t.Fatalf("fields: %v", got)
	}
}

func TestLintShadowed(t *testing.T) {
	cases := []struct {
		above, below string
		code         string // "": none
	}{
		{"proxy(all)", "direct(example.com)", "shadowed"},
		{"proxy(*)", "direct(11.0.0.0/8, udp/53)", "shadowed"},
		{"proxy(suffix:example.com)", "direct(www.example.com)", "shadowed"},
		{"proxy(suffix:example.com)", "direct(example.com)", "shadowed"},
		{"proxy(suffix:example.com)", "direct(suffix:a.example.com)", "shadowed"},
		{"proxy(suffix:example.com)", "direct(*.example.com)", "shadowed"},
		{"proxy(suffix:example.com)", "direct(notexample.com)", ""},
		{"proxy(suffix:example.com)", "direct(*example.com)", ""},
		{"proxy(*.example.com)", "direct(a.example.com)", "shadowed"},
		{"proxy(*.example.com)", "direct(example.com)", ""},
		{"proxy(*.com)", "direct(suffix:example.com)", "shadowed"},
		{"proxy(*example.com)", "direct(*.example.com)", "shadowed"},
		{"proxy(Example.COM.)", "direct(example.com)", "shadowed"},
		{"proxy(11.0.0.0/8)", "direct(11.1.2.3)", "shadowed"},
		{"proxy(11.0.0.0/8)", "direct(11.1.0.0/16)", "shadowed"},
		{"proxy(11.1.0.0/16)", "direct(11.0.0.0/8)", ""},
		{"proxy(11.0.0.0/8)", "direct(example.com)", ""},
		{"proxy(suffix:example.com)", "direct(1.2.3.4)", ""},
		{"proxy(geoip:ru)", "direct(5.6.7.8)", "shadowed"},
		{"proxy(geoip:ru)", "direct(6.6.7.8)", ""},
		{"proxy(geosite:google)", "direct(mail.google.com)", "shadowed"},
		{"proxy(geosite:google)", "direct(geosite:google@ads)", "shadowed"},
		{"proxy(geosite:google@ads)", "direct(geosite:google)", ""},
		{"proxy(all, tcp)", "direct(a.com)", ""},
		{"proxy(all, tcp)", "direct(a.com, tcp/443)", "shadowed"},
		{"proxy(all, */400-500)", "direct(a.com, udp/443)", "shadowed"},
		{"proxy(all, */400-500)", "direct(a.com, udp/300-450)", ""},
		{"proxy(all, */443)", "direct(a.com)", ""},
		{"direct(a.com, tcp/443)", "direct(A.com, TCP/443)", "duplicate"},
		{"direct(a.com, *, 1.1.1.1)", "direct(a.com, *, 1.1.1.1)", "duplicate"},
		{"direct(a.com)", "proxy(a.com)", "shadowed"},
		{"#~off proxy(all)", "direct(a.com)", ""},
	}
	for _, c := range cases {
		ps := Check(Parse(safe+c.above+"\n"+c.below), Env{Outbounds: []string{"proxy"}, Geo: testGeo{}})
		var got string
		for _, p := range ps {
			if p.Rule == 2 {
				got = p.Code
				if p.Other == nil || *p.Other != 1 {
					t.Errorf("%s / %s: other %v", c.above, c.below, p.Other)
				}
			}
		}
		if got != c.code {
			t.Errorf("%s / %s: %q, want %q", c.above, c.below, got, c.code)
		}
	}
}

func TestLintPrivate(t *testing.T) {
	quiet := []string{
		safe,
		"reject(127.0.0.0/8)\nreject(::1)\nreject(10.0.0.0/8)\nreject(172.16.0.0/12)\nreject(192.168.0.0/16)\nreject(169.254.0.0/16)\nreject(fc00::/7)\nreject(fe80::/10)\ndirect(all)",
		"direct(suffix:example.com)\nreject(geoip:private)\nproxy(all)",
	}
	for _, text := range quiet {
		if got := codes(Check(Parse(text), Env{Outbounds: []string{"proxy"}})); len(got[-1]) != 0 {
			t.Errorf("%q: %v", text, got)
		}
	}
	for text, open := range map[string][]string{
		"":                     {"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"},
		"direct(all)\n" + safe: {"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10"},
		"reject(127.0.0.0/8, tcp)\nreject(geoip:private, udp)\nreject(::/0)\nreject(10.0.0.0/8)\nreject(172.16.0.0/12)\nreject(192.168.0.0/16)\ndirect(169.254.169.254, tcp/80)\nreject(169.254.0.0/16)": {"127.0.0.0/8", "169.254.0.0/16"},
	} {
		ps := Check(Parse(text), Env{})
		var fix []string
		for _, p := range ps {
			if p.Code == "private" {
				for _, r := range p.Fix {
					fix = append(fix, r.Address)
				}
				if p.Rule != -1 || p.Level != Warn {
					t.Errorf("%+v", p)
				}
			}
		}
		if !slices.Equal(fix, open) {
			t.Errorf("%q: %v, want %v", text, fix, open)
		}
		// Applying the fix at the top quiets it.
		for _, p := range ps {
			if p.Code == "private" {
				d := Parse(text)
				d.Rules = append(slices.Clone(p.Fix), d.Rules...)
				if got := codes(Check(d, Env{})); slices.Contains(got[-1], "private") {
					t.Errorf("%q: fixed, still %v", text, got)
				}
			}
		}
	}
	// A user outbound named reject is not the built-in one: no advice.
	if got := codes(Check(Parse(""), Env{Outbounds: []string{"Reject"}})); len(got[-1]) != 0 {
		t.Fatalf("user reject: %v", got)
	}
}

func TestLintResolver(t *testing.T) {
	for _, c := range []struct {
		text, resolver string
		entry, warn    bool
	}{
		{safe, "", true, true},
		{safe, "system", true, true},
		{safe, "udp", true, true},
		{safe, "https", true, false},
		{safe, "tls", true, false},
		{safe, "", false, false},
		{"", "", true, false},
		{"", "tcp", true, true},
		{"# only a comment", "", true, true},
	} {
		ps := Check(Parse(c.text), Env{Entry: c.entry, Resolver: hyconfig.Resolver{Type: c.resolver}})
		if got := slices.Contains(codes(ps)[-1], "plain_resolver"); got != c.warn {
			t.Errorf("%+v: %v", c, got)
		}
	}
}

func TestLintPunycode(t *testing.T) {
	ps := Check(Parse(safe+"direct(xn--d1acpjx3f.xn--p1ai)\ndirect(suffix:xn--p1ai)\ndirect(*.xn--p1ai)\ndirect(пример.рф)\ndirect(example.com)"), Env{})
	var msgs []string
	for _, p := range ps {
		if p.Code == "punycode" {
			msgs = append(msgs, p.Message)
		}
	}
	if len(msgs) != 3 || !strings.Contains(msgs[0], "«яндекс.рф»") || !strings.Contains(msgs[1], "«suffix:рф»") || !strings.Contains(msgs[2], "«*.рф»") {
		t.Fatalf("%q", msgs)
	}
}

func TestKindOf(t *testing.T) {
	for a, k := range map[string]string{
		"all": KindAll, "*": KindAll, "ALL": KindAll, "1.2.3.4": KindIP, "::1": KindIP, "10.0.0.0/8": KindCIDR,
		"example.com": KindDomain, "Example.com.": KindDomain, "*.example.com": KindWildcard, "suffix:example.com": KindSuffix,
		"geoip:ru": KindGeoIP, "GeoSite:google@ads": KindGeoSite,
	} {
		if got := KindOf(a); got != k {
			t.Errorf("%s: %s, want %s", a, got, k)
		}
	}
}

func TestEnvOf(t *testing.T) {
	c := &hyconfig.Server{Outbounds: []hyconfig.Outbound{{Name: "cascade"}, {Name: "direct"}}, Resolver: hyconfig.Resolver{Type: "https"}}
	if e := EnvOf(c); !reflect.DeepEqual(e.Outbounds, []string{"cascade", "direct"}) || e.Resolver.Type != "https" {
		t.Fatalf("%+v", e)
	}
}
